// Package identity manages Hub service Ed25519 identity material.
//
// Hub authenticates WebSocket connections with short-lived signed tokens.
// Token format matches the Bun hub-service keychain:
//
//	key.{publicKeyBase64}.{signatureBase64}.{expiryUnixSeconds}
//
// The signature is Ed25519 over the ASCII expiry string. Identity material is
// stored as the Bun keychain format: base64 of PKCS8 DER private key (48 bytes)
// concatenated with SPKI DER public key (44 bytes).
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// privateKeyDERBytes is the length of a PKCS8-encoded Ed25519 private key.
const privateKeyDERBytes = 48

// publicKeyDERBytes is the length of an SPKI-encoded Ed25519 public key.
const publicKeyDERBytes = 44

// Identity holds an Ed25519 service identity used to authenticate with Hub.
type Identity struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// Load reads identity material from the given path, generating and persisting a
// fresh identity when the file is absent or empty.
func Load(path string) (*Identity, error) {
	encoded, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("identity: read %s: %w", path, err)
	}
	trimmed := strings.TrimSpace(string(encoded))
	if trimmed != "" {
		return parseIdentity(trimmed)
	}
	generated, err := Generate()
	if err != nil {
		return nil, err
	}
	if err := generated.Save(path); err != nil {
		return nil, err
	}
	return generated, nil
}

// Generate creates a new random Ed25519 identity.
func Generate() (*Identity, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate key: %w", err)
	}
	return &Identity{privateKey: privateKey, publicKey: publicKey}, nil
}

// parseIdentity decodes the Bun keychain base64 blob back into key material.
func parseIdentity(encoded string) (*Identity, error) {
	combined, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("identity: decode base64: %w", err)
	}
	if len(combined) != privateKeyDERBytes+publicKeyDERBytes {
		return nil, fmt.Errorf("identity: unexpected key material length %d", len(combined))
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(combined[:privateKeyDERBytes])
	if err != nil {
		return nil, fmt.Errorf("identity: parse private key: %w", err)
	}
	ed25519PrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("identity: private key is not Ed25519")
	}
	publicKey, err := x509.ParsePKIXPublicKey(combined[privateKeyDERBytes:])
	if err != nil {
		return nil, fmt.Errorf("identity: parse public key: %w", err)
	}
	ed25519PublicKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("identity: public key is not Ed25519")
	}
	return &Identity{privateKey: ed25519PrivateKey, publicKey: ed25519PublicKey}, nil
}

// Save persists the identity in the Bun keychain format.
func (i *Identity) Save(path string) error {
	encoded, err := i.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(encoded), 0o600); err != nil {
		return fmt.Errorf("identity: write %s: %w", path, err)
	}
	return nil
}

// Encode returns the base64 PKCS8-private || SPKI-public blob.
func (i *Identity) Encode() (string, error) {
	privateDER, err := x509.MarshalPKCS8PrivateKey(i.privateKey)
	if err != nil {
		return "", fmt.Errorf("identity: marshal private key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(i.publicKey)
	if err != nil {
		return "", fmt.Errorf("identity: marshal public key: %w", err)
	}
	combined := make([]byte, 0, len(privateDER)+len(publicDER))
	combined = append(combined, privateDER...)
	combined = append(combined, publicDER...)
	return base64.StdEncoding.EncodeToString(combined), nil
}

// PublicKey returns the Ed25519 public key.
func (i *Identity) PublicKey() ed25519.PublicKey { return i.publicKey }

// PrivateKey returns the Ed25519 private key. Required by callers that sign
// envelopes in non-Hub domains (for example, the hub-net agent signing local
// share attestations). Callers MUST treat the return value as secret.
func (i *Identity) PrivateKey() ed25519.PrivateKey { return i.privateKey }

// PublicKeyBase64 returns the SPKI public key encoded as base64, matching the
// Bun keychain public-key representation.
func (i *Identity) PublicKeyBase64() (string, error) {
	publicDER, err := x509.MarshalPKIXPublicKey(i.publicKey)
	if err != nil {
		return "", fmt.Errorf("identity: marshal public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(publicDER), nil
}

// PEMPublicKey returns the public key as a PEM-encoded SPKI block.
func (i *Identity) PEMPublicKey() (string, error) {
	publicDER, err := x509.MarshalPKIXPublicKey(i.publicKey)
	if err != nil {
		return "", fmt.Errorf("identity: marshal public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}
	return string(pem.EncodeToMemory(block)), nil
}

// Sign produces an Ed25519 signature over data, returned base64-encoded.
func (i *Identity) Sign(data []byte) string {
	signature := ed25519.Sign(i.privateKey, data)
	return base64.StdEncoding.EncodeToString(signature)
}

// SignChallenge signs a local-agent challenge nonce string. The signature is
// Ed25519 over the raw nonce bytes, base64-encoded — matching the Bun
// signNetworkChallenge behavior used for local-agent attestation.
func (i *Identity) SignChallenge(nonce string) (string, error) {
	return i.Sign([]byte(nonce)), nil
}

// AuthToken returns a short-lived Hub authentication token valid for the given
// duration. Format: key.{publicKeyBase64}.{signatureBase64}.{expiryUnixSeconds}
func (i *Identity) AuthToken(validFor time.Duration) (string, error) {
	publicKey, err := i.PublicKeyBase64()
	if err != nil {
		return "", err
	}
	expiry := time.Now().Add(validFor).Unix()
	data := fmt.Sprintf("%d", expiry)
	signature := i.Sign([]byte(data))
	return fmt.Sprintf("key.%s.%s.%s", publicKey, signature, data), nil
}
