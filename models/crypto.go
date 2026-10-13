// crypto.go is the Go mirror of hub-pro src/network/crypto.ts.
//
// Hub Network signs four envelope types in purpose-separated domains so a
// signature for one cannot be replayed as another. The wire bytes are
// canonical-JSON UTF-8 prefixed with the ASCII domain string, a NUL byte, a
// four-byte big-endian payload length, and the payload. This file keeps the
// Go signing/verifying byte-for-byte compatible with the Bun implementation
// so test vectors in testdata/crypto-v1.json pass on both sides.
package models

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SignaturePurpose labels a Hub Network signature domain.
type SignaturePurpose string

const (
	PurposeAgentAttestation        SignaturePurpose = "agent-attestation"
	PurposeProfileBinding          SignaturePurpose = "profile-binding"
	PurposeConnectionGrant         SignaturePurpose = "connection-grant"
	PurposeRendezvousTicket        SignaturePurpose = "rendezvous-ticket"
	PurposeNetworkInvitation       SignaturePurpose = "network-invitation"
	PurposeAppleAppAgentReadiness  SignaturePurpose = "apple-app-agent-readiness"
	PurposeDirectBootstrapRequest  SignaturePurpose = "direct-bootstrap-request"
	PurposeDirectBootstrapResponse SignaturePurpose = "direct-bootstrap-response"
	PurposeInviterRegistration     SignaturePurpose = "inviter-registration"
)

// SignatureDomains maps each purpose to its ASCII domain string. Matches the
// Bun SIGNATURE_DOMAINS exactly so signatures cross-verify.
var SignatureDomains = map[SignaturePurpose]string{
	PurposeAgentAttestation:        "hub-network/agent-attestation/v1",
	PurposeProfileBinding:          "hub-network/profile-binding/v1",
	PurposeConnectionGrant:         "hub-network/connection-grant/v1",
	PurposeRendezvousTicket:        "hub-network/rendezvous-ticket/v1",
	PurposeNetworkInvitation:       "hub-network/invitation/v1",
	PurposeAppleAppAgentReadiness:  "hub-network/apple-app-agent-readiness/v1",
	PurposeDirectBootstrapRequest:  "hub-network/direct-bootstrap-request/v1",
	PurposeDirectBootstrapResponse: "hub-network/direct-bootstrap-response/v1",
	PurposeInviterRegistration:     "hub-network/inviter-registration/v1",
}

// DomainFor returns the ASCII domain string for purpose.
func DomainFor(purpose SignaturePurpose) (string, error) {
	domain, ok := SignatureDomains[purpose]
	if !ok {
		return "", fmt.Errorf("protocol: unknown signature purpose %q", purpose)
	}
	return domain, nil
}

// ConnectionGrantMaxLifetime bounds a connection grant's validity. Matches
// Bun CONNECTION_GRANT_MAX_LIFETIME_MS.
const ConnectionGrantMaxLifetime = 5 * time.Minute

// RendezvousTicketMaxLifetime bounds a rendezvous ticket's validity.
const RendezvousTicketMaxLifetime = 10 * time.Minute

// DirectBootstrapMaxLifetime bounds a direct bootstrap response's validity. The
// temporary tunnel is meant to last only until the joiner reaches hub-pro and
// performs an ordinary bind, which replaces it with permanent addresses.
const DirectBootstrapMaxLifetime = 10 * time.Minute

// AttestationMaxLifetime bounds an agent attestation's validity.
const AttestationMaxLifetime = 10 * time.Minute

// MaxClockSkew allows for clock drift when comparing issuedAt to now.
const MaxClockSkew = 30 * time.Second

// CanonicalJSON returns the deterministic JSON encoding used in Hub Network
// signatures. Object keys are sorted; undefined-valued map entries are
// dropped; arrays preserve order; numbers use JSON's default rendering. The
// result mirrors Bun canonicalJSON byte-for-byte for the envelope shapes Hub
// Network signs.
func CanonicalJSON(value any) (string, error) {
	return canonicalJSON(value)
}

func canonicalJSON(value any) (string, error) {
	switch v := value.(type) {
	case nil:
		return "null", nil
	case bool:
		if v {
			return "true", nil
		}
		return "false", nil
	case string:
		encoded, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(encoded), nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		encoded, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(encoded), nil
	case json.Number:
		return string(v), nil
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			encoded, err := canonicalJSON(item)
			if err != nil {
				return "", err
			}
			parts = append(parts, encoded)
		}
		return "[" + strings.Join(parts, ",") + "]", nil
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key, val := range v {
			if val == nil {
				continue
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			encoded, err := canonicalJSON(v[key])
			if err != nil {
				return "", err
			}
			keyJSON, err := json.Marshal(key)
			if err != nil {
				return "", err
			}
			parts = append(parts, string(keyJSON)+":"+encoded)
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	default:
		// Re-encode through JSON so structs (envelopes) become map[string]any
		// and drop omitempty fields consistently. The Bun side signs a plain
		// object that omits undefined fields; encoding/json with omitempty
		// produces the same key set for our envelope structs.
		raw, err := json.Marshal(v)
		if err != nil {
			return "", fmt.Errorf("protocol: unsupported signed value %T: %w", v, err)
		}
		var decoded any
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.UseNumber()
		if err := dec.Decode(&decoded); err != nil {
			return "", err
		}
		return canonicalJSON(decoded)
	}
}

// SignatureInput returns the signed bytes for an envelope. envelope is the
// full record (with or without a signature field); the signature field is
// removed before signing. The output is
//
//	domain || 0x00 || uint32BE(payloadLen) || payload
//
// matching Bun signatureInput.
func SignatureInput(purpose SignaturePurpose, envelope any) ([]byte, error) {
	domain, err := DomainFor(purpose)
	if err != nil {
		return nil, err
	}
	stripped, err := stripSignature(envelope)
	if err != nil {
		return nil, err
	}
	payload, err := canonicalJSON(stripped)
	if err != nil {
		return nil, err
	}
	return assembleSignatureInput(domain, []byte(payload)), nil
}

// assembleSignatureInput concatenates the framing bytes.
func assembleSignatureInput(domain string, payload []byte) []byte {
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(payload)))
	out := make([]byte, 0, len(domain)+1+4+len(payload))
	out = append(out, domain...)
	out = append(out, 0)
	out = append(out, length...)
	out = append(out, payload...)
	return out
}

// stripSignature returns a copy of envelope without the signature field. Map
// values are copied so callers retain their original.
func stripSignature(envelope any) (any, error) {
	if envelope == nil {
		return nil, errors.New("protocol: nil envelope")
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}
	delete(decoded, "signature")
	return decoded, nil
}

// SignEnvelope signs envelope with privateKey and returns the base64
// signature. The envelope's signature field (if any) is ignored.
func SignEnvelope(purpose SignaturePurpose, envelope any, privateKey ed25519.PrivateKey) (string, error) {
	input, err := SignatureInput(purpose, envelope)
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(privateKey, input)
	return base64.StdEncoding.EncodeToString(signature), nil
}

// VerifyEnvelope reports whether signature is a valid Ed25519 signature over
// envelope under publicKey.
func VerifyEnvelope(purpose SignaturePurpose, envelope any, publicKey ed25519.PublicKey, signature string) (bool, error) {
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("protocol: decode signature: %w", err)
	}
	input, err := SignatureInput(purpose, envelope)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(publicKey, input, sigBytes), nil
}

// SignatureInputForBytes returns the signed bytes for a raw byte payload under
// purpose. The framing is identical to SignatureInput
// (domain || 0x00 || uint32BE(len) || payload); it exists for signatures over
// non-envelope payloads such as the online-inviter registration nonce.
func SignatureInputForBytes(purpose SignaturePurpose, payload []byte) ([]byte, error) {
	domain, err := DomainFor(purpose)
	if err != nil {
		return nil, err
	}
	return assembleSignatureInput(domain, payload), nil
}

// SignBytes signs a raw byte payload with privateKey under purpose and returns
// the base64 signature. Use for non-envelope payloads (e.g. challenge nonces).
func SignBytes(purpose SignaturePurpose, payload []byte, privateKey ed25519.PrivateKey) (string, error) {
	input, err := SignatureInputForBytes(purpose, payload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, input)), nil
}

// VerifyBytes reports whether signature is a valid Ed25519 signature over a raw
// byte payload under purpose.
func VerifyBytes(purpose SignaturePurpose, payload []byte, publicKey ed25519.PublicKey, signature string) (bool, error) {
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("protocol: decode signature: %w", err)
	}
	input, err := SignatureInputForBytes(purpose, payload)
	if err != nil {
		return false, err
	}
	return ed25519.Verify(publicKey, input, sigBytes), nil
}

// HashSignatureInput returns the SHA-256 hex digest of the signature input.
// Used by conformance tests that pin the canonical bytes.
func HashSignatureInput(purpose SignaturePurpose, envelope any) (string, error) {
	input, err := SignatureInput(purpose, envelope)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(input)
	return fmt.Sprintf("%x", sum[:]), nil
}

// HasValidLifetime reports whether issuedAt/expiresAt form a bounded lifetime
// within max, with a small clock-skew tolerance. Times are RFC3339 strings.
func HasValidLifetime(issuedAt, expiresAt string, max time.Duration, now time.Time) bool {
	issued, err := time.Parse(time.RFC3339Nano, issuedAt)
	if err != nil {
		return false
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return false
	}
	if issued.After(now.Add(MaxClockSkew)) {
		return false
	}
	if !expires.After(now) {
		return false
	}
	if !expires.After(issued) {
		return false
	}
	if expires.Sub(issued) > max {
		return false
	}
	return true
}
