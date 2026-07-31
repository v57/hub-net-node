package invitation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	SignatureDomain = "hub-network/invitation/v1"
	MaxLifetime     = 10 * time.Minute
	MaxCodeBytes    = 4096
)

type Scope struct {
	Audience string   `json:"audience"`
	Actions  []string `json:"actions"`
}

type Envelope struct {
	Version              int     `json:"version"`
	SignatureDomain      string  `json:"signatureDomain"`
	TokenID              string  `json:"tokenId"`
	IssuedAt             string  `json:"issuedAt"`
	ExpiresAt            string  `json:"expiresAt"`
	HubKey               string  `json:"hubKey"`
	InvitingAgentKey     string  `json:"invitingAgentKey"`
	InvitingAgentAddress string  `json:"invitingAgentAddress"`
	HubProHost           string  `json:"hubProHost"`
	Node                 string  `json:"node,omitempty"`
	BindingKind          string  `json:"bindingKind,omitempty"`
	TunnelInstanceID     string  `json:"tunnelInstanceId,omitempty"`
	Generation           uint64  `json:"generation,omitempty"`
	Scopes               []Scope `json:"scopes"`
	Signature            string  `json:"signature"`
}

type Verified struct {
	Envelope
	TokenDigest string
}

func VerifyCode(code string, now time.Time) (Verified, error) {
	if len(code) == 0 || len(code) > MaxCodeBytes {
		return Verified{}, errors.New("invitation size is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != code {
		return Verified{}, errors.New("invitation is not canonical base64url")
	}
	var value map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return Verified{}, errors.New("invalid invitation JSON")
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Verified{}, errors.New("invitation JSON is not canonical")
	}
	var envelope Envelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Verified{}, errors.New("invalid invitation envelope")
	}
	if envelope.Version != 1 || envelope.SignatureDomain != SignatureDomain {
		return Verified{}, errors.New("unsupported invitation version")
	}
	issuedAt, err1 := time.Parse(time.RFC3339Nano, envelope.IssuedAt)
	expiresAt, err2 := time.Parse(time.RFC3339Nano, envelope.ExpiresAt)
	if err1 != nil || err2 != nil || expiresAt.Sub(issuedAt) != MaxLifetime ||
		issuedAt.After(now.Add(30*time.Second)) || !expiresAt.After(now) {
		return Verified{}, errors.New("invitation expired or has invalid lifetime")
	}
	if !hasNodeScope(envelope.Scopes) {
		return Verified{}, errors.New("invitation lacks node bootstrap scope")
	}
	if envelope.BindingKind != "" && envelope.BindingKind != "machine" && envelope.BindingKind != "apple-app" {
		return Verified{}, errors.New("invalid invitation binding kind")
	}
	if envelope.BindingKind == "apple-app" {
		if envelope.TunnelInstanceID == "" || envelope.Generation == 0 {
			return Verified{}, errors.New("incomplete Apple invitation binding")
		}
	} else if envelope.TunnelInstanceID != "" || envelope.Generation != 0 {
		return Verified{}, errors.New("unexpected Apple invitation binding")
	}
	token, err := base64.RawURLEncoding.DecodeString(envelope.TokenID)
	if err != nil || len(token) != 32 {
		return Verified{}, errors.New("invalid invitation token")
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return Verified{}, errors.New("invalid invitation signature")
	}
	der, err := base64.StdEncoding.DecodeString(envelope.HubKey)
	if err != nil {
		return Verified{}, errors.New("invalid Hub key")
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return Verified{}, errors.New("invalid Hub key")
	}
	publicKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return Verified{}, errors.New("Hub key is not Ed25519")
	}
	unsigned := make(map[string]any, len(value))
	for key, item := range value {
		if key != "signature" {
			unsigned[key] = item
		}
	}
	payload, _ := json.Marshal(unsigned)
	domain := []byte(SignatureDomain)
	input := make([]byte, 0, len(domain)+5+len(payload))
	input = append(input, domain...)
	input = append(input, 0)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(payload)))
	input = append(input, length...)
	input = append(input, payload...)
	if !ed25519.Verify(publicKey, input, signature) {
		return Verified{}, errors.New("invalid invitation signature")
	}
	digest := sha256.Sum256(token)
	return Verified{Envelope: envelope, TokenDigest: base64.RawURLEncoding.EncodeToString(digest[:])}, nil
}

func ValidatePeer(invite Verified, agentKey string) error {
	if agentKey == "" {
		return errors.New("bootstrap agent key required")
	}
	if agentKey == invite.HubKey {
		return fmt.Errorf("Hub key cannot be bootstrap peer")
	}
	return nil
}

func hasNodeScope(scopes []Scope) bool {
	for _, scope := range scopes {
		if scope.Audience != "node" {
			continue
		}
		for _, action := range scope.Actions {
			if action == "bootstrap-rendezvous" {
				return true
			}
		}
	}
	return false
}
