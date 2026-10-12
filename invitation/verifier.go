package invitation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/url"
	"strings"
	"time"
)

const (
	SignatureDomain = "hub-network/invitation/v1"
	MaxLifetime     = 8 * 24 * time.Hour
	MaxCodeBytes    = 1024
	URLPrefix       = "hub://join/"
)

var ed25519SPKIPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

type Verified struct {
	Payload          string
	Nonce            uint32
	Expires          uint32
	ExpiresAt        string
	IssuedAt         string
	AgentKey         string
	InvitingKey      string
	HubKey           string
	Endpoint         string
	TokenDigest      string
	BindingKind      string
	TunnelInstanceID string
	Generation       uint64
}

func VerifyCode(input string, now time.Time) (Verified, error) {
	code := strings.TrimSpace(input)
	if strings.HasPrefix(code, URLPrefix) {
		code = strings.TrimPrefix(code, URLPrefix)
	}
	if code == "" || len(code) > MaxCodeBytes {
		return Verified{}, errors.New("invitation size is invalid")
	}
	slash := strings.LastIndexByte(code, '/')
	if slash <= 0 || slash == len(code)-1 {
		return Verified{}, errors.New("invalid invitation format")
	}
	payload, signaturePart := code[:slash], code[slash+1:]
	base, rawQuery, _ := strings.Cut(payload, "?")
	parts := strings.Split(base, ".")
	if len(parts) != 3 {
		return Verified{}, errors.New("unsupported invitation version")
	}
	agentRaw, err := decodePart(parts[0], ed25519.PublicKeySize)
	if err != nil {
		return Verified{}, errors.New("invalid agent key")
	}
	expiresRaw, err := decodePart(parts[1], 4)
	if err != nil {
		return Verified{}, errors.New("invalid expiration")
	}
	nonceRaw, err := decodePart(parts[2], 4)
	if err != nil {
		return Verified{}, errors.New("invalid nonce")
	}
	signature, err := decodePart(signaturePart, ed25519.SignatureSize)
	if err != nil {
		return Verified{}, errors.New("invalid invitation signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(agentRaw), []byte(payload), signature) {
		return Verified{}, errors.New("invalid invitation signature")
	}
	expires := binary.BigEndian.Uint32(expiresRaw)
	expiresTime := time.Unix(int64(expires), 0).UTC()
	if !expiresTime.After(now) || expiresTime.After(now.Add(MaxLifetime)) {
		return Verified{}, errors.New("invitation expired or exceeds maximum lifetime")
	}
	endpoint := ""
	if rawQuery != "" {
		query, err := url.ParseQuery(rawQuery)
		if err != nil || len(query) != 1 || len(query["e"]) != 1 || query.Encode() != rawQuery || query.Get("e") == "" {
			return Verified{}, errors.New("invalid invitation query")
		}
		endpoint = query.Get("e")
	}
	digest := sha256.Sum256([]byte(payload))
	spki := append(append([]byte{}, ed25519SPKIPrefix...), agentRaw...)
	agentKey := base64.StdEncoding.EncodeToString(spki)
	return Verified{
		Payload: payload, Nonce: binary.BigEndian.Uint32(nonceRaw), Expires: expires,
		ExpiresAt: expiresTime.Format(time.RFC3339), IssuedAt: now.UTC().Format(time.RFC3339),
		AgentKey: agentKey, InvitingKey: agentKey, HubKey: agentKey, Endpoint: endpoint,
		TokenDigest: base64.RawURLEncoding.EncodeToString(digest[:]),
	}, nil
}

func ValidatePeer(invite Verified, key string) error {
	if key == "" {
		return errors.New("bootstrap agent key required")
	}
	return nil
}

func decodePart(value string, size int) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") {
		return nil, errors.New("non-canonical base64url")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("non-canonical base64url")
	}
	return decoded, nil
}
