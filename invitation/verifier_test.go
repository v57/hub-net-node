package invitation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"
)

func signedCode(t *testing.T, now time.Time, apple bool) string {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(publicKey)
	token := make([]byte, 32)
	_, _ = rand.Read(token)
	value := map[string]any{
		"version": 1, "signatureDomain": SignatureDomain,
		"tokenId":  base64.RawURLEncoding.EncodeToString(token),
		"issuedAt": now.Format(time.RFC3339Nano), "expiresAt": now.Add(MaxLifetime).Format(time.RFC3339Nano),
		"hubKey":               base64.StdEncoding.EncodeToString(der),
		"invitingAgentKey":     base64.StdEncoding.EncodeToString(publicKey),
		"invitingAgentAddress": "100.96.0.2", "hubProHost": "100.96.0.1",
		"scopes": []any{
			map[string]any{"audience": "node", "actions": []any{"bootstrap-rendezvous"}},
		},
	}
	if apple {
		value["bindingKind"] = "apple-app"
		value["tunnelInstanceId"] = "tunnel-1"
		value["generation"] = uint64(7)
	}
	payload, _ := json.Marshal(value)
	input := append([]byte(SignatureDomain), 0)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(payload)))
	input = append(input, length...)
	input = append(input, payload...)
	value["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, input))
	envelope, _ := json.Marshal(value)
	return base64.RawURLEncoding.EncodeToString(envelope)
}

func TestVerifyCodeAcceptsScopedInvitationAndRejectsTamperExpiryAndOversize(t *testing.T) {
	now := time.Date(2026, 7, 29, 0, 0, 0, 0, time.UTC)
	code := signedCode(t, now, false)
	verified, err := VerifyCode(code, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.TokenDigest == "" || verified.InvitingAgentKey == "" {
		t.Fatal("verified invitation lacks bootstrap bindings")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(code)
	raw[len(raw)/2] ^= 1
	if _, err := VerifyCode(base64.RawURLEncoding.EncodeToString(raw), now); err == nil {
		t.Fatal("tampered invitation accepted")
	}
	if _, err := VerifyCode(code, now.Add(MaxLifetime)); err == nil {
		t.Fatal("expired invitation accepted")
	}
	if _, err := VerifyCode(string(make([]byte, MaxCodeBytes+1)), now); err == nil {
		t.Fatal("oversized invitation accepted")
	}
}

func TestVerifyCodeAuthenticatesAppleBindingPins(t *testing.T) {
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	verified, err := VerifyCode(signedCode(t, now, true), now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.BindingKind != "apple-app" || verified.TunnelInstanceID != "tunnel-1" || verified.Generation != 7 {
		t.Fatalf("Apple pins = %+v", verified)
	}
}
