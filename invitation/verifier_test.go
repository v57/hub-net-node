package invitation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"
)

func signedCode(t *testing.T, now time.Time, lifetime time.Duration, endpoint string) string {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var expires, nonce [4]byte
	binary.BigEndian.PutUint32(expires[:], uint32(now.Add(lifetime).Unix()))
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(publicKey) + "." +
		base64.RawURLEncoding.EncodeToString(expires[:]) + "." + base64.RawURLEncoding.EncodeToString(nonce[:])
	if endpoint != "" {
		payload += "?e=" + endpoint
	}
	return payload + "/" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(payload)))
}

func TestVerifyCode(t *testing.T) {
	now := time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)
	code := signedCode(t, now, 7*24*time.Hour, "34.25.235.23")
	verified, err := VerifyCode(code, now)
	if err != nil {
		t.Fatal(err)
	}
	if verified.TokenDigest == "" || verified.AgentKey == "" || verified.Endpoint != "34.25.235.23" {
		t.Fatalf("bad result: %+v", verified)
	}
	tampered := "A" + code[1:]
	if _, err := VerifyCode(tampered, now); err == nil {
		t.Fatal("tampered invitation accepted")
	}
	if _, err := VerifyCode(code, now.Add(7*24*time.Hour)); err == nil {
		t.Fatal("expired invitation accepted")
	}
	if _, err := VerifyCode(signedCode(t, now, MaxLifetime+time.Second, ""), now); err == nil {
		t.Fatal("oversized lifetime accepted")
	}
}
