package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strconv"
	"strings"
	"testing"
)

func osStat(path string) (os.FileInfo, error) { return os.Stat(path) }

func TestGenerateEncodeParseRoundTrip(t *testing.T) {
	first, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	encoded, err := first.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := parseIdentity(encoded)
	if err != nil {
		t.Fatalf("parseIdentity: %v", err)
	}
	if !equal(first, parsed) {
		t.Fatalf("identity changed across encode/parse")
	}
}

func TestLoadGeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/auth"
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load (generate): %v", err)
	}
	info, err := osStat(path)
	if err != nil {
		t.Fatalf("stat identity file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("identity file mode = %o, want 0600", mode)
	}
	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load (persisted): %v", err)
	}
	if !equal(loaded, reloaded) {
		t.Fatalf("Load did not persist identity")
	}
}

func TestAuthTokenFormatAndSignature(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	token, err := id.AuthToken(0)
	if err != nil {
		t.Fatalf("AuthToken: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "key" {
		t.Fatalf("unexpected token shape %q", token)
	}
	publicKeyB64, signatureB64, expiry := parts[1], parts[2], parts[3]
	if publicKeyB64 == "" || signatureB64 == "" {
		t.Fatalf("token missing fields %q", token)
	}
	if _, err := strconv.ParseInt(expiry, 10, 64); err != nil {
		t.Fatalf("expiry not integer: %v", err)
	}
	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(id.PublicKey(), []byte(expiry), signature) {
		t.Fatalf("signature does not verify")
	}
}

func equal(a, b *Identity) bool {
	return a.privateKey.Equal(b.privateKey) && ed25519.PublicKey(a.publicKey).Equal(ed25519.PublicKey(b.publicKey))
}
