package models

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// vectorFile mirrors hub-server testdata/crypto-v1.json.
type vectorFile struct {
	Seed      string         `json:"seed"`
	PublicKey string         `json:"publicKey"`
	Vectors   []signedVector `json:"vectors"`
}

type signedVector struct {
	Purpose     string         `json:"purpose"`
	Envelope    map[string]any `json:"envelope"`
	InputSHA256 string         `json:"inputSha256"`
	Signature   string         `json:"signature"`
}

func loadVectors(t *testing.T) *vectorFile {
	t.Helper()
	path := filepath.Join("testdata", "crypto-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &vectors
}

// privateKeyFromSeed reconstructs the Ed25519 private key used by the Bun
// test fixtures. ed25519.NewKeyFromSeed expands the 32-byte seed into the
// 64-byte expanded private key form.
func privateKeyFromSeed(t *testing.T, seedHex string) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed length = %d, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestCryptoVectorsRoundTrip(t *testing.T) {
	vectors := loadVectors(t)
	priv := privateKeyFromSeed(t, vectors.Seed)
	pub := priv.Public().(ed25519.PublicKey)
	expectedPub := parseSPKIPublicKey(t, vectors.PublicKey)
	if !equalBytes(pub, expectedPub) {
		t.Fatalf("public key mismatch: got %x, want %x", pub, expectedPub)
	}

	for _, vector := range vectors.Vectors {
		t.Run(vector.Purpose, func(t *testing.T) {
			purpose := SignaturePurpose(vector.Purpose)
			inputHash, err := HashSignatureInput(purpose, vector.Envelope)
			if err != nil {
				t.Fatalf("HashSignatureInput: %v", err)
			}
			if inputHash != vector.InputSHA256 {
				t.Fatalf("input hash = %s, want %s", inputHash, vector.InputSHA256)
			}
			signature, err := SignEnvelope(purpose, vector.Envelope, priv)
			if err != nil {
				t.Fatalf("SignEnvelope: %v", err)
			}
			if signature != vector.Signature {
				t.Fatalf("signature = %s, want %s", signature, vector.Signature)
			}
			signedEnvelope := copyEnvelope(vector.Envelope)
			signedEnvelope["signature"] = vector.Signature
			ok, err := VerifyEnvelope(purpose, signedEnvelope, pub, vector.Signature)
			if err != nil {
				t.Fatalf("VerifyEnvelope: %v", err)
			}
			if !ok {
				t.Fatalf("signature did not verify")
			}
		})
	}
}

func TestSignatureDomainsAreUnique(t *testing.T) {
	seen := make(map[string]SignaturePurpose)
	for purpose, domain := range SignatureDomains {
		if other, ok := seen[domain]; ok {
			t.Fatalf("domain %q shared by %s and %s", domain, other, purpose)
		}
		seen[domain] = purpose
	}
	if len(SignatureDomains) != 10 {
		t.Fatalf("expected 10 domains, got %d", len(SignatureDomains))
	}
}

func TestSignaturesDifferAcrossPurposes(t *testing.T) {
	vectors := loadVectors(t)
	priv := privateKeyFromSeed(t, vectors.Seed)
	envelope := vectors.Vectors[0].Envelope
	signatures := make(map[string]struct{})
	for purpose := range SignatureDomains {
		sig, err := SignEnvelope(purpose, envelope, priv)
		if err != nil {
			t.Fatalf("SignEnvelope %s: %v", purpose, err)
		}
		signatures[sig] = struct{}{}
	}
	if len(signatures) != len(SignatureDomains) {
		t.Fatalf("expected %d distinct signatures, got %d", len(SignatureDomains), len(signatures))
	}
}

func TestVerifyRejectsMutation(t *testing.T) {
	vectors := loadVectors(t)
	priv := privateKeyFromSeed(t, vectors.Seed)
	pub := priv.Public().(ed25519.PublicKey)
	grantVector := vectors.Vectors[2]
	envelope := copyEnvelope(grantVector.Envelope)
	envelope["signature"] = grantVector.Signature
	mutated := copyEnvelope(envelope)
	mutated["generation"] = 999
	ok, err := VerifyEnvelope(PurposeConnectionGrant, mutated, pub, grantVector.Signature)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if ok {
		t.Fatalf("verify accepted mutated generation")
	}
}

func TestVerifyRejectsCrossPurpose(t *testing.T) {
	vectors := loadVectors(t)
	priv := privateKeyFromSeed(t, vectors.Seed)
	pub := priv.Public().(ed25519.PublicKey)
	grantVector := vectors.Vectors[2]
	envelope := copyEnvelope(grantVector.Envelope)
	envelope["signature"] = grantVector.Signature
	ok, err := VerifyEnvelope(PurposeRendezvousTicket, envelope, pub, grantVector.Signature)
	if err != nil {
		t.Fatalf("VerifyEnvelope: %v", err)
	}
	if ok {
		t.Fatalf("cross-purpose verify unexpectedly succeeded")
	}
}

func TestHasValidLifetime(t *testing.T) {
	now := time.Date(2026, 7, 25, 0, 2, 30, 0, time.UTC)
	issued := "2026-07-25T00:00:00.000Z"
	expires := "2026-07-25T00:05:00.000Z"
	if !HasValidLifetime(issued, expires, AttestationMaxLifetime, now) {
		t.Fatalf("expected valid lifetime")
	}
	// Past expiry.
	if HasValidLifetime(issued, "2026-07-25T00:02:00.000Z", AttestationMaxLifetime, now) {
		t.Fatalf("expected expiry rejection")
	}
	// Lifetime over max.
	if HasValidLifetime(issued, "2026-07-25T00:20:00.000Z", AttestationMaxLifetime, now) {
		t.Fatalf("expected over-max rejection")
	}
}

func TestCanonicalJSONStable(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{
		"b": 1,
		"a": "x",
		"c": []any{3, 2, 1},
	})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := `{"a":"x","b":1,"c":[3,2,1]}`
	if got != want {
		t.Fatalf("canonical json = %s, want %s", got, want)
	}
}

func TestCanonicalJSONDropsNil(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{
		"present": "y",
		"absent":  nil,
	})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	want := `{"present":"y"}`
	if got != want {
		t.Fatalf("canonical json = %s, want %s", got, want)
	}
}

func TestHashDeterministic(t *testing.T) {
	vectors := loadVectors(t)
	vector := vectors.Vectors[0]
	purpose := SignaturePurpose(vector.Purpose)
	first, err := HashSignatureInput(purpose, vector.Envelope)
	if err != nil {
		t.Fatalf("HashSignatureInput: %v", err)
	}
	// Re-order map fields; canonical form must stay stable.
	reordered := copyEnvelope(vector.Envelope)
	second, err := HashSignatureInput(purpose, reordered)
	if err != nil {
		t.Fatalf("HashSignatureInput reordered: %v", err)
	}
	if first != second {
		t.Fatalf("hash not stable across map order: %s != %s", first, second)
	}
	// Sanity: hash matches sha256 of input bytes (computed independently here).
	input, err := SignatureInput(purpose, vector.Envelope)
	if err != nil {
		t.Fatalf("SignatureInput: %v", err)
	}
	sum := sha256.Sum256(input)
	manual := fmt.Sprintf("%x", sum[:])
	if first != manual {
		t.Fatalf("HashSignatureInput disagrees with sha256: %s != %s", first, manual)
	}
}

func copyEnvelope(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func parseSPKIPublicKey(t *testing.T, b64 string) ed25519.PublicKey {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode spki: %v", err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("parse spki: %v", err)
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("spki not ed25519")
	}
	return ed
}
