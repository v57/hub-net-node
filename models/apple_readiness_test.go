package models

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type appleReadinessFixture struct {
	PublicKey            string                          `json:"publicKey"`
	InputSHA256          string                          `json:"inputSha256"`
	SignatureInputBase64 string                          `json:"signatureInputBase64"`
	Valid                AppleAppAgentReadinessAssertion `json:"valid"`
}

func TestAppleAppAgentReadinessGoldenVector(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "v1", "apple-app-agent-readiness.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture appleReadinessFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	input, err := SignatureInput(PurposeAppleAppAgentReadiness, fixture.Valid)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(input); got != fixture.SignatureInputBase64 {
		t.Fatalf("signature input mismatch")
	}
	hash, err := HashSignatureInput(PurposeAppleAppAgentReadiness, fixture.Valid)
	if err != nil {
		t.Fatal(err)
	}
	if hash != fixture.InputSHA256 {
		t.Fatalf("input hash = %s, want %s", hash, fixture.InputSHA256)
	}
	publicKey := parseSPKIPublicKey(t, fixture.PublicKey)
	ok, err := VerifyEnvelope(
		PurposeAppleAppAgentReadiness,
		fixture.Valid,
		publicKey,
		fixture.Valid.Signature,
	)
	if err != nil || !ok {
		t.Fatalf("valid readiness did not verify: %v", err)
	}

	mutated := fixture.Valid
	mutated.WireGuardKey = "bXV0YXRlZC13aXJlZ3VhcmQta2V5"
	ok, err = VerifyEnvelope(
		PurposeAppleAppAgentReadiness,
		mutated,
		publicKey,
		mutated.Signature,
	)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("mutated readiness verified")
	}
}
