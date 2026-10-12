package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	network "github.com/v57/hub-service-go/protocol"
)

// newServiceKey generates an Ed25519 key and returns (spkiBase64, privateKey).
func newServiceKey(t *testing.T) (string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der), priv
}

// signChallenge signs the decoded nonce under the inviter-registration domain.
func signChallenge(t *testing.T, priv ed25519.PrivateKey, nonce string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := network.SignBytes(network.PurposeInviterRegistration, raw, priv)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestChallengeIssuesNonceAndVerifyAcceptsValidSignature(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	reg := New(Options{now: func() time.Time { return now }})
	spki, priv := newServiceKey(t)

	nonce, err := reg.Challenge(spki)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	if nonce == "" {
		t.Fatal("empty nonce")
	}
	if reg.Online(spki) {
		t.Fatal("online before Verify")
	}
	_, err = reg.Verify(spki, signChallenge(t, priv, nonce))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !reg.Online(spki) {
		t.Fatal("not online after Verify")
	}
}

func TestVerifyRejectsUnknownChallenge(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	reg := New(Options{now: func() time.Time { return now }})
	spki, priv := newServiceKey(t)
	// No Challenge() issued first.
	if _, err := reg.Verify(spki, signChallenge(t, priv, "AAAAAAAAAAAAAAAAAAAA")); !errors.Is(err, ErrUnknownChallenge) {
		t.Fatalf("Verify = %v, want ErrUnknownChallenge", err)
	}
}

func TestVerifyRejectsInvalidSignature(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	reg := New(Options{now: func() time.Time { return now }})
	spki, _ := newServiceKey(t)
	if _, err := reg.Challenge(spki); err != nil {
		t.Fatal(err)
	}
	// A valid base64 string that is not a signature over the nonce.
	bogus := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, err := reg.Verify(spki, bogus); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsMalformedServiceKey(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	reg := New(Options{now: func() time.Time { return now }})
	if _, err := reg.Challenge("not-a-spki"); !errors.Is(err, ErrMalformedServiceKey) {
		t.Fatalf("Challenge = %v, want ErrMalformedServiceKey", err)
	}
	if _, err := reg.Verify("not-a-spki", "AAAA"); !errors.Is(err, ErrMalformedServiceKey) {
		t.Fatalf("Verify = %v, want ErrMalformedServiceKey", err)
	}
}

func TestVerifyRejectsNonceReplay(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	reg := New(Options{now: func() time.Time { return now }})
	spki, priv := newServiceKey(t)
	nonce, err := reg.Challenge(spki)
	if err != nil {
		t.Fatal(err)
	}
	sig := signChallenge(t, priv, nonce)
	if _, err := reg.Verify(spki, sig); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	// Same nonce/signature cannot register a second time.
	if _, err := reg.Verify(spki, sig); !errors.Is(err, ErrUnknownChallenge) {
		t.Fatalf("replay Verify = %v, want ErrUnknownChallenge", err)
	}
}

func TestChallengeExpiryTreatedAsUnknown(t *testing.T) {
	clock := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	reg := New(Options{Lease: time.Minute, ChallengeTTL: time.Minute, now: func() time.Time { return clock }})
	spki, priv := newServiceKey(t)
	nonce, err := reg.Challenge(spki)
	if err != nil {
		t.Fatal(err)
	}
	// Advance past the challenge TTL.
	clock = clock.Add(2 * time.Minute)
	if _, err := reg.Verify(spki, signChallenge(t, priv, nonce)); !errors.Is(err, ErrUnknownChallenge) {
		t.Fatalf("Verify = %v, want ErrUnknownChallenge after challenge expiry", err)
	}
}

func TestDisconnectMakesOffline(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	reg := New(Options{now: func() time.Time { return now }})
	spki, priv := newServiceKey(t)
	nonce, err := reg.Challenge(spki)
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Verify(spki, signChallenge(t, priv, nonce))
	if err != nil {
		t.Fatal(err)
	}
	reg.Disconnect(spki)
	if reg.Online(spki) {
		t.Fatal("online after Disconnect")
	}
	// Re-registration works after disconnect.
	nonce2, err := reg.Challenge(spki)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Verify(spki, signChallenge(t, priv, nonce2)); err != nil {
		t.Fatal(err)
	}
	if !reg.Online(spki) {
		t.Fatal("not online after re-registration")
	}
}

func TestSweepExpiresRegistration(t *testing.T) {
	clock := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	reg := New(Options{Lease: time.Minute, now: func() time.Time { return clock }})
	spki, priv := newServiceKey(t)
	nonce, err := reg.Challenge(spki)
	if err != nil {
		t.Fatal(err)
	}
	_, err = reg.Verify(spki, signChallenge(t, priv, nonce))
	if err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Fatalf("Len = %d, want 1", reg.Len())
	}
	clock = clock.Add(2 * time.Minute)
	if reg.Online(spki) {
		t.Fatal("online after lease expiry")
	}
	if removed := reg.Sweep(); removed != 1 {
		t.Fatalf("Sweep removed %d, want 1", removed)
	}
	if reg.Len() != 0 {
		t.Fatalf("Len = %d after Sweep, want 0", reg.Len())
	}
}

func TestRegistryBoundByMaxEntries(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	reg := New(Options{MaxEntries: 1, now: func() time.Time { return now }})
	spki1, _ := newServiceKey(t)
	if _, err := reg.Challenge(spki1); err != nil {
		t.Fatal(err)
	}
	spki2, _ := newServiceKey(t)
	if _, err := reg.Challenge(spki2); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("Challenge = %v, want ErrCapacityExceeded", err)
	}
}

func TestOnlineFalseForUnknownKey(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	reg := New(Options{now: func() time.Time { return now }})
	spki, _ := newServiceKey(t)
	if reg.Online(spki) {
		t.Fatal("online for never-registered key")
	}
}
