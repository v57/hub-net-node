package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	network "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net-node/protocol"
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
	sig, err := network.SignBytes(network.PurposePresence, raw, priv)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

type owner struct{ name string }

// register issues a challenge and answers it for owner.
func register(t *testing.T, reg *Registry, spki string, priv ed25519.PrivateKey, by *owner) {
	t.Helper()
	challenge, err := reg.NewChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Register(spki, challenge, signChallenge(t, priv, challenge.Nonce), by); err != nil {
		t.Fatalf("Register: %v", err)
	}
}

func clock(now *time.Time) Options {
	return Options{now: func() time.Time { return *now }}
}

func TestRegisterAcceptsValidSignature(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	reg := New(clock(&now))
	spki, priv := newServiceKey(t)
	if reg.Online(spki) {
		t.Fatal("online before Register")
	}
	register(t, reg, spki, priv, &owner{})
	if !reg.Online(spki) {
		t.Fatal("not online after Register")
	}
}

func TestRegisterRejectsMissingChallenge(t *testing.T) {
	now := time.Now()
	reg := New(clock(&now))
	spki, _ := newServiceKey(t)
	if _, err := reg.Register(spki, Challenge{}, "c2ln", &owner{}); !errors.Is(err, ErrUnknownChallenge) {
		t.Fatalf("Register = %v, want ErrUnknownChallenge", err)
	}
}

func TestRegisterRejectsInvalidSignature(t *testing.T) {
	now := time.Now()
	reg := New(clock(&now))
	spki, _ := newServiceKey(t)
	_, otherPriv := newServiceKey(t)
	challenge, _ := reg.NewChallenge()
	if _, err := reg.Register(spki, challenge, signChallenge(t, otherPriv, challenge.Nonce), &owner{}); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Register = %v, want ErrInvalidSignature", err)
	}
	if reg.Online(spki) {
		t.Fatal("online after a bad signature")
	}
}

func TestRegisterRejectsMalformedServiceKey(t *testing.T) {
	now := time.Now()
	reg := New(clock(&now))
	challenge, _ := reg.NewChallenge()
	if _, err := reg.Register("not-a-key", challenge, "c2ln", &owner{}); !errors.Is(err, ErrMalformedServiceKey) {
		t.Fatalf("Register = %v, want ErrMalformedServiceKey", err)
	}
}

func TestExpiredChallengeIsRejected(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	reg := New(Options{ChallengeTTL: time.Minute, now: func() time.Time { return now }})
	spki, priv := newServiceKey(t)
	challenge, _ := reg.NewChallenge()
	now = now.Add(2 * time.Minute)
	if _, err := reg.Register(spki, challenge, signChallenge(t, priv, challenge.Nonce), &owner{}); !errors.Is(err, ErrUnknownChallenge) {
		t.Fatalf("Register = %v, want ErrUnknownChallenge", err)
	}
}

// Asking for a challenge used to reset the key's registration, so anyone who
// knew an inviter's public key could knock it offline.
func TestChallengeDoesNotDisplaceRegisteredInviter(t *testing.T) {
	now := time.Now()
	reg := New(clock(&now))
	spki, priv := newServiceKey(t)
	register(t, reg, spki, priv, &owner{"inviter"})
	if _, err := reg.NewChallenge(); err != nil {
		t.Fatal(err)
	}
	if !reg.Online(spki) {
		t.Fatal("a challenge request displaced the registered inviter")
	}
}

// A reconnecting inviter registers on a new connection before the old one is
// cleaned up; the old connection must not drop the new registration.
func TestStaleConnectionDisconnectKeepsNewerRegistration(t *testing.T) {
	now := time.Now()
	reg := New(clock(&now))
	spki, priv := newServiceKey(t)
	old, current := &owner{"old"}, &owner{"current"}
	register(t, reg, spki, priv, old)
	register(t, reg, spki, priv, current)
	reg.Disconnect(spki, old)
	if !reg.Online(spki) {
		t.Fatal("stale connection dropped the newer registration")
	}
	reg.Disconnect(spki, current)
	if reg.Online(spki) {
		t.Fatal("owner disconnect left the registration online")
	}
}

func TestPushReachesOnlyBoundOwner(t *testing.T) {
	now := time.Now()
	reg := New(clock(&now))
	spki, priv := newServiceKey(t)
	current := &owner{}
	register(t, reg, spki, priv, current)
	reg.Bind(spki, &owner{"other"}, func(protocol.Envelope) { t.Fatal("bound by a non-owner") })
	if reg.Push(spki, protocol.Envelope{}) {
		t.Fatal("push succeeded with no bound connection")
	}
	pushed := false
	reg.Bind(spki, current, func(protocol.Envelope) { pushed = true })
	if !reg.Push(spki, protocol.Envelope{}) || !pushed {
		t.Fatal("push to the owner failed")
	}
}

func TestSweepExpiresRegistration(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	reg := New(Options{Lease: time.Minute, now: func() time.Time { return now }})
	spki, priv := newServiceKey(t)
	register(t, reg, spki, priv, &owner{})
	now = now.Add(2 * time.Minute)
	if reg.Online(spki) {
		t.Fatal("online after lease expiry")
	}
	if removed := reg.Sweep(); removed != 1 || reg.Len() != 0 {
		t.Fatalf("Sweep removed %d, Len %d", removed, reg.Len())
	}
}

// Capacity counts registrations only: challenges for random keys must not
// fill the registry.
func TestCapacityCountsRegistrationsOnly(t *testing.T) {
	now := time.Now()
	reg := New(Options{MaxEntries: 1, now: func() time.Time { return now }})
	for range 10 {
		if _, err := reg.NewChallenge(); err != nil {
			t.Fatal(err)
		}
	}
	spki1, priv1 := newServiceKey(t)
	register(t, reg, spki1, priv1, &owner{})
	spki2, priv2 := newServiceKey(t)
	challenge, _ := reg.NewChallenge()
	if _, err := reg.Register(spki2, challenge, signChallenge(t, priv2, challenge.Nonce), &owner{}); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("Register = %v, want ErrCapacityExceeded", err)
	}
}

func TestOnlineFalseForUnknownKey(t *testing.T) {
	now := time.Now()
	reg := New(clock(&now))
	spki, _ := newServiceKey(t)
	if reg.Online(spki) {
		t.Fatal("online for never-registered key")
	}
}
