// Package registry tracks online inviter agents keyed by their service public
// key.
//
// An inviter that can issue compact invitations registers here after proving
// possession of the service Ed25519 key that signs its invitations. A joiner's
// session.open carrying an invitation is accepted only when the invitation's
// signing key is currently online (Connected and within its lease). The node
// never forwards application traffic; the registry is coordination-only and
// lives entirely in memory, so a node restart drops every registration —
// inviters simply re-register.
//
// Auth model: signed challenge. The node issues a random nonce; the agent
// signs it under the inviter-registration signature domain; the node verifies
// against the raw 32-byte service public key decoded from the agent's base64
// SPKI key. Possession of the private key, not a bare assertion of the public
// key, is what registers the entry.
package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/v57/hub-net-node/protocol"
	network "github.com/v57/hub-service-go/protocol"
)

// ed25519SPKIPrefix is the DER prefix for an Ed25519 SubjectPublicKeyInfo.
// A base64 SPKI service key is the 12-byte prefix followed by the 32 raw key
// bytes.
var ed25519SPKIPrefix = []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}

// Sentinel errors. Callers map these to wire-shaped protocol.NetworkError codes.
var (
	ErrUnknownChallenge    = errors.New("registry: no challenge issued for service key")
	ErrInvalidSignature    = errors.New("registry: invalid challenge signature")
	ErrMalformedServiceKey = errors.New("registry: service key is not a canonical Ed25519 SPKI")
	ErrCapacityExceeded    = errors.New("registry: registration capacity exceeded")
)

// Entry is the live registration state for one inviter.
type Entry struct {
	ServiceKey        string
	ChallengeNonce    string
	ChallengeBytes    []byte
	ChallengeIssuedAt time.Time
	ExpiresAt         time.Time
	// Connected is true once the agent answered the challenge and holds the
	// registration while its connection is open.
	Connected bool
	// send pushes an envelope to the agent's open connection so the node can
	// notify it of an unregistration event. nil when no connection is bound.
	send func(protocol.Envelope)
}

// Options configures a Registry.
type Options struct {
	// Lease is the registration lease. Defaults to protocol.DefaultRegistrationLifetime.
	Lease time.Duration
	// MaxEntries bounds the total number of registered/challenged inviters.
	// Defaults to 1024, the same order as the UDP observation capacity.
	MaxEntries int
	// ChallengeTTL bounds how long an unverified challenge remains valid
	// before it must be re-requested. Defaults to Lease.
	ChallengeTTL time.Duration
	// now is the clock; tests inject a controllable time.
	now func() time.Time
}

// Registry is the concurrency-safe online-inviter map.
type Registry struct {
	mu           sync.Mutex
	entries      map[string]*Entry
	lease        time.Duration
	maxEntries   int
	challengeTTL time.Duration
	now          func() time.Time
}

// New constructs a Registry from options, applying defaults for zero fields.
func New(options Options) *Registry {
	lease := options.Lease
	if lease <= 0 {
		lease = protocol.DefaultRegistrationLifetime
	}
	maxEntries := options.MaxEntries
	if maxEntries <= 0 {
		maxEntries = 1024
	}
	challengeTTL := options.ChallengeTTL
	if challengeTTL <= 0 {
		challengeTTL = lease
	}
	now := options.now
	if now == nil {
		now = time.Now
	}
	return &Registry{
		entries:      make(map[string]*Entry),
		lease:        lease,
		maxEntries:   maxEntries,
		challengeTTL: challengeTTL,
		now:          now,
	}
}

// Challenge issues a fresh random nonce for serviceKey and returns its
// base64url encoding. The nonce is valid for the challenge TTL; a repeat
// request for an in-flight challenge refreshes it. Re-issuing a challenge for
// an already-Connected entry re-opens it (the old connection is responsible
// for unbinding itself on disconnect). Returns ErrCapacityExceeded when the
// total entry bound would be exceeded by a brand-new key.
func (r *Registry) Challenge(serviceKey string) (string, error) {
	if err := validateServiceKey(serviceKey); err != nil {
		return "", err
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("registry: generate nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw[:])
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(now)
	entry, ok := r.entries[serviceKey]
	if !ok {
		if len(r.entries) >= r.maxEntries {
			return "", ErrCapacityExceeded
		}
		entry = &Entry{ServiceKey: serviceKey}
		r.entries[serviceKey] = entry
	}
	entry.ChallengeNonce = nonce
	entry.ChallengeBytes = append(entry.ChallengeBytes[:0], raw[:]...)
	entry.ChallengeIssuedAt = now
	// A new challenge invalidates any prior Connected state; the caller that
	// completes this challenge becomes the current registrant.
	entry.Connected = false
	entry.send = nil
	return nonce, nil
}

// Verify checks the agent's signature over its outstanding challenge nonce
// and, on success, marks the entry Connected with a fresh lease. The signature
// is over the raw nonce bytes under the inviter-registration domain. The nonce
// is consumed: a second Verify with the same nonce fails as unknown. Returns
// the registration expiry on success.
func (r *Registry) Verify(serviceKey, signature string) (time.Time, error) {
	rawPub, err := decodeServiceKey(serviceKey)
	if err != nil {
		return time.Time{}, err
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(now)
	entry, ok := r.entries[serviceKey]
	if !ok || len(entry.ChallengeBytes) == 0 || !entry.ChallengeIssuedAt.Add(r.challengeTTL).After(now) {
		return time.Time{}, ErrUnknownChallenge
	}
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return time.Time{}, ErrInvalidSignature
	}
	input, err := network.SignatureInputForBytes(network.PurposeInviterRegistration, entry.ChallengeBytes)
	if err != nil {
		return time.Time{}, err
	}
	if !ed25519.Verify(ed25519.PublicKey(rawPub), input, sigBytes) {
		return time.Time{}, ErrInvalidSignature
	}
	entry.Connected = true
	entry.ExpiresAt = now.Add(r.lease)
	expiry := entry.ExpiresAt
	// Consume the nonce so it cannot be replayed into a second registration.
	entry.ChallengeNonce = ""
	entry.ChallengeBytes = nil
	entry.ChallengeIssuedAt = time.Time{}
	return expiry, nil
}

// Online reports whether serviceKey is currently Connected and within its
// lease. Used by the invitation session.open path to gate joins on inviter
// presence.
func (r *Registry) Online(serviceKey string) bool {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[serviceKey]
	if !ok {
		return false
	}
	return entry.Connected && entry.ExpiresAt.After(now)
}

// Bind attaches a write callback to a Connected entry so the node can push an
// inviter.unregistered envelope when the registration ends. No-op if the entry
// is absent or not Connected.
func (r *Registry) Bind(serviceKey string, send func(protocol.Envelope)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[serviceKey]
	if !ok || !entry.Connected {
		return
	}
	entry.send = send
}

// Push delivers one envelope to a Connected registrant's connection. It
// returns false when the entry is absent, not Connected, or has no bound
// connection. The callback runs outside the registry lock so a slow or
// blocked connection cannot stall registration state.
func (r *Registry) Push(serviceKey string, envelope protocol.Envelope) bool {
	r.mu.Lock()
	entry, ok := r.entries[serviceKey]
	if !ok || !entry.Connected || entry.send == nil {
		r.mu.Unlock()
		return false
	}
	send := entry.send
	r.mu.Unlock()
	send(envelope)
	return true
}

// Disconnect clears the Connected/send state for serviceKey. Called from a
// connection's cleanup path. The entry is dropped entirely: an agent must
// re-challenge to register again.
func (r *Registry) Disconnect(serviceKey string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entries[serviceKey]; !ok {
		return
	}
	delete(r.entries, serviceKey)
}

// Sweep removes every entry whose lease has expired or whose challenge has
// expired without being answered. Returns the count removed.
func (r *Registry) Sweep() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sweepLocked(r.now())
}

// Len returns the number of tracked entries (challenged + connected). Used by
// health reporting.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// sweepLocked reclaims expired entries. An entry is removable when it has no
// live challenge window and no live connected lease.
func (r *Registry) sweepLocked(now time.Time) int {
	removed := 0
	for key, entry := range r.entries {
		challengeLive := len(entry.ChallengeBytes) > 0 && entry.ChallengeIssuedAt.Add(r.challengeTTL).After(now)
		leaseLive := entry.Connected && entry.ExpiresAt.After(now)
		if !challengeLive && !leaseLive {
			delete(r.entries, key)
			removed++
		}
	}
	return removed
}

// validateServiceKey reports whether serviceKey is a canonical base64 Ed25519
// SPKI (12-byte DER prefix + 32 raw key bytes). Canonical means the decoded
// bytes re-encode to exactly the input string, mirroring the invitation
// verifier's base64url canonicalization but for standard base64 SPKI keys.
func validateServiceKey(serviceKey string) error {
	raw, err := base64.StdEncoding.DecodeString(serviceKey)
	if err != nil || len(raw) != len(ed25519SPKIPrefix)+ed25519.PublicKeySize {
		return ErrMalformedServiceKey
	}
	if base64.StdEncoding.EncodeToString(raw) != serviceKey {
		return ErrMalformedServiceKey
	}
	return nil
}

// decodeServiceKey returns the raw 32-byte Ed25519 public key from a base64
// SPKI service key.
func decodeServiceKey(serviceKey string) ([]byte, error) {
	if err := validateServiceKey(serviceKey); err != nil {
		return nil, err
	}
	raw, _ := base64.StdEncoding.DecodeString(serviceKey)
	return raw[len(ed25519SPKIPrefix):], nil
}
