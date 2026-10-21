// Package registry tracks online inviter agents keyed by their service public
// key.
//
// An inviter that can issue compact invitations registers here after proving
// possession of the service Ed25519 key that signs its invitations. A joiner's
// session.open carrying an invitation is accepted only when the invitation's
// signing key is currently online (registered and within its lease). The node
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

	network "github.com/v57/hub-net-node/models"
	"github.com/v57/hub-net-node/protocol"
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
	ServiceKey string
	ExpiresAt  time.Time
	// owner identifies the connection that proved the key. Only that
	// connection can bind, refresh or drop the registration.
	owner any
	// send pushes an envelope to the agent's open connection so the node can
	// notify it of an unregistration event. nil when no connection is bound.
	send func(protocol.Envelope)
}

// Challenge is a nonce issued to one connection. The connection keeps it;
// the registry is untouched until the signature over it verifies, so asking
// for a challenge can neither displace a registered inviter nor fill the
// registry.
type Challenge struct {
	Nonce    string
	bytes    []byte
	issuedAt time.Time
}

// Options configures a Registry.
type Options struct {
	// Lease is the registration lease. Defaults to protocol.DefaultRegistrationLifetime.
	Lease time.Duration
	// MaxEntries bounds the total number of registered inviters.
	// Defaults to 1024, the same order as the UDP observation capacity.
	MaxEntries int
	// ChallengeTTL bounds how long an issued challenge can be answered.
	// Defaults to Lease.
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

// NewChallenge issues a random nonce for the calling connection to keep.
func (r *Registry) NewChallenge() (Challenge, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Challenge{}, fmt.Errorf("registry: generate nonce: %w", err)
	}
	return Challenge{
		Nonce:    base64.RawURLEncoding.EncodeToString(raw[:]),
		bytes:    raw[:],
		issuedAt: r.now(),
	}, nil
}

// Register verifies the agent's signature over challenge (the inviter-
// registration domain over the raw nonce bytes) and registers serviceKey for
// owner with a fresh lease. A newer registration of the same key replaces the
// previous owner. Returns the registration expiry.
func (r *Registry) Register(serviceKey string, challenge Challenge, signature string, owner any) (time.Time, error) {
	rawPub, err := decodeServiceKey(serviceKey)
	if err != nil {
		return time.Time{}, err
	}
	now := r.now()
	if len(challenge.bytes) == 0 || !challenge.issuedAt.Add(r.challengeTTL).After(now) {
		return time.Time{}, ErrUnknownChallenge
	}
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return time.Time{}, ErrInvalidSignature
	}
	input, err := network.SignatureInputForBytes(network.PurposeInviterRegistration, challenge.bytes)
	if err != nil {
		return time.Time{}, err
	}
	if !ed25519.Verify(ed25519.PublicKey(rawPub), input, sigBytes) {
		return time.Time{}, ErrInvalidSignature
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweepLocked(now)
	entry, ok := r.entries[serviceKey]
	if !ok {
		if len(r.entries) >= r.maxEntries {
			return time.Time{}, ErrCapacityExceeded
		}
		entry = &Entry{ServiceKey: serviceKey}
		r.entries[serviceKey] = entry
	}
	if entry.owner != owner {
		entry.send = nil
	}
	entry.owner = owner
	entry.ExpiresAt = now.Add(r.lease)
	return entry.ExpiresAt, nil
}

// Online reports whether serviceKey is registered and within its
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
	return entry.ExpiresAt.After(now)
}

// Bind attaches owner's write callback to its registration so the node can
// push to the inviter. No-op unless owner holds the registration.
func (r *Registry) Bind(serviceKey string, owner any, send func(protocol.Envelope)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[serviceKey]
	if !ok || entry.owner != owner {
		return
	}
	entry.send = send
}

// Push delivers one envelope to a registrant's connection. It
// returns false when the entry is absent, expired, or has no bound
// connection. The callback runs outside the registry lock so a slow or
// blocked connection cannot stall registration state.
func (r *Registry) Push(serviceKey string, envelope protocol.Envelope) bool {
	r.mu.Lock()
	entry, ok := r.entries[serviceKey]
	if !ok || entry.send == nil || !entry.ExpiresAt.After(r.now()) {
		r.mu.Unlock()
		return false
	}
	send := entry.send
	r.mu.Unlock()
	send(envelope)
	return true
}

// Disconnect drops owner's registration of serviceKey. Called from a
// connection's cleanup path; a connection that was replaced by a newer
// registration of the same key leaves that registration alone. Reports whether
// a registration was dropped.
func (r *Registry) Disconnect(serviceKey string, owner any) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.entries[serviceKey]; ok && entry.owner == owner {
		delete(r.entries, serviceKey)
		return true
	}
	return false
}

// Lookup returns serviceKey's lease expiry, for diagnostics: ok is false when
// the key holds no registration (never registered, disconnected or swept).
func (r *Registry) Lookup(serviceKey string) (expiresAt time.Time, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[serviceKey]
	if !ok {
		return time.Time{}, false
	}
	return entry.ExpiresAt, true
}

// Sweep removes every entry whose lease has expired. Returns the count
// removed.
func (r *Registry) Sweep() int {
	return len(r.SweepExpired())
}

// SweepExpired removes every entry whose lease has expired and returns their
// service keys.
func (r *Registry) SweepExpired() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.expireLocked(r.now())
}

// Len returns the number of registered inviters. Used by health reporting.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// sweepLocked reclaims entries whose lease expired.
func (r *Registry) sweepLocked(now time.Time) int {
	return len(r.expireLocked(now))
}

func (r *Registry) expireLocked(now time.Time) []string {
	var removed []string
	for key, entry := range r.entries {
		if !entry.ExpiresAt.After(now) {
			delete(r.entries, key)
			removed = append(removed, key)
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
