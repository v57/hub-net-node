// Package session implements the hub-net-node rendezvous session store.
//
// The node exchanges coordination candidates between two authenticated agents
// under a short-lived, opaque session id. It never forwards application
// traffic; the protocol envelope exposes only ticket, session, candidate,
// capability, and error fields. This package owns the in-memory state and the
// limits enforced per HN-402 (session lifecycle, candidate exchange, observed
// endpoint, opaque ids, session expiry) and HN-403 (per-agent session, per-
// session candidate, message-size, and retention limits).
//
// Sessions are matched when two openers share a Hub network id and bind
// distinct agent keys. v1 rendezvous tickets bind only the opener's identity,
// so the node pairs the first two compatible sessions in arrival order; a
// future ticket field naming the intended peer can refine the matcher without
// changing this package's surface.
package session

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/v57/hub-net-node/protocol"
	network "github.com/v57/hub-service-go/protocol"
)

// ObservedEndpoint remains an alias for callers of session.Store; wire shape
// lives in shared protocol package.
type ObservedEndpoint = protocol.ObservedEndpoint

// Session is the live rendezvous state for one opener.
type Session struct {
	ID               string
	HubNetworkID     string
	AgentKey         string
	ProfileKey       string
	TransactionID    string
	TunnelInstanceID string
	Generation       uint64
	OpenedAt         time.Time
	ExpiresAt        time.Time
	// PeerID is the matched peer's session id, empty until paired.
	PeerID string
	// Observed is the transport source the node saw on open, reported to the
	// peer alongside client-declared candidates.
	Observed protocol.ObservedEndpoint
	// Candidates submitted by this session's agent, awaiting delivery to the
	// matched peer. Each carries its own expiry; the store prunes stale ones.
	Candidates []network.Candidate
}

// Limits is the subset of protocol limits the store enforces.
type Limits struct {
	MaxSessionsPerAgent int
	MaxCandidates       int
	SessionLifetime     time.Duration
	CandidateLifetime   time.Duration
}

func fromProtocolLimits(limits protocol.Limits) Limits {
	return Limits{
		MaxSessionsPerAgent: limits.MaxSessionsPerAgent,
		MaxCandidates:       limits.MaxCandidates,
		SessionLifetime:     limits.SessionLifetime,
		CandidateLifetime:   limits.CandidateLifetime,
	}
}

// Sentinels for the documented failure modes. Callers map these to wire-shaped
// protocol.NetworkError codes.
var (
	ErrSessionNotFound      = errors.New("session: not found")
	ErrSessionLimitExceeded = errors.New("session: per-agent session limit exceeded")
	ErrCandidateLimit       = errors.New("session: candidate limit exceeded")
	ErrSessionExpired       = errors.New("session: expired")
	ErrCandidateExpired     = errors.New("session: candidate expired")
	ErrNotMatched           = errors.New("session: no matched peer")
	ErrCandidateBinding     = errors.New("session: candidate binding mismatch")
	ErrBootstrapPeer        = errors.New("session: invalid bootstrap peer")
)

// Store is the concurrency-safe rendezvous session map. Construct with New and
// drive with Open/Offer/List/Close. Sweep reclaims expired state.
type Store struct {
	mu       sync.Mutex
	sessions map[string]*Session
	limits   Limits
	now      func() time.Time
}

// OpenBootstrap opens one invitation-scoped session. Exactly two distinct
// peers may use a token and one of them must be the invitation's bound agent.
func (s *Store) OpenBootstrap(ticket network.RendezvousTicket, observed protocol.ObservedEndpoint, invitingAgentKey, transactionID, tunnelInstanceID string, generation uint64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var live []*Session
	for _, existing := range s.sessions {
		if existing.HubNetworkID == ticket.HubNetworkID && !s.expiredLocked(existing, now) {
			live = append(live, existing)
		}
	}
	if len(live) >= 2 {
		return "", ErrBootstrapPeer
	}
	for _, existing := range live {
		if existing.AgentKey == ticket.AgentKey ||
			(existing.AgentKey != invitingAgentKey && ticket.AgentKey != invitingAgentKey) ||
			existing.TransactionID != transactionID ||
			existing.TunnelInstanceID != tunnelInstanceID || existing.Generation != generation {
			return "", ErrBootstrapPeer
		}
	}
	id, err := s.openLocked(ticket, observed, now)
	if err == nil {
		s.sessions[id].TransactionID = transactionID
		s.sessions[id].TunnelInstanceID = tunnelInstanceID
		s.sessions[id].Generation = generation
	}
	return id, err
}

// New returns a Store enforcing the given protocol limits. now defaults to
// time.Now; tests inject a controllable clock.
func New(limits protocol.Limits, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		sessions: make(map[string]*Session),
		limits:   fromProtocolLimits(limits),
		now:      now,
	}
}

// Limits returns the limits the store enforces.
func (s *Store) Limits() Limits { return s.limits }

// Open records a verified ticket as a new session and returns its opaque id.
// Fails when the agent already holds MaxSessionsPerAgent sessions on this node.
// Two sessions pair when they share a Hub network id and bind distinct agent
// keys; the first compatible unmatched session becomes the peer.
func (s *Store) Open(ticket network.RendezvousTicket, observed protocol.ObservedEndpoint) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.openLocked(ticket, observed, s.now())
}

func (s *Store) openLocked(ticket network.RendezvousTicket, observed protocol.ObservedEndpoint, now time.Time) (string, error) {
	agent := ticket.AgentKey
	if agent == "" {
		return "", errors.New("session: ticket has no agent binding")
	}
	count := 0
	for _, existing := range s.sessions {
		if existing.AgentKey == agent && !s.expiredLocked(existing, now) {
			count++
		}
	}
	if count >= s.limits.MaxSessionsPerAgent {
		return "", ErrSessionLimitExceeded
	}

	id, err := newSessionID()
	if err != nil {
		return "", fmt.Errorf("session: generate id: %w", err)
	}
	session := &Session{
		ID:           id,
		HubNetworkID: ticket.HubNetworkID,
		AgentKey:     agent,
		ProfileKey:   ticket.ProfileKey,
		OpenedAt:     now,
		ExpiresAt:    now.Add(s.limits.SessionLifetime),
		Observed:     observed,
	}
	if ticketExpiresAt, err := time.Parse(time.RFC3339Nano, ticket.ExpiresAt); err == nil && ticketExpiresAt.Before(session.ExpiresAt) {
		session.ExpiresAt = ticketExpiresAt
	}
	session.Observed.Version = network.WireVersion
	session.Observed.AgentKey = agent
	// Pair with the first compatible unmatched session in arrival order.
	for _, existing := range s.sessions {
		if existing.ID == id || existing.PeerID != "" {
			continue
		}
		if s.expiredLocked(existing, now) {
			continue
		}
		if existing.HubNetworkID == session.HubNetworkID && existing.AgentKey != session.AgentKey {
			existing.PeerID = id
			session.PeerID = existing.ID
			break
		}
	}
	s.sessions[id] = session
	return id, nil
}

// Offer stores one candidate from a session's agent. The candidate's SessionID
// must match the caller's session. Fails on candidate-limit, session expiry,
// candidate expiry, or binding mismatch.
func (s *Store) Offer(sessionID string, candidate network.Candidate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	session, ok := s.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}
	if s.expiredLocked(session, now) {
		return ErrSessionExpired
	}
	if candidate.SessionID != sessionID || candidate.AgentKey != session.AgentKey {
		return ErrCandidateBinding
	}
	// Drop stale candidates before counting so an expired one never silently
	// pads the per-session budget.
	s.pruneCandidatesLocked(session, now)
	if len(session.Candidates) >= s.limits.MaxCandidates {
		return ErrCandidateLimit
	}
	candExpiresAt, err := time.Parse(time.RFC3339Nano, candidate.ExpiresAt)
	if err != nil || !candExpiresAt.After(now) {
		return ErrCandidateExpired
	}
	session.Candidates = append(session.Candidates, candidate)
	return nil
}

// List returns the matched peer's candidates plus the peer's observed endpoint
// as a synthetic server-reflexive candidate. Fails until the session is paired.
// Offered candidates are returned in place — the node relays coordination data
// only to the matched peer, never to a third party.
func (s *Store) List(sessionID string) ([]network.Candidate, protocol.ObservedEndpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, protocol.ObservedEndpoint{}, ErrSessionNotFound
	}
	if s.expiredLocked(session, now) {
		return nil, protocol.ObservedEndpoint{}, ErrSessionExpired
	}
	if session.PeerID == "" {
		return nil, protocol.ObservedEndpoint{}, ErrNotMatched
	}
	peer, ok := s.sessions[session.PeerID]
	if !ok {
		return nil, protocol.ObservedEndpoint{}, ErrNotMatched
	}
	s.pruneCandidatesLocked(peer, now)
	// Copy so callers cannot mutate stored state.
	out := make([]network.Candidate, len(peer.Candidates))
	copy(out, peer.Candidates)
	// Session ids are connection-local capabilities. Rebind peer candidates to
	// the recipient id before delivery so one peer never learns or can target
	// the other's session capability.
	for index := range out {
		out[index].SessionID = sessionID
	}
	return out, peer.Observed, nil
}

// Session returns a snapshot copy of one session, or ErrSessionNotFound.
func (s *Store) Session(sessionID string) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return Session{}, ErrSessionNotFound
	}
	return *session, nil
}

// Close removes a session and its candidates and unlinks its peer.
func (s *Store) Close(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return
	}
	if session.PeerID != "" {
		if peer, ok := s.sessions[session.PeerID]; ok {
			peer.PeerID = ""
		}
	}
	delete(s.sessions, sessionID)
}

// Sweep removes every expired session and stale candidate. Returns the number
// of sessions removed so the server can decrement its health counter once.
func (s *Store) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()

	removed := 0
	for id, session := range s.sessions {
		if s.expiredLocked(session, now) {
			if session.PeerID != "" {
				if peer, ok := s.sessions[session.PeerID]; ok {
					peer.PeerID = ""
				}
			}
			delete(s.sessions, id)
			removed++
			continue
		}
		s.pruneCandidatesLocked(session, now)
	}
	return removed
}

// Count returns the number of live sessions. Used by health reporting.
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	count := 0
	for _, session := range s.sessions {
		if !s.expiredLocked(session, now) {
			count++
		}
	}
	return count
}

func (s *Store) expiredLocked(session *Session, now time.Time) bool {
	return !session.ExpiresAt.After(now)
}

func (s *Store) pruneCandidatesLocked(session *Session, now time.Time) {
	kept := session.Candidates[:0]
	for _, candidate := range session.Candidates {
		expiresAt, err := time.Parse(time.RFC3339Nano, candidate.ExpiresAt)
		if err == nil && expiresAt.After(now) {
			kept = append(kept, candidate)
		}
	}
	session.Candidates = kept
}

// newSessionID returns an opaque, unpredictable 26-character base32 id from
// 16 bytes of crypto/rand. Unpredictability prevents enumeration of active
// sessions; opacity means the id carries no agent, Hub, or peer identity.
func newSessionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]), nil
}
