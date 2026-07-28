package session

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/v57/hub-net-node/protocol"
	network "github.com/v57/hub-service-go/protocol"
)

func testLimits() protocol.Limits {
	return protocol.DefaultLimits()
}

func fixedClock(t *testing.T, now time.Time) func() time.Time {
	t.Helper()
	return func() time.Time { return now }
}

func ticketFor(networkID, agentKey string) network.RendezvousTicket {
	return network.RendezvousTicket{
		Version:        network.WireVersion,
		TicketID:       "ticket-" + agentKey,
		HubNetworkID:   networkID,
		ProfileKey:     "profile-" + agentKey,
		AgentKey:       agentKey,
		NodeID:         "node-1",
		Roles:          []string{"rendezvous"},
		SessionPurpose: "peer-connect",
	}
}

func TestOpenReturnsOpaqueUnpredictableID(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := New(testLimits(), fixedClock(t, now))
	id1, err := store.Open(ticketFor("net-1", "agent-1"), ObservedEndpoint{Address: "10.0.0.1"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	id2, err := store.Open(ticketFor("net-1", "agent-2"), ObservedEndpoint{Address: "10.0.0.2"})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if id1 == "" || id2 == "" || id1 == id2 {
		t.Fatalf("ids must be distinct and non-empty: %q %q", id1, id2)
	}
	// Opaque: the id must not leak agent, network, or node identity.
	for _, secret := range []string{"agent", "net", "node", "profile"} {
		if strings.Contains(strings.ToLower(id1), secret) {
			t.Fatalf("session id %q leaks %q", id1, secret)
		}
	}
}

func TestTwoSessionsMatchAcrossSharedNetwork(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := New(testLimits(), fixedClock(t, now))

	id1, err := store.Open(ticketFor("net-1", "agent-1"), ObservedEndpoint{Address: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	// Before the peer opens, listing reports no match.
	if _, _, err := store.List(id1); !errors.Is(err, ErrNotMatched) {
		t.Fatalf("List before peer = %v, want ErrNotMatched", err)
	}
	id2, err := store.Open(ticketFor("net-1", "agent-2"), ObservedEndpoint{Address: "10.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	s1, _ := store.Session(id1)
	s2, _ := store.Session(id2)
	if s1.PeerID != id2 || s2.PeerID != id1 {
		t.Fatalf("sessions not paired: s1.Peer=%q s2.Peer=%q", s1.PeerID, s2.PeerID)
	}
	// Same agent key in a different network must NOT pair.
	id3, err := store.Open(ticketFor("net-2", "agent-1"), ObservedEndpoint{Address: "10.0.0.3"})
	if err != nil {
		t.Fatal(err)
	}
	s3, _ := store.Session(id3)
	if s3.PeerID != "" {
		t.Fatalf("same-agent sessions must not pair: got peer %q", s3.PeerID)
	}
}

func TestOfferEnforcesCandidateLimit(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := New(testLimits(), fixedClock(t, now))

	id1, _ := store.Open(ticketFor("net-1", "agent-1"), ObservedEndpoint{Address: "10.0.0.1"})
	id2, _ := store.Open(ticketFor("net-1", "agent-2"), ObservedEndpoint{Address: "10.0.0.2"})

	limits := store.Limits()
	for i := 0; i < limits.MaxCandidates; i++ {
		candidate := network.Candidate{
			Version:     network.WireVersion,
			CandidateID: "cand-" + string(rune('a'+i)),
			SessionID:   id1,
			AgentKey:    "agent-1",
			Kind:        "host",
			Transport:   "udp",
			Address:     "192.0.2.1",
			Port:        5000,
			Priority:    uint32(i),
			ExpiresAt:   now.Add(protocol.DefaultCandidateLifetime).Format(time.RFC3339Nano),
		}
		if err := store.Offer(id1, candidate); err != nil {
			t.Fatalf("Offer %d: %v", i, err)
		}
	}
	over := network.Candidate{
		Version:     network.WireVersion,
		CandidateID: "cand-overflow",
		SessionID:   id1,
		AgentKey:    "agent-1",
		Kind:        "host",
		Transport:   "udp",
		Address:     "192.0.2.1",
		Port:        5000,
		ExpiresAt:   now.Add(protocol.DefaultCandidateLifetime).Format(time.RFC3339Nano),
	}
	if err := store.Offer(id1, over); !errors.Is(err, ErrCandidateLimit) {
		t.Fatalf("Offer over limit = %v, want ErrCandidateLimit", err)
	}

	// Peer receives the offered candidates plus the observed endpoint.
	got, observed, err := store.List(id2)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != limits.MaxCandidates {
		t.Fatalf("peer received %d candidates, want %d", len(got), limits.MaxCandidates)
	}
	if observed.Address != "10.0.0.1" {
		t.Fatalf("observed = %q, want 10.0.0.1", observed.Address)
	}
}

func TestOfferRejectsBindingMismatch(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := New(testLimits(), fixedClock(t, now))
	id1, _ := store.Open(ticketFor("net-1", "agent-1"), ObservedEndpoint{Address: "10.0.0.1"})

	// Candidate claims a different session id.
	cross := network.Candidate{
		Version: network.WireVersion, CandidateID: "cand-cross",
		SessionID: "someone-else", AgentKey: "agent-1",
		Kind: "host", Transport: "udp", Address: "192.0.2.9", Port: 5000,
		ExpiresAt: now.Add(protocol.DefaultCandidateLifetime).Format(time.RFC3339Nano),
	}
	if err := store.Offer(id1, cross); !errors.Is(err, ErrCandidateBinding) {
		t.Fatalf("Offer cross-session = %v, want ErrCandidateBinding", err)
	}
}

func TestOfferRejectsExpiredCandidate(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := New(testLimits(), fixedClock(t, now))
	id1, _ := store.Open(ticketFor("net-1", "agent-1"), ObservedEndpoint{Address: "10.0.0.1"})

	stale := network.Candidate{
		Version: network.WireVersion, CandidateID: "cand-stale",
		SessionID: id1, AgentKey: "agent-1",
		Kind: "host", Transport: "udp", Address: "192.0.2.9", Port: 5000,
		ExpiresAt: now.Add(-time.Second).Format(time.RFC3339Nano),
	}
	if err := store.Offer(id1, stale); !errors.Is(err, ErrCandidateExpired) {
		t.Fatalf("Offer stale = %v, want ErrCandidateExpired", err)
	}
}

func TestOpenEnforcesPerAgentSessionLimit(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := New(testLimits(), fixedClock(t, now))
	limits := store.Limits()

	// Each network counts as a distinct session for the same agent.
	for i := 0; i < limits.MaxSessionsPerAgent; i++ {
		if _, err := store.Open(ticketFor("net-"+string(rune('a'+i)), "agent-1"), ObservedEndpoint{}); err != nil {
			t.Fatalf("Open %d: %v", i, err)
		}
	}
	if _, err := store.Open(ticketFor("net-overflow", "agent-1"), ObservedEndpoint{}); !errors.Is(err, ErrSessionLimitExceeded) {
		t.Fatalf("Open over limit = %v, want ErrSessionLimitExceeded", err)
	}
}

func TestSweepExpiresSessionsAndCandidates(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := New(testLimits(), fixedClock(t, now))
	id1, _ := store.Open(ticketFor("net-1", "agent-1"), ObservedEndpoint{Address: "10.0.0.1"})
	id2, _ := store.Open(ticketFor("net-1", "agent-2"), ObservedEndpoint{Address: "10.0.0.2"})

	// Offer a candidate that expires before the session does.
	shortCandidate := network.Candidate{
		Version: network.WireVersion, CandidateID: "cand-short",
		SessionID: id1, AgentKey: "agent-1",
		Kind: "host", Transport: "udp", Address: "192.0.2.1", Port: 5000,
		ExpiresAt: now.Add(10 * time.Second).Format(time.RFC3339Nano),
	}
	if err := store.Offer(id1, shortCandidate); err != nil {
		t.Fatal(err)
	}

	// Advance past the candidate lifetime but before the session lifetime.
	store.now = func() time.Time { return now.Add(protocol.DefaultCandidateLifetime + time.Second) }
	removed := store.Sweep()
	if removed != 0 {
		t.Fatalf("Sweep removed %d sessions, want 0 (sessions still live)", removed)
	}
	got, _, _ := store.List(id2)
	if len(got) != 0 {
		t.Fatalf("stale candidate retained: %d", len(got))
	}

	// Advance past the session lifetime; both sessions are reclaimed.
	store.now = func() time.Time { return now.Add(protocol.DefaultSessionLifetime + time.Second) }
	removed = store.Sweep()
	if removed != 2 {
		t.Fatalf("Sweep removed %d, want 2", removed)
	}
	if store.Count() != 0 {
		t.Fatalf("Count after sweep = %d, want 0", store.Count())
	}
}

func TestCloseUnlinksPeer(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := New(testLimits(), fixedClock(t, now))
	id1, _ := store.Open(ticketFor("net-1", "agent-1"), ObservedEndpoint{})
	id2, _ := store.Open(ticketFor("net-1", "agent-2"), ObservedEndpoint{})

	store.Close(id1)
	if _, err := store.Session(id1); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("Session after close = %v, want ErrSessionNotFound", err)
	}
	// The peer is unlinked and may now match a new opener.
	peer, _ := store.Session(id2)
	if peer.PeerID != "" {
		t.Fatalf("peer still linked: %q", peer.PeerID)
	}
}

func TestListReturnsCopyNotAlias(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	store := New(testLimits(), fixedClock(t, now))
	id1, _ := store.Open(ticketFor("net-1", "agent-1"), ObservedEndpoint{})
	id2, _ := store.Open(ticketFor("net-1", "agent-2"), ObservedEndpoint{})
	candidate := network.Candidate{
		Version: network.WireVersion, CandidateID: "cand-1",
		SessionID: id1, AgentKey: "agent-1",
		Kind: "host", Transport: "udp", Address: "192.0.2.1", Port: 5000,
		ExpiresAt: now.Add(protocol.DefaultCandidateLifetime).Format(time.RFC3339Nano),
	}
	_ = store.Offer(id1, candidate)

	got, _, _ := store.List(id2)
	got[0].Address = "mutated"
	again, _, _ := store.List(id2)
	if again[0].Address == "mutated" {
		t.Fatal("List returned an alias; caller mutated stored state")
	}
}
