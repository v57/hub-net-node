package ticket

import (
	"errors"
	"testing"
	"time"

	"github.com/v57/hub-service-go/identity"
	network "github.com/v57/hub-service-go/protocol"
)

func TestVerifierAcceptsSelfContainedHubTicket(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	ticket := signedTicket(t, now)
	verifier := Verifier{NodeID: "node-public-1", Now: func() time.Time { return now }}
	if err := verifier.Verify(ticket); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifierRejectsMutationsAndInvalidLifetime(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	base := signedTicket(t, now)
	tests := []struct {
		name   string
		mutate func(*network.RendezvousTicket)
	}{
		{"profile binding", func(ticket *network.RendezvousTicket) { ticket.ProfileKey = "substituted" }},
		{"agent binding", func(ticket *network.RendezvousTicket) { ticket.AgentKey = "substituted" }},
		{"network binding", func(ticket *network.RendezvousTicket) { ticket.HubNetworkID = "substituted" }},
		{"node binding", func(ticket *network.RendezvousTicket) { ticket.NodeID = "other-node" }},
		{"purpose", func(ticket *network.RendezvousTicket) { ticket.SessionPurpose = "relay" }},
		{"role", func(ticket *network.RendezvousTicket) { ticket.Roles = []string{"gateway"} }},
		{"expired", func(ticket *network.RendezvousTicket) {
			ticket.IssuedAt = now.Add(-11 * time.Minute).Format(time.RFC3339Nano)
			ticket.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
		}},
	}
	verifier := Verifier{NodeID: "node-public-1", Now: func() time.Time { return now }}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ticket := base
			ticket.Roles = append([]string(nil), base.Roles...)
			test.mutate(&ticket)
			if err := verifier.Verify(ticket); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Verify error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestVerifierRejectsHubKeySubstitution(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	ticket := signedTicket(t, now)
	other, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	ticket.HubKey, err = other.PublicKeyBase64()
	if err != nil {
		t.Fatal(err)
	}
	verifier := Verifier{Now: func() time.Time { return now }}
	if err := verifier.Verify(ticket); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Verify error = %v, want ErrInvalid", err)
	}
}

func TestInvalidSignatureNeverAllocatesReplayState(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	verifier := Verifier{NodeID: "node-public-1", Now: func() time.Time { return now }}
	cache := NewReplayCache(1, 1, func() time.Time { return now })
	value := signedTicket(t, now)
	value.AgentKey = "signature-tampered"
	if err := verifier.Verify(value); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Verify error = %v, want ErrInvalid", err)
	}
	if got := cache.Len(); got != 0 {
		t.Fatalf("replay entries = %d, want 0", got)
	}
}

func signedTicket(t *testing.T, now time.Time) network.RendezvousTicket {
	t.Helper()
	hub, err := identity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	hubKey, err := hub.PublicKeyBase64()
	if err != nil {
		t.Fatal(err)
	}
	ticket := network.RendezvousTicket{
		Version:        network.WireVersion,
		TicketID:       "ticket-1",
		HubKey:         hubKey,
		HubNetworkID:   "network-1",
		ProfileKey:     "profile-1",
		AgentKey:       "agent-1",
		NodeID:         "node-public-1",
		Roles:          []string{"rendezvous"},
		SessionPurpose: "peer-connect",
		IssuedAt:       now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt:      now.Add(time.Minute).Format(time.RFC3339Nano),
	}
	ticket.Signature, err = network.SignEnvelope(
		network.PurposeRendezvousTicket,
		ticket,
		hub.PrivateKey(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return ticket
}
