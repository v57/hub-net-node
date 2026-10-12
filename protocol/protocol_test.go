package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	network "github.com/v57/hub-service-go/protocol"
)

func TestCapabilitiesAdvertiseRendezvousOnly(t *testing.T) {
	capabilities := ServerCapabilities(DefaultLimits())
	if len(capabilities.Roles) != 1 || capabilities.Roles[0] != RoleRendezvous {
		t.Fatalf("unexpected roles: %v", capabilities.Roles)
	}
	if capabilities.MajorVersion != 1 || capabilities.Limits.MaxCandidates != 16 {
		t.Fatalf("unexpected capabilities: %#v", capabilities)
	}
}

func TestCandidateLifecycleIsBounded(t *testing.T) {
	now := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	candidate := network.Candidate{
		Version:     1,
		CandidateID: "candidate-1",
		SessionID:   "opaque-session",
		Key:         "agent-key",
		Kind:        "server-reflexive",
		Transport:   "udp",
		Address:     "203.0.113.10",
		Port:        51820,
		Priority:    100,
		ExpiresAt:   now.Add(30 * time.Second).Format(time.RFC3339Nano),
	}
	message := Envelope{
		MajorVersion: 1,
		MinorVersion: 0,
		Type:         MessageOfferCandidate,
		SessionID:    candidate.SessionID,
		Candidate:    &candidate,
	}
	if err := message.Validate(now, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	message.SessionID = "substituted-session"
	if err := message.Validate(now, DefaultLimits()); err == nil {
		t.Fatal("expected a candidate/session binding error")
	}
}

func TestCandidateListBindsObservedEndpointToPeer(t *testing.T) {
	now := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	candidate := network.Candidate{
		Version: 1, CandidateID: "candidate-1", SessionID: "recipient-session",
		Key: "peer-agent", Kind: "host", Transport: "udp",
		Address: "10.0.0.2", Port: 51820, Priority: 100,
		ExpiresAt: now.Add(30 * time.Second).Format(time.RFC3339Nano),
	}
	observed := ObservedEndpoint{
		Version: 1, Key: "peer-agent", Transport: "udp",
		Address: "203.0.113.10", Port: 43123,
	}
	message := Envelope{
		MajorVersion: 1, MinorVersion: 0, Type: MessageCandidates,
		SessionID: "recipient-session", Candidates: []network.Candidate{candidate},
		Observed: &observed,
	}
	if err := message.Validate(now, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	message.Observed.Key = "substituted-agent"
	if err := message.Validate(now, DefaultLimits()); err == nil {
		t.Fatal("expected candidate/observed peer binding error")
	}
}

func TestProtocolHasNoApplicationPayloadField(t *testing.T) {
	message := Envelope{MajorVersion: 1, MinorVersion: 0, Type: MessageCloseSession, SessionID: "session-1"}
	encoded, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{`"payload"`, `"data"`, `"packet"`} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("rendezvous envelope exposes application field %s", forbidden)
		}
	}

	var decoded Envelope
	if err := json.Unmarshal([]byte(`{"majorVersion":1,"minorVersion":0,"type":"session.close","sessionId":"session-1","payload":"forbidden"}`), &decoded); err != nil {
		t.Fatal(err)
	}
	if encodedAgain, _ := json.Marshal(decoded); strings.Contains(string(encodedAgain), "forbidden") {
		t.Fatal("unknown application payload survived decoding")
	}
}

func TestRejectsUnsupportedMajorVersion(t *testing.T) {
	message := Envelope{MajorVersion: 2, Type: MessageCloseSession, SessionID: "session-1"}
	if err := message.Validate(time.Now(), DefaultLimits()); err == nil {
		t.Fatal("expected unsupported version error")
	}
}

func TestBootstrapPendingCarriesExactTransactionIdentity(t *testing.T) {
	now := time.Now()
	message := Envelope{
		MajorVersion:   1,
		MinorVersion:   0,
		Type:           MessageBootstrapPending,
		InvitationCode: "payload/signature",
		Key:            "joiner-service-key",
		TokenDigest:    "digest",
		TransactionID:  "transaction-1",
		TunnelInstance: "tunnel-1",
		Generation:     7,
	}
	if err := message.Validate(now, DefaultLimits()); err != nil {
		t.Fatalf("valid inviter.bootstrap rejected: %v", err)
	}

	for name, mutate := range map[string]func(*Envelope){
		"missing code":        func(m *Envelope) { m.InvitationCode = "" },
		"missing key":         func(m *Envelope) { m.Key = "" },
		"missing digest":      func(m *Envelope) { m.TokenDigest = "" },
		"missing transaction": func(m *Envelope) { m.TransactionID = "" },
		"session field":       func(m *Envelope) { m.SessionID = "leaked-session" },
		"candidate field": func(m *Envelope) {
			m.Candidate = &network.Candidate{Version: 1, SessionID: "x", Key: "x"}
		},
		"registration field": func(m *Envelope) { m.ServiceKey = "inviter" },
	} {
		t.Run(name, func(t *testing.T) {
			broken := message
			mutate(&broken)
			if err := broken.Validate(now, DefaultLimits()); err == nil {
				t.Fatalf("inviter.bootstrap with %s accepted", name)
			}
		})
	}
}
