package server

import (
	"net"
	"testing"
	"time"

	network "github.com/v57/hub-service-go/protocol"
)

func observationTicket(hubKey, ticketID, agentKey string) network.RendezvousTicket {
	return network.RendezvousTicket{
		HubKey: hubKey, TicketID: ticketID, AgentKey: agentKey,
	}
}

func TestUDPObservationsBoundAndSweep(t *testing.T) {
	now := time.Now()
	observations := newUDPObservationsWithLimits(2, 1)
	first := observationTicket("hub", "first", "agent-a")
	second := observationTicket("hub", "second", "agent-b")
	third := observationTicket("hub", "third", "agent-c")

	if !observations.put(first, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1001}, now.Add(time.Minute), now) {
		t.Fatal("first observation rejected")
	}
	if observations.put(second, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1002}, now.Add(time.Minute), now) {
		t.Fatal("per-source overflow accepted")
	}
	if !observations.put(second, &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1002}, now.Add(time.Minute), now) {
		t.Fatal("second source rejected")
	}
	if observations.put(third, &net.UDPAddr{IP: net.ParseIP("192.0.2.3"), Port: 1003}, now.Add(time.Minute), now) {
		t.Fatal("global overflow accepted")
	}
	if got := observations.len(); got != 2 {
		t.Fatalf("observations = %d, want 2", got)
	}
	if removed := observations.sweep(now.Add(time.Minute)); removed != 2 {
		t.Fatalf("removed = %d, want 2", removed)
	}
	if !observations.put(third, &net.UDPAddr{IP: net.ParseIP("192.0.2.3"), Port: 1003}, now.Add(2*time.Minute), now.Add(time.Minute)) {
		t.Fatal("capacity not reclaimed after expiry")
	}
}

func TestUDPObservationsUseHubScopedTicketID(t *testing.T) {
	now := time.Now()
	observations := newUDPObservationsWithLimits(2, 2)
	first := observationTicket("hub-a", "same", "agent-a")
	second := observationTicket("hub-b", "same", "agent-b")
	if !observations.put(first, &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 1001}, now.Add(time.Minute), now) ||
		!observations.put(second, &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 1002}, now.Add(time.Minute), now) {
		t.Fatal("Hub-scoped observations collided")
	}
	got, ok := observations.get(first, now)
	if !ok || got.AgentKey != "agent-a" || got.Port != 1001 {
		t.Fatalf("first observation = %+v, %v", got, ok)
	}
}
