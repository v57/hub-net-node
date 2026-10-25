package server

import (
	"net"
	"testing"
	"time"
)

type observation struct{ key, agent string }

func (o *udpObservations) put(entry observation, address *net.UDPAddr, expiresAt, now time.Time) bool {
	return o.putKey(entry.key, entry.agent, address, expiresAt, now)
}

func TestUDPObservationsBoundAndSweep(t *testing.T) {
	now := time.Now()
	observations := newUDPObservationsWithLimits(2, 1)
	first := observation{"first", "agent-a"}
	second := observation{"second", "agent-b"}
	third := observation{"third", "agent-c"}

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
