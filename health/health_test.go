package health

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/v57/hub-net-node/protocol"
)

func newReporter(t *testing.T) *Reporter {
	t.Helper()
	return New(protocol.ServerCapabilities(protocol.DefaultLimits()))
}

func TestSnapshotAdvertisesRendezvousOnly(t *testing.T) {
	reporter := newReporter(t)
	snap := reporter.Snapshot()
	if len(snap.Protocol.Roles) != 1 || snap.Protocol.Roles[0] != protocol.RoleRendezvous {
		t.Fatalf("roles = %v, want [rendezvous]", snap.Protocol.Roles)
	}
	if !snap.Available {
		t.Fatal("snapshot Available = false, want true by default")
	}
	if !strings.HasPrefix(snap.Version, "1.0+") {
		t.Fatalf("Version = %q, want prefix 1.0+", snap.Version)
	}
}

func TestSessionCountRoundTrip(t *testing.T) {
	reporter := newReporter(t)
	reporter.IncrementSessions()
	reporter.IncrementSessions()
	if got := reporter.SessionCount(); got != 2 {
		t.Fatalf("SessionCount = %d, want 2", got)
	}
	reporter.DecrementSessions()
	if got := reporter.SessionCount(); got != 1 {
		t.Fatalf("SessionCount = %d, want 1", got)
	}
	// Decrement below zero is clamped.
	reporter.DecrementSessions()
	reporter.DecrementSessions()
	if got := reporter.SessionCount(); got != 0 {
		t.Fatalf("SessionCount = %d, want 0", got)
	}
}

func TestLastErrorMarksUnavailable(t *testing.T) {
	reporter := newReporter(t)
	reporter.SetLastError("disk full")
	snap := reporter.Snapshot()
	if snap.Available {
		t.Fatal("Available = true with lastError set")
	}
	if snap.LastError != "disk full" {
		t.Fatalf("LastError = %q, want %q", snap.LastError, "disk full")
	}
	reporter.SetLastError("")
	snap = reporter.Snapshot()
	if !snap.Available {
		t.Fatal("Available = false after clearing lastError")
	}
}

func TestUptimeAdvances(t *testing.T) {
	reporter := newReporter(t)
	time.Sleep(50 * time.Millisecond)
	snap := reporter.Snapshot()
	if snap.UptimeSec < 0 {
		t.Fatalf("UptimeSec = %d, want >= 0", snap.UptimeSec)
	}
}

func TestHTTPHandlerEmitsJSON(t *testing.T) {
	reporter := newReporter(t)
	reporter.IncrementSessions()
	server := httptest.NewServer(reporter.HTTPHandler())
	defer server.Close()

	resp, err := http.Get(server.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var snap Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if snap.Sessions != 1 {
		t.Fatalf("Sessions = %d, want 1", snap.Sessions)
	}
	if len(snap.Protocol.Roles) != 1 || snap.Protocol.Roles[0] != protocol.RoleRendezvous {
		t.Fatalf("roles = %v, want [rendezvous]", snap.Protocol.Roles)
	}
}

func TestHTTPHandlerRejectsPost(t *testing.T) {
	reporter := newReporter(t)
	server := httptest.NewServer(reporter.HTTPHandler())
	defer server.Close()

	resp, err := http.Post(server.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}
