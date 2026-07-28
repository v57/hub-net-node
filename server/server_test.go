package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/v57/hub-net-node/config"
	"github.com/v57/hub-net-node/protocol"
)

// newServer returns a Server bound to a temporary state dir and a random
// local port so tests never touch real addresses or /var/lib.
func newServer(t *testing.T) *Server {
	t.Helper()
	cfg := config.Defaults()
	cfg.StateDir = t.TempDir() + "/node-state"
	cfg.ListenAddress = "127.0.0.1:0"
	if err := cfg.Resolve(); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	server, err := New(Options{Config: cfg})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return server
}

func TestNewAdvertisesRendezvousOnly(t *testing.T) {
	server := newServer(t)
	caps := server.Capabilities()
	if caps.MajorVersion != protocol.MajorVersion {
		t.Fatalf("MajorVersion = %d, want %d", caps.MajorVersion, protocol.MajorVersion)
	}
	if caps.MinorVersion != protocol.MinorVersion {
		t.Fatalf("MinorVersion = %d, want %d", caps.MinorVersion, protocol.MinorVersion)
	}
	if len(caps.Roles) != 1 || caps.Roles[0] != protocol.RoleRendezvous {
		t.Fatalf("Roles = %v, want [rendezvous]", caps.Roles)
	}
	if caps.Limits.MaxCandidates != protocol.DefaultMaxCandidates {
		t.Fatalf("MaxCandidates = %d, want %d", caps.Limits.MaxCandidates, protocol.DefaultMaxCandidates)
	}
}

func TestPrepareIsIdempotent(t *testing.T) {
	server := newServer(t)
	ctx := context.Background()
	if err := server.Prepare(ctx); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := server.Prepare(ctx); err != nil {
		t.Fatalf("second Prepare: %v", err)
	}
}

// TestRendezvousRequiresWebSocketUpgrade verifies the handler rejects a plain
// GET without WebSocket upgrade headers rather than performing a half-open
// handshake. The node only speaks the rendezvous protocol over WebSocket.
func TestRendezvousRequiresWebSocketUpgrade(t *testing.T) {
	server := newServer(t)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, RendezvousPath, nil)
	server.httpServer.Handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestRendezvousRejectsPost(t *testing.T) {
	server := newServer(t)
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, RendezvousPath, strings.NewReader("{}"))
	server.httpServer.Handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", recorder.Code)
	}
}

// TestRunServesHealth verifies a real Run loop: bind, accept health request,
// shut down. Uses a real listener on a random port.
func TestRunServesHealth(t *testing.T) {
	server := newServer(t)
	runErr := make(chan error, 1)
	runCtx, cancel := context.WithCancel(context.Background())
	go func() {
		runErr <- server.Run(runCtx)
	}()

	// Poll until health responds — the listener binds asynchronously inside
	// Run. Bound by the request deadline; failure to come up is a real bug.
	healthURL := ""
	for i := 0; i < 50; i++ {
		addr := server.ActualAddress()
		if addr == "" {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		healthURL = "http://" + addr + HealthPath
		resp, err := http.Get(healthURL)
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("health status = %d, want 200; body=%s", resp.StatusCode, body)
		}
		var snap map[string]any
		if err := json.Unmarshal(body, &snap); err != nil {
			t.Fatalf("Unmarshal health: %v", err)
		}
		if snap["available"] != true {
			t.Fatalf("health.available = %v, want true", snap["available"])
		}
		break
	}
	if healthURL == "" {
		t.Fatal("health endpoint never came up")
	}

	cancel()
	select {
	case err := <-runErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit after cancel")
	}
}

func TestShutdownIsIdempotent(t *testing.T) {
	server := newServer(t)
	server.Shutdown() // No-op: not running.
	server.Shutdown()
}
