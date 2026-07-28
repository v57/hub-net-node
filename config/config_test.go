package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/v57/hub-net-node/logging"
	"github.com/v57/hub-net-node/protocol"
)

// newConfig returns a Config rooted beneath a temporary directory so tests
// never touch /var/lib. StateDir is one level below the temp dir so
// EnsureStateDir creates it with the documented 0700 mode.
func newConfig(t *testing.T) Config {
	t.Helper()
	defaults := Defaults()
	stateDir := filepath.Join(t.TempDir(), "node-state")
	defaults.StateDir = stateDir
	return defaults
}

func TestResolveFillsDefaults(t *testing.T) {
	var c Config
	if err := c.Resolve(); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.ListenAddress != DefaultListenAddress {
		t.Fatalf("ListenAddress = %q, want %q", c.ListenAddress, DefaultListenAddress)
	}
	if c.NodeID != DefaultNodeID {
		t.Fatalf("NodeID = %q, want %q", c.NodeID, DefaultNodeID)
	}
	if c.Limits.MaxSessionsPerAgent != protocol.DefaultMaxSessionsPerAgent {
		t.Fatalf("MaxSessionsPerAgent = %d, want %d", c.Limits.MaxSessionsPerAgent, protocol.DefaultMaxSessionsPerAgent)
	}
	if c.Limits.SessionLifetime != protocol.DefaultSessionLifetime {
		t.Fatalf("SessionLifetime = %s, want %s", c.Limits.SessionLifetime, protocol.DefaultSessionLifetime)
	}
	if c.LogFormat != logging.FormatJSON {
		t.Fatalf("LogFormat = %q, want %q", c.LogFormat, logging.FormatJSON)
	}
}

func TestResolveRejectsZeroLimits(t *testing.T) {
	c := newConfig(t)
	c.Limits.MaxSessionsPerAgent = 0
	if err := c.Resolve(); err == nil {
		t.Fatal("Resolve accepted zero maxSessionsPerAgent")
	}
}

func TestResolveRejectsRaisedSessionLifetime(t *testing.T) {
	c := newConfig(t)
	c.Limits.SessionLifetime = protocol.DefaultSessionLifetime + time.Minute
	if err := c.Resolve(); err == nil {
		t.Fatal("Resolve accepted a raised sessionLifetime")
	}
}

func TestResolveAcceptsLoweredLimits(t *testing.T) {
	c := newConfig(t)
	c.Limits.MaxSessionsPerAgent = 4
	c.Limits.MaxCandidates = 4
	c.Limits.SessionLifetime = 30 * time.Second
	if err := c.Resolve(); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.Limits.MaxSessionsPerAgent != 4 {
		t.Fatalf("MaxSessionsPerAgent = %d, want 4", c.Limits.MaxSessionsPerAgent)
	}
}

func TestEnsureStateDirCreatesDir(t *testing.T) {
	c := newConfig(t)
	if err := c.Resolve(); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := c.EnsureStateDir(); err != nil {
		t.Fatalf("EnsureStateDir: %v", err)
	}
	info, err := statMode(c.StateDir)
	if err != nil {
		t.Fatalf("statMode: %v", err)
	}
	if mode := info & 0o777; mode != 0o700 {
		t.Fatalf("StateDir mode = %o, want 700", mode)
	}
}

// statMode reports the permission bits of path.
func statMode(path string) (os.FileMode, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	return info.Mode(), nil
}
