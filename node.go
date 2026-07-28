// Package hubnetnode hosts the hub-net-node rendezvous process.
//
// hub-net-node is a coordination service, never a WireGuard peer or
// application traffic relay. The first release advertises exactly one role:
// rendezvous. This root package aggregates the lower-level config, server,
// and health packages into a single Agent entry point so binaries (see
// examples/basic) and operators get a thin wrapper around server.Server,
// mirroring how hubnet.Agent wraps the local-agent packages.
package hubnetnode

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/v57/hub-net-node/config"
	"github.com/v57/hub-net-node/logging"
	"github.com/v57/hub-net-node/protocol"
	"github.com/v57/hub-net-node/server"
	"github.com/v57/hub-net-node/version"
)

// Options configures the rendezvous node.
type Options struct {
	// Config is the resolved node configuration.
	Config config.Config
	// Logger is the structured logger. Defaults to JSON to stderr.
	Logger *slog.Logger
}

// Agent is the hub-net-node process. Construct with New and run with Run.
type Agent struct {
	server *server.Server
}

// New constructs an Agent from options. Missing Logger defaults to JSON to
// stderr matching logging.New(logging.Options{}).
func New(options Options) (*Agent, error) {
	cfg := options.Config
	if err := cfg.Resolve(); err != nil {
		return nil, fmt.Errorf("hubnetnode: resolve config: %w", err)
	}
	logger := options.Logger
	if logger == nil {
		logger = logging.New(logging.Options{Format: cfg.LogFormat, Level: cfg.LogLevel})
	}
	srv, err := server.New(server.Options{Config: cfg, Logger: logger})
	if err != nil {
		return nil, err
	}
	return &Agent{server: srv}, nil
}

// Server returns the underlying rendezvous server for tests and tooling.
func (a *Agent) Server() *server.Server { return a.server }

// Version reports the build identifier advertised by this node.
func (a *Agent) Version() string { return version.String() }

// Capabilities returns the protocol capabilities advertised to clients.
func (a *Agent) Capabilities() protocol.Capabilities { return a.server.Capabilities() }

// Prepare resolves bind state without accepting connections. Idempotent.
func (a *Agent) Prepare(ctx context.Context) error { return a.server.Prepare(ctx) }

// Run binds the HTTP/WebSocket server and blocks until ctx is cancelled or a
// fatal serve error occurs. Calls Prepare if not yet prepared.
func (a *Agent) Run(ctx context.Context) error { return a.server.Run(ctx) }

// Shutdown requests a graceful Run exit. Safe to call multiple times.
func (a *Agent) Shutdown() { a.server.Shutdown() }
