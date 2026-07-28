// Command hubnetnode runs a self-hostable Hub Network rendezvous node.
//
// This is a thin wrapper around hubnetnode.Agent. It binds an HTTP/WebSocket
// server that advertises the rendezvous role and the configured coordination
// limits. Health is served at /healthz. The /rendezvous endpoint exists with a
// wire-shaped protocol.NetworkError until HN-401 wires ticket verification
// and HN-402 wires session lifecycle.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	hubnetnode "github.com/v57/hub-net-node"
	"github.com/v57/hub-net-node/config"
	"github.com/v57/hub-net-node/logging"
)

func main() {
	nodeID := flag.String("node-id", config.DefaultNodeID, "stable rendezvous node identifier")
	listen := flag.String("listen", config.DefaultListenAddress, "HTTP/WebSocket bind address")
	stateDir := flag.String("state-dir", config.DefaultStateDir(), "node state directory")
	logJSON := flag.Bool("log-json", true, "emit JSON structured logs")
	flag.Parse()

	cfg := config.Defaults()
	cfg.NodeID = *nodeID
	cfg.ListenAddress = *listen
	cfg.StateDir = *stateDir
	cfg.LogFormat = format(*logJSON)

	agent, err := hubnetnode.New(hubnetnode.Options{
		Config: cfg,
		Logger: logging.New(logging.Options{Format: cfg.LogFormat}),
	})
	if err != nil {
		// Logger not yet built; write to stderr directly.
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := agent.Run(ctx); err != nil && !isContextDone(ctx) {
		slog.Default().Error("node run failed", slog.String("err", err.Error()))
		os.Exit(1)
	}
}

func format(json bool) logging.Format {
	if json {
		return logging.FormatJSON
	}
	return logging.FormatText
}

func isContextDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}
