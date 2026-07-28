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
	"github.com/v57/hub-net-node/version"
)

func main() {
	nodeID := flag.String("node-id", config.DefaultNodeID, "stable rendezvous node identifier")
	listen := flag.String("listen", config.DefaultListenAddress, "HTTP/WebSocket bind address")
	stateDir := flag.String("state-dir", config.DefaultStateDir(), "node state directory")
	logJSON := flag.Bool("log-json", true, "emit JSON structured logs")
	showVersion := flag.Bool("version", false, "print version and exit")
	maxConnections := flag.Int("max-connections", config.DefaultMaxConnections, "maximum accepted TCP connections")
	maxConnectionsPerSource := flag.Int("max-connections-per-source", config.DefaultMaxConnectionsPerSource, "maximum accepted TCP connections per source IP")
	flag.Parse()

	if *showVersion {
		_, _ = os.Stdout.WriteString(version.String() + "\n")
		return
	}

	cfg := config.Defaults()
	cfg.NodeID = *nodeID
	cfg.ListenAddress = *listen
	cfg.StateDir = *stateDir
	cfg.MaxConnections = *maxConnections
	cfg.MaxConnectionsPerSource = *maxConnectionsPerSource
	if !*logJSON {
		cfg.LogFormat = logging.FormatText
	}
	logger := logging.New(logging.Options{Format: cfg.LogFormat})

	agent, err := hubnetnode.New(hubnetnode.Options{Config: cfg, Logger: logger})
	if err != nil {
		logger.Error("node configuration failed", slog.String("err", err.Error()))
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := agent.Run(ctx); err != nil && ctx.Err() == nil {
		logger.Error("node run failed", slog.String("err", err.Error()))
		os.Exit(1)
	}
}
