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
	udpListen := flag.String("udp-listen", "", "UDP observation bind address (default: the -listen address); must be the port of the node URL agents use")
	proxyProtocolFrom := flag.String("proxy-protocol-from", "", "comma-separated proxy addresses or CIDRs whose TCP connections carry a PROXY protocol v1/v2 header")
	stateDir := flag.String("state-dir", config.DefaultStateDir(), "node state directory")
	logJSON := flag.Bool("log-json", true, "emit JSON structured logs")
	showVersion := flag.Bool("version", false, "print version and exit")
	registrationLease := flag.Duration("registration-lease", 0, "online-inviter registration lease (default and maximum 2m; lower for tests)")
	sessionLifetime := flag.Duration("session-lifetime", 0, "idle limit of a rendezvous connection (default and maximum 2m; lower for tests)")
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
	cfg.UDPListenAddress = *udpListen
	cfg.StateDir = *stateDir
	cfg.MaxConnections = *maxConnections
	cfg.MaxConnectionsPerSource = *maxConnectionsPerSource
	if *registrationLease != 0 {
		cfg.RegistrationLease = *registrationLease
	}
	if *sessionLifetime != 0 {
		cfg.Limits.SessionLifetime = *sessionLifetime
	}
	if !*logJSON {
		cfg.LogFormat = logging.FormatText
	}
	logger := logging.New(logging.Options{Format: cfg.LogFormat})
	trustedProxies, err := config.ParseTrustedProxies(*proxyProtocolFrom)
	if err != nil {
		logger.Error("node configuration failed", slog.String("err", err.Error()))
		os.Exit(1)
	}
	cfg.TrustedProxies = trustedProxies

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
