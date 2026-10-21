// Package config defines hub-net-node configuration.
//
// The rendezvous node reads a single configuration document. The document is
// intentionally small: bind address, trusted Hub public key path, state
// directory, operator-tunable coordination limits, and logging knobs. Default
// values mirror PROTOCOL.md. Operators may lower limits; raising them is a
// deployment choice and does not change the wire protocol.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/v57/hub-net-node/logging"
	"github.com/v57/hub-net-node/protocol"
)

// DefaultListenAddress is the HTTP/WebSocket bind endpoint. The node serves
// /healthz and /rendezvous on this address.
const DefaultListenAddress = ":1964"

// DefaultNodeID is the ticket binding used by a single default deployment.
const DefaultNodeID = "default"

const (
	// AdmissionOpen accepts self-contained tickets from arbitrary Hub keys.
	// Ticket signatures provide integrity, not operator trust or Sybil resistance.
	AdmissionOpen = "open"

	DefaultMaxConnections          = 256
	DefaultMaxConnectionsPerSource = 16
	DefaultHandshakeTimeout        = 10 * time.Second
	DefaultMaxHeaderBytes          = 8 * 1024
)

// DefaultStateDir is the per-platform node state directory. Root-owned on
// Darwin/Linux so the trusted Hub public key, session state, and runtime
// files are colocated.
func DefaultStateDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "/var/lib/hub-net-node"
	case "linux":
		return "/var/lib/hub-net-node"
	case "windows":
		return filepath.Join(os.Getenv("ProgramData"), "hub-net-node")
	default:
		return filepath.Join(os.TempDir(), "hub-net-node")
	}
}

// Config is the hub-net-node configuration document.
type Config struct {
	// NodeID is the stable identifier Hub tickets must target.
	NodeID string `json:"nodeId,omitempty"`
	// ListenAddress is the HTTP/WebSocket bind endpoint. Defaults to
	// DefaultListenAddress.
	ListenAddress string `json:"listenAddress,omitempty"`
	// StateDir holds the trusted Hub public key and runtime state. Defaults
	// to DefaultStateDir().
	StateDir string `json:"stateDir,omitempty"`
	// Limits bounds coordination traffic. Defaults to
	// protocol.DefaultLimits(). Operators may lower these values; raising
	// them is a deployment choice that does not change the wire protocol.
	Limits protocol.Limits `json:"limits,omitempty"`
	// LogFormat selects JSON or text slog output. Defaults to JSON.
	LogFormat logging.Format `json:"logFormat,omitempty"`
	// LogLevel is the slog level. Defaults to Info when zero.
	LogLevel slog.Level `json:"logLevel,omitempty"`
	// AdmissionPolicy is explicit because self-contained tickets do not prove
	// operator trust. Version 1 supports open public admission protected by
	// source/global resource bounds.
	AdmissionPolicy string `json:"admissionPolicy,omitempty"`
	// MaxConnections bounds accepted TCP sockets, including incomplete HTTP
	// handshakes and silent pre-auth clients.
	MaxConnections int `json:"maxConnections,omitempty"`
	// MaxConnectionsPerSource bounds sockets by remote IP, independent of
	// attacker-controlled Hub or agent identities.
	MaxConnectionsPerSource int           `json:"maxConnectionsPerSource,omitempty"`
	HandshakeTimeout        time.Duration `json:"-"`
	MaxHeaderBytes          int           `json:"maxHeaderBytes,omitempty"`
	// RegistrationLease is how long an online inviter's registration lasts
	// without a renewal. Defaults to protocol.DefaultRegistrationLifetime; it may
	// only be lowered (tests use a few seconds).
	RegistrationLease time.Duration `json:"-"`
}

// Defaults returns a Config populated with documented defaults. Caller may
// override fields before calling Resolve.
func Defaults() Config {
	return Config{
		NodeID:                  DefaultNodeID,
		ListenAddress:           DefaultListenAddress,
		StateDir:                DefaultStateDir(),
		Limits:                  protocol.DefaultLimits(),
		LogFormat:               logging.FormatJSON,
		LogLevel:                logging.DefaultLevel,
		AdmissionPolicy:         AdmissionOpen,
		MaxConnections:          DefaultMaxConnections,
		MaxConnectionsPerSource: DefaultMaxConnectionsPerSource,
		HandshakeTimeout:        DefaultHandshakeTimeout,
		MaxHeaderBytes:          DefaultMaxHeaderBytes,
		RegistrationLease:       protocol.DefaultRegistrationLifetime,
	}
}

// Resolve fills empty fields with defaults and validates required ones. It
// does not touch the filesystem.
func (c *Config) Resolve() error {
	if c.NodeID == "" {
		c.NodeID = DefaultNodeID
	}
	if c.ListenAddress == "" {
		c.ListenAddress = DefaultListenAddress
	}
	if c.StateDir == "" {
		c.StateDir = DefaultStateDir()
	}
	if c.LogFormat == "" {
		c.LogFormat = logging.FormatJSON
	}
	if c.AdmissionPolicy == "" {
		c.AdmissionPolicy = AdmissionOpen
	}
	if c.AdmissionPolicy != AdmissionOpen {
		return fmt.Errorf("config: unsupported admissionPolicy %q", c.AdmissionPolicy)
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = DefaultMaxConnections
	}
	if c.MaxConnectionsPerSource == 0 {
		c.MaxConnectionsPerSource = DefaultMaxConnectionsPerSource
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if c.MaxHeaderBytes == 0 {
		c.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if c.MaxConnections < 1 || c.MaxConnectionsPerSource < 1 ||
		c.MaxConnectionsPerSource > c.MaxConnections {
		return errors.New("config: connection limits must be positive and per-source must not exceed global")
	}
	if c.HandshakeTimeout <= 0 || c.MaxHeaderBytes < 1024 {
		return errors.New("config: handshakeTimeout must be positive and maxHeaderBytes at least 1024")
	}
	if c.Limits.SessionLifetime == 0 {
		c.Limits = protocol.DefaultLimits()
	}
	if c.RegistrationLease == 0 {
		c.RegistrationLease = protocol.DefaultRegistrationLifetime
	}
	if c.RegistrationLease < 0 || c.RegistrationLease > protocol.DefaultRegistrationLifetime {
		return fmt.Errorf("config: registrationLease must be positive and at most %s", protocol.DefaultRegistrationLifetime)
	}
	if err := validateLimits(c.Limits); err != nil {
		return err
	}
	return nil
}

// validateLimits rejects non-positive or oversized operator overrides. The
// rendezvous protocol freezes the default values; an operator may lower them
// for a deployment, but a zero or negative value would silently disable the
// limit rather than apply the documented default.
func validateLimits(limits protocol.Limits) error {
	if limits.MaxSessionsPerAgent <= 0 {
		return errors.New("config: maxSessionsPerAgent must be positive")
	}
	if limits.MaxCandidates <= 0 {
		return errors.New("config: maxCandidates must be positive")
	}
	if limits.MaxMessageBytes <= 0 {
		return errors.New("config: maxMessageBytes must be positive")
	}
	if limits.MessagesPerSecond <= 0 {
		return errors.New("config: messagesPerSecond must be positive")
	}
	if limits.SessionLifetime <= 0 {
		return errors.New("config: sessionLifetime must be positive")
	}
	if limits.CandidateLifetime <= 0 {
		return errors.New("config: candidateLifetime must be positive")
	}
	if limits.SessionLifetime > protocol.DefaultSessionLifetime {
		return fmt.Errorf("config: sessionLifetime %s exceeds protocol default %s", limits.SessionLifetime, protocol.DefaultSessionLifetime)
	}
	if limits.CandidateLifetime > protocol.DefaultCandidateLifetime {
		return fmt.Errorf("config: candidateLifetime %s exceeds protocol default %s", limits.CandidateLifetime, protocol.DefaultCandidateLifetime)
	}
	return nil
}

// EnsureStateDir creates StateDir with restrictive permissions when absent.
// The trusted Hub public key and runtime state live beneath it; only the node
// user should read it.
func (c *Config) EnsureStateDir() error {
	if c.StateDir == "" {
		return errors.New("config: stateDir empty (call Resolve first)")
	}
	if err := os.MkdirAll(c.StateDir, 0o700); err != nil {
		return fmt.Errorf("config: create state dir %s: %w", c.StateDir, err)
	}
	return nil
}

// SessionLifetimeDuration exposes the resolved session lifetime for callers
// that prefer time.Duration over the wire millisecond form.
func (c Config) SessionLifetimeDuration() time.Duration { return c.Limits.SessionLifetime }

// CandidateLifetimeDuration exposes the resolved candidate lifetime.
func (c Config) CandidateLifetimeDuration() time.Duration { return c.Limits.CandidateLifetime }
