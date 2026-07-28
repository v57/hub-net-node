// Package server hosts the hub-net-node HTTP/WebSocket rendezvous endpoint.
//
// The node advertises exactly one role: rendezvous. The first release rejects
// inbound session handling with a wire-shaped error so HN-401 (ticket
// verification) and HN-402 (session lifecycle, candidate exchange) can fill
// the handler without changing the server shape. The node never forwards
// application traffic; see PROTOCOL.md "No-payload invariant".
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/v57/hub-net-node/config"
	"github.com/v57/hub-net-node/health"
	"github.com/v57/hub-net-node/limiter"
	"github.com/v57/hub-net-node/logging"
	"github.com/v57/hub-net-node/protocol"
	"github.com/v57/hub-net-node/session"
	"github.com/v57/hub-net-node/ticket"
	"github.com/v57/hub-net-node/transport/ws"
	network "github.com/v57/hub-service-go/protocol"
)

// RendezvousPath is the WebSocket endpoint an agent opens to coordinate.
const RendezvousPath = "/rendezvous"

// HealthPath is the HTTP health endpoint.
const HealthPath = "/healthz"

// Options configures the rendezvous server.
type Options struct {
	// Config is the resolved node configuration.
	Config config.Config
	// Logger is the structured logger. Defaults to JSON to stderr.
	Logger *slog.Logger
}

// Server is the hub-net-node rendezvous process. Construct with New and run
// with Run.
type Server struct {
	cfg          config.Config
	logger       *slog.Logger
	capabilities protocol.Capabilities
	reporter     *health.Reporter
	tickets      ticket.Verifier
	replays      *ticket.ReplayCache
	sessions     *session.Store
	udpObserved  *udpObservations
	httpServer   *http.Server

	// peers maps a live session id to its connection's writer, so candidate
	// updates can be pushed to the matched peer's open connection. A connection
	// registers on session.open and deregisters on close/disconnect.
	peersMu       sync.RWMutex
	peers         map[string]func(protocol.Envelope)
	listenAddress string

	mu            sync.Mutex
	prepared      bool
	started       bool
	runCancel     context.CancelFunc
	shutdownCh    chan struct{}
	actualAddress string
}

// New constructs a Server from options. Missing Logger defaults to JSON to
// stderr matching logging.New(logging.Options{}). The capabilities advertised
// to clients come from the configured limits.
func New(options Options) (*Server, error) {
	cfg := options.Config
	if err := cfg.Resolve(); err != nil {
		return nil, fmt.Errorf("hubnetnode: resolve config: %w", err)
	}
	logger := options.Logger
	if logger == nil {
		logger = logging.New(logging.Options{Format: cfg.LogFormat, Level: cfg.LogLevel})
	}
	capabilities := protocol.ServerCapabilities(cfg.Limits)
	reporter := health.New(capabilities)
	sessions := session.New(cfg.Limits, nil)
	server := &Server{
		cfg:           cfg,
		logger:        logger,
		capabilities:  capabilities,
		reporter:      reporter,
		tickets:       ticket.Verifier{NodeID: cfg.NodeID},
		replays:       ticket.NewReplayCache(ticket.DefaultReplayCapacity, ticket.DefaultReplayPerSource, nil),
		sessions:      sessions,
		udpObserved:   newUDPObservations(),
		peers:         make(map[string]func(protocol.Envelope)),
		listenAddress: cfg.ListenAddress,
		shutdownCh:    make(chan struct{}),
	}
	mux := http.NewServeMux()
	mux.Handle(HealthPath, reporter.HTTPHandler())
	mux.HandleFunc(RendezvousPath, server.handleRendezvous)
	httpServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: cfg.HandshakeTimeout,
		ReadTimeout:       cfg.HandshakeTimeout,
		WriteTimeout:      cfg.HandshakeTimeout,
		IdleTimeout:       cfg.Limits.SessionLifetime,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}
	server.httpServer = httpServer
	return server, nil
}

// Capabilities returns the protocol capabilities advertised to clients.
func (s *Server) Capabilities() protocol.Capabilities { return s.capabilities }

// Reporter exposes the health reporter for tests and operational tooling.
func (s *Server) Reporter() *health.Reporter { return s.reporter }

// Config returns the resolved node configuration.
func (s *Server) Config() config.Config { return s.cfg }

// VerifyTicket authenticates one self-contained Hub ticket and enforces this
// deployment's node binding. No Hub allowlist or prior registration is used.
func (s *Server) VerifyTicket(value network.RendezvousTicket) error {
	return s.tickets.Verify(value)
}

// ActualAddress returns the bound address once Run has accepted a listener.
// Empty before Run.
func (s *Server) ActualAddress() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.actualAddress
}

// Prepare resolves the bind state without accepting connections. Idempotent.
// HN-401 will load and validate the trusted Hub public key here; the scaffold
// only ensures the state directory exists.
func (s *Server) Prepare(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.prepared {
		return nil
	}
	if err := s.cfg.EnsureStateDir(); err != nil {
		return fmt.Errorf("hubnetnode: ensure state dir: %w", err)
	}
	s.prepared = true
	s.logger.Info("node prepared",
		slog.String("listen", s.listenAddress),
		slog.String("stateDir", s.cfg.StateDir),
		slog.Int("maxSessionsPerAgent", s.cfg.Limits.MaxSessionsPerAgent),
	)
	return nil
}

// Run binds the HTTP/WebSocket server and blocks until ctx is cancelled or a
// fatal serve error occurs. Calls Prepare if not yet prepared.
func (s *Server) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("hubnetnode: already running")
	}
	if !s.prepared {
		s.mu.Unlock()
		if err := s.Prepare(ctx); err != nil {
			return err
		}
		s.mu.Lock()
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.runCancel = cancel
	s.started = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.started = false
		s.runCancel = nil
		s.mu.Unlock()
		close(s.shutdownCh)
		// Reset for re-run.
		s.shutdownCh = make(chan struct{})
	}()

	listenerClosed := make(chan struct{})
	listener, err := newListener(s.listenAddress)
	if err != nil {
		return fmt.Errorf("hubnetnode: listen %s: %w", s.listenAddress, err)
	}
	s.mu.Lock()
	s.actualAddress = listener.Addr().String()
	s.mu.Unlock()
	s.logger.Info("node listening", slog.String("address", listener.Addr().String()))
	listener = newAdmissionListener(
		listener,
		s.cfg.MaxConnections,
		s.cfg.MaxConnectionsPerSource,
		func(source string) {
			// Source IP is operational metadata. Tickets, signatures, and keys
			// are deliberately never logged on admission rejection.
			s.logger.Warn("connection admission rejected", slog.String("source", source))
		},
	)

	udpAddress, err := net.ResolveUDPAddr("udp", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("hubnetnode: resolve UDP observation address: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("hubnetnode: listen UDP observation %s: %w", udpAddress, err)
	}
	defer udpConn.Close()
	udpStopped := make(chan struct{})
	go s.serveUDPObservations(runCtx.Done(), udpConn, udpStopped)

	serveErr := make(chan error, 1)
	go func() {
		err := s.httpServer.Serve(listener)
		close(listenerClosed)
		serveErr <- err
	}()

	// Reclaim expired sessions and stale candidates on the candidate-lifetime
	// cadence. Each tick decrements the health counter for the sessions it
	// removes so /healthz reflects live coordination state.
	sweepStopped := make(chan struct{})
	go s.runSweepLoop(runCtx, sweepStopped)

	select {
	case <-runCtx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), protocol.DefaultCandidateLifetime)
		defer shutdownCancel()
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.logger.Error("node shutdown failed", slog.String("err", err.Error()))
		}
		_ = udpConn.Close()
		<-udpStopped
		<-sweepStopped
		<-listenerClosed
		return runCtx.Err()
	case err := <-serveErr:
		_ = udpConn.Close()
		<-udpStopped
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.reporter.SetLastError(err.Error())
			return fmt.Errorf("hubnetnode: serve: %w", err)
		}
		<-sweepStopped
		return nil
	}
}

// runSweepLoop periodically expires sessions and stale candidates. The tick
// interval is the candidate lifetime so the shortest-lived retained metadata
// is reclaimed within one interval of expiry.
func (s *Server) runSweepLoop(ctx context.Context, stopped chan struct{}) {
	defer close(stopped)
	interval := s.cfg.Limits.CandidateLifetime
	if interval <= 0 {
		interval = protocol.DefaultCandidateLifetime
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed := s.sessions.Sweep()
			s.replays.Sweep()
			s.udpObserved.sweep(time.Now())
			for i := 0; i < removed; i++ {
				s.reporter.DecrementSessions()
			}
		}
	}
}

// Shutdown requests a graceful Run exit. Safe to call multiple times.
func (s *Server) Shutdown() {
	s.mu.Lock()
	cancel := s.runCancel
	ch := s.shutdownCh
	s.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if ch != nil {
		<-ch
	}
}

// handleRendezvous upgrades one WebSocket connection and drives the session
// lifecycle for it. The first message must be session.open with a valid Hub
// ticket; subsequent messages exchange candidates until session.close or
// disconnect. Every message is size- and rate-limited and validated against
// the no-payload envelope contract before any session state is touched.
func (s *Server) handleRendezvous(writer http.ResponseWriter, request *http.Request) {
	conn, err := ws.Upgrade(writer, request, s.cfg.Limits.MaxMessageBytes)
	if err != nil {
		// Upgrade already wrote the HTTP error response; only log here.
		if !errors.Is(err, ws.ErrBadRequest) {
			s.logger.Error("rendezvous upgrade failed", slog.String("err", err.Error()))
		}
		return
	}
	defer conn.Close()
	// Bound the whole connection so a silent peer cannot hold state forever.
	_ = conn.SetDeadline(time.Now().Add(s.cfg.Limits.SessionLifetime))

	state := &connState{
		conn:    conn,
		limiter: limiter.New(s.cfg.Limits.MessagesPerSecond, nil),
		source:  remoteSourceIP(request.RemoteAddr),
	}
	s.serveRendezvous(request.Context(), state)
}

// serveRendezvous is the read loop for one upgraded connection. The read loop
// and any peer-push goroutine both write to the same connection, so all writes
// go through writeEnvelope which holds the per-connection write mutex.
func (s *Server) serveRendezvous(ctx context.Context, state *connState) {
	// Refresh the deadline on every message so active sessions are not killed
	// mid-exchange, but idle connections still expire.
	defer func() {
		if state.sessionID != "" {
			s.unregisterPeer(state.sessionID)
			s.sessions.Close(state.sessionID)
			s.reporter.DecrementSessions()
		}
	}()

	for {
		// Reset per-message deadline: a peer may stay connected as long as it
		// keeps exchanging coordination messages within the session lifetime.
		_ = state.conn.SetDeadline(time.Now().Add(s.cfg.Limits.SessionLifetime))
		payload, err := state.conn.ReadMessage()
		if err != nil {
			return
		}
		if !state.limiter.Allow() {
			s.writeError(state, "rate_limited", "message rate exceeded", true)
			continue
		}
		if done := s.processEnvelope(ctx, state, payload); done {
			return
		}
	}
}

// processEnvelope decodes, validates, and dispatches one inbound envelope.
// Returns true when the connection should close (session.close, fatal error).
// Errors are always reported as a wire-shaped MessageError rather than dropped.
func (s *Server) processEnvelope(_ context.Context, state *connState, payload []byte) bool {
	// Disallow unknown fields so a payload-bearing or experimental message
	// cannot smuggle data through the rendezvous node (HN-404 invariant).
	var envelope protocol.Envelope
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		s.writeError(state, "bad_request", "malformed envelope", false)
		return false
	}
	// A WebSocket message must contain exactly one JSON value. Decode again
	// and require EOF so a valid envelope followed by another value cannot
	// bypass the no-payload invariant.
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		s.writeError(state, "bad_request", "malformed envelope", false)
		return false
	}
	if err := envelope.Validate(time.Now(), s.cfg.Limits); err != nil {
		s.writeError(state, "bad_request", err.Error(), false)
		return false
	}

	switch envelope.Type {
	case protocol.MessageOpenSession:
		rendezvousTicket := *envelope.Ticket
		if err := s.tickets.Verify(rendezvousTicket); err != nil {
			s.writeError(state, "unauthorized", "ticket rejected", false)
			return false
		}
		if state.sessionID != "" {
			s.writeError(state, "bad_request", "session already open", false)
			return false
		}
		observed, ok := s.udpObserved.get(rendezvousTicket, time.Now())
		if !ok {
			s.writeError(state, "udp_observation_required", "authenticated UDP probe required before session.open", true)
			return false
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, rendezvousTicket.ExpiresAt)
		if err != nil {
			s.writeError(state, "unauthorized", "ticket rejected", false)
			return false
		}
		replayKey := rendezvousTicket.HubKey + "\x00" + rendezvousTicket.TicketID
		if err := s.replays.Consume(replayKey, state.source, expiresAt); err != nil {
			code := "replay_detected"
			retryable := false
			if errors.Is(err, ticket.ErrReplayCapacity) {
				code = "capacity_exceeded"
				retryable = true
			}
			s.writeError(state, code, err.Error(), retryable)
			return false
		}
		id, err := s.sessions.Open(rendezvousTicket, observed)
		if err != nil {
			s.replays.Release(replayKey)
			s.writeError(state, errorCode(err), err.Error(), errors.Is(err, session.ErrSessionLimitExceeded))
			return false
		}
		state.sessionID = id
		state.ticket = rendezvousTicket
		s.reporter.IncrementSessions()
		// Register this connection so the matched peer's offers can push
		// candidate updates here. writeEnvelope holds the per-connection write
		// lock, so concurrent writes from a peer-push goroutine are safe.
		s.registerPeer(id, func(envelope protocol.Envelope) { s.writeEnvelope(state, envelope) })
		s.writeEnvelope(state, protocol.Envelope{
			MajorVersion: protocol.MajorVersion,
			MinorVersion: protocol.MinorVersion,
			Type:         protocol.MessageSessionOpened,
			RequestID:    envelope.RequestID,
			SessionID:    id,
		})
		// If a peer was already waiting, deliver its candidates now.
		s.deliverPeerCandidates(state)
		return false

	case protocol.MessageOfferCandidate:
		if state.sessionID == "" {
			s.writeError(state, "bad_request", "no open session", false)
			return false
		}
		candidate := *envelope.Candidate
		if err := s.sessions.Offer(state.sessionID, candidate); err != nil {
			retryable := !errors.Is(err, session.ErrCandidateExpired)
			s.writeError(state, errorCode(err), err.Error(), retryable)
			return false
		}
		// Push the updated candidate list to the matched peer's open connection
		// so it learns about this offer without polling.
		s.pushToPeer(state.sessionID)
		return false

	case protocol.MessageCloseSession:
		if state.sessionID != "" {
			s.unregisterPeer(state.sessionID)
			s.sessions.Close(state.sessionID)
			s.reporter.DecrementSessions()
			state.sessionID = ""
		}
		return true

	default:
		// Validate already rejected unknown types; defensive double check.
		s.writeError(state, "bad_request", "unsupported message type", false)
		return false
	}
}

// deliverPeerCandidates sends the matched peer's candidates (plus the peer's
// observed endpoint) to this connection. No-op until the session is paired.
func (s *Server) deliverPeerCandidates(state *connState) {
	if state.sessionID == "" {
		return
	}
	candidates, observed, err := s.sessions.List(state.sessionID)
	if err != nil {
		return // Not matched yet; will be delivered when the peer offers.
	}
	envelope := protocol.Envelope{
		MajorVersion: protocol.MajorVersion,
		MinorVersion: protocol.MinorVersion,
		Type:         protocol.MessageCandidates,
		SessionID:    state.sessionID,
		Candidates:   candidates,
		Observed:     &observed,
	}
	s.writeEnvelope(state, envelope)
	s.logger.Debug("delivered candidates",
		slog.String("session", state.sessionID),
		slog.Int("candidates", len(candidates)),
		slog.String("peerObserved", observed.Address),
	)
}

// pushToPeer delivers the caller's candidates to the matched peer's open
// connection. If the peer is not currently connected, the candidates remain
// stored and are delivered when the peer next offers or polls.
func (s *Server) pushToPeer(sessionID string) {
	state, err := s.sessions.Session(sessionID)
	if err != nil || state.PeerID == "" {
		return
	}
	candidates, observed, err := s.sessions.List(state.PeerID)
	if err != nil {
		return
	}
	envelope := protocol.Envelope{
		MajorVersion: protocol.MajorVersion,
		MinorVersion: protocol.MinorVersion,
		Type:         protocol.MessageCandidates,
		SessionID:    state.PeerID,
		Candidates:   candidates,
		Observed:     &observed,
	}
	s.peersMu.RLock()
	send, ok := s.peers[state.PeerID]
	s.peersMu.RUnlock()
	if ok {
		send(envelope)
	}
	// Log observed endpoint so operators can confirm the node reports transport
	// source distinct from client-declared candidates.
	s.logger.Debug("pushed candidates to peer",
		slog.String("session", sessionID),
		slog.String("peer", state.PeerID),
		slog.Int("candidates", len(candidates)),
		slog.String("peerObserved", observed.Address),
	)
}

// registerPeer records the write callback for a live session's connection.
func (s *Server) registerPeer(sessionID string, send func(protocol.Envelope)) {
	s.peersMu.Lock()
	s.peers[sessionID] = send
	s.peersMu.Unlock()
}

// unregisterPeer removes a session's write callback. Safe to call when absent.
func (s *Server) unregisterPeer(sessionID string) {
	s.peersMu.Lock()
	delete(s.peers, sessionID)
	s.peersMu.Unlock()
}

// writeError sends one MessageError envelope. retryable controls whether the
// agent may reopen (e.g. rate limit) versus must back off (unauthorized).
func (s *Server) writeError(state *connState, code, message string, retryable bool) {
	s.writeEnvelope(state, protocol.Envelope{
		MajorVersion: protocol.MajorVersion,
		MinorVersion: protocol.MinorVersion,
		Type:         protocol.MessageError,
		Error: &network.NetworkError{
			Version:   protocol.MajorVersion,
			Code:      code,
			Message:   message,
			Retryable: retryable,
		},
	})
}

// writeEnvelope serializes one envelope to the connection. The per-connection
// write mutex serializes this with peer-push writes from another goroutine.
// Write failures are fatal to the connection; the caller's defer cleans up.
func (s *Server) writeEnvelope(state *connState, envelope protocol.Envelope) {
	body, err := json.Marshal(envelope)
	if err != nil {
		return
	}
	state.writeMu.Lock()
	defer state.writeMu.Unlock()
	_ = state.conn.WriteMessage(body)
}

// errorCode maps a session-store error to its wire-shaped NetworkError code.
func errorCode(err error) string {
	switch {
	case errors.Is(err, session.ErrSessionLimitExceeded):
		return "session_limit_exceeded"
	case errors.Is(err, session.ErrCandidateLimit):
		return "candidate_limit_exceeded"
	case errors.Is(err, session.ErrSessionNotFound), errors.Is(err, session.ErrSessionExpired):
		return "session_expired"
	case errors.Is(err, session.ErrNotMatched):
		return "not_matched"
	case errors.Is(err, session.ErrCandidateBinding), errors.Is(err, session.ErrCandidateExpired):
		return "bad_request"
	default:
		return "internal_error"
	}
}

// connState is the per-connection rendezvous state owned by serveRendezvous.
type connState struct {
	conn      *ws.Conn
	writeMu   sync.Mutex
	limiter   *limiter.RateLimiter
	sessionID string
	ticket    network.RendezvousTicket
	source    string
}

func remoteSourceIP(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return remoteAddress
	}
	return host
}
