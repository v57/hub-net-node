// Package health reports hub-net-node liveness and advertised protocol.
//
// The node is a standalone HTTP/WebSocket service: it has no Hub RPC
// connection of its own (it validates rendezvous tickets directly per HN-401),
// so health is reported as a JSON snapshot over HTTP rather than through a Hub
// stream. The snapshot covers availability, build version, advertised
// protocol capabilities, the current open-session count, and uptime.
package health

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/v57/hub-net-node/protocol"
	"github.com/v57/hub-net-node/version"
)

// Snapshot is the JSON health response served at /healthz.
type Snapshot struct {
	Available bool                  `json:"available"`
	Version   string                `json:"version"`
	Protocol  protocol.Capabilities `json:"protocol"`
	Sessions  int                   `json:"sessions"`
	UptimeSec int64                 `json:"uptimeSec"`
	LastError string                `json:"lastError,omitempty"`
}

// Reporter tracks node liveness, session count, and advertised protocol.
type Reporter struct {
	capabilities protocol.Capabilities
	startTime    time.Time
	sessions     atomic.Int64
	lastError    atomic.Pointer[string]
}

// New returns a Reporter advertising the given capabilities. startTime is
// captured now so UptimeSec reflects process lifetime.
func New(capabilities protocol.Capabilities) *Reporter {
	return &Reporter{
		capabilities: capabilities,
		startTime:    time.Now(),
	}
}

// SetAvailable marks the node ready to serve coordination traffic.
func (r *Reporter) SetAvailable(available bool) {
	if available {
		r.lastError.Store(nil)
	}
}

// IncrementSessions records an opened session.
func (r *Reporter) IncrementSessions() { r.sessions.Add(1) }

// DecrementSessions records a closed session.
func (r *Reporter) DecrementSessions() {
	for {
		current := r.sessions.Load()
		if current <= 0 {
			return
		}
		if r.sessions.CompareAndSwap(current, current-1) {
			return
		}
	}
}

// SessionCount returns the current open-session count.
func (r *Reporter) SessionCount() int64 { return r.sessions.Load() }

// SetLastError stores an operational diagnostic. Pass an empty string to clear.
func (r *Reporter) SetLastError(message string) {
	if message == "" {
		r.lastError.Store(nil)
		return
	}
	msg := message
	r.lastError.Store(&msg)
}

// Snapshot returns the current health snapshot. Available is true when no
// blocking error is set and the protocol is advertised.
func (r *Reporter) Snapshot() Snapshot {
	last := ""
	if ptr := r.lastError.Load(); ptr != nil {
		last = *ptr
	}
	return Snapshot{
		Available: last == "",
		Version:   version.String(),
		Protocol:  r.capabilities,
		Sessions:  int(r.sessions.Load()),
		UptimeSec: int64(time.Since(r.startTime).Seconds()),
		LastError: last,
	}
}

// HTTPHandler returns an http.HandlerFunc that emits the snapshot as JSON.
func (r *Reporter) HTTPHandler() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		snapshot := r.Snapshot()
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(snapshot); err != nil {
			// Header already sent; nothing more to do but record.
			http.Error(writer, "encode failed", http.StatusInternalServerError)
		}
	}
}
