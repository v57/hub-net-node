// Package limiter bounds per-connection message rates on the rendezvous node.
//
// The node advertises a per-connection message ceiling (default 20 messages
// per second). This package enforces it with a fixed sliding window so the
// rate is exact and stateless across windows. Each WebSocket connection owns
// one RateLimiter; the server rejects any message beyond the window with a
// rate_limited NetworkError.
package limiter

import (
	"sync"
	"time"
)

// RateLimiter bounds messages per second on one connection. The window holds
// at most limit timestamps; a message is admitted when fewer than limit were
// admitted in the trailing one-second window.
type RateLimiter struct {
	mu     sync.Mutex
	now    func() time.Time
	limit  int
	window time.Duration
	events []time.Time
}

// New returns a RateLimiter admitting at most messagesPerSecond messages in
// any trailing one-second window.
func New(messagesPerSecond int, now func() time.Time) *RateLimiter {
	if messagesPerSecond <= 0 {
		messagesPerSecond = 1
	}
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{
		now:    now,
		limit:  messagesPerSecond,
		window: time.Second,
	}
}

// Allow reports whether one more message may be admitted now. When true the
// event is recorded; when false the caller rejects the message and the event
// is not counted, so a burst of rejections never widens the window.
func (r *RateLimiter) Allow() bool {
	return r.AllowAt(r.now())
}

// AllowAt is the injectable-clock form used by tests.
func (r *RateLimiter) AllowAt(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	threshold := now.Add(-r.window)
	// Drop events older than the window from the front of the slice.
	start := 0
	for start < len(r.events) && !r.events[start].After(threshold) {
		start++
	}
	if start > 0 {
		r.events = r.events[start:]
	}
	if len(r.events) >= r.limit {
		return false
	}
	r.events = append(r.events, now)
	return true
}
