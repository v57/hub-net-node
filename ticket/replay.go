package ticket

import (
	"errors"
	"sync"
	"time"
)

const (
	DefaultReplayCapacity  = 16384
	DefaultReplayPerSource = 256
)

var (
	ErrReplay         = errors.New("ticket: rendezvous ticket already consumed")
	ErrReplayCapacity = errors.New("ticket: replay cache capacity exceeded")
)

type replayEntry struct {
	source    string
	expiresAt time.Time
}

// ReplayCache atomically records fully verified, consumed tickets until expiry.
// State is deliberately memory-only; a new process starts with an empty cache.
type ReplayCache struct {
	mu        sync.Mutex
	entries   map[string]replayEntry
	bySource  map[string]int
	max       int
	perSource int
	now       func() time.Time
}

func NewReplayCache(max, perSource int, now func() time.Time) *ReplayCache {
	if max <= 0 || perSource <= 0 {
		panic("ticket: replay cache limits must be positive")
	}
	if now == nil {
		now = time.Now
	}
	return &ReplayCache{entries: make(map[string]replayEntry), bySource: make(map[string]int), max: max, perSource: perSource, now: now}
}

// Consume records key as used. Exactly one concurrent caller can succeed.
func (c *ReplayCache) Consume(key, source string, expiresAt time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweepLocked(c.now())
	if _, exists := c.entries[key]; exists {
		return ErrReplay
	}
	if len(c.entries) >= c.max || c.bySource[source] >= c.perSource {
		return ErrReplayCapacity
	}
	c.entries[key] = replayEntry{source: source, expiresAt: expiresAt}
	c.bySource[source]++
	return nil
}

// Release removes consumption when later session creation fails.
func (c *ReplayCache) Release(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.removeLocked(key)
}

func (c *ReplayCache) Sweep() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sweepLocked(c.now())
}

func (c *ReplayCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *ReplayCache) sweepLocked(now time.Time) int {
	removed := 0
	for key, entry := range c.entries {
		if !entry.expiresAt.After(now) {
			c.removeLocked(key)
			removed++
		}
	}
	return removed
}

func (c *ReplayCache) removeLocked(key string) {
	entry, ok := c.entries[key]
	if !ok {
		return
	}
	delete(c.entries, key)
	c.bySource[entry.source]--
	if c.bySource[entry.source] == 0 {
		delete(c.bySource, entry.source)
	}
}
