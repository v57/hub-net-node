// Package link keeps the peer links the node is introducing: who opened each one, whether its target accepted,
// what the node observed for each side and what each side declared, until both sides hold the path themselves.
//
// A link is keyed by its grant (hub key and grant id), so a device that opens the same grant again replaces the old
// attempt. Nothing about a side is released before the target accepts.
package link

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	network "github.com/v57/hub-net-node/models"
)

var (
	ErrNotFound    = errors.New("link: no such link")
	ErrNotSide     = errors.New("link: caller is not a side of the grant")
	ErrNotTarget   = errors.New("link: only the target accepts or rejects")
	ErrLinkLimit   = errors.New("link: too many links for this device")
	ErrRateLimited = errors.New("link: too many links opened toward this device")
	ErrCandidates  = errors.New("link: too many candidates")
)

const (
	DefaultSetupLifetime     = time.Minute
	DefaultReadyLifetime     = 2 * time.Minute
	DefaultMaxLinksPerKey    = 16
	DefaultIncomingPerMinute = 10
	DefaultMaxCandidates     = 16
)

// Side is one device of a link as the node sees it.
type Side struct {
	Key        string
	ProbeToken string
	Observed   *network.ObservedEndpoint
	Candidates []network.LinkEndpoint
}

// Link is a copy of one link's state; the store never hands out its own.
type Link struct {
	ID        string
	Grant     network.PeerLinkGrant
	Opener    Side
	Target    Side
	Accepted  bool
	CreatedAt time.Time
	ReadyAt   time.Time
}

// Ready is when the target accepted and the node observed both sides.
func (l Link) Ready() bool {
	return l.Accepted && l.Opener.Observed != nil && l.Target.Observed != nil
}

// SideOf returns the caller's side and the other one.
func (l Link) SideOf(key string) (own, other Side, ok bool) {
	switch key {
	case l.Opener.Key:
		return l.Opener, l.Target, true
	case l.Target.Key:
		return l.Target, l.Opener, true
	}
	return Side{}, Side{}, false
}

// Options bounds a Store; zero fields take the defaults.
type Options struct {
	SetupLifetime     time.Duration
	ReadyLifetime     time.Duration
	MaxLinksPerKey    int
	IncomingPerMinute int
	MaxCandidates     int
	Now               func() time.Time
}

type tokenRef struct {
	id     string
	opener bool
}

// Store is the concurrency-safe set of links.
type Store struct {
	mu       sync.Mutex
	links    map[string]*Link
	byGrant  map[string]string
	byToken  map[string]tokenRef
	incoming map[string][]time.Time
	options  Options
}

func New(options Options) *Store {
	if options.SetupLifetime <= 0 {
		options.SetupLifetime = DefaultSetupLifetime
	}
	if options.ReadyLifetime <= 0 {
		options.ReadyLifetime = DefaultReadyLifetime
	}
	if options.MaxLinksPerKey <= 0 {
		options.MaxLinksPerKey = DefaultMaxLinksPerKey
	}
	if options.IncomingPerMinute <= 0 {
		options.IncomingPerMinute = DefaultIncomingPerMinute
	}
	if options.MaxCandidates <= 0 {
		options.MaxCandidates = DefaultMaxCandidates
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Store{
		links:    make(map[string]*Link),
		byGrant:  make(map[string]string),
		byToken:  make(map[string]tokenRef),
		incoming: make(map[string][]time.Time),
		options:  options,
	}
}

func grantKey(grant network.PeerLinkGrant) string { return grant.HubKey + "\x00" + grant.GrantID }

// Open starts a link for an already verified grant, opened by one of its sides. It returns the new link and, when
// the same grant had a live link, the one it replaced so its sides can be told.
func (s *Store) Open(grant network.PeerLinkGrant, openerKey string) (Link, *Link, error) {
	target := grant.A.Key
	switch openerKey {
	case grant.A.Key:
		target = grant.B.Key
	case grant.B.Key:
	default:
		return Link{}, nil, ErrNotSide
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.options.Now()
	s.sweepLocked(now)
	var replaced *Link
	if id, ok := s.byGrant[grantKey(grant)]; ok {
		old := s.removeLocked(id)
		replaced = &old
	}
	if s.countLocked(openerKey) >= s.options.MaxLinksPerKey || s.countLocked(target) >= s.options.MaxLinksPerKey {
		return Link{}, replaced, ErrLinkLimit
	}
	recent := s.incoming[target][:0]
	for _, at := range s.incoming[target] {
		if now.Sub(at) < time.Minute {
			recent = append(recent, at)
		}
	}
	if len(recent) >= s.options.IncomingPerMinute {
		s.incoming[target] = recent
		return Link{}, replaced, ErrRateLimited
	}
	s.incoming[target] = append(recent, now)
	created := &Link{
		ID:        newID(),
		Grant:     grant,
		Opener:    Side{Key: openerKey, ProbeToken: newID()},
		Target:    Side{Key: target, ProbeToken: newID()},
		CreatedAt: now,
	}
	s.links[created.ID] = created
	s.byGrant[grantKey(grant)] = created.ID
	s.byToken[created.Opener.ProbeToken] = tokenRef{id: created.ID, opener: true}
	s.byToken[created.Target.ProbeToken] = tokenRef{id: created.ID}
	return copyLink(created), replaced, nil
}

// Accept marks the link accepted by its target.
func (s *Store) Accept(id, key string) (Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.options.Now())
	current, ok := s.links[id]
	if !ok {
		return Link{}, ErrNotFound
	}
	if current.Target.Key != key {
		return Link{}, ErrNotTarget
	}
	current.Accepted = true
	s.markReadyLocked(current)
	return copyLink(current), nil
}

// Close removes a link at a side's request (a close, or the target's rejection).
func (s *Store) Close(id, key string) (Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.links[id]
	if !ok {
		return Link{}, ErrNotFound
	}
	if current.Opener.Key != key && current.Target.Key != key {
		return Link{}, ErrNotSide
	}
	return s.removeLocked(id), nil
}

// Observe records the node-measured endpoint of the side whose probe token arrived for this link. It returns the
// link and whether the link and token were known together.
func (s *Store) Observe(id, token string, endpoint network.ObservedEndpoint) (Link, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.options.Now())
	ref, ok := s.byToken[token]
	if !ok || ref.id != id {
		return Link{}, false
	}
	current := s.links[ref.id]
	side := &current.Target
	if ref.opener {
		side = &current.Opener
	}
	endpoint.Key = side.Key
	side.Observed = &endpoint
	s.markReadyLocked(current)
	return copyLink(current), true
}

// Offer replaces a side's declared candidates.
func (s *Store) Offer(id, key string, candidates []network.LinkEndpoint) (Link, error) {
	if len(candidates) > s.options.MaxCandidates {
		return Link{}, ErrCandidates
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked(s.options.Now())
	current, ok := s.links[id]
	if !ok {
		return Link{}, ErrNotFound
	}
	declared := append([]network.LinkEndpoint(nil), candidates...)
	switch key {
	case current.Opener.Key:
		current.Opener.Candidates = declared
	case current.Target.Key:
		current.Target.Candidates = declared
	default:
		return Link{}, ErrNotSide
	}
	return copyLink(current), nil
}

// CloseForKey removes every link a device is a side of (its presence connection went away).
func (s *Store) CloseForKey(key string) []Link {
	s.mu.Lock()
	defer s.mu.Unlock()
	var removed []Link
	for id, current := range s.links {
		if current.Opener.Key == key || current.Target.Key == key {
			removed = append(removed, s.removeLocked(id))
		}
	}
	return removed
}

// Sweep removes links whose setup or ready time ran out and returns them.
func (s *Store) Sweep() []Link {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(s.options.Now())
}

// Len is the number of live links.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.links)
}

func (s *Store) sweepLocked(now time.Time) []Link {
	var removed []Link
	for id, current := range s.links {
		expired := false
		if current.ReadyAt.IsZero() {
			expired = now.Sub(current.CreatedAt) >= s.options.SetupLifetime
		} else {
			expired = now.Sub(current.ReadyAt) >= s.options.ReadyLifetime
		}
		if expired {
			removed = append(removed, s.removeLocked(id))
		}
	}
	for target, times := range s.incoming {
		if len(times) == 0 || now.Sub(times[len(times)-1]) >= time.Minute {
			delete(s.incoming, target)
		}
	}
	return removed
}

func (s *Store) markReadyLocked(current *Link) {
	if current.ReadyAt.IsZero() && current.Ready() {
		current.ReadyAt = s.options.Now()
	}
}

func (s *Store) countLocked(key string) int {
	count := 0
	for _, current := range s.links {
		if current.Opener.Key == key || current.Target.Key == key {
			count++
		}
	}
	return count
}

func (s *Store) removeLocked(id string) Link {
	current, ok := s.links[id]
	if !ok {
		return Link{}
	}
	delete(s.links, id)
	if s.byGrant[grantKey(current.Grant)] == id {
		delete(s.byGrant, grantKey(current.Grant))
	}
	delete(s.byToken, current.Opener.ProbeToken)
	delete(s.byToken, current.Target.ProbeToken)
	return copyLink(current)
}

func copyLink(current *Link) Link {
	copied := *current
	copied.Opener.Candidates = append([]network.LinkEndpoint(nil), current.Opener.Candidates...)
	copied.Target.Candidates = append([]network.LinkEndpoint(nil), current.Target.Candidates...)
	if current.Opener.Observed != nil {
		observed := *current.Opener.Observed
		copied.Opener.Observed = &observed
	}
	if current.Target.Observed != nil {
		observed := *current.Target.Observed
		copied.Target.Observed = &observed
	}
	return copied
}

// newID is 16 random bytes, unpadded base64url: unguessable link ids and probe tokens.
func newID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		panic("link: random source failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(raw[:])
}
