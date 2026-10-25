package link

import (
	"errors"
	"testing"
	"time"

	network "github.com/v57/hub-net-node/models"
)

type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func grantBetween(id, a, b string) network.PeerLinkGrant {
	return network.PeerLinkGrant{
		GrantID: id, HubKey: "hub",
		A: network.PeerLinkSide{Key: a, WireGuardKey: "wg-" + a},
		B: network.PeerLinkSide{Key: b, WireGuardKey: "wg-" + b},
	}
}

func TestOpenReplacesTheSameGrantAndOnlySidesOpen(t *testing.T) {
	store := New(Options{})
	first, replaced, err := store.Open(grantBetween("g", "a", "b"), "a")
	if err != nil || replaced != nil || first.Target.Key != "b" || first.Opener.ProbeToken == first.Target.ProbeToken {
		t.Fatalf("first open = %+v, %v, %v", first, replaced, err)
	}
	second, replaced, err := store.Open(grantBetween("g", "a", "b"), "b")
	if err != nil || replaced == nil || replaced.ID != first.ID || second.Target.Key != "a" || store.Len() != 1 {
		t.Fatalf("reopen = %+v, replaced %+v, %v", second, replaced, err)
	}
	if _, _, err := store.Open(grantBetween("other", "a", "b"), "c"); !errors.Is(err, ErrNotSide) {
		t.Fatalf("stranger open = %v", err)
	}
}

func TestReadyNeedsAcceptAndBothObservations(t *testing.T) {
	store := New(Options{})
	created, _, _ := store.Open(grantBetween("g", "a", "b"), "a")
	observed := network.ObservedEndpoint{Address: "198.51.100.1", Port: 4000}
	if l, ok := store.Observe(created.ID, created.Opener.ProbeToken, observed); !ok || l.Ready() {
		t.Fatalf("after one observation ready=%v ok=%v", l.Ready(), ok)
	}
	if _, ok := store.Observe("another-link", created.Target.ProbeToken, observed); ok {
		t.Fatal("a token observed under another link id")
	}
	if l, _ := store.Observe(created.ID, created.Target.ProbeToken, observed); l.Ready() {
		t.Fatal("ready before the target accepted")
	}
	if _, err := store.Accept(created.ID, "a"); !errors.Is(err, ErrNotTarget) {
		t.Fatalf("opener accepted its own link: %v", err)
	}
	accepted, err := store.Accept(created.ID, "b")
	if err != nil || !accepted.Ready() || accepted.ReadyAt.IsZero() {
		t.Fatalf("accept = %+v, %v", accepted, err)
	}
	if accepted.Opener.Observed.Key != "a" || accepted.Target.Observed.Key != "b" {
		t.Fatalf("observations bound to the wrong sides: %+v", accepted)
	}
}

func TestLimitsPerDeviceAndIncomingRate(t *testing.T) {
	now := &clock{now: time.Unix(1_000_000, 0)}
	store := New(Options{MaxLinksPerKey: 2, IncomingPerMinute: 3, Now: now.Now})
	for i, peer := range []string{"b", "c"} {
		if _, _, err := store.Open(grantBetween(string(rune('0'+i)), "a", peer), "a"); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := store.Open(grantBetween("2", "a", "d"), "a"); !errors.Is(err, ErrLinkLimit) {
		t.Fatalf("third link of a = %v", err)
	}
	rated := New(Options{IncomingPerMinute: 3, Now: now.Now})
	for i, opener := range []string{"x", "y", "z"} {
		if _, _, err := rated.Open(grantBetween("t"+string(rune('0'+i)), opener, "target"), opener); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := rated.Open(grantBetween("t3", "w", "target"), "w"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("fourth opening toward target within a minute = %v", err)
	}
	now.now = now.now.Add(2 * time.Minute)
	if _, _, err := rated.Open(grantBetween("t4", "v", "target"), "v"); err != nil {
		t.Fatalf("after a minute = %v", err)
	}
}

func TestSweepEndsUnreadyLinksAndCloseForKey(t *testing.T) {
	now := &clock{now: time.Unix(2_000_000, 0)}
	store := New(Options{Now: now.Now})
	stale, _, _ := store.Open(grantBetween("stale", "a", "b"), "a")
	kept, _, _ := store.Open(grantBetween("kept", "c", "d"), "c")
	now.now = now.now.Add(DefaultSetupLifetime)
	removed := store.Sweep()
	if len(removed) != 2 {
		t.Fatalf("swept %d links, want both unready ones", len(removed))
	}
	_ = stale
	_ = kept
	if _, _, err := store.Open(grantBetween("live", "a", "b"), "a"); err != nil {
		t.Fatal(err)
	}
	if closed := store.CloseForKey("b"); len(closed) != 1 || store.Len() != 0 {
		t.Fatalf("CloseForKey = %d links, %d left", len(closed), store.Len())
	}
}
