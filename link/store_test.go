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

func grantFromHub(id, hub, a, b string) network.PeerLinkGrant {
	grant := grantBetween(id, a, b)
	grant.HubKey = hub
	return grant
}

func TestOneHubKeyCantUseUpAnothersBudget(t *testing.T) {
	now := &clock{now: time.Unix(3_000_000, 0)}
	store := New(Options{IncomingPerMinute: 3, Now: now.Now})
	for i := range 3 {
		if _, _, err := store.Open(grantFromHub(string(rune('0'+i)), "self-made", "attacker", "target"), "attacker"); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := store.Open(grantFromHub("3", "self-made", "attacker", "target"), "attacker"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("fourth opening by one Hub key = %v", err)
	}
	if _, _, err := store.Open(grantFromHub("mine", "real", "member", "target"), "member"); err != nil {
		t.Fatalf("another Hub key toward the same target = %v", err)
	}
}

func TestKeysATargetNeverAcceptedShareATotal(t *testing.T) {
	now := &clock{now: time.Unix(4_000_000, 0)}
	store := New(Options{IncomingPerMinute: 2, IncomingTotalPerMinute: 5, MaxLinksPerKey: 1000, Now: now.Now})

	// The target accepted this Hub once, which was its stranger's first open: it's no stranger from then on
	first, _, err := store.Open(grantFromHub("first", "real", "member", "target"), "member")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Accept(first.ID, "target"); err != nil {
		t.Fatal(err)
	}

	for i := range 4 {
		hub := "self-made-" + string(rune('a'+i))
		if _, _, err := store.Open(grantFromHub("s", hub, "attacker", "target"), "attacker"); err != nil {
			t.Fatalf("stranger %d = %v", i, err)
		}
	}
	if _, _, err := store.Open(grantFromHub("s", "self-made-z", "attacker", "target"), "attacker"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("a fifth self-made key = %v", err)
	}
	if _, _, err := store.Open(grantFromHub("second", "real", "member", "target"), "member"); err != nil {
		t.Fatalf("a Hub the target accepted, past the total = %v", err)
	}
	// Another device's total is its own
	if _, _, err := store.Open(grantFromHub("s", "self-made-z", "attacker", "elsewhere"), "attacker"); err != nil {
		t.Fatalf("another target = %v", err)
	}
	now.now = now.now.Add(2 * time.Minute)
	if _, _, err := store.Open(grantFromHub("s", "self-made-y", "attacker", "target"), "attacker"); err != nil {
		t.Fatalf("after a minute = %v", err)
	}
}

func TestStrangersHoldingSlotsDontLockOutAKnownHub(t *testing.T) {
	store := New(Options{MaxLinksPerKey: 3, IncomingTotalPerMinute: 100})
	first, _, err := store.Open(grantFromHub("first", "real", "member", "target"), "member")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Accept(first.ID, "target"); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		opener := "attacker-" + string(rune('a'+i))
		if _, _, err := store.Open(grantFromHub("s", "self-made-"+opener, opener, "target"), opener); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := store.Open(grantFromHub("s", "self-made-c", "attacker-c", "target"), "attacker-c"); !errors.Is(err, ErrLinkLimit) {
		t.Fatalf("a stranger past the slots = %v", err)
	}
	if _, _, err := store.Open(grantFromHub("second", "real", "member-2", "target"), "member-2"); err != nil {
		t.Fatalf("a known Hub with strangers on the slots = %v", err)
	}
}
