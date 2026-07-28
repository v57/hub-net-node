package limiter

import (
	"testing"
	"time"
)

func TestAllowsUpToLimitThenRejects(t *testing.T) {
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	limiter := New(3, clock)

	for i := 0; i < 3; i++ {
		if !limiter.Allow() {
			t.Fatalf("Allow %d = false, want true within limit", i)
		}
	}
	if limiter.Allow() {
		t.Fatal("Allow over limit = true, want false")
	}
}

func TestWindowSlidesAndReallows(t *testing.T) {
	base := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	current := base
	clock := func() time.Time { return current }
	limiter := New(2, clock)

	if !limiter.Allow() {
		t.Fatal("first Allow false")
	}
	if !limiter.Allow() {
		t.Fatal("second Allow false")
	}
	if limiter.Allow() {
		t.Fatal("third Allow within window = true, want false")
	}
	// Advance just past the one-second window: both events age out.
	current = base.Add(1100 * time.Millisecond)
	if !limiter.Allow() {
		t.Fatal("Allow after window slide = false, want true")
	}
	if !limiter.Allow() {
		t.Fatal("second Allow after window slide = false, want true")
	}
	if limiter.Allow() {
		t.Fatal("third Allow after only two events aged out = true, want false")
	}
}

func TestRejectionsDoNotCountAgainstFutureWindows(t *testing.T) {
	base := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	current := base
	clock := func() time.Time { return current }
	limiter := New(1, clock)

	if !limiter.Allow() {
		t.Fatal("first Allow false")
	}
	// A burst of rejections must not widen the window or consume budget.
	for i := 0; i < 10; i++ {
		if limiter.Allow() {
			t.Fatal("rejection counted as admit")
		}
	}
	// One second later the single admit has aged out; budget is full again.
	current = base.Add(time.Second)
	if !limiter.Allow() {
		t.Fatal("Allow after window slide = false despite rejections not counting")
	}
}
