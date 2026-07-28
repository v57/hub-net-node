package ticket

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReplayCacheFirstUseAndSequentialReplay(t *testing.T) {
	now := time.Now()
	cache := NewReplayCache(4, 2, func() time.Time { return now })
	if err := cache.Consume("hub:ticket", "source", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := cache.Consume("hub:ticket", "source", now.Add(time.Minute)); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay error = %v, want ErrReplay", err)
	}
}

func TestReplayCacheConcurrentSingleWinner(t *testing.T) {
	now := time.Now()
	cache := NewReplayCache(32, 32, func() time.Time { return now })
	var successes atomic.Int32
	var wait sync.WaitGroup
	for i := 0; i < 32; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if cache.Consume("same", "source", now.Add(time.Minute)) == nil {
				successes.Add(1)
			}
		}()
	}
	wait.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("successful consumers = %d, want 1", got)
	}
}

func TestReplayCacheExpiryReclamation(t *testing.T) {
	now := time.Now()
	cache := NewReplayCache(1, 1, func() time.Time { return now })
	if err := cache.Consume("old", "source", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if removed := cache.Sweep(); removed != 1 {
		t.Fatalf("Sweep = %d, want 1", removed)
	}
	if err := cache.Consume("fresh", "source", now.Add(time.Minute)); err != nil {
		t.Fatalf("capacity not reclaimed: %v", err)
	}
}

func TestReplayCacheGlobalAndPerSourceBounds(t *testing.T) {
	now := time.Now()
	cache := NewReplayCache(3, 2, func() time.Time { return now })
	for i := 0; i < 2; i++ {
		if err := cache.Consume(fmt.Sprintf("a-%d", i), "a", now.Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if err := cache.Consume("a-over", "a", now.Add(time.Minute)); !errors.Is(err, ErrReplayCapacity) {
		t.Fatalf("per-source error = %v", err)
	}
	if err := cache.Consume("b", "b", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := cache.Consume("global-over", "c", now.Add(time.Minute)); !errors.Is(err, ErrReplayCapacity) {
		t.Fatalf("global error = %v", err)
	}
}

func TestReplayCacheRestartAndRelease(t *testing.T) {
	now := time.Now()
	first := NewReplayCache(1, 1, func() time.Time { return now })
	if err := first.Consume("ticket", "source", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	restarted := NewReplayCache(1, 1, func() time.Time { return now })
	if err := restarted.Consume("ticket", "source", now.Add(time.Minute)); err != nil {
		t.Fatalf("new cache retained state: %v", err)
	}
	restarted.Release("ticket")
	if err := restarted.Consume("fresh", "source", now.Add(time.Minute)); err != nil {
		t.Fatalf("Release did not reclaim capacity: %v", err)
	}
}
