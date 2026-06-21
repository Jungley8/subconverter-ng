package ratelimit

import (
	"sync"
	"testing"
	"time"
)

// fakeClock is a controllable time source for deterministic tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestAllowUpToBurstThenDenies(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	l := New(60, 5) // 1 token/sec, burst 5
	l.now = clk.now

	for i := 0; i < 5; i++ {
		if !l.Allow("a") {
			t.Fatalf("request %d should be allowed within burst", i+1)
		}
	}
	if l.Allow("a") {
		t.Fatal("request beyond burst should be denied")
	}
}

func TestRefillsOverTime(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	l := New(60, 2) // 1 token/sec, burst 2
	l.now = clk.now

	if !l.Allow("a") || !l.Allow("a") {
		t.Fatal("first two requests should be allowed")
	}
	if l.Allow("a") {
		t.Fatal("third request should be denied (bucket empty)")
	}

	// After 1 second, exactly one token should have refilled.
	clk.advance(time.Second)
	if !l.Allow("a") {
		t.Fatal("request should be allowed after refill")
	}
	if l.Allow("a") {
		t.Fatal("only one token should have refilled")
	}
}

func TestRefillCapsAtBurst(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	l := New(60, 3) // 1 token/sec, burst 3
	l.now = clk.now

	l.Allow("a") // spend 1, 2 left

	// Idle for a long time: tokens must cap at burst, not exceed it.
	clk.advance(time.Hour)
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("request %d should be allowed (capped at burst)", i+1)
		}
	}
	if l.Allow("a") {
		t.Fatal("bucket should not exceed burst after long idle")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	l := New(60, 1) // burst 1
	l.now = clk.now

	if !l.Allow("a") {
		t.Fatal("first request for a should pass")
	}
	if l.Allow("a") {
		t.Fatal("second request for a should be denied")
	}
	if !l.Allow("b") {
		t.Fatal("first request for b should pass (independent bucket)")
	}
}

func TestStaleEviction(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	l := New(60, 5)
	l.now = clk.now

	l.Allow("old")
	if len(l.buckets) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(l.buckets))
	}

	// Advance past the TTL, then a new key triggers eviction of "old".
	clk.advance(l.ttl + time.Minute)
	l.Allow("new")
	if _, ok := l.buckets["old"]; ok {
		t.Fatal("stale bucket should have been evicted")
	}
	if _, ok := l.buckets["new"]; !ok {
		t.Fatal("new bucket should be present")
	}
}

func TestZeroRateNoRefill(t *testing.T) {
	clk := &fakeClock{t: time.Unix(0, 0)}
	l := New(0, 2) // no refill, burst 2
	l.now = clk.now

	if !l.Allow("a") || !l.Allow("a") {
		t.Fatal("first two should pass")
	}
	clk.advance(time.Hour)
	if l.Allow("a") {
		t.Fatal("no refill expected with zero rate")
	}
}

func TestBurstDefaultsToOne(t *testing.T) {
	l := New(60, 0)
	if !l.Allow("a") {
		t.Fatal("first request should pass with default burst 1")
	}
	if l.Allow("a") {
		t.Fatal("second request should be denied with burst 1")
	}
}

func TestConcurrentAllow(t *testing.T) {
	l := New(6000, 1000)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				l.Allow("shared")
			}
		}()
	}
	wg.Wait()
	// Just ensure no race/panic; -race will catch data races.
}
