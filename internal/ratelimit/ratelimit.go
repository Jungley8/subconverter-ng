// Package ratelimit provides a thread-safe, per-client token-bucket limiter
// with no external dependencies. Each client key (typically an IP address) gets
// its own bucket that refills continuously at a fixed rate up to a burst
// capacity. Stale buckets are evicted lazily to bound memory usage.
package ratelimit

import (
	"sync"
	"time"
)

// bucket is the per-key token-bucket state. tokens is fractional so that
// sub-token refills between requests are not lost.
type bucket struct {
	tokens   float64
	lastSeen time.Time
}

// Limiter is a thread-safe collection of per-key token buckets.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket

	// refillPerSec is how many tokens are added per second.
	refillPerSec float64
	// burst is the maximum number of tokens a bucket may hold.
	burst float64
	// ttl bounds how long an idle bucket is retained before eviction.
	ttl time.Duration

	// evictInterval bounds how often we scan for stale buckets.
	evictInterval time.Duration
	lastEvict     time.Time

	// now is the time source, injectable for testing. Defaults to time.Now.
	now func() time.Time
}

// New returns a Limiter allowing ratePerMin requests per minute per key, with a
// maximum burst of burst requests. If ratePerMin <= 0 the refill rate is
// treated as zero (no replenishment). If burst <= 0 it defaults to 1.
func New(ratePerMin, burst int) *Limiter {
	if burst <= 0 {
		burst = 1
	}
	var refill float64
	if ratePerMin > 0 {
		refill = float64(ratePerMin) / 60.0
	}
	return &Limiter{
		buckets:       make(map[string]*bucket),
		refillPerSec:  refill,
		burst:         float64(burst),
		ttl:           10 * time.Minute,
		evictInterval: time.Minute,
		now:           time.Now,
	}
}

// Allow reports whether a request for the given key may proceed, consuming one
// token if so. It is safe for concurrent use.
func (l *Limiter) Allow(key string) bool {
	now := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		// New key starts with a full bucket, then spends one token.
		l.buckets[key] = &bucket{tokens: l.burst - 1, lastSeen: now}

		// Decoupled eviction: scan for stale buckets at most once per evictInterval
		// instead of scanning the full map on every single new IP.
		if l.lastEvict.IsZero() {
			l.lastEvict = now
		} else if now.Sub(l.lastEvict) >= l.evictInterval {
			l.lastEvict = now
			l.evictStale(now)
		}
		return true
	}

	// Refill based on elapsed time since this bucket was last touched.
	elapsed := now.Sub(b.lastSeen).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.refillPerSec
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
	}
	b.lastSeen = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// EvictStale removes buckets that have been idle longer than the TTL.
// It is safe for concurrent use.
func (l *Limiter) EvictStale() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evictStale(l.now())
}

// evictStale removes buckets that have been idle longer than the TTL. Assumes l.mu is held.
func (l *Limiter) evictStale(now time.Time) {
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) > l.ttl {
			delete(l.buckets, k)
		}
	}
}
