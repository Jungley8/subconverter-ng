package fetch

import (
	"net/http"
	"sync"
	"time"
)

// Cache is a thread-safe, in-memory TTL cache for successful GET responses,
// keyed by URL. Entries retain both the body and the response headers so
// metadata (e.g. Subscription-Userinfo) survives a cache hit.
//
// The cache is keyed by URL only; it deliberately ignores per-request proxy
// differences. Callers that need a fresh fetch must bypass (use a Client with
// caching disabled) or Flush the cache.
type Cache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]cacheEntry
	now     func() time.Time // injectable clock for tests
}

type cacheEntry struct {
	body    []byte
	header  http.Header
	expires time.Time
}

// NewCache creates a cache with the given TTL.
func NewCache(ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	return &Cache{
		ttl:     ttl,
		entries: make(map[string]cacheEntry),
		now:     time.Now,
	}
}

// get returns a cached body+headers for url if present and unexpired.
func (c *Cache) get(url string) ([]byte, http.Header, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[url]
	if !ok {
		return nil, nil, false
	}
	if !c.now().Before(e.expires) {
		delete(c.entries, url)
		return nil, nil, false
	}
	return e.body, e.header, true
}

// set stores body+headers for url with the cache's TTL.
func (c *Cache) set(url string, body []byte, header http.Header) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[url] = cacheEntry{
		body:    body,
		header:  header.Clone(),
		expires: c.now().Add(c.ttl),
	}
}

// Flush removes all entries.
func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}

// Len reports the number of stored entries (including possibly-expired ones).
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
