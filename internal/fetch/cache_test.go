package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// countingHandler serves a fixed body and counts how many times the origin is
// actually hit, so we can assert cache hits avoid the network.
func countingHandler(hits *int32, body string, header http.Header) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		for k, vs := range header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.Write([]byte(body))
	})
}

func TestCache_HitAvoidsSecondFetch(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(countingHandler(&hits, "cached-body", nil))
	defer srv.Close()

	c, _ := New(Options{}) // default caching on
	for i := 0; i < 3; i++ {
		body, err := c.Get(context.Background(), srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "cached-body" {
			t.Fatalf("body = %q", body)
		}
	}
	if hits != 1 {
		t.Errorf("origin hit %d times, want 1 (rest from cache)", hits)
	}
}

func TestCache_Disabled(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(countingHandler(&hits, "x", nil))
	defer srv.Close()

	c, _ := New(Options{CacheTTL: -1}) // disabled
	if c.cache != nil {
		t.Fatal("cache should be nil when CacheTTL < 0")
	}
	for i := 0; i < 3; i++ {
		if _, err := c.Get(context.Background(), srv.URL); err != nil {
			t.Fatal(err)
		}
	}
	if hits != 3 {
		t.Errorf("origin hit %d times, want 3 (caching disabled)", hits)
	}
}

func TestCache_Expiry(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(countingHandler(&hits, "y", nil))
	defer srv.Close()

	c, _ := New(Options{CacheTTL: time.Hour})
	// Drive a fake clock so expiry is deterministic.
	var nowVal atomic.Int64
	nowVal.Store(time.Now().UnixNano())
	c.cache.now = func() time.Time { return time.Unix(0, nowVal.Load()) }

	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	// Within TTL -> served from cache.
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 before expiry", hits)
	}
	// Advance past TTL -> refetch.
	nowVal.Add(int64(2 * time.Hour))
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Errorf("hits = %d, want 2 after expiry", hits)
	}
}

func TestCache_Flush(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(countingHandler(&hits, "z", nil))
	defer srv.Close()

	c, _ := New(Options{})
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if c.cache.Len() != 1 {
		t.Fatalf("cache len = %d, want 1", c.cache.Len())
	}
	c.FlushCache()
	if c.cache.Len() != 0 {
		t.Fatalf("cache len = %d after flush, want 0", c.cache.Len())
	}
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Errorf("hits = %d, want 2 (refetch after flush)", hits)
	}
}

func TestCache_SharedAcrossClients(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(countingHandler(&hits, "shared", nil))
	defer srv.Close()

	shared := NewCache(time.Hour)
	c1, _ := New(Options{Cache: shared})
	c2, _ := New(Options{Cache: shared})

	if _, err := c1.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := c2.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Errorf("hits = %d, want 1 (shared cache)", hits)
	}
}

func TestGetWithMeta_ReturnsHeaderAndCaches(t *testing.T) {
	var hits int32
	hdr := http.Header{"Subscription-Userinfo": []string{"upload=1; download=2; total=3; expire=4"}}
	srv := httptest.NewServer(countingHandler(&hits, "body", hdr))
	defer srv.Close()

	c, _ := New(Options{})
	body, gotHdr, err := c.GetWithMeta(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "body" {
		t.Fatalf("body = %q", body)
	}
	want := "upload=1; download=2; total=3; expire=4"
	if gotHdr.Get("Subscription-Userinfo") != want {
		t.Errorf("header = %q, want %q", gotHdr.Get("Subscription-Userinfo"), want)
	}
	// Second call: header must survive the cache hit.
	_, gotHdr2, _ := c.GetWithMeta(context.Background(), srv.URL)
	if gotHdr2.Get("Subscription-Userinfo") != want {
		t.Errorf("cached header lost: %q", gotHdr2.Get("Subscription-Userinfo"))
	}
	if hits != 1 {
		t.Errorf("hits = %d, want 1", hits)
	}
}

func TestCache_DoesNotCacheNon200(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("missing"))
	}))
	defer srv.Close()

	c, _ := New(Options{})
	for i := 0; i < 2; i++ {
		// 404 is not a Cloudflare challenge and not an error, but must not cache.
		if _, _, err := c.GetWithMeta(context.Background(), srv.URL); err != nil {
			t.Fatal(err)
		}
	}
	if hits != 2 {
		t.Errorf("hits = %d, want 2 (non-200 not cached)", hits)
	}
}
