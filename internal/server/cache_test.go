package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/config"
)

// countingAirport serves a subscription + INI and counts subscription hits, and
// sets a Subscription-Userinfo header on the subscription response.
func countingAirport(subHits *int32) *httptest.Server {
	sub := b64(strings.Join([]string{
		"ss://" + b64("aes-256-gcm:pw") + "@1.1.1.1:8388#🇭🇰 HK",
		"trojan://pw@2.2.2.2:443?sni=h#🇺🇲 US",
	}, "\n"))
	ini := "[custom]\n" +
		"ruleset=🐟 Final,[]FINAL\n" +
		"custom_proxy_group=🚀 Select`select`.*`\n" +
		"enable_rule_generator=true\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/sub.txt", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(subHits, 1)
		w.Header().Set("Subscription-Userinfo", "upload=1; download=2; total=3; expire=4")
		w.Write([]byte(sub))
	})
	mux.HandleFunc("/config.init", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(ini)) })
	return httptest.NewServer(mux)
}

func subURL(base, air string, extra string) string {
	return base + "?target=clash&url=" + url.QueryEscape(air+"/sub.txt") +
		"&config=" + url.QueryEscape(air+"/config.init") + extra
}

func TestHandleSub_PassesSubscriptionUserinfo(t *testing.T) {
	var hits int32
	air := countingAirport(&hits)
	defer air.Close()

	h := New(config.Default()).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, subURL("/sub", air.URL, ""), nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	got := rec.Header().Get("Subscription-Userinfo")
	if got != "upload=1; download=2; total=3; expire=4" {
		t.Errorf("Subscription-Userinfo = %q", got)
	}
}

func TestHandleSub_CacheReusesSubscription(t *testing.T) {
	var hits int32
	air := countingAirport(&hits)
	defer air.Close()

	h := New(config.Default()).Handler() // caching on by default
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, subURL("/sub", air.URL, ""), nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}
	}
	if hits != 1 {
		t.Errorf("subscription fetched %d times, want 1 (cache hit on 2nd request)", hits)
	}
}

func TestHandleSub_NoCacheBypasses(t *testing.T) {
	var hits int32
	air := countingAirport(&hits)
	defer air.Close()

	h := New(config.Default()).Handler()
	// Warm the cache.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, subURL("/sub", air.URL, ""), nil))
	// nocache=1 must bypass and re-hit the origin.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, subURL("/sub", air.URL, "&nocache=1"), nil))
	if hits != 2 {
		t.Errorf("hits = %d, want 2 (nocache bypassed the cache)", hits)
	}
}

func TestHandleSub_FlushCacheParam(t *testing.T) {
	var hits int32
	air := countingAirport(&hits)
	defer air.Close()

	h := New(config.Default()).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, subURL("/sub", air.URL, ""), nil))
	// flushcache=1 clears before serving -> origin hit again.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, subURL("/sub", air.URL, "&flushcache=1"), nil))
	if hits != 2 {
		t.Errorf("hits = %d, want 2 (flushcache cleared the cache)", hits)
	}
}

func TestHandleFlushCacheEndpoint(t *testing.T) {
	var hits int32
	air := countingAirport(&hits)
	defer air.Close()

	srv := New(config.Default())
	h := srv.Handler()
	// Warm the cache.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, subURL("/sub", air.URL, ""), nil))

	// Hit the dedicated endpoint.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/flushcache", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "flushed") {
		t.Fatalf("flushcache endpoint: code=%d body=%q", rec.Code, rec.Body.String())
	}

	// Next /sub re-hits the origin.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, subURL("/sub", air.URL, ""), nil))
	if hits != 2 {
		t.Errorf("hits = %d, want 2 (endpoint flush forced refetch)", hits)
	}
}

func TestNew_CacheDisabledWhenTTLNegative(t *testing.T) {
	cfg := config.Default()
	cfg.Fetch.CacheTTL = -1
	s := New(cfg)
	if s.cache != nil {
		t.Error("expected nil shared cache when CacheTTL < 0")
	}
}
