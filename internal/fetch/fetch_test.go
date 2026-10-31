package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNew_Defaults(t *testing.T) {
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if c.opts.UserAgent != defaultUA || c.opts.Timeout == 0 || c.opts.MaxRetries == 0 {
		t.Errorf("defaults not applied: %+v", c.opts)
	}
}

func TestNew_FallsBackToEnvProxy(t *testing.T) {
	// With no explicit proxy, the transport must use ProxyFromEnvironment so
	// standard HTTP_PROXY/HTTPS_PROXY/NO_PROXY are honoured.
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	tr := c.http.Transport.(*http.Transport)
	if tr.Proxy == nil {
		t.Fatal("expected env-based proxy func, got nil")
	}

	// And an explicit proxy overrides it with a fixed URL.
	c2, err := New(Options{Proxy: "http://127.0.0.1:7890", TrustedProxy: "http://127.0.0.1:7890"})
	if err != nil {
		t.Fatal(err)
	}
	tr2 := c2.http.Transport.(*http.Transport)
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	u, err := tr2.Proxy(req)
	if err != nil || u == nil || u.Host != "127.0.0.1:7890" {
		t.Errorf("explicit proxy not used: u=%v err=%v", u, err)
	}
}

func TestNew_InvalidProxy(t *testing.T) {
	if _, err := New(Options{Proxy: "://bad"}); err == nil {
		t.Error("expected error for invalid proxy URL")
	}
}

func TestGet_OKAndUserAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != defaultUA {
			t.Errorf("UA = %q, want %q", r.Header.Get("User-Agent"), defaultUA)
		}
		_, _ = w.Write([]byte("hello-body"))
	}))
	defer srv.Close()

	c, _ := New(Options{AllowPrivateIPs: true})
	body, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello-body" {
		t.Errorf("body = %q", body)
	}
}

func TestGet_Non200FailsClosed(t *testing.T) {
	// A 404 body is an error page, not a subscription/config: it must surface
	// as an error rather than a successful fetch of garbage.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 page not found"))
	}))
	defer srv.Close()

	c, _ := New(Options{AllowPrivateIPs: true})
	if _, err := c.Get(context.Background(), srv.URL); err == nil {
		t.Fatal("expected error for 404")
	} else if !strings.Contains(err.Error(), "unexpected status 404") {
		t.Errorf("error = %q, want unexpected-status mention", err)
	}
}

func TestGet_Non200ServerErrorFailsClosed(t *testing.T) {
	// Same fail-closed behaviour for 5xx: an upstream error page must not be
	// parsed as a subscription or config.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	c, _ := New(Options{AllowPrivateIPs: true})
	if _, err := c.Get(context.Background(), srv.URL); err == nil {
		t.Fatal("expected error for 500")
	} else if !strings.Contains(err.Error(), "unexpected status 500") {
		t.Errorf("error = %q, want unexpected-status mention", err)
	}
}

func TestIsCloudflareChallenge(t *testing.T) {
	if !isCloudflareChallenge(403, []byte("<title>Just a moment...</title>")) {
		t.Error("should detect 'Just a moment'")
	}
	if !isCloudflareChallenge(200, []byte("blah _cf_chl_opt blah")) {
		t.Error("should detect challenge marker on 200")
	}
	if isCloudflareChallenge(200, []byte("normal content")) {
		t.Error("false positive on normal 200")
	}
	if isCloudflareChallenge(404, []byte("not found")) {
		t.Error("404 plain should not be a challenge")
	}
}

func TestGet_CloudflareSolvedViaFlareSolverr(t *testing.T) {
	// Origin returns the CF interstitial until a cf_clearance cookie is present.
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Cookie"), "cf_clearance=token123") {
			_, _ = w.Write([]byte("REAL-SUBSCRIPTION"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("<title>Just a moment...</title>"))
	}))
	defer origin.Close()

	// FlareSolverr stub returns the clearance cookie + a UA.
	fs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","solution":{"userAgent":"fs-ua","cookies":[{"name":"cf_clearance","value":"token123"}]}}`))
	}))
	defer fs.Close()

	c, _ := New(Options{FlareSolverrURL: fs.URL, AllowPrivateIPs: true})
	body, err := c.Get(context.Background(), origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "REAL-SUBSCRIPTION" {
		t.Errorf("body = %q, want REAL-SUBSCRIPTION", body)
	}
}

func TestGet_CloudflareNoSolverrErrors(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Attention Required! | Cloudflare"))
	}))
	defer origin.Close()

	c, _ := New(Options{AllowPrivateIPs: true})
	_, err := c.Get(context.Background(), origin.URL)
	if err == nil || !strings.Contains(err.Error(), "Cloudflare") {
		t.Errorf("expected Cloudflare error, got %v", err)
	}
}

func TestGet_FlareSolverrFailure(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("Just a moment..."))
	}))
	defer origin.Close()
	fs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"error","message":"boom"}`))
	}))
	defer fs.Close()

	c, _ := New(Options{FlareSolverrURL: fs.URL, AllowPrivateIPs: true})
	if _, err := c.Get(context.Background(), origin.URL); err == nil {
		t.Error("expected solve failure error")
	}
}

func TestSSRF_DefenseBlocksPrivateAndLoopback(t *testing.T) {
	c, err := New(Options{}) // AllowPrivateIPs: false by default
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	targets := []string{
		"http://127.0.0.1:8080/sub",
		"http://localhost:8080/sub",
		"http://sub.localhost:8080/sub",
		"http://internal.local:8080/sub",
		"http://0.0.0.1:8080/sub",
		"http://255.255.255.255:8080/sub",
		"http://10.0.0.1:8080/sub",
		"http://192.168.1.1:8080/sub",
		"http://172.16.0.1:8080/sub",
		"http://169.254.169.254/latest/meta-data",
		"http://[::1]:8080/sub",
		"ftp://example.com/test",
	}

	for _, target := range targets {
		_, err := c.Get(ctx, target)
		if err == nil {
			t.Errorf("expected SSRF block for %s, but got nil error", target)
		}
	}
}

func TestSSRF_RedirectBlocked(t *testing.T) {
	// 1. Direct unit test of safeCheckRedirect func
	check := safeCheckRedirect(false)
	via := []*http.Request{{}}

	blockedRedirects := []string{
		"http://127.0.0.1:80/secret",
		"http://localhost:80/secret",
		"http://sub.localhost:80/secret",
		"http://10.0.0.1:80/secret",
		"http://192.168.1.1:80/secret",
		"http://169.254.169.254/latest",
		"http://[::1]:80/secret",
		"ftp://example.com/file",
	}

	for _, target := range blockedRedirects {
		req, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := check(req, via); err == nil {
			t.Errorf("expected redirect to %s to be blocked, got nil", target)
		} else if !errors.Is(err, ErrBlockedRedirect) {
			t.Errorf("redirect to %s error = %v, want %v", target, err, ErrBlockedRedirect)
		}
	}

	// 2. Integration test via http.Client with custom transport allowing initial hop
	var redirectHandlerCalled atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		redirectHandlerCalled.Store(true)
		http.Redirect(w, r, "http://127.0.0.1:9999/secret", http.StatusFound)
	}))
	defer srv.Close()

	httpClient := &http.Client{
		CheckRedirect: safeCheckRedirect(false),
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	_, err := httpClient.Do(req)
	if err == nil {
		t.Fatal("expected SSRF redirect error, got nil")
	}
	if !redirectHandlerCalled.Load() {
		t.Fatal("expected mock server to be invoked before redirect")
	}
	if !strings.Contains(err.Error(), "redirect to private/loopback address blocked") {
		t.Errorf("error = %q, expected redirect blocked mention", err)
	}
}

func TestSSRF_UntrustedProxyBlocked(t *testing.T) {
	// Attempt to configure untrusted private proxy when AllowPrivateIPs is false
	_, err := New(Options{
		Proxy:           "http://127.0.0.1:8080",
		AllowPrivateIPs: false,
	})
	if err == nil {
		t.Fatal("expected error for untrusted loopback proxy")
	}

	// Operator's explicitly trusted proxy is allowed
	_, err = New(Options{
		Proxy:           "http://127.0.0.1:8080",
		TrustedProxy:    "http://127.0.0.1:8080",
		AllowPrivateIPs: false,
	})
	if err != nil {
		t.Fatalf("trusted proxy should be allowed: %v", err)
	}
}

func TestSingleFlight_CollapsesConcurrentRequests(t *testing.T) {
	var requestCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		time.Sleep(50 * time.Millisecond) // simulate work
		_, _ = w.Write([]byte("singleflight-result"))
	}))
	defer srv.Close()

	c, _ := New(Options{AllowPrivateIPs: true, CacheTTL: -1}) // disable cache to isolate singleflight

	concurrency := 8
	var wg sync.WaitGroup
	wg.Add(concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			body, err := c.Get(context.Background(), srv.URL)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if string(body) != "singleflight-result" {
				t.Errorf("unexpected body: %q", string(body))
			}
		}()
	}
	wg.Wait()

	if got := requestCount.Load(); got != 1 {
		t.Errorf("singleflight requestCount = %d, want 1", got)
	}
}

func TestFetchDirect_BodySizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 1<<20) // 1MB chunk
		for i := 0; i < 12; i++ {    // write 12MB total
			_, _ = w.Write(chunk)
		}
	}))
	defer srv.Close()

	c, err := New(Options{AllowPrivateIPs: true, CacheTTL: -1})
	if err != nil {
		t.Fatal(err)
	}
	body, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 10<<20 {
		t.Fatalf("expected body capped at 10MB (%d bytes), got %d", 10<<20, len(body))
	}
}
