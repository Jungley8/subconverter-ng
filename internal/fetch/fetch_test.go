package fetch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
	c2, _ := New(Options{Proxy: "http://127.0.0.1:7890"})
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
		w.Write([]byte("hello-body"))
	}))
	defer srv.Close()

	c, _ := New(Options{})
	body, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello-body" {
		t.Errorf("body = %q", body)
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
			w.Write([]byte("REAL-SUBSCRIPTION"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("<title>Just a moment...</title>"))
	}))
	defer origin.Close()

	// FlareSolverr stub returns the clearance cookie + a UA.
	fs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","solution":{"userAgent":"fs-ua","cookies":[{"name":"cf_clearance","value":"token123"}]}}`))
	}))
	defer fs.Close()

	c, _ := New(Options{FlareSolverrURL: fs.URL})
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
		w.Write([]byte("Attention Required! | Cloudflare"))
	}))
	defer origin.Close()

	c, _ := New(Options{})
	_, err := c.Get(context.Background(), origin.URL)
	if err == nil || !strings.Contains(err.Error(), "Cloudflare") {
		t.Errorf("expected Cloudflare error, got %v", err)
	}
}

func TestGet_FlareSolverrFailure(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Just a moment..."))
	}))
	defer origin.Close()
	fs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"error","message":"boom"}`))
	}))
	defer fs.Close()

	c, _ := New(Options{FlareSolverrURL: fs.URL})
	if _, err := c.Get(context.Background(), origin.URL); err == nil {
		t.Error("expected solve failure error")
	}
}
