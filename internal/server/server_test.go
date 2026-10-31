package server

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Jungley8/subconverter-ng/internal/config"
	"gopkg.in/yaml.v3"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// fakeAirport serves a base64 subscription and an INI config.
func fakeAirport() *httptest.Server {
	sub := b64(strings.Join([]string{
		"ss://" + b64("aes-256-gcm:pw") + "@1.1.1.1:8388#🇭🇰 HK",
		"trojan://pw@2.2.2.2:443?sni=h#🇺🇲 US",
	}, "\n"))
	ini := "[custom]\n" +
		"ruleset=🐟 Final,[]FINAL\n" +
		"custom_proxy_group=🚀 Select`select`.*`\n" +
		"enable_rule_generator=true\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/sub.txt", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(sub)) })
	mux.HandleFunc("/config.init", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(ini)) })
	return httptest.NewServer(mux)
}

func testConfig() *config.Config {
	c := config.Default()
	c.Fetch.AllowPrivateIPs = true
	return c
}

func TestHandleSub_EndToEnd(t *testing.T) {
	air := fakeAirport()
	defer air.Close()

	h := New(testConfig()).Handler()
	target := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt") +
		"&config=" + url.QueryEscape(air.URL+"/config.init") + "&sort=true"

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "yaml") {
		t.Errorf("content-type = %q", ct)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("invalid yaml output: %v", err)
	}
	proxies, _ := doc["proxies"].([]any)
	if len(proxies) != 2 {
		t.Errorf("proxies = %d, want 2", len(proxies))
	}
	if doc["proxy-groups"] == nil || doc["rules"] == nil {
		t.Error("missing groups/rules")
	}
}

func TestHandleSub_DefaultConfigURL(t *testing.T) {
	air := fakeAirport()
	defer air.Close()

	cfg := testConfig()
	cfg.DefaultConfigURL = air.URL + "/config.init"
	h := New(cfg).Handler()

	// No &config=: the server default is used — groups/rules must be present.
	target := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var doc map[string]any
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("invalid yaml output: %v", err)
	}
	if doc["proxy-groups"] == nil || doc["rules"] == nil {
		t.Error("default config not applied: missing groups/rules")
	}
}

func TestHandleSub_ExplicitConfigWinsOverDefault(t *testing.T) {
	air := fakeAirport()
	defer air.Close()
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("[custom]\nruleset=🐟 Final,[]FINAL\ncustom_proxy_group=Other`select`.*`\n"))
	}))
	defer other.Close()

	cfg := testConfig()
	cfg.DefaultConfigURL = other.URL + "/other.init"
	h := New(cfg).Handler()

	target := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt") +
		"&config=" + url.QueryEscape(air.URL+"/config.init")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "🚀 Select") || strings.Contains(body, "Other") {
		t.Errorf("explicit &config= did not win over default, body:\n%s", body)
	}
}

func TestHandleSub_BrokenDefaultConfigFailsClosed(t *testing.T) {
	// fakeAirport serves no /missing.init -> fetch fails.
	air := fakeAirport()
	defer air.Close()

	cfg := testConfig()
	cfg.DefaultConfigURL = air.URL + "/missing.init"
	h := New(cfg).Handler()

	target := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 Bad Gateway", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "fetch external config") {
		t.Errorf("expected fetch-external-config error hint, got:\n%s", body)
	}
	if strings.Contains(body, "proxy-groups:") {
		t.Error("must not fall back to rendering on default-config failure")
	}
}

func TestHandleSub_BrokenDefaultConfig500FailsClosed(t *testing.T) {
	// A 500 from the default-config origin is an upstream failure, not an empty
	// config: same fail-closed expectation as the 404 case.
	air := fakeAirport()
	defer air.Close()
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer broken.Close()

	cfg := testConfig()
	cfg.DefaultConfigURL = broken.URL + "/config.init"
	h := New(cfg).Handler()

	target := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 Bad Gateway", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "fetch external config") {
		t.Errorf("expected fetch-external-config error hint, got:\n%s", body)
	}
	if strings.Contains(body, "proxy-groups:") {
		t.Error("must not fall back to rendering on default-config failure")
	}
}

func TestHandleSub_NoUsableNodesReturnsHint(t *testing.T) {
	air := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("garbage://nothing\nalso-bad"))
	}))
	defer air.Close()

	h := New(testConfig()).Handler()
	target := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/x")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 Unprocessable Entity", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Errorf("content-type = %q, want text/plain", ct)
	}
	if body := rec.Body.String(); !strings.Contains(body, "无可用节点") {
		t.Errorf("body missing hint: %q", body)
	}
}

func TestHandleSub_MissingURL(t *testing.T) {
	h := New(config.Default()).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub?target=clash", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestHandleVersion(t *testing.T) {
	h := New(config.Default()).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/version", nil))
	body, _ := io.ReadAll(rec.Result().Body)
	if rec.Code != http.StatusOK || !strings.Contains(string(body), "subconverter-ng") {
		t.Errorf("version handler: code=%d body=%q", rec.Code, body)
	}
}

func TestHandleRootServesWebUI(t *testing.T) {
	h := New(config.Default()).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "subconverter-ng") {
		t.Error("body missing branding")
	}
	if !strings.Contains(body, `id="urls"`) {
		t.Error("body missing form marker id=\"urls\"")
	}
}

func TestSplitURLs(t *testing.T) {
	got := splitURLs(" a | b |  | c ")
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Errorf("splitURLs = %#v", got)
	}
}

func TestBoolParam(t *testing.T) {
	if !boolParam("true", false) || !boolParam("1", false) {
		t.Error("truthy")
	}
	if boolParam("false", true) || boolParam("0", true) {
		t.Error("falsey overrides default")
	}
	if boolParam("", true) != true || boolParam("garbage", false) != false {
		t.Error("default fallthrough")
	}
}

func TestBoolTri(t *testing.T) {
	for _, on := range []string{"true", "1", "yes", "ON"} {
		if v := boolTri(on); v == nil || !*v {
			t.Errorf("boolTri(%q) should be true", on)
		}
	}
	for _, off := range []string{"false", "0", "no", "OFF"} {
		if v := boolTri(off); v == nil || *v {
			t.Errorf("boolTri(%q) should be false", off)
		}
	}
	for _, none := range []string{"", "maybe"} {
		if v := boolTri(none); v != nil {
			t.Errorf("boolTri(%q) should be nil", none)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if firstNonEmpty("", "", "x", "y") != "x" {
		t.Error("should pick first non-empty")
	}
	if firstNonEmpty("", "") != "" {
		t.Error("all empty -> empty")
	}
}

// rlConfig returns a config with a tight rate limit for deterministic tests.
func rlConfig(rpm, burst int) *config.Config {
	c := config.Default()
	c.RateLimit.Enabled = true
	c.RateLimit.RequestsPerMinute = rpm
	c.RateLimit.Burst = burst
	return c
}

func TestRateLimit_SubEventually429(t *testing.T) {
	// burst 2: third request from the same IP within the window is blocked.
	h := New(rlConfig(1, 2)).Handler()
	var lastCode int
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/sub?target=clash", nil)
		req.RemoteAddr = "203.0.113.7:54321"
		h.ServeHTTP(rec, req)
		lastCode = rec.Code
		if i < 2 && rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d unexpectedly throttled within burst", i+1)
		}
		if i == 2 {
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("request %d code = %d, want 429", i+1, rec.Code)
			}
			if ra := rec.Header().Get("Retry-After"); ra == "" {
				t.Error("429 missing Retry-After header")
			}
			if !strings.Contains(rec.Body.String(), "rate limit") {
				t.Errorf("429 body = %q", rec.Body.String())
			}
		}
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("final code = %d, want 429", lastCode)
	}
}

func TestRateLimit_FlushCacheThrottled(t *testing.T) {
	h := New(rlConfig(1, 2)).Handler()
	var lastCode int
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/flushcache", nil)
		req.RemoteAddr = "203.0.113.9:54321"
		h.ServeHTTP(rec, req)
		lastCode = rec.Code
		if i < 2 && rec.Code == http.StatusTooManyRequests {
			t.Fatalf("flushcache request %d unexpectedly throttled within burst", i+1)
		}
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("final flushcache code = %d, want 429", lastCode)
	}
}

func TestRateLimit_VersionAndRootNeverThrottled(t *testing.T) {
	h := New(rlConfig(1, 1)).Handler()
	// Exhaust /sub first to prove the limiter is active.
	subReq := httptest.NewRequest(http.MethodGet, "/sub?target=clash", nil)
	subReq.RemoteAddr = "203.0.113.8:1000"
	h.ServeHTTP(httptest.NewRecorder(), subReq)

	for _, path := range []string{"/version", "/"} {
		for i := 0; i < 5; i++ {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, nil)
			req.RemoteAddr = "203.0.113.8:1000"
			h.ServeHTTP(rec, req)
			if rec.Code == http.StatusTooManyRequests {
				t.Fatalf("%s request %d was throttled (code 429)", path, i+1)
			}
		}
	}
}

func TestRateLimit_XForwardedForSeparatesBuckets(t *testing.T) {
	cfg := rlConfig(1, 1)
	cfg.RateLimit.TrustedProxies = []string{"10.0.0.0/8"}
	h := New(cfg).Handler()

	doReq := func(xff string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/sub?target=clash", nil)
		req.RemoteAddr = "10.0.0.1:9999" // shared connection (e.g. reverse proxy)
		req.Header.Set("X-Forwarded-For", xff)
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// First IP: allowed then blocked.
	if c := doReq("198.51.100.1"); c == http.StatusTooManyRequests {
		t.Fatalf("first XFF IP first request = %d, want not 429", c)
	}
	if c := doReq("198.51.100.1"); c != http.StatusTooManyRequests {
		t.Fatalf("first XFF IP second request = %d, want 429", c)
	}
	// Different IP gets its own bucket: still allowed.
	if c := doReq("198.51.100.2"); c == http.StatusTooManyRequests {
		t.Fatalf("second XFF IP should have its own bucket, got 429")
	}
	// XFF first hop is used when a chain is present.
	if c := doReq("198.51.100.3, 70.0.0.1"); c == http.StatusTooManyRequests {
		t.Fatalf("third XFF IP (chain) should be allowed, got 429")
	}
}

func TestRateLimit_UntrustedProxyIgnoresXForwardedFor(t *testing.T) {
	cfg := rlConfig(1, 1) // no trusted proxies configured
	h := New(cfg).Handler()

	doReq := func(xff string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/sub?target=clash", nil)
		req.RemoteAddr = "203.0.113.5:12345" // untrusted client trying to spoof XFF
		req.Header.Set("X-Forwarded-For", xff)
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// First request from 203.0.113.5 succeeds
	if c := doReq("198.51.100.1"); c == http.StatusTooManyRequests {
		t.Fatalf("first request should pass, got %d", c)
	}
	// Second request from 203.0.113.5 with different spoofed XFF should still be throttled because XFF is ignored!
	if c := doReq("198.51.100.2"); c != http.StatusTooManyRequests {
		t.Fatalf("second request should be throttled (spoofed XFF ignored), got %d", c)
	}
}

func TestRateLimit_DisabledIsPassThrough(t *testing.T) {
	c := config.Default()
	c.RateLimit.Enabled = false
	h := New(c).Handler()
	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/sub?target=clash", nil)
		req.RemoteAddr = "192.0.2.1:1234"
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d throttled while disabled", i+1)
		}
	}
}

func TestClientIP(t *testing.T) {
	s := New(&config.Config{
		RateLimit: config.RateLimit{
			TrustedProxies: []string{"10.0.0.1"},
		},
	})
	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		xrip       string
		want       string
	}{
		{"remoteaddr", "192.0.2.5:4444", "", "", "192.0.2.5"},
		{"xff first hop (trusted)", "10.0.0.1:1", "203.0.113.9, 70.0.0.1", "", "203.0.113.9"},
		{"x-real-ip (trusted)", "10.0.0.1:1", "", "198.51.100.50", "198.51.100.50"},
		{"xff beats xrip (trusted)", "10.0.0.1:1", "203.0.113.10", "198.51.100.50", "203.0.113.10"},
		{"remoteaddr no port", "192.0.2.6", "", "", "192.0.2.6"},
		{"untrusted xff ignored", "203.0.113.5:1234", "198.51.100.1", "", "203.0.113.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/sub", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xrip != "" {
				req.Header.Set("X-Real-IP", tc.xrip)
			}
			if got := s.clientIP(req); got != tc.want {
				t.Errorf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHandleSub_Tailscale(t *testing.T) {
	air := fakeAirport()
	defer air.Close()

	h := New(testConfig()).Handler()
	target := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt") +
		"&config=" + url.QueryEscape(air.URL+"/config.init") + "&tailscale=true"

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var doc struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("invalid yaml: %v", err)
	}
	if len(doc.Rules) < 3 {
		t.Fatalf("rules len=%d, want >=3", len(doc.Rules))
	}
	if doc.Rules[0] != "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve" || doc.Rules[1] != "IP-CIDR,fd7a:115c:a1e0::/48,DIRECT,no-resolve" {
		t.Errorf("rules[0..1] mismatch: %v", doc.Rules[:2])
	}
}

func TestHandleSub_TokenAuth(t *testing.T) {
	air := fakeAirport()
	defer air.Close()

	cfg := testConfig()
	cfg.APIAccessToken = "secret123"
	h := New(cfg).Handler()

	baseURL := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt") +
		"&config=" + url.QueryEscape(air.URL+"/config.init")

	// 1. Missing token -> 401
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, baseURL, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("missing token code = %d, want 401", rec.Code)
	}

	// 2. Invalid token -> 401
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, baseURL+"&token=wrong", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid token code = %d, want 401", rec.Code)
	}

	// 3. Valid token via query param -> 200
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, baseURL+"&token=secret123", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("query token code = %d, want 200", rec.Code)
	}

	// 4. Valid token via Authorization: Bearer -> 200
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, baseURL, nil)
	req.Header.Set("Authorization", "Bearer secret123")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer token code = %d, want 200", rec.Code)
	}

	// 5. Valid token via X-API-Token -> 200
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, baseURL, nil)
	req.Header.Set("X-API-Token", "secret123")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("X-API-Token code = %d, want 200", rec.Code)
	}
}

func TestHandleFlushCache_TokenAuth(t *testing.T) {
	cfg := config.Default()
	cfg.APIAccessToken = "flush-key"
	h := New(cfg).Handler()

	// Missing token -> 401
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/flushcache", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401", rec.Code)
	}

	// Valid token -> 200
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/flushcache?token=flush-key", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
}

func TestHealthzAndReadyz(t *testing.T) {
	h := New(config.Default()).Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
		t.Fatalf("healthz: code=%d body=%q", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ready\n" {
		t.Fatalf("readyz: code=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestHandleSub_SSRFProtected(t *testing.T) {
	// Default config has AllowPrivateIPs: false
	h := New(config.Default()).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub?target=clash&url=http://127.0.0.1:9999/sub.txt", nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 Bad Gateway for SSRF block", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "SSRF") {
		t.Errorf("expected SSRF error message in body, got: %s", rec.Body.String())
	}
}

func TestHandleSub_RedactsTokenInErrorResponse(t *testing.T) {
	cfg := testConfig()
	h := New(cfg).Handler()

	secretSubURL := "http://127.0.0.1:54321/sub?token=SuperSecretTokenValue"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub?target=clash&url="+url.QueryEscape(secretSubURL), nil))

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "SuperSecretTokenValue") {
		t.Fatalf("error response body leaked secret token:\n%s", body)
	}
	if !strings.Contains(body, "token=***") {
		t.Errorf("expected token=*** in redacted body, got:\n%s", body)
	}
}

func TestHandleSub_ProxyParamSSRFBlocked(t *testing.T) {
	air := fakeAirport()
	defer air.Close()

	// Default config has AllowPrivateIPs: false
	h := New(config.Default()).Handler()

	blockedProxies := []string{
		"http://127.0.0.1:8080",
		"http://localhost:8080",
		"http://sub.localhost:8080",
		"http://169.254.169.254:80",
		"http://10.0.0.1:8080",
		"http://0.0.0.1:8080",
		"socks5://192.168.1.1:1080",
	}

	for _, proxy := range blockedProxies {
		target := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt") +
			"&proxy=" + url.QueryEscape(proxy)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("proxy=%q: code = %d, want 400 Bad Request", proxy, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "invalid proxy parameter") {
			t.Errorf("proxy=%q: body = %q, want invalid proxy parameter mention", proxy, rec.Body.String())
		}
	}
}

func TestHandleSub_SingleFlightAcrossRequests(t *testing.T) {
	var requestCount atomic.Int32
	subContent := b64("ss://" + b64("aes-256-gcm:pw") + "@1.1.1.1:8388#Node1\n")
	air := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		time.Sleep(50 * time.Millisecond) // simulate work
		_, _ = w.Write([]byte(subContent))
	}))
	defer air.Close()

	cfg := testConfig()
	cfg.Fetch.CacheTTL = -1 // disable cache to isolate singleflight deduplication
	h := New(cfg).Handler()

	concurrency := 6
	var wg sync.WaitGroup
	wg.Add(concurrency)

	target := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt")

	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
			if rec.Code != http.StatusOK {
				t.Errorf("request status = %d, body = %s", rec.Code, rec.Body.String())
			}
		}()
	}
	wg.Wait()

	if got := requestCount.Load(); got != 1 {
		t.Errorf("singleflight across server requests: upstream requestCount = %d, want 1", got)
	}
}

func TestServer_InvalidTrustedProxiesPanics(t *testing.T) {
	cfg := config.Default()
	cfg.RateLimit.TrustedProxies = []string{"10.0.0.1/bad-cidr"}

	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected server.New to panic on invalid trusted proxy, but did not")
		}
	}()
	_ = New(cfg)
}

func TestHandleSub_ExcludeProtocol(t *testing.T) {
	air := fakeAirport()
	defer air.Close()

	h := New(testConfig()).Handler()

	// 1. Exclude trojan -> only ss remains
	req1 := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt") +
		"&config=" + url.QueryEscape(air.URL+"/config.init") + "&exclude_protocol=trojan"
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, req1, nil))
	if rec1.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec1.Code, rec1.Body.String())
	}
	var doc1 map[string]any
	if err := yaml.Unmarshal(rec1.Body.Bytes(), &doc1); err != nil {
		t.Fatalf("unmarshal yaml: %v", err)
	}
	proxies1, _ := doc1["proxies"].([]any)
	if len(proxies1) != 1 {
		t.Fatalf("proxies count = %d, want 1", len(proxies1))
	}
	p1, _ := proxies1[0].(map[string]any)
	if p1["type"] != "ss" {
		t.Errorf("remaining proxy type = %v, want ss", p1["type"])
	}

	// 2. Exclude shadowsocks via alias and comma delimiter
	req2 := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt") +
		"&config=" + url.QueryEscape(air.URL+"/config.init") + "&exclude_protocols=shadowsocks"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, req2, nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec2.Code, rec2.Body.String())
	}
	var doc2 map[string]any
	if err := yaml.Unmarshal(rec2.Body.Bytes(), &doc2); err != nil {
		t.Fatalf("unmarshal yaml: %v", err)
	}
	proxies2, _ := doc2["proxies"].([]any)
	if len(proxies2) != 1 {
		t.Fatalf("proxies count = %d, want 1", len(proxies2))
	}
	p2, _ := proxies2[0].(map[string]any)
	if p2["type"] != "trojan" {
		t.Errorf("remaining proxy type = %v, want trojan", p2["type"])
	}

	// 3. Exclude both via pipe delimiter: ss|trojan -> 0 proxies remain
	req3 := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt") +
		"&config=" + url.QueryEscape(air.URL+"/config.init") + "&exclude_type=ss|trojan"
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, req3, nil))
	if rec3.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec3.Code, rec3.Body.String())
	}
	var doc3 map[string]any
	if err := yaml.Unmarshal(rec3.Body.Bytes(), &doc3); err != nil {
		t.Fatalf("unmarshal yaml: %v", err)
	}
	proxies3, _ := doc3["proxies"].([]any)
	if len(proxies3) != 0 {
		t.Errorf("proxies count = %d, want 0", len(proxies3))
	}

	// 4. Test filter_type alias
	req4 := "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt") +
		"&config=" + url.QueryEscape(air.URL+"/config.init") + "&filter_type=trojan"
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, httptest.NewRequest(http.MethodGet, req4, nil))
	if rec4.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec4.Code, rec4.Body.String())
	}
	var doc4 map[string]any
	if err := yaml.Unmarshal(rec4.Body.Bytes(), &doc4); err != nil {
		t.Fatalf("unmarshal yaml: %v", err)
	}
	proxies4, _ := doc4["proxies"].([]any)
	if len(proxies4) != 1 {
		t.Fatalf("proxies count = %d, want 1", len(proxies4))
	}
	p4, _ := proxies4[0].(map[string]any)
	if p4["type"] != "ss" {
		t.Errorf("remaining proxy type = %v, want ss", p4["type"])
	}
}
