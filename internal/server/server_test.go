package server

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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
	mux.HandleFunc("/sub.txt", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sub)) })
	mux.HandleFunc("/config.init", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(ini)) })
	return httptest.NewServer(mux)
}

func TestHandleSub_EndToEnd(t *testing.T) {
	air := fakeAirport()
	defer air.Close()

	h := New(config.Default()).Handler()
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
	h := New(rlConfig(1, 1)).Handler()

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
	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		xrip       string
		want       string
	}{
		{"remoteaddr", "192.0.2.5:4444", "", "", "192.0.2.5"},
		{"xff first hop", "10.0.0.1:1", "203.0.113.9, 70.0.0.1", "", "203.0.113.9"},
		{"x-real-ip", "10.0.0.1:1", "", "198.51.100.50", "198.51.100.50"},
		{"xff beats xrip", "10.0.0.1:1", "203.0.113.10", "198.51.100.50", "203.0.113.10"},
		{"remoteaddr no port", "192.0.2.6", "", "", "192.0.2.6"},
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
			if got := clientIP(req); got != tc.want {
				t.Errorf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}
