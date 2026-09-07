package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Jungley8/subconverter-ng/internal/config"
)

const testAccessToken = "0123456789abcdef0123456789abcdef"

func managedConfig(upstream string, expires time.Time) *config.Config {
	c := config.Default()
	c.Access.Enabled = true
	c.Access.Profiles = []config.AccessProfile{{
		Name: "user-a", Token: testAccessToken, Enabled: true,
		ExpiresAt: config.ExpiryTime{Time: expires},
		URLs:      []string{upstream + "/sub"},
		ConfigURL: upstream + "/config",
	}}
	return c
}

func managedUpstream(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/sub", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Subscription-Userinfo", "upload=1; download=2; total=3; expire=4")
		links := "ss://YWVzLTI1Ni1nY206cHc@1.1.1.1:8388#Node"
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(links))))
	})
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("[custom]\nruleset=DIRECT,[]FINAL\n"))
	})
	return httptest.NewServer(mux)
}

func TestManagedSubscriptionSuccessAndExpiryHeader(t *testing.T) {
	var hits atomic.Int32
	upstream := managedUpstream(t, &hits)
	defer upstream.Close()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	expires := now.Add(24 * time.Hour)
	s := New(managedConfig(upstream.URL, expires))
	s.now = func() time.Time { return now }

	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet,
		"/sub?token="+testAccessToken+"&target=clash&dedup=true", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	wantInfo := "upload=1; download=2; total=3; expire=" + strconv.FormatInt(expires.Unix(), 10)
	if got := rec.Header().Get("Subscription-Userinfo"); got != wantInfo {
		t.Errorf("Subscription-Userinfo=%q, want %q", got, wantInfo)
	}
	if hits.Load() != 2 {
		t.Errorf("upstream hits=%d, want 2", hits.Load())
	}
}

func TestManagedSubscriptionDenialsDoNotFetch(t *testing.T) {
	var hits atomic.Int32
	upstream := managedUpstream(t, &hits)
	defer upstream.Close()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		path   string
		mutate func(*config.Config)
		status int
	}{
		{"missing token", "/sub", func(*config.Config) {}, http.StatusUnauthorized},
		{"unknown token", "/sub?token=" + strings.Repeat("f", 32), func(*config.Config) {}, http.StatusUnauthorized},
		{"disabled", "/sub?token=" + testAccessToken, func(c *config.Config) { c.Access.Profiles[0].Enabled = false }, http.StatusOK},
		{"expired before", "/sub?token=" + testAccessToken, func(c *config.Config) {
			c.Access.Profiles[0].ExpiresAt = config.ExpiryTime{Time: now.Add(-time.Second)}
		}, http.StatusOK},
		{"expired boundary", "/sub?token=" + testAccessToken, func(c *config.Config) { c.Access.Profiles[0].ExpiresAt = config.ExpiryTime{Time: now} }, http.StatusOK},
		{"expired non-clash", "/sub?token=" + testAccessToken + "&target=singbox", func(c *config.Config) { c.Access.Profiles[0].ExpiresAt = config.ExpiryTime{Time: now} }, http.StatusGone},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := managedConfig(upstream.URL, now.Add(time.Hour))
			tc.mutate(cfg)
			s := New(cfg)
			s.now = func() time.Time { return now }
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != tc.status {
				t.Errorf("status=%d, want %d", rec.Code, tc.status)
			}
			if tc.status == http.StatusOK {
				body := rec.Body.String()
				if !strings.Contains(body, "proxies: []") || !strings.Contains(body, "MATCH,DIRECT") {
					t.Errorf("expired Clash profile was not cleared: %q", body)
				}
				if got := rec.Header().Get("Profile-Update-Interval"); got != "1" {
					t.Errorf("update interval=%q, want 1", got)
				}
			}
		})
	}
	if hits.Load() != 0 {
		t.Errorf("denied requests reached upstream: %d hits", hits.Load())
	}
}

func TestManagedSubscriptionRejectsSourceAndCacheOverrides(t *testing.T) {
	var hits atomic.Int32
	upstream := managedUpstream(t, &hits)
	defer upstream.Close()
	now := time.Now()
	for _, param := range []string{"url=https%3A%2F%2Fevil.example", "config=x", "proxy=x", "nocache=1", "flushcache=1"} {
		t.Run(strings.SplitN(param, "=", 2)[0], func(t *testing.T) {
			s := New(managedConfig(upstream.URL, now.Add(time.Hour)))
			s.now = func() time.Time { return now }
			rec := httptest.NewRecorder()
			path := "/sub?token=" + testAccessToken + "&" + param
			s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status=%d, want 400", rec.Code)
			}
		})
	}
	if hits.Load() != 0 {
		t.Errorf("rejected requests reached upstream: %d hits", hits.Load())
	}
}

func TestWithExpiry(t *testing.T) {
	if got := withExpiry("upload=1; expire=2; download=3", 99); got != "upload=1; download=3; expire=99" {
		t.Errorf("withExpiry=%q", got)
	}
	if got := withExpiry("", 99); got != "expire=99" {
		t.Errorf("withExpiry(empty)=%q", got)
	}
}

func TestCreateAccessProfileAndUseToken(t *testing.T) {
	var hits atomic.Int32
	upstream := managedUpstream(t, &hits)
	defer upstream.Close()
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	expires := now.Add(48 * time.Hour)
	s := New(config.Default())
	s.now = func() time.Time { return now }
	h := s.Handler()

	payload, _ := json.Marshal(createAccessRequest{
		URLs: []string{upstream.URL + "/sub"}, ExpiresAt: expires.Format(time.RFC3339),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/access/create", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created createAccessResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if len(created.Token) != 64 || created.ExpiresAt != expires.Format(time.RFC3339) {
		t.Fatalf("unexpected create response: %+v", created)
	}

	secondRec := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodPost, "/access/create", bytes.NewReader(payload))
	secondReq.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(secondRec, secondReq)
	if secondRec.Code != http.StatusCreated {
		t.Fatalf("second create status=%d body=%s", secondRec.Code, secondRec.Body.String())
	}
	var second createAccessResponse
	if err := json.Unmarshal(secondRec.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if len(second.Token) != 64 || second.Token == created.Token {
		t.Fatalf("tokens must be unique: first=%q second=%q", created.Token, second.Token)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, created.Path+"&target=clash", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("managed status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Subscription-Userinfo"); got != "upload=1; download=2; total=3; expire="+strconv.FormatInt(expires.Unix(), 10) {
		t.Errorf("Subscription-Userinfo=%q", got)
	}
	if hits.Load() != 1 {
		t.Errorf("upstream hits=%d, want 1", hits.Load())
	}
}

func TestCreateAccessProfileValidation(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	s := New(config.Default())
	s.now = func() time.Time { return now }
	h := s.Handler()

	tests := []struct {
		name   string
		method string
		body   string
		status int
	}{
		{"method", http.MethodGet, "", http.StatusMethodNotAllowed},
		{"bad json", http.MethodPost, "{", http.StatusBadRequest},
		{"no urls", http.MethodPost, `{"expires_at":"2026-09-08T12:00:00Z"}`, http.StatusBadRequest},
		{"bad expiry", http.MethodPost, `{"urls":["https://air.example/sub"],"expires_at":"tomorrow"}`, http.StatusBadRequest},
		{"past expiry", http.MethodPost, `{"urls":["https://air.example/sub"],"expires_at":"2026-09-07T11:59:59Z"}`, http.StatusBadRequest},
		{"unknown field", http.MethodPost, `{"urls":["https://air.example/sub"],"expires_at":"2026-09-08T12:00:00Z","admin":true}`, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tc.method, "/access/create", strings.NewReader(tc.body)))
			if rec.Code != tc.status {
				t.Errorf("status=%d, want %d; body=%s", rec.Code, tc.status, rec.Body.String())
			}
		})
	}
}

func TestDisabledStaticProfilesAreNotActive(t *testing.T) {
	cfg := config.Default()
	cfg.Access.Profiles = []config.AccessProfile{{
		Token: testAccessToken, Enabled: true,
		ExpiresAt: config.ExpiryTime{Time: time.Now().Add(time.Hour)},
		URLs:      []string{"https://air.example/sub"},
	}}
	rec := httptest.NewRecorder()
	New(cfg).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub?token="+testAccessToken, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401 while static access is disabled", rec.Code)
	}
}
