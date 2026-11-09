package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func paramURL(air *httptest.Server, extra string) string {
	return "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt") +
		"&config=" + url.QueryEscape(air.URL+"/config.init") + extra
}

func TestHandleSub_ListOnly(t *testing.T) {
	air := fakeAirport()
	defer air.Close()
	h := New(testConfig()).Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, paramURL(air, "&list=true"), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var doc map[string]any
	if err := yaml.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["proxies"] == nil {
		t.Error("list output missing proxies")
	}
	if doc["proxy-groups"] != nil || doc["rules"] != nil {
		t.Error("list=true must omit groups/rules")
	}
}

func TestHandleSub_FilenameAndInterval(t *testing.T) {
	air := fakeAirport()
	defer air.Close()
	h := New(testConfig()).Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, paramURL(air, "&filename=my%20clash.yaml&interval=12"), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, `filename="my clash.yaml"`) {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if iv := rec.Header().Get("Profile-Update-Interval"); iv != "12" {
		t.Errorf("Profile-Update-Interval = %q, want 12", iv)
	}
}

func TestSanitizeFilename(t *testing.T) {
	if got := sanitizeFilename("a\"b\\c\r\nd/e"); got != "abcde" {
		t.Errorf("sanitizeFilename = %q", got)
	}
}

func TestHandleSub_InvalidTargetVersion(t *testing.T) {
	h := New(testConfig()).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub?target=singbox/abc&url=x", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "invalid target") {
		t.Errorf("body = %q", body)
	}
}

// TestHandleSub_UAPriority verifies the fetch User-Agent precedence: explicit
// &ua= beats the fetch client's built-in default (testConfig leaves
// fetch.user_agent unset). Each case uses its own upstream path so the shared
// fetch cache never serves one case's response to another.
func TestHandleSub_UAPriority(t *testing.T) {
	gotUA := map[string]string{}
	sub := b64("ss://" + b64("aes-256-gcm:pw") + "@1.1.1.1:8388#HK")
	ini := "[custom]\nruleset=🐟 Final,[]FINAL\ncustom_proxy_group=🚀 Select`select`.*`\nenable_rule_generator=true\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotUA[r.URL.Path] = r.Header.Get("User-Agent")
		switch {
		case strings.HasSuffix(r.URL.Path, "/sub.txt"):
			_, _ = w.Write([]byte(sub))
		case strings.HasSuffix(r.URL.Path, "/config.init"):
			_, _ = w.Write([]byte(ini))
		default:
			http.NotFound(w, r)
		}
	})
	air := httptest.NewServer(mux)
	defer air.Close()

	h := New(testConfig()).Handler()
	do := func(query string) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub?target=clash"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
		}
	}
	cfg := url.QueryEscape(air.URL + "/c/config.init")

	// Explicit &ua= wins over everything.
	do("&ua=MyCustomUA/1.0&url=" + url.QueryEscape(air.URL+"/s3/sub.txt") + "&config=" + cfg)
	if ua := gotUA["/s3/sub.txt"]; ua != "MyCustomUA/1.0" {
		t.Errorf("ua override: upstream UA = %q, want MyCustomUA/1.0", ua)
	}

	// Without &ua= the fetch client's built-in default is used.
	do("&url=" + url.QueryEscape(air.URL+"/s1/sub.txt") + "&config=" + cfg)
	if ua := gotUA["/s1/sub.txt"]; ua != "clash.meta/1.18.0 mihomo/1.18.0" {
		t.Errorf("default UA: upstream UA = %q, want clash.meta/1.18.0 mihomo/1.18.0", ua)
	}
}
