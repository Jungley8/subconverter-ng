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
