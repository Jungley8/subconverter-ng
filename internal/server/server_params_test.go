package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/config"
	"gopkg.in/yaml.v3"
)

func paramURL(air *httptest.Server, extra string) string {
	return "/sub?target=clash&url=" + url.QueryEscape(air.URL+"/sub.txt") +
		"&config=" + url.QueryEscape(air.URL+"/config.init") + extra
}

func TestHandleSub_ListOnly(t *testing.T) {
	air := fakeAirport()
	defer air.Close()
	h := New(config.Default()).Handler()

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
	h := New(config.Default()).Handler()

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
