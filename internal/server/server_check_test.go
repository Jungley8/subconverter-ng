package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// checkAirport serves a subscription that exercises the three things the
// &check=true report is for: an unparseable line, a group that matches no node,
// and a rule the target cannot render.
func checkAirport() *httptest.Server {
	sub := strings.Join([]string{
		"ss://" + b64("aes-256-gcm:pw") + "@1.1.1.1:8388#🇭🇰 HK",
		"trojan://pw@2.2.2.2:443?sni=h#🇺🇲 US",
		"vmess://SEVERE_PASSWORD_SECRET",
	}, "\n")
	ini := "[custom]\n" +
		"enable_rule_generator=true\n" +
		"custom_proxy_group=🚀 Select`select`.*\n" +
		"custom_proxy_group=🇯🇵 JP`url-test`(?i)JP\n" +
		"ruleset=DIRECT,[]IP-CIDR,10.0.0.0/8,no-resolve,extra\n" +
		"ruleset=🐟 Final,[]FINAL\n"
	mux := http.NewServeMux()
	mux.HandleFunc("/sub.txt", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(sub)) })
	mux.HandleFunc("/config.init", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(ini)) })
	return httptest.NewServer(mux)
}

func TestHandleSub_CheckReport(t *testing.T) {
	air := checkAirport()
	defer air.Close()
	h := New(testConfig()).Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, paramURL(air, "&check=true"), nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	var report checkReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("response is not JSON: %v\n%s", err, rec.Body.String())
	}
	if report.Target != "clash" {
		t.Errorf("target = %q, want clash", report.Target)
	}
	if report.Nodes != 2 {
		t.Errorf("nodes = %d, want 2", report.Nodes)
	}
	if report.SkippedLines != 1 {
		t.Errorf("skipped_lines = %d, want 1", report.SkippedLines)
	}
	if !contains(report.EmptyGroups, "🇯🇵 JP") {
		t.Errorf("empty_groups = %v, want 🇯🇵 JP (its selector matches no node)", report.EmptyGroups)
	}
	if len(report.DroppedRules) != 1 || !strings.Contains(report.DroppedRules[0], "no-resolve,extra") {
		t.Errorf("dropped_rules = %v, want the 4-field rule", report.DroppedRules)
	}
	if report.OutputBytes == 0 {
		t.Error("output_bytes = 0: the report must describe a real render")
	}
	if report.Provider {
		t.Error("provider = true without &provider=true")
	}

	// The report must not echo the subscription. Malformed share links are
	// exactly the lines most likely to still contain a password.
	body := rec.Body.String()
	for _, leaked := range []string{"SEVERE_PASSWORD_SECRET", b64("aes-256-gcm:pw"), air.URL} {
		if strings.Contains(body, leaked) {
			t.Errorf("check report leaked %q", leaked)
		}
	}

	// Empty lists must be [] and not null, so a consumer can iterate without a
	// nil check.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if got := string(raw["unsupported_nodes"]); got != "[]" {
		t.Errorf("unsupported_nodes = %s, want []", got)
	}
}

// TestHandleSub_CheckReportProvider pins provider mode reporting: the flag says
// whether node fetching was delegated to the client, because that changes what
// `nodes` means (it then counts inline share-link entries only).
func TestHandleSub_CheckReportProvider(t *testing.T) {
	air := fakeAirport()
	defer air.Close()
	h := New(testConfig()).Handler()

	req := "/sub?target=clash&provider=true&check=true&url=" +
		url.QueryEscape(air.URL+"/sub.txt|trojan://pw@3.3.3.3:443#Local") +
		"&config=" + url.QueryEscape(air.URL+"/config.init")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, req, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var report checkReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("response is not JSON: %v\n%s", err, rec.Body.String())
	}
	if !report.Provider {
		t.Error("provider = false, want true with &provider=true")
	}
	if report.Nodes != 1 {
		t.Errorf("nodes = %d, want 1 (only the share-link entry is inlined)", report.Nodes)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
