package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestHandleSub_ErrorStatuses pins who can fix a failure: 400 when the request
// is wrong, 422 when the subscription has no nodes, 424 when an upstream fetch
// failed. A 424 on a typo sends the user to debug their airport.
func TestHandleSub_ErrorStatuses(t *testing.T) {
	air := fakeAirport()
	defer air.Close()

	tmpl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"outbounds": []}`)) // no {{ Nodes }} placeholder
	}))
	defer tmpl.Close()

	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("this is not a subscription"))
	}))
	defer empty.Close()

	h := New(testConfig()).Handler()
	sub := url.QueryEscape(air.URL + "/sub.txt")

	cases := []struct {
		name  string
		query string
		want  int
	}{
		{"unknown target", "/sub?target=nope&url=" + sub, http.StatusBadRequest},
		{
			"provider mode with only a share link",
			"/sub?target=clash&provider=true&url=" + url.QueryEscape("trojan://pw@1.1.1.1:443#Local"),
			http.StatusBadRequest,
		},
		{
			"template without the Nodes placeholder",
			"/sub?target=singbox&template=" + url.QueryEscape(tmpl.URL+"/t.json") + "&url=" + sub,
			http.StatusBadRequest,
		},
		{"template spec is not a URL", "/sub?target=singbox&template=my-template&url=" + sub, http.StatusBadRequest},
		{"upstream unreachable", "/sub?target=clash&url=" + url.QueryEscape("http://127.0.0.1:1/sub.txt"), http.StatusFailedDependency},
		{"subscription has no nodes", "/sub?target=clash&url=" + url.QueryEscape(empty.URL+"/sub.txt"), http.StatusUnprocessableEntity},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.query, nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d, body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestHandleSub_BadRequestBody keeps the 400 body distinguishable from the
// upstream-failure body, so a user can tell the two apart when the status is
// hidden by a client.
func TestHandleSub_BadRequestBody(t *testing.T) {
	h := New(testConfig()).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sub?target=nope&url=http://example.com/s", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "invalid request") {
		t.Errorf("body = %q, want an invalid-request hint", body)
	}
}
