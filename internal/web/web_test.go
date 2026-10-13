package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler_ServesIndex(t *testing.T) {
	h := Handler()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	body := rec.Body.String()
	for _, expected := range []string{
		"subconverter-ng",
		"<!DOCTYPE html>",
		"tabBtnConvert",
		"tabBtnManage",
		"subDialog",
		"backupDialog",
		"subExpireDate",
		"subResetDay",
		"subCost",
		"subCycle",
		"subWebsite",
		"subng.subscriptions.v1",
		// The config input must tell users that leaving it blank falls back to
		// the server-side default (SUBNG_DEFAULT_CONFIG_URL).
		"留空用服务端默认",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("expected body to contain %q", expected)
		}
	}
}
