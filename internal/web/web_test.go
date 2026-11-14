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
		"isSubFormDirty",
		"dialog-shake",
		"subConfirmBox",
		"dialog-confirm-backdrop",
		"qrBox",
		"QRCode",
		"Shadowrocket 推荐",
		"需公网可访问",
		// The config input must tell users that leaving it blank falls back to
		// the server-side default (SUBNG_DEFAULT_CONFIG_URL).
		"留空用服务端默认",
		// The provider interval field is seconds and must send provider_interval;
		// `interval` means the client profile update interval in hours.
		"provider_interval=",
		// Provider mode changes which node processing applies, so the switch
		// must say what stops working before the user enables it.
		"id=\"providerHint\"",
		"emoji、改名、fdn、去重都不生效",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("expected body to contain %q", expected)
		}
	}
	if strings.Contains(body, "$('interval')") {
		t.Error("the provider interval field must not send interval= (that param is hours, not provider seconds)")
	}
}
