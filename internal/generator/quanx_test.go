package generator

import (
	"context"
	"strings"
	"testing"
)

func TestGenerateQuanX(t *testing.T) {
	cfg, f := surgeSampleConfig() // Proxy select(.*), PROXY.list + GEOIP,CN + FINAL
	res, err := GenerateQuanX(context.Background(), surgeNodes(t), cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)

	for _, want := range []string{
		"[server_local]",
		"shadowsocks=1.2.3.4:8388, method=aes-256-gcm, password=pass",
		"vmess=jp.example.com:443, method=chacha20-ietf-poly1305, password=uuid-1, obfs=wss, obfs-uri=/path, obfs-host=jp.example.com, tls-host=jp.example.com, tls-verification=true",
		"trojan=sg.example.com:443, password=pass, over-tls=true, tls-host=sg.example.com, tls-verification=true",
		"vless=us.example.com:443, method=none, password=uuid-2",
		"tag=HK",
		"[policy]",
		"static=Proxy",
		"[filter_local]",
		"host-suffix, google.com, Proxy",
		"geoip, cn, Proxy",
		"final, Proxy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("quanx output missing %q\n---\n%s", want, out)
		}
	}
	// GEOSITE (from PROXY.list) is not a QuanX keyword: dropped.
	if strings.Contains(out, "geosite") {
		t.Error("GEOSITE should be dropped from quanx rules")
	}
	if len(res.SkippedRules) == 0 {
		t.Error("expected GEOSITE in SkippedRules")
	}
}
