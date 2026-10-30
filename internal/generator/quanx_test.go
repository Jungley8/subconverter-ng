package generator

import (
	"context"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
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

func TestGenerateQuanX_Enhancements(t *testing.T) {
	nodes := surgeNodes(t)
	// add a reality node
	p := proxy.New("vless", "US-REALITY", "us.example.com", 443)
	p.Set("uuid", "uuid-reality")
	p.SetRaw("tls", true)
	p.Set("servername", "www.microsoft.com")
	p.Set("reality-opts", map[string]any{"public-key": "PUBKEY", "short-id": "sid"})
	nodes = append(nodes, p)

	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups:         []extconfig.ProxyGroup{{Name: "Proxy", Type: "select", Selectors: []string{".*"}}},
		Rulesets: []extconfig.Ruleset{
			{Group: "Proxy", Inline: "DST-PORT,443"},
			{Group: "Proxy", Inline: "SRC-PORT,1080"},
			{Group: "Proxy", Inline: "IP6-CIDR,2001:db8::/32"},
			{Group: "Proxy", Inline: "FINAL"},
		},
	}

	res, err := GenerateQuanX(context.Background(), nodes, cfg, fakeFetcher{}, Options{TFO: true})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)

	// fast-open
	if !strings.Contains(out, "fast-open=true") {
		t.Errorf("quanx missing fast-open=true: %s", out)
	}

	// Reality
	if !strings.Contains(out, "public-key=PUBKEY, short-id=sid") {
		t.Errorf("quanx missing reality fields: %s", out)
	}

	// Filter rules: dest-port, src-port, ip6-cidr
	for _, want := range []string{
		"dest-port, 443, Proxy",
		"src-port, 1080, Proxy",
		"ip6-cidr, 2001:db8::/32, Proxy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("quanx rules missing %q\n---\n%s", want, out)
		}
	}
}

func TestGenerateQuanX_ListOnly(t *testing.T) {
	nodes := surgeNodes(t)
	res, err := GenerateQuanX(context.Background(), nodes, &extconfig.Config{}, fakeFetcher{}, Options{ListOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	if !strings.HasPrefix(out, "[server_local]\n") {
		t.Errorf("quanx list must start with [server_local]: %s", out)
	}
	if strings.Contains(out, "[policy]") || strings.Contains(out, "[filter_local]") {
		t.Errorf("quanx list must omit policy/filter: %s", out)
	}
}
