package generator

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/parser"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// surgeNodes parses a small multi-protocol subscription into nodes.
func surgeNodes(t *testing.T) []*proxy.Proxy {
	t.Helper()
	links := []string{
		"ss://" + b64("aes-256-gcm:pass") + "@1.2.3.4:8388#HK",
		"vmess://" + b64(`{"v":"2","ps":"JP","add":"jp.example.com","port":"443","id":"uuid-1","aid":"0","scy":"auto","net":"ws","host":"jp.example.com","path":"/path","tls":"tls","sni":"jp.example.com"}`),
		"trojan://pass@sg.example.com:443?sni=sg.example.com#SG",
		"vless://uuid-2@us.example.com:443?encryption=none&security=tls&sni=us.example.com&type=tcp#US",
	}
	sub := []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
	nodes, _, err := parser.Parse(sub)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return nodes
}

func surgeSampleConfig() (*extconfig.Config, fakeFetcher) {
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups:         []extconfig.ProxyGroup{{Name: "Proxy", Type: "select", Selectors: []string{".*"}}},
		Rulesets: []extconfig.Ruleset{
			{Group: "Proxy", URL: "https://rules/PROXY.list"},
			{Group: "Proxy", Inline: "GEOIP,CN"},
			{Group: "Proxy", Inline: "FINAL"},
		},
	}
	f := fakeFetcher{"PROXY.list": []byte("DOMAIN-SUFFIX,google.com\nGEOSITE,google\n")}
	return cfg, f
}

func TestGenerateSurge(t *testing.T) {
	cfg, f := surgeSampleConfig()
	res, err := GenerateSurge(context.Background(), surgeNodes(t), cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)

	for _, want := range []string{
		"[Proxy]",
		"HK = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=pass",
		"JP = vmess, jp.example.com, 443, username=uuid-1, vmess-aead=true, tls=true, sni=jp.example.com, ws=true, ws-path=/path, ws-headers=Host:jp.example.com",
		"SG = trojan, sg.example.com, 443, password=pass, sni=sg.example.com",
		"[Proxy Group]",
		"Proxy = select,",
		"[Rule]",
		"DOMAIN-SUFFIX,google.com,Proxy",
		"GEOIP,CN,Proxy",
		"FINAL,Proxy",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("surge output missing %q\n---\n%s", want, out)
		}
	}

	// VLESS is unsupported by Surge: skipped, not emitted.
	if strings.Contains(out, "US = vless") {
		t.Error("surge should not emit vless")
	}
	if len(res.SkippedNodes) != 1 || !strings.Contains(res.SkippedNodes[0], "vless") {
		t.Errorf("SkippedNodes = %v, want one vless entry", res.SkippedNodes)
	}
	// GEOSITE is not a Surge rule type: dropped.
	if strings.Contains(out, "GEOSITE") {
		t.Error("GEOSITE should be dropped from surge rules")
	}
	if len(res.SkippedRules) == 0 {
		t.Error("expected GEOSITE in SkippedRules")
	}
	if res.ContentType != ctText {
		t.Errorf("content type = %q", res.ContentType)
	}
}

func TestGenerateShadowrocket_VLESS(t *testing.T) {
	cfg, f := surgeSampleConfig()
	res, err := GenerateShadowrocket(context.Background(), surgeNodes(t), cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	if !strings.Contains(out, "US = vless, us.example.com, 443, username=uuid-2, tls=true, sni=us.example.com") {
		t.Errorf("shadowrocket should emit vless line:\n%s", out)
	}
}

func TestGenerateLoon(t *testing.T) {
	cfg, f := surgeSampleConfig()
	res, err := GenerateLoon(context.Background(), surgeNodes(t), cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	if !strings.Contains(out, `HK = Shadowsocks,1.2.3.4,8388,aes-256-gcm,"pass"`) {
		t.Errorf("loon ss line wrong:\n%s", out)
	}
	if !strings.Contains(out, `SG = trojan,sg.example.com,443,"pass",tls-name=sg.example.com`) {
		t.Errorf("loon trojan line wrong:\n%s", out)
	}
	if !strings.Contains(out, `US = VLESS,us.example.com,443,"uuid-2"`) {
		t.Errorf("loon vless line wrong:\n%s", out)
	}
}
