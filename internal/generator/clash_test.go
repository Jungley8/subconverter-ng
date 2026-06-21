package generator

import (
	"context"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
	"gopkg.in/yaml.v3"
)

type fakeFetcher map[string][]byte

func (f fakeFetcher) Get(_ context.Context, url string) ([]byte, error) {
	for k, v := range f {
		if strings.Contains(url, k) {
			return v, nil
		}
	}
	return nil, errNotFound
}

var errNotFound = &fetchErr{}

type fetchErr struct{}

func (e *fetchErr) Error() string { return "not found" }

func mkNodes() []*proxy.Proxy {
	a := proxy.New("ss", "🇭🇰 HK", "1.1.1.1", 8388)
	b := proxy.New("vmess", "🇺🇲 US", "2.2.2.2", 443)
	return []*proxy.Proxy{a, b}
}

func TestUnescapeUnicode(t *testing.T) {
	cases := []struct{ in, want string }{
		{`name: "\U0001F1ED\U0001F1F0 HK"`, `name: "🇭🇰 HK"`},
		{`x: "中文"`, `x: "中文"`},                 // BMP CJK
		{`path: "	tab"`, `path: "	tab"`},        // control char (<0x80) preserved
		{`p: "a\\Ufake"`, `p: "a\\Ufake"`},                // literal backslash preserved
	}
	for _, c := range cases {
		got := string(unescapeUnicode([]byte(c.in)))
		if got != c.want {
			t.Errorf("unescapeUnicode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestApplyNodeOptions(t *testing.T) {
	nodes := mkNodes()
	applyNodeOptions(nodes, Options{UDP: true, TFO: true, SkipCertVerify: true})
	for _, n := range nodes {
		if n.Clash["udp"] != true || n.Clash["tfo"] != true || n.Clash["skip-cert-verify"] != true {
			t.Errorf("node options not applied: %v", n.Clash)
		}
	}
}

func TestExpandRemoteRuleset(t *testing.T) {
	data := `# comment
; semicolon
// slash
DOMAIN-SUFFIX,google.com
IP-CIDR,8.8.8.8/32,no-resolve
payload:
  - 'DOMAIN,example.org'
DIRECT-SUFFIX,dash.cloudflare.com
GARBAGE,foo,bar
FINAL
`
	out, skipped := expandRemoteRuleset([]byte(data), "🚀 PROXY")
	joined := strings.Join(out, "\n")
	for _, want := range []string{
		"DOMAIN-SUFFIX,google.com,🚀 PROXY",
		"IP-CIDR,8.8.8.8/32,🚀 PROXY,no-resolve",
		"DOMAIN,example.org,🚀 PROXY",
		"MATCH,🚀 PROXY",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, out)
		}
	}
	// Unsupported rule types must be dropped (else mihomo rejects the config).
	if strings.Contains(joined, "DIRECT-SUFFIX") || strings.Contains(joined, "GARBAGE") {
		t.Errorf("unsupported rule types leaked into output: %v", out)
	}
	if len(skipped) != 2 {
		t.Errorf("skipped = %d, want 2 (DIRECT-SUFFIX, GARBAGE), got %v", len(skipped), skipped)
	}
}

func TestExpandInlineRule(t *testing.T) {
	if got, ok := expandInlineRule("FINAL", "G"); !ok || got != "MATCH,G" {
		t.Errorf("FINAL -> %q,%v", got, ok)
	}
	if got, ok := expandInlineRule("GEOIP,CN", "G"); !ok || got != "GEOIP,CN,G" {
		t.Errorf("GEOIP -> %q,%v", got, ok)
	}
	if _, ok := expandInlineRule("DIRECT-SUFFIX,x", "G"); ok {
		t.Error("unsupported inline rule type should be rejected")
	}
}

func TestGenerateClash_DefaultBase(t *testing.T) {
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups: []extconfig.ProxyGroup{
			{Name: "🚀 Select", Type: "select", Selectors: []string{".*", "[]DIRECT"}},
			{Name: "🇩🇪 DE", Type: "url-test", Selectors: []string{"(德|DE)"}, TestURL: "http://x/204", Interval: 300},
		},
		Rulesets: []extconfig.Ruleset{{Group: "🐟 Final", Inline: "FINAL"}},
	}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.NodeCount != 2 {
		t.Errorf("NodeCount = %d", res.NodeCount)
	}
	if len(res.EmptyGroups) != 1 || res.EmptyGroups[0] != "🇩🇪 DE" {
		t.Errorf("EmptyGroups = %v, want [🇩🇪 DE]", res.EmptyGroups)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(res.YAML, &doc); err != nil {
		t.Fatalf("invalid yaml: %v", err)
	}
	if doc["mixed-port"] == nil || doc["dns"] == nil {
		t.Error("default base skeleton missing")
	}
}

func TestGenerateClash_CustomRuleBase(t *testing.T) {
	base := `mixed-port: 1080
allow-lan: false
custom-key: keep-me
rules:
  - DOMAIN,preexisting,DIRECT
`
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ClashRuleBase:       "https://example.com/base.yml",
		OverwriteRules:      true,
		Rulesets:            []extconfig.Ruleset{{Group: "G", Inline: "FINAL"}},
	}
	f := fakeFetcher{"base.yml": []byte(base)}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(res.YAML, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["custom-key"] != "keep-me" || doc["mixed-port"] != 1080 {
		t.Errorf("custom base fields lost: %v", doc)
	}
	if doc["proxies"] == nil || doc["proxy-groups"] == nil {
		t.Error("proxies/groups not injected into custom base")
	}
	// OverwriteRules=true: preexisting rule replaced by generated MATCH,G.
	rules, _ := doc["rules"].([]any)
	if len(rules) != 1 || rules[0] != "MATCH,G" {
		t.Errorf("rules not overwritten: %v", rules)
	}
}

func TestFilterNodes_Include(t *testing.T) {
	cfg := extconfig.Parse([]byte("include_remarks=US\n"))
	out := filterNodes(mkNodes(), cfg)
	if len(out) != 1 || !strings.Contains(out[0].Name, "US") {
		t.Errorf("include filter failed: %+v", out)
	}
}
