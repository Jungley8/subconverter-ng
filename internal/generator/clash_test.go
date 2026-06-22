package generator

import (
	"context"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/emoji"
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
		{`x: "中文"`, `x: "中文"`},             // BMP CJK
		{`path: "	tab"`, `path: "	tab"`},   // control char (<0x80) preserved
		{`p: "a\\Ufake"`, `p: "a\\Ufake"`}, // literal backslash preserved
	}
	for _, c := range cases {
		got := string(unescapeUnicode([]byte(c.in)))
		if got != c.want {
			t.Errorf("unescapeUnicode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestApplyNodeOptions_RemoveEmoji(t *testing.T) {
	nodes := mkNodes() // names: "🇭🇰 HK", "🇺🇲 US"
	applyNodeOptions(nodes, Options{RemoveEmoji: true})
	if nodes[0].Name != "HK" || nodes[0].Clash["name"] != "HK" {
		t.Errorf("node[0] not stripped/synced: name=%q clash=%v", nodes[0].Name, nodes[0].Clash["name"])
	}
	if nodes[1].Name != "US" {
		t.Errorf("node[1] = %q, want US", nodes[1].Name)
	}
}

func TestApplyNodeOptions_RemoveThenAddEmoji(t *testing.T) {
	rules := emoji.ParseRules([]string{`(?i:HK|香港|港),🇭🇰`, `(?i:US|美国),🇺🇸`})
	nodes := mkNodes() // "🇭🇰 HK", "🇺🇲 US" (note US carries the wrong 🇺🇲 flag)
	applyNodeOptions(nodes, Options{RemoveEmoji: true, AddEmoji: true, EmojiRules: rules})
	if nodes[0].Name != "🇭🇰 HK" {
		t.Errorf("node[0] = %q, want '🇭🇰 HK'", nodes[0].Name)
	}
	// US started with 🇺🇲; remove+add normalizes it to 🇺🇸.
	if nodes[1].Name != "🇺🇸 US" {
		t.Errorf("node[1] = %q, want '🇺🇸 US'", nodes[1].Name)
	}
}

func TestApplyNodeOptions_Rename(t *testing.T) {
	// Simple substring rename: 美国 -> US.
	rules := CompileRenameRules([]string{`美国@US`})
	a := proxy.New("ss", "香港 美国 节点", "1.1.1.1", 8388)
	applyNodeOptions([]*proxy.Proxy{a}, Options{RenameRules: rules})
	if a.Name != "香港 US 节点" || a.Clash["name"] != "香港 US 节点" {
		t.Errorf("rename failed: name=%q clash=%v", a.Name, a.Clash["name"])
	}
}

func TestCompileRenameRules_Backref(t *testing.T) {
	// subconverter-style \1 backref must work like Go's $1.
	rules := CompileRenameRules([]string{`\[(.+?)\]@\1`})
	if len(rules) != 1 {
		t.Fatalf("expected 1 compiled rule, got %d", len(rules))
	}
	a := proxy.New("ss", "[HK] Premium", "1.1.1.1", 8388)
	applyNodeOptions([]*proxy.Proxy{a}, Options{RenameRules: rules})
	if a.Name != "HK Premium" {
		t.Errorf("backref rename = %q, want 'HK Premium'", a.Name)
	}

	// Go-style $1 backref must also work.
	rules2 := CompileRenameRules([]string{`(\d+)x@$1`})
	b := proxy.New("ss", "10x node", "1.1.1.1", 8388)
	applyNodeOptions([]*proxy.Proxy{b}, Options{RenameRules: rules2})
	if b.Name != "10 node" {
		t.Errorf("dollar backref rename = %q, want '10 node'", b.Name)
	}

	// Empty replacement is valid; entries without "@" or with a bad pattern are skipped.
	rules3 := CompileRenameRules([]string{`xxx@`, `no-at-sign`, `(@whatever`})
	if len(rules3) != 1 {
		t.Fatalf("expected 1 valid rule (empty-replace), got %d", len(rules3))
	}
}

func TestApplyNodeOptions_RenameOrderBetweenEmoji(t *testing.T) {
	// Order: remove emoji -> rename -> add emoji. Renaming "US"->"美国" should
	// then let the add-emoji rule for 美国 attach the correct flag.
	emojiRules := emoji.ParseRules([]string{`(?i:US|美国),🇺🇸`})
	renameRules := CompileRenameRules([]string{`US@美国`})
	n := proxy.New("vmess", "🇨🇳 US", "2.2.2.2", 443) // wrong flag, name "US"
	applyNodeOptions([]*proxy.Proxy{n}, Options{
		RemoveEmoji: true, RenameRules: renameRules, AddEmoji: true, EmojiRules: emojiRules,
	})
	if n.Name != "🇺🇸 美国" {
		t.Errorf("name = %q, want '🇺🇸 美国'", n.Name)
	}
}

func TestGenerateClash_RuleProviders(t *testing.T) {
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups: []extconfig.ProxyGroup{
			{Name: "🚀 Proxy", Type: "select", Selectors: []string{".*"}},
		},
		Rulesets: []extconfig.Ruleset{
			{Group: "🚀 Proxy", URL: "https://example.com/rules/proxy.list"},
			{Group: "🚀 Proxy", URL: "https://example.com/rules/proxy.list"}, // dup URL+group -> one provider, one RULE-SET
			{Group: "🎯 Direct", URL: "https://example.com/rules/direct.list"},
			{Group: "🐟 Final", Inline: "GEOIP,CN"},
			{Group: "🐟 Final", Inline: "FINAL"},
		},
	}
	// fakeFetcher is empty: rule-providers mode must NOT fetch the rulesets.
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{}, Options{UseRuleProviders: true})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		RuleProviders map[string]map[string]any `yaml:"rule-providers"`
		Rules         []string                  `yaml:"rules"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("invalid yaml: %v", err)
	}
	// Two distinct URLs -> two providers.
	if len(doc.RuleProviders) != 2 {
		t.Fatalf("rule-providers count = %d, want 2: %v", len(doc.RuleProviders), doc.RuleProviders)
	}
	for name, p := range doc.RuleProviders {
		if p["type"] != "http" || p["behavior"] != "classical" {
			t.Errorf("provider %q wrong type/behavior: %v", name, p)
		}
		if p["url"] == nil || p["format"] != "text" {
			t.Errorf("provider %q missing url/format: %v", name, p)
		}
	}
	joined := strings.Join(doc.Rules, "\n")
	for _, want := range []string{
		"RULE-SET,provider_1,🚀 Proxy",
		"RULE-SET,provider_2,🎯 Direct",
		"GEOIP,CN,🐟 Final", // inline kept as a direct rule
		"MATCH,🐟 Final",    // []FINAL still present
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in rules: %v", want, doc.Rules)
		}
	}
	// The dup (URL,group) must yield exactly one RULE-SET line.
	if got := strings.Count(joined, "RULE-SET,provider_1,🚀 Proxy"); got != 1 {
		t.Errorf("RULE-SET,provider_1 appears %d times, want 1", got)
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
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
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
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
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
