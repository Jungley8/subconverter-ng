package generator

import (
	"context"
	"errors"
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
		{`x: "中文"`, `x: "中文"`},                                       // BMP CJK
		{`path: "	tab"`, `path: "	tab"`},                             // control char (<0x80) preserved
		{`p: "a\\Ufake"`, `p: "a\\Ufake"`},                           // literal backslash preserved
		{`key: "a\"b\U0001F1ED"`, `key: "a\"b🇭"`},                    // escaped quote stays in the scalar
		{`{note: "\U0001F1ED"}`, `{note: "🇭"}`},                      // flow mapping
		{`note: 'C:\u4e2d'`, `note: 'C:\u4e2d'`},                     // single-quoted: literal text
		{`note: 'a: "C:\u4e2d"'`, `note: 'a: "C:\u4e2d"'`},           // colon inside single quotes
		{`note: C:\u4e2d`, `note: C:\u4e2d`},                         // plain scalar: literal text
		{`note: a-"C:\u4e2d"`, `note: a-"C:\u4e2d"`},                 // quote inside a plain scalar
		{"# see \\u4e2d\n", "# see \\u4e2d\n"},                       // comment: literal text
		{"note: |\n  \"C:\\u4e2d\"\n", "note: |\n  \"C:\\u4e2d\"\n"}, // block scalar
		{"note: |\n  key: \"C:\\u4e2d\"\n", "note: |\n  key: \"C:\\u4e2d\"\n"},
		{"note: |\n  \"unclosed\npath: 'C:\\u4e2d'\n", "note: |\n  \"unclosed\npath: 'C:\\u4e2d'\n"},
		{"note: >\n  \"C:\\u4e2d\"\n", "note: >\n  \"C:\\u4e2d\"\n"}, // folded block
		{"note: >\n  key: \"C:\\u4e2d\"\n", "note: >\n  key: \"C:\\u4e2d\"\n"},
		{"note: |2\n  \"C:\\u4e2d\"\n", "note: |2\n  \"C:\\u4e2d\"\n"}, // indent indicator
		{"note: |2\n  key: \"C:\\u4e2d\"\n", "note: |2\n  key: \"C:\\u4e2d\"\n"},
		{"note: 'line one\n  \"C:\\u4e2d\" line two'\n", "note: 'line one\n  \"C:\\u4e2d\" line two'\n"},
		{"note: line one\n  \"C:\\u4e2d\" line two\n", "note: line one\n  \"C:\\u4e2d\" line two\n"},
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
	if err := applyNodeOptions(nodes, Options{RemoveEmoji: true}); err != nil {
		t.Fatal(err)
	}
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
	if err := applyNodeOptions(nodes, Options{RemoveEmoji: true, AddEmoji: true, EmojiRules: rules}); err != nil {
		t.Fatal(err)
	}
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
	if err := applyNodeOptions([]*proxy.Proxy{a}, Options{RenameRules: rules}); err != nil {
		t.Fatal(err)
	}
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
	if err := applyNodeOptions([]*proxy.Proxy{a}, Options{RenameRules: rules}); err != nil {
		t.Fatal(err)
	}
	if a.Name != "HK Premium" {
		t.Errorf("backref rename = %q, want 'HK Premium'", a.Name)
	}

	// Go-style $1 backref must also work.
	rules2 := CompileRenameRules([]string{`(\d+)x@$1`})
	b := proxy.New("ss", "10x node", "1.1.1.1", 8388)
	if err := applyNodeOptions([]*proxy.Proxy{b}, Options{RenameRules: rules2}); err != nil {
		t.Fatal(err)
	}
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
	if err := applyNodeOptions([]*proxy.Proxy{n}, Options{
		RemoveEmoji: true, RenameRules: renameRules, AddEmoji: true, EmojiRules: emojiRules,
	}); err != nil {
		t.Fatal(err)
	}
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
	if err := applyNodeOptions(nodes, Options{UDP: true, TFO: true, SkipCertVerify: true}); err != nil {
		t.Fatal(err)
	}
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

func TestParseInlineRuleParams(t *testing.T) {
	// TYPE,VALUE[,FLAG]: the value is the second field and a third field is the
	// flag. Anything past the flag, or a missing value, is not rule-shaped.
	cases := []struct {
		body  string
		group string
		want  Rule
	}{
		{"GEOIP,CN", "G", Rule{Type: "GEOIP", Value: "CN", Group: "G"}},
		{"GEOIP,PRIVATE,no-resolve", "G", Rule{Type: "GEOIP", Value: "PRIVATE", Group: "G", Flag: "no-resolve"}},
		{"GEOIP,CN,no-resolve", "G", Rule{Type: "GEOIP", Value: "CN", Group: "G", Flag: "no-resolve"}},
		{"IP-CIDR,1.2.3.0/24,no-resolve", "G", Rule{Type: "IP-CIDR", Value: "1.2.3.0/24", Group: "G", Flag: "no-resolve"}},
		{"DST-PORT,443", "G", Rule{Type: "DST-PORT", Value: "443", Group: "G"}},
		// Logical matchers keep their comma-filled remainder as the value.
		{"AND,((DOMAIN,a),(NETWORK,udp))", "G", Rule{Type: "AND", Value: "((DOMAIN,a),(NETWORK,udp))", Group: "G"}},
	}
	for _, c := range cases {
		got, ok := parseInlineRule(c.body, c.group)
		if !ok || got != c.want {
			t.Errorf("parseInlineRule(%q) = %+v,%v, want %+v", c.body, got, ok, c.want)
		}
	}
	for _, body := range []string{"GEOIP,PRIVATE,policy,no-resolve", "IP-CIDR,1.2.3.0/24,no-resolve,src", "DOMAIN-SUFFIX,"} {
		if r, ok := parseInlineRule(body, "G"); ok {
			t.Errorf("parseInlineRule(%q) = %+v, want rejected", body, r)
		}
	}
	// The clash line re-emits the parameter after the group.
	r, _ := parseInlineRule("GEOIP,PRIVATE,no-resolve", "G")
	if line, ok := formatClashRule(r); !ok || line != "GEOIP,PRIVATE,G,no-resolve" {
		t.Errorf("formatClashRule = %q,%v, want GEOIP,PRIVATE,G,no-resolve", line, ok)
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
	out, _, err := filterNodes(mkNodes(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || !strings.Contains(out[0].Name, "US") {
		t.Errorf("include filter failed: %+v", out)
	}
}

func TestGenerateClash_PCREExclusionGroup(t *testing.T) {
	nodes := []*proxy.Proxy{
		proxy.New("ss", "香港 IPLC 01", "1.1.1.1", 8388),
		proxy.New("ss", "台湾 HiNet 01", "1.1.1.1", 8389),
		proxy.New("ss", "测试 节点", "1.1.1.1", 8390),
		proxy.New("ss", "新加坡 AWS 01", "1.1.1.1", 8391),
		proxy.New("ss", "日本 AWS 01", "1.1.1.1", 8392),
	}
	cfg := &extconfig.Config{ProxyGroups: []extconfig.ProxyGroup{{
		Name: "AI节点", Type: "url-test",
		Selectors: []string{`^(?!.*(港|(?i)HK|台|(?i)TW|测试|(?i)test)).*$`},
		TestURL:   "http://www.gstatic.com/generate_204",
		Interval:  300,
	}}}
	res, err := GenerateClash(context.Background(), nodes, cfg, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Groups []struct {
			Name    string   `yaml:"name"`
			Proxies []string `yaml:"proxies"`
		} `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Groups) != 1 {
		t.Fatalf("groups = %d, want 1", len(doc.Groups))
	}
	got := doc.Groups[0].Proxies
	want := []string{"新加坡 AWS 01", "日本 AWS 01"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("AI节点 = %v, want %v", got, want)
	}
	if len(res.EmptyGroups) != 0 {
		t.Errorf("EmptyGroups = %v, want none", res.EmptyGroups)
	}
}

func TestGenerateClash_InvalidSelector(t *testing.T) {
	cfg := &extconfig.Config{ProxyGroups: []extconfig.ProxyGroup{{
		Name: "Bad", Type: "select", Selectors: []string{`([`},
	}}}
	_, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{}, Options{})
	if !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("err = %v, want ErrConfigInvalid", err)
	}
	if !strings.Contains(err.Error(), "Bad") || !strings.Contains(err.Error(), "([") {
		t.Errorf("error should name the group and selector: %v", err)
	}
}

func TestGenerateClash_UnknownAttributeSelector(t *testing.T) {
	cfg := &extconfig.Config{ProxyGroups: []extconfig.ProxyGroup{{
		Name: "ByType", Type: "select", Selectors: []string{`!!NOPE=ss`},
	}}}
	_, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{}, Options{})
	if !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("err = %v, want ErrConfigInvalid", err)
	}
	if !strings.Contains(err.Error(), "!!NOPE") {
		t.Errorf("error should name the selector: %v", err)
	}
}

func TestGenerateClash_ProviderAttributeSelector(t *testing.T) {
	cfg := extconfig.Parse([]byte("[custom]\ncustom_proxy_group=ByType`select`!!TYPE=ss\n"))
	opts := Options{ProviderMode: true, ProviderURLs: []string{"https://airport.example/sub"}}
	_, err := GenerateClashProvider(context.Background(), nil, cfg, fakeFetcher{}, opts)
	if !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("err = %v, want ErrConfigInvalid", err)
	}
	if !strings.Contains(err.Error(), "provider filter") {
		t.Errorf("error should explain the provider filter limit: %v", err)
	}
}

func TestGenerateClash_CustomRuleBaseKeepsLayout(t *testing.T) {
	base := `# hand-written base
mixed-port: 7890
profile:
  store-selected: true
dns:
  fake-ip-filter:
    - "+.lan"
tcp-concurrent: true
`
	// Extra keys make the readable order differ from the alphabetical one.
	node := proxy.New("ss", "🇭🇰 HK", "1.1.1.1", 8388)
	node.Set("cipher", "aes-256-gcm")
	node.Set("password", "pass")
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ClashRuleBase:       "https://example.com/base.yml",
		Rulesets:            []extconfig.Ruleset{{Group: "G", Inline: "FINAL"}},
	}
	res, err := GenerateClash(context.Background(), []*proxy.Proxy{node}, cfg, fakeFetcher{"base.yml": []byte(base)}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	for _, want := range []string{
		"# hand-written base\n",
		"\n  store-selected: true\n",
		`    - "+.lan"` + "\n",
		"proxies:\n  - name: \"🇭🇰 HK\"\n    type: ss\n    server: 1.1.1.1\n    port: 8388\n    cipher: aes-256-gcm\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// The base's own key order survives; generated sections are appended.
	order := []string{"mixed-port: 7890", "profile:", "dns:", "tcp-concurrent: true", "proxies:", "proxy-groups:", "rules:"}
	last := -1
	for _, key := range order {
		i := strings.Index(out, key)
		if i < 0 {
			t.Fatalf("output missing %q:\n%s", key, out)
		}
		if i < last {
			t.Errorf("%q moved out of order:\n%s", key, out)
		}
		last = i
	}
}

func TestGenerateClash_CustomRuleBaseErrors(t *testing.T) {
	cases := []struct {
		name   string
		base   []byte
		wantIs error
		want   string
	}{
		{"missing", nil, nil, "fetch clash_rule_base"},
		{"not a mapping", []byte("- a\n- b\n"), ErrConfigInvalid, "YAML mapping"},
		{"invalid yaml", []byte("a: [\n"), ErrConfigInvalid, "not valid YAML"},
	}
	for _, c := range cases {
		f := fakeFetcher{}
		if c.base != nil {
			f["base.yml"] = c.base
		}
		cfg := &extconfig.Config{ClashRuleBase: "https://example.com/base.yml"}
		_, err := GenerateClash(context.Background(), mkNodes(), cfg, f, Options{})
		if err == nil {
			t.Errorf("%s: expected error", c.name)
			continue
		}
		if c.wantIs != nil && !errors.Is(err, c.wantIs) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.wantIs)
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want substring %q", c.name, err, c.want)
		}
	}
}

func TestGenerateClash_CustomRuleBaseTailscalePrepend(t *testing.T) {
	base := "rules:\n  - MATCH,G\n"
	cfg := &extconfig.Config{
		ClashRuleBase:  "https://example.com/base.yml",
		OverwriteRules: false,
	}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{Tailscale: true})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	ts := strings.Index(out, "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve")
	match := strings.Index(out, "MATCH,G")
	if ts < 0 || match < 0 || ts > match {
		t.Errorf("tailscale rules not prepended before base rules:\n%s", out)
	}
}

func TestGenerateClash_CustomRuleBaseNullRules(t *testing.T) {
	base := "rules:\nproxies:\n"
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ClashRuleBase:       "https://example.com/base.yml",
		Rulesets:            []extconfig.Ruleset{{Group: "G", Inline: "FINAL"}},
	}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 1 || doc.Rules[0] != "MATCH,G" {
		t.Errorf("rules = %v, want the generated [MATCH,G]", doc.Rules)
	}
}

func TestGenerateClash_CustomRuleBaseAliasRules(t *testing.T) {
	base := "x-rules: &r\n  - MATCH,BASE\nrules: *r\n"
	cfg := &extconfig.Config{
		ClashRuleBase: "https://example.com/base.yml",
	}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{Tailscale: true})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
		"IP-CIDR,fd7a:115c:a1e0::/48,DIRECT,no-resolve",
		"MATCH,BASE",
	}
	if len(doc.Rules) != len(want) {
		t.Fatalf("rules = %v, want %v", doc.Rules, want)
	}
	for i := range want {
		if doc.Rules[i] != want[i] {
			t.Errorf("rules[%d] = %q, want %q", i, doc.Rules[i], want[i])
		}
	}
}

func TestGenerateClash_CustomRuleBaseMergedRules(t *testing.T) {
	base := "defaults: &d\n  rules:\n    - MATCH,MERGED\n<<: *d\n"
	cfg := &extconfig.Config{ClashRuleBase: "https://example.com/base.yml"}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 1 || doc.Rules[0] != "MATCH,MERGED" {
		t.Errorf("rules = %v, want the merged [MATCH,MERGED]", doc.Rules)
	}
}

func TestGenerateClash_CustomRuleBaseDuplicateMergeKey(t *testing.T) {
	base := "a: &a\n  x: 1\nb: &b\n  y: 2\n<<: *a\n<<: *b\n"
	cfg := &extconfig.Config{ClashRuleBase: "https://example.com/base.yml"}
	_, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{})
	if !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("err = %v, want ErrConfigInvalid", err)
	}
}

func TestGenerateClash_CustomRuleBaseDuplicateKey(t *testing.T) {
	base := "rules:\n  - MATCH,ONE\nrules:\n  - MATCH,TWO\n"
	cfg := &extconfig.Config{ClashRuleBase: "https://example.com/base.yml", OverwriteRules: true}
	_, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{})
	if !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("err = %v, want ErrConfigInvalid", err)
	}
	if !strings.Contains(err.Error(), "rules") {
		t.Errorf("error should name the key: %v", err)
	}
}

func TestGenerateClash_CustomRuleBaseKeepsRuleProviders(t *testing.T) {
	base := "rule-providers:\n  base-prov:\n    type: http\n    url: https://example.com/p.yaml\nrules:\n  - RULE-SET,base-prov,G\n"
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ClashRuleBase:       "https://example.com/base.yml",
		Rulesets:            []extconfig.Ruleset{{Group: "G", URL: "https://rules.example.com/a.list"}},
	}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{UseRuleProviders: true})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	if !strings.Contains(out, "base-prov:") {
		t.Errorf("base rule-providers dropped:\n%s", out)
	}
	if strings.Contains(out, "provider_1:") {
		t.Errorf("generated providers injected while base rules kept:\n%s", out)
	}
}

func TestGenerateClash_RenamePCRERule(t *testing.T) {
	cfg := &extconfig.Config{RenameRules: []string{`(?<=]) (HK)@_$1`}}
	opts := Options{RenameRules: CompileRenameRules(cfg.RenameRules)}
	res, err := GenerateClash(context.Background(), []*proxy.Proxy{proxy.New("ss", "[ss] HK", "1.1.1.1", 8388)}, cfg, fakeFetcher{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	if !strings.Contains(out, "[ss]_HK") {
		t.Errorf("PCRE rename not applied:\n%s", out)
	}
}

func TestGenerateClash_CustomRuleBaseAliasToNull(t *testing.T) {
	base := "x: &r\nrules: *r\n"
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ClashRuleBase:       "https://example.com/base.yml",
		Rulesets:            []extconfig.Ruleset{{Group: "G", Inline: "FINAL"}},
	}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 1 || doc.Rules[0] != "MATCH,G" {
		t.Errorf("rules = %v, want the generated [MATCH,G]", doc.Rules)
	}
}

func TestGenerateClash_CustomRuleBaseQuotedMergeKey(t *testing.T) {
	base := "\"<<\":\n  rules:\n    - MATCH,FAKE\n"
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ClashRuleBase:       "https://example.com/base.yml",
		Rulesets:            []extconfig.Ruleset{{Group: "G", Inline: "FINAL"}},
	}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 1 || doc.Rules[0] != "MATCH,G" {
		t.Errorf("rules = %v, want the generated [MATCH,G]; a quoted key is not a merge", doc.Rules)
	}
}

func TestGenerateClash_CustomRuleBaseChainedMerge(t *testing.T) {
	base := "a: &a\n  rules:\n    - MATCH,A\nb: &b\n  <<: *a\n<<: *b\n"
	cfg := &extconfig.Config{ClashRuleBase: "https://example.com/base.yml"}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 1 || doc.Rules[0] != "MATCH,A" {
		t.Errorf("rules = %v, want the chained merged [MATCH,A]", doc.Rules)
	}
}

func TestGenerateClash_CustomRuleBaseNullOverridesMerge(t *testing.T) {
	base := "a: &a\n  rules:\n    - MATCH,MERGED\n<<: *a\nrules:\n"
	cfg := &extconfig.Config{ClashRuleBase: "https://example.com/base.yml"}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{Tailscale: true})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 2 {
		t.Fatalf("rules = %v, want only the two tailscale lines", doc.Rules)
	}
	for _, r := range doc.Rules {
		if r == "MATCH,MERGED" {
			t.Errorf("explicit null rules must not fall back to the merge: %v", doc.Rules)
		}
	}
}

func TestGenerateClash_CustomRuleBaseKeyCommentStays(t *testing.T) {
	base := "mixed-port: 7890\nrules: # keep me\nproxies:\n"
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ClashRuleBase:       "https://example.com/base.yml",
		OverwriteRules:      true,
	}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	if strings.Contains(out, "keep me") {
		t.Errorf("key comment leaked onto another key:\n%s", out)
	}
}

func TestGenerateClash_CustomRuleBaseMergeNullShadowsLaterSource(t *testing.T) {
	base := "a: &a\n  rules:\nb: &b\n  rules:\n    - MATCH,B\n<<: [*a, *b]\n"
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ClashRuleBase:       "https://example.com/base.yml",
		Rulesets:            []extconfig.Ruleset{{Group: "G", Inline: "FINAL"}},
	}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 1 || doc.Rules[0] != "MATCH,G" {
		t.Errorf("rules = %v, want [MATCH,G]: the earlier null source wins", doc.Rules)
	}
}

func TestGenerateClash_CustomRuleBaseMixedMergeDuplicates(t *testing.T) {
	base := "<<: {a: 1}\n\"<<\": {b: 2}\n"
	cfg := &extconfig.Config{ClashRuleBase: "https://example.com/base.yml"}
	_, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{})
	if !errors.Is(err, ErrConfigInvalid) {
		t.Fatalf("err = %v, want ErrConfigInvalid", err)
	}
}
