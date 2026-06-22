package convert

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/generator"
	"gopkg.in/yaml.v3"
)

// fakeFetcher serves canned bodies keyed by a substring of the requested URL.
type fakeFetcher map[string][]byte

func (f fakeFetcher) Get(_ context.Context, url string) ([]byte, error) {
	for key, body := range f {
		if strings.Contains(url, key) {
			return body, nil
		}
	}
	return nil, &notFound{url}
}

type notFound struct{ url string }

func (e *notFound) Error() string { return "no canned body for " + e.url }

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// sampleSubscription returns a base64 subscription covering all six protocols
// plus one node that must be filtered out by exclude_remarks.
func sampleSubscription() []byte {
	vmessJSON := `{"v":"2","ps":"🇯🇵 JP-Test","add":"jp.example.com","port":"443","id":"uuid-1","aid":"0","scy":"auto","net":"ws","host":"jp.example.com","path":"/path","tls":"tls","sni":"jp.example.com"}`
	links := []string{
		"ss://" + b64("aes-256-gcm:pass") + "@1.2.3.4:8388#🇭🇰 HK-Test",
		"vmess://" + b64(vmessJSON),
		"vless://uuid-2@us.example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=ab&flow=xtls-rprx-vision&type=tcp#🇺🇲 US-Test",
		"trojan://pass@sg.example.com:443?sni=sg.example.com&type=ws&host=sg.example.com&path=/tj#🇸🇬 SG-Test",
		"hysteria2://authpass@hk2.example.com:443?sni=hk2.example.com&insecure=1&obfs=salamander&obfs-password=xyz#🇭🇰 HK2-Test",
		"tuic://uuid-3:tpass@tw.example.com:443?congestion_control=bbr&alpn=h3&sni=tw.example.com#🇨🇳 TW-Test",
		"ss://" + b64("aes-256-gcm:pass") + "@9.9.9.9:8388#套餐到期2099", // excluded
	}
	return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
}

const sampleINI = `[custom]
ruleset=🎯 全球直连,[]GEOIP,CN
ruleset=🐟 漏网之鱼,[]FINAL
ruleset=🚀 节点选择,https://rules.example.com/PROXY.list
custom_proxy_group=🚀 节点选择` + "`select`" + `[]♻️ 自动选择` + "`" + `[]🇭🇰 香港节点` + "`" + `[]DIRECT
custom_proxy_group=♻️ 自动选择` + "`url-test`" + `.*` + "`" + `http://www.gstatic.com/generate_204` + "`" + `300,,50
custom_proxy_group=🇭🇰 香港节点` + "`url-test`" + `(港|HK|Hong Kong)` + "`" + `http://www.gstatic.com/generate_204` + "`" + `300,,50
custom_proxy_group=🇺🇲 美国节点` + "`url-test`" + `(美|US)` + "`" + `http://www.gstatic.com/generate_204` + "`" + `300,,150
custom_proxy_group=🇩🇪 德国节点` + "`url-test`" + `(德|DE)` + "`" + `http://www.gstatic.com/generate_204` + "`" + `300,,50
exclude_remarks=(到期|过期|官网)
enable_rule_generator=true
overwrite_original_rules=true
`

const samplePROXYList = `# a comment
DOMAIN-SUFFIX,google.com
DOMAIN-KEYWORD,google
IP-CIDR,8.8.8.8/32,no-resolve
`

func runSample(t *testing.T) map[string]any {
	t.Helper()
	f := fakeFetcher{
		"client/subscribe": sampleSubscription(),
		"config.init":      []byte(sampleINI),
		"PROXY.list":       []byte(samplePROXYList),
	}
	req := Request{
		Target:    "clash",
		SubURLs:   []string{"https://airport.example.com/api/v1/client/subscribe?token=x"},
		ConfigURL: "https://github.com/x/config.init",
	}
	data, diag, err := Run(context.Background(), f, req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if diag.NodeCount != 6 {
		t.Fatalf("NodeCount = %d, want 6 (one node should be excluded)", diag.NodeCount)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output is not valid YAML: %v", err)
	}
	return doc
}

func TestConvertProxies(t *testing.T) {
	doc := runSample(t)
	proxies, _ := doc["proxies"].([]any)
	if len(proxies) != 6 {
		t.Fatalf("proxies len = %d, want 6", len(proxies))
	}
	types := map[string]bool{}
	for _, p := range proxies {
		m, _ := p.(map[string]any)
		types[m["type"].(string)] = true
	}
	for _, want := range []string{"ss", "vmess", "vless", "trojan", "hysteria2", "tuic"} {
		if !types[want] {
			t.Errorf("missing proxy type %q", want)
		}
	}
}

func TestConvertGroups(t *testing.T) {
	doc := runSample(t)
	groups, _ := doc["proxy-groups"].([]any)
	byName := map[string]map[string]any{}
	for _, g := range groups {
		m, _ := g.(map[string]any)
		byName[m["name"].(string)] = m
	}

	hk := byName["🇭🇰 香港节点"]
	if hk == nil {
		t.Fatal("missing 🇭🇰 香港节点 group")
	}
	hkProxies := toStrings(hk["proxies"])
	if !contains(hkProxies, "🇭🇰 HK-Test") || !contains(hkProxies, "🇭🇰 HK2-Test") {
		t.Errorf("HK group should match both HK nodes, got %v", hkProxies)
	}

	// 🇩🇪 德国节点 matches no nodes -> must be filled with DIRECT to stay valid.
	de := byName["🇩🇪 德国节点"]
	if de == nil || !contains(toStrings(de["proxies"]), "DIRECT") {
		t.Errorf("empty group should fall back to DIRECT, got %v", de)
	}

	// select group keeps its []literal references.
	sel := toStrings(byName["🚀 节点选择"]["proxies"])
	if !contains(sel, "♻️ 自动选择") || !contains(sel, "DIRECT") {
		t.Errorf("select group lost literal refs, got %v", sel)
	}
}

func TestConvertRules(t *testing.T) {
	doc := runSample(t)
	rules := toStrings(doc["rules"])
	joined := strings.Join(rules, "\n")
	for _, want := range []string{
		"GEOIP,CN,🎯 全球直连",
		"MATCH,🐟 漏网之鱼",
		"DOMAIN-SUFFIX,google.com,🚀 节点选择",
		"IP-CIDR,8.8.8.8/32,🚀 节点选择,no-resolve",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing rule %q", want)
		}
	}
}

// b64Sub wraps one or more node share-links into a base64 subscription body.
func b64Sub(links ...string) []byte {
	return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
}

func TestRun_InsertURL(t *testing.T) {
	ssLink := func(server, name string) string {
		return "ss://" + b64("aes-256-gcm:pass") + "@" + server + ":8388#" + name
	}
	f := fakeFetcher{
		"main": b64Sub(ssLink("1.1.1.1", "MAIN")),
		"ins":  b64Sub(ssLink("2.2.2.2", "INSERT")),
	}
	names := func(req Request) []string {
		req.Target = "clash"
		req.SubURLs = []string{"https://x/main"}
		req.Gen = generator.Options{ListOnly: true}
		data, _, err := Run(context.Background(), f, req)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		var doc struct {
			Proxies []map[string]any `yaml:"proxies"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatalf("invalid yaml: %v", err)
		}
		var out []string
		for _, p := range doc.Proxies {
			out = append(out, p["name"].(string))
		}
		return out
	}

	if got := names(Request{InsertURLs: []string{"https://x/ins"}, InsertPrepend: true}); strings.Join(got, ",") != "INSERT,MAIN" {
		t.Errorf("prepend order = %v, want [INSERT MAIN]", got)
	}
	if got := names(Request{InsertURLs: []string{"https://x/ins"}, InsertPrepend: false}); strings.Join(got, ",") != "MAIN,INSERT" {
		t.Errorf("append order = %v, want [MAIN INSERT]", got)
	}
	if got := names(Request{}); strings.Join(got, ",") != "MAIN" {
		t.Errorf("no-insert = %v, want [MAIN]", got)
	}
	// A failing insert source must not break the main conversion.
	if got := names(Request{InsertURLs: []string{"https://x/missing"}, InsertPrepend: true}); strings.Join(got, ",") != "MAIN" {
		t.Errorf("insert-failure fallback = %v, want [MAIN]", got)
	}
}

func TestRun_UnsupportedTarget(t *testing.T) {
	_, _, err := Run(context.Background(), fakeFetcher{}, Request{Target: "quan", SubURLs: []string{"x"}})
	if err == nil || !strings.Contains(err.Error(), "unsupported target") {
		t.Errorf("expected unsupported target error, got %v", err)
	}
}

func TestRun_NoURL(t *testing.T) {
	_, _, err := Run(context.Background(), fakeFetcher{}, Request{Target: "clash"})
	if err == nil || !strings.Contains(err.Error(), "no subscription") {
		t.Errorf("expected no-url error, got %v", err)
	}
}

func TestRun_SubscriptionFetchError(t *testing.T) {
	// Empty fetcher returns notFound for any URL.
	_, _, err := Run(context.Background(), fakeFetcher{}, Request{
		Target:  "clash",
		SubURLs: []string{"https://airport/sub"},
	})
	if err == nil || !strings.Contains(err.Error(), "subscription 1") {
		t.Errorf("expected subscription fetch error, got %v", err)
	}
}

func TestRun_NoUsableNodes(t *testing.T) {
	f := fakeFetcher{"sub": []byte(base64.StdEncoding.EncodeToString([]byte("garbage://nothing\nalso-bad")))}
	_, _, err := Run(context.Background(), f, Request{Target: "clash", SubURLs: []string{"https://x/sub"}})
	if err == nil || !strings.Contains(err.Error(), "no usable nodes") {
		t.Errorf("expected no usable nodes error, got %v", err)
	}
}

func TestRun_ConfigFetchError(t *testing.T) {
	f := fakeFetcher{"client/subscribe": sampleSubscription()} // config.init missing
	_, _, err := Run(context.Background(), f, Request{
		Target:    "clash",
		SubURLs:   []string{"https://airport/api/v1/client/subscribe"},
		ConfigURL: "https://x/config.init",
	})
	if err == nil || !strings.Contains(err.Error(), "external config") {
		t.Errorf("expected external config error, got %v", err)
	}
}

func TestRun_NoConfigDefaultsRuleGen(t *testing.T) {
	// Without a config URL, conversion still succeeds with bare proxies.
	f := fakeFetcher{"client/subscribe": sampleSubscription()}
	data, diag, err := Run(context.Background(), f, Request{
		Target:  "clash",
		SubURLs: []string{"https://airport/api/v1/client/subscribe"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// No config => no exclude_remarks, so the "套餐到期" node is kept too (7).
	if diag.NodeCount != 7 || len(data) == 0 {
		t.Errorf("bare conversion wrong: nodes=%d bytes=%d", diag.NodeCount, len(data))
	}
}

func TestRun_Rename(t *testing.T) {
	// rename= rewrites node names; the regex backref form (\1) must work too.
	ini := sampleINI + "rename=HK-Test@HongKong\nrename=US-(.+)@\\1-USA\n"
	f := fakeFetcher{
		"client/subscribe": sampleSubscription(),
		"config.init":      []byte(ini),
		"PROXY.list":       []byte(samplePROXYList),
	}
	data, _, err := Run(context.Background(), f, Request{
		Target:    "clash",
		SubURLs:   []string{"https://airport.example.com/api/v1/client/subscribe?token=x"},
		ConfigURL: "https://github.com/x/config.init",
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range toAnys(doc["proxies"]) {
		m, _ := p.(map[string]any)
		names = append(names, m["name"].(string))
	}
	joined := strings.Join(names, "\n")
	if !strings.Contains(joined, "🇭🇰 HongKong") {
		t.Errorf("plain rename not applied, names: %v", names)
	}
	if !strings.Contains(joined, "Test-USA") {
		t.Errorf("backref rename not applied, names: %v", names)
	}
}

func TestRun_ExpandFalseRuleProviders(t *testing.T) {
	f := fakeFetcher{
		"client/subscribe": sampleSubscription(),
		"config.init":      []byte(sampleINI),
		// PROXY.list intentionally NOT served: expand=false must not fetch it.
	}
	req := Request{
		Target:    "clash",
		SubURLs:   []string{"https://airport.example.com/api/v1/client/subscribe?token=x"},
		ConfigURL: "https://github.com/x/config.init",
	}
	req.Gen.UseRuleProviders = true
	data, _, err := Run(context.Background(), f, req)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	rp, _ := doc["rule-providers"].(map[string]any)
	if len(rp) != 1 {
		t.Fatalf("rule-providers = %v, want 1 entry", rp)
	}
	rules := strings.Join(toStrings(doc["rules"]), "\n")
	if !strings.Contains(rules, "RULE-SET,provider_1,🚀 节点选择") {
		t.Errorf("missing RULE-SET rule: %s", rules)
	}
	if !strings.Contains(rules, "MATCH,🐟 漏网之鱼") {
		t.Errorf("inline MATCH lost in rule-providers mode: %s", rules)
	}
}

func TestResolveEmoji(t *testing.T) {
	tr := func(b bool) *bool { return &b }

	// Defaults: both true.
	if r, a := resolveEmoji(&extconfig.Config{}, Request{}); !r || !a {
		t.Errorf("defaults = remove %v add %v, want true true", r, a)
	}
	// External config overrides defaults.
	cfg := &extconfig.Config{AddEmoji: tr(false), RemoveOldEmoji: tr(false)}
	if r, a := resolveEmoji(cfg, Request{}); r || a {
		t.Errorf("config override = remove %v add %v, want false false", r, a)
	}
	// URL params override config.
	if r, a := resolveEmoji(cfg, Request{AddEmoji: tr(true), RemoveEmoji: tr(true)}); !r || !a {
		t.Errorf("url override = remove %v add %v, want true true", r, a)
	}
	// emoji shortcut forces remove=true and sets add.
	if r, a := resolveEmoji(&extconfig.Config{}, Request{Emoji: tr(false)}); !r || a {
		t.Errorf("emoji shortcut = remove %v add %v, want true false", r, a)
	}
}

func toAnys(v any) []any {
	arr, _ := v.([]any)
	return arr
}

func toStrings(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
