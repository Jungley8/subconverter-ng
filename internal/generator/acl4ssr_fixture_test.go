package generator

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
	"gopkg.in/yaml.v3"
)

// acl4ssr-real.ini is an excerpt of a real ACL4SSR config: a selector that
// references other groups by name, url-test groups with a test URL and
// `300,,50` (interval, tolerance), and rulesets that mix FINAL, GEOIP, CIDR
// with no-resolve, and domain rules.
//
// These tests pin the structure the fixture must keep producing. The unit tests
// elsewhere check one feature each; this one catches the case where a change is
// fine in isolation but reorders groups, drops a literal selector, or loses a
// rule flag in a config shaped like the one most users run.
func acl4ssrFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func acl4ssrNodes() []*proxy.Proxy {
	return []*proxy.Proxy{
		proxy.New("ss", "🇭🇰 香港 01", "1.2.3.4", 8388),
		proxy.New("ss", "🇯🇵 日本 01", "2.2.3.4", 8388),
		proxy.New("ss", "🇺🇸 美国 01", "3.2.3.4", 8388),
		proxy.New("ss", "🇸🇬 新加坡 01", "4.2.3.4", 8388),
	}
}

type fixtureGroup struct {
	Name      string   `yaml:"name"`
	Type      string   `yaml:"type"`
	Proxies   []string `yaml:"proxies"`
	URL       string   `yaml:"url"`
	Interval  int      `yaml:"interval"`
	Tolerance int      `yaml:"tolerance"`
}

type fixtureClash struct {
	ProxyGroups []fixtureGroup `yaml:"proxy-groups"`
	Rules       []string       `yaml:"rules"`
}

func TestACL4SSRFixture_ClashStructure(t *testing.T) {
	cfg := extconfig.Parse(acl4ssrFixture(t, "acl4ssr-real.ini"))
	res, err := GenerateClash(context.Background(), acl4ssrNodes(), cfg, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatalf("GenerateClash: %v", err)
	}
	if len(res.EmptyGroups) != 0 || len(res.SkippedRules) != 0 {
		t.Fatalf("fixture should be fully expressible: empty=%v skipped=%v", res.EmptyGroups, res.SkippedRules)
	}

	var doc fixtureClash
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("parse rendered YAML: %v", err)
	}

	// 1. Groups keep the order the INI declares. Clients show this order, and
	//    ACL4SSR puts the main selector first on purpose.
	wantOrder := []string{
		"🚀 节点选择", "♻️ 自动选择", "🇭🇰 香港节点", "🇯🇵 日本节点",
		"🇺🇸 美国节点", "📲 电报消息", "🐟 漏网之鱼",
	}
	if len(doc.ProxyGroups) != len(wantOrder) {
		t.Fatalf("got %d groups, want %d: %+v", len(doc.ProxyGroups), len(wantOrder), doc.ProxyGroups)
	}
	for i, want := range wantOrder {
		if doc.ProxyGroups[i].Name != want {
			t.Errorf("group[%d] = %q, want %q", i, doc.ProxyGroups[i].Name, want)
		}
	}
	byName := map[string]fixtureGroup{}
	for _, g := range doc.ProxyGroups {
		byName[g.Name] = g
	}

	// 2. A `[]literal` selector list survives in order, including group names.
	if got, want := byName["🚀 节点选择"].Proxies,
		[]string{"♻️ 自动选择", "🇭🇰 香港节点", "🇯🇵 日本节点", "🇺🇸 美国节点", "DIRECT"}; !equalStrings(got, want) {
		t.Errorf("节点选择 proxies = %v, want %v", got, want)
	}

	// 3. The test URL and the `300,,50` interval spec reach the group intact.
	auto := byName["♻️ 自动选择"]
	if auto.Type != "url-test" || auto.URL != "http://www.gstatic.com/generate_204" {
		t.Errorf("自动选择 = %+v, want url-test on gstatic", auto)
	}
	if auto.Interval != 300 || auto.Tolerance != 50 {
		t.Errorf("自动选择 interval/tolerance = %d/%d, want 300/50", auto.Interval, auto.Tolerance)
	}
	if len(auto.Proxies) != 4 {
		t.Errorf("自动选择 has %d nodes, want all 4: %v", len(auto.Proxies), auto.Proxies)
	}

	// 4. Region regexes select only their region.
	for group, node := range map[string]string{
		"🇭🇰 香港节点": "🇭🇰 香港 01",
		"🇯🇵 日本节点": "🇯🇵 日本 01",
		"🇺🇸 美国节点": "🇺🇸 美国 01",
	} {
		if got, want := byName[group].Proxies, []string{node}; !equalStrings(got, want) {
			t.Errorf("%s proxies = %v, want %v", group, got, want)
		}
	}

	// 5. A node with no matching region group joins exactly one group (the
	//    catch-all). More than one means a selector is matching too much.
	sgCount := 0
	for _, g := range doc.ProxyGroups {
		for _, p := range g.Proxies {
			if p == "🇸🇬 新加坡 01" {
				sgCount++
			}
		}
	}
	if sgCount != 1 {
		t.Errorf("🇸🇬 新加坡 01 appears in %d groups, want 1", sgCount)
	}

	// 6. Rules keep their declared order, their group, and their flag. A lost
	//    `no-resolve` makes the client resolve LAN addresses, which is slow and
	//    leaks DNS.
	wantRules := []string{
		"GEOIP,CN,🚀 节点选择",
		"DOMAIN-SUFFIX,telegram.org,📲 电报消息",
		"GEOIP,LAN,DIRECT,no-resolve",
		"IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
		"IP-CIDR6,fc00::/7,DIRECT,no-resolve",
		"DOMAIN-KEYWORD,adservice,REJECT",
		"MATCH,🐟 漏网之鱼",
	}
	if !equalStrings(doc.Rules, wantRules) {
		t.Errorf("rules =\n  %v\nwant\n  %v", doc.Rules, wantRules)
	}

	// 7. Every group a rule points at exists, and FINAL stays last.
	groups := map[string]bool{"DIRECT": true, "REJECT": true}
	for _, g := range doc.ProxyGroups {
		groups[g.Name] = true
	}
	for _, rule := range doc.Rules[:len(doc.Rules)-1] {
		target := ruleTarget(rule)
		if !groups[target] {
			t.Errorf("rule %q points at missing group %q", rule, target)
		}
	}
	if last := doc.Rules[len(doc.Rules)-1]; last != "MATCH,🐟 漏网之鱼" {
		t.Errorf("last rule = %q, want MATCH,🐟 漏网之鱼", last)
	}
}

// TestACL4SSRFixture_SingboxReferences checks the same fixture rendered for
// sing-box. The shapes differ, but one invariant holds across targets: every
// reference resolves. sing-box refuses to start on a dangling outbound or
// rule_set tag, so a rename that misses one place must fail here.
func TestACL4SSRFixture_SingboxReferences(t *testing.T) {
	cfg := extconfig.Parse(acl4ssrFixture(t, "acl4ssr-real.ini"))
	res, err := GenerateSingbox(context.Background(), acl4ssrNodes(), cfg, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatalf("GenerateSingbox: %v", err)
	}

	var doc struct {
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
		Route struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
			// rule_set is nested under route; a root-level field is rejected
			// by 1.14 and must stay impossible here.
			RuleSet []struct {
				Tag string `json:"tag"`
			} `json:"rule_set"`
		} `json:"route"`
	}
	if err := json.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("parse rendered JSON: %v", err)
	}

	tags := map[string]bool{}
	for _, o := range doc.Outbounds {
		if tags[o.Tag] {
			t.Errorf("duplicate outbound tag %q", o.Tag)
		}
		tags[o.Tag] = true
	}
	ruleSets := map[string]bool{}
	for _, rs := range doc.Route.RuleSet {
		ruleSets[rs.Tag] = true
	}

	for i, rule := range doc.Route.Rules {
		if out, ok := rule["outbound"].(string); ok && !tags[out] {
			t.Errorf("rule[%d] outbound %q is not an outbound tag: %v", i, out, rule)
		}
		if refs, ok := rule["rule_set"].([]any); ok {
			for _, ref := range refs {
				if tag, _ := ref.(string); !ruleSets[tag] {
					t.Errorf("rule[%d] rule_set %q is not defined under route.rule_set", i, tag)
				}
			}
		}
	}
	if doc.Route.Final == "" {
		t.Fatal("route.final is empty: the MATCH rule must become the final outbound")
	}
	if !tags[doc.Route.Final] {
		t.Errorf("route.final %q is not an outbound tag", doc.Route.Final)
	}
}

// ruleTarget returns the group a rendered clash rule points at.
func ruleTarget(rule string) string {
	parts := splitCSV(rule)
	if len(parts) >= 3 && parts[len(parts)-1] == "no-resolve" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}

func splitCSV(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
