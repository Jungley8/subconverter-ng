package generator

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"gopkg.in/yaml.v3"
)

func TestGenerateClashProvider_ProvidersAndGroups(t *testing.T) {
	const ini = `
[custom]
enable_rule_generator=true
custom_proxy_group=🚀 节点选择` + "`" + `select` + "`" + `[]♻️ 自动选择` + "`" + `[]DIRECT` + "\n" +
		`custom_proxy_group=♻️ 自动选择` + "`" + `url-test` + "`" + `.*` + "\n" +
		`custom_proxy_group=🇭🇰 香港节点` + "`" + `select` + "`" + `港|HK` + "\n"
	cfg := extconfig.Parse([]byte(ini))

	nodes, _, err := parseLinks("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#HK-Test")
	if err != nil {
		t.Fatalf("parse local link: %v", err)
	}
	opts := Options{
		ProviderMode:     true,
		ProviderURLs:     []string{"https://airport.example/sub?token=x", "https://other.example/api"},
		ProviderUA:       "clash.meta/1.19.0",
		ProviderInterval: 3600,
		ProviderInclude:  "(?i)hk|港",
		ProviderExclude:  "(?i)(弃用)|(到期)",
		UDP:              true,
		SkipCertVerify:   true,
	}
	res, err := GenerateClashProvider(context.Background(), nodes, cfg, fakeFetcher{}, opts)
	if err != nil {
		t.Fatalf("GenerateClashProvider: %v", err)
	}
	cfgYAML := string(res.Output)
	for _, want := range []string{
		"proxy-providers:",
		"sub-1:",
		"sub-2:",
		"url: https://airport.example/sub?token=x",
		"interval: 3600",
		"User-Agent:",
		"- clash.meta/1.19.0",
		"filter: (?i)hk|港",
		"exclude-filter: (?i)(弃用)|(到期)",
		"udp: true",
		"skip-cert-verify: true",
		"health-check:",
		"type: ss",
	} {
		if !strings.Contains(cfgYAML, want) {
			t.Errorf("output missing %q\n%s", want, cfgYAML)
		}
	}
	if strings.Contains(cfgYAML, "proxies: []") {
		t.Errorf("empty proxies list leaked into output\n%s", cfgYAML)
	}

	// Assert the groups structurally: a global string search would pass even
	// when the providers are wired to the wrong group (or to none at all).
	var doc struct {
		ProxyGroups []struct {
			Name    string   `yaml:"name"`
			Type    string   `yaml:"type"`
			Proxies []string `yaml:"proxies"`
			Use     []string `yaml:"use"`
			Filter  string   `yaml:"filter"`
		} `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("invalid yaml: %v", err)
	}
	group := func(name string) (proxies, use []string, filter string) {
		t.Helper()
		for _, g := range doc.ProxyGroups {
			if g.Name == name {
				return g.Proxies, g.Use, g.Filter
			}
		}
		t.Fatalf("group %q missing from output\n%s", name, cfgYAML)
		return nil, nil, ""
	}
	wantProviders := []string{"sub-1", "sub-2"}
	// ".*" group: every provider, no filter. This is the ACL4SSR main-select
	// shape; losing `use` here sends all traffic to DIRECT.
	proxies, use, filter := group("♻️ 自动选择")
	if filter != "" {
		t.Errorf("♻️ 自动选择 filter = %q, want empty for a match-all selector", filter)
	}
	if strings.Join(use, ",") != strings.Join(wantProviders, ",") {
		t.Errorf("♻️ 自动选择 use = %v, want %v", use, wantProviders)
	}
	if len(proxies) != 1 || proxies[0] != "HK-Test" {
		t.Errorf("♻️ 自动选择 proxies = %v, want the inlined local node only", proxies)
	}
	// Region group: regex selector becomes filter + use.
	proxies, use, filter = group("🇭🇰 香港节点")
	if filter != "港|HK" {
		t.Errorf("🇭🇰 香港节点 filter = %q, want 港|HK", filter)
	}
	if strings.Join(use, ",") != strings.Join(wantProviders, ",") {
		t.Errorf("🇭🇰 香港节点 use = %v, want %v", use, wantProviders)
	}
	if len(proxies) != 1 || proxies[0] != "HK-Test" {
		t.Errorf("🇭🇰 香港节点 proxies = %v, want the matching local node", proxies)
	}
	// Literal-only group: subgroup names, no provider reference.
	proxies, use, _ = group("🚀 节点选择")
	if len(use) != 0 {
		t.Errorf("🚀 节点选择 use = %v, want none (literal selectors only)", use)
	}
	if strings.Join(proxies, ",") != "♻️ 自动选择,DIRECT" {
		t.Errorf("🚀 节点选择 proxies = %v", proxies)
	}
}

// TestGenerateClashProvider_MatchAllSelectorUsesProviders pins the ACL4SSR
// "🚀 节点选择`select`.*" shape: a match-all group must reference every provider,
// not fall back to a DIRECT-only group.
func TestGenerateClashProvider_MatchAllSelectorUsesProviders(t *testing.T) {
	const ini = `
[custom]
custom_proxy_group=🚀 节点选择` + "`" + `select` + "`" + `.*` + "\n" +
		`custom_proxy_group=♻️ 自动选择` + "`" + `url-test` + "`" + `.*` + "\n"
	cfg := extconfig.Parse([]byte(ini))
	res, err := GenerateClashProvider(context.Background(), nil, cfg, fakeFetcher{}, Options{
		ProviderMode: true,
		ProviderURLs: []string{"https://airport.example/sub"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.EmptyGroups) != 0 {
		t.Errorf("EmptyGroups = %v, want none: a .* group is not empty", res.EmptyGroups)
	}
	var doc struct {
		ProxyGroups []struct {
			Name    string   `yaml:"name"`
			Proxies []string `yaml:"proxies"`
			Use     []string `yaml:"use"`
			Filter  string   `yaml:"filter"`
		} `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("invalid yaml: %v", err)
	}
	if len(doc.ProxyGroups) != 2 {
		t.Fatalf("groups = %d, want 2\n%s", len(doc.ProxyGroups), res.Output)
	}
	for _, g := range doc.ProxyGroups {
		if len(g.Use) != 1 || g.Use[0] != "sub-1" {
			t.Errorf("%s use = %v, want [sub-1]", g.Name, g.Use)
		}
		if g.Filter != "" {
			t.Errorf("%s filter = %q, want empty", g.Name, g.Filter)
		}
		for _, p := range g.Proxies {
			if p == "DIRECT" {
				t.Errorf("%s fell back to DIRECT: %v", g.Name, g.Proxies)
			}
		}
	}
}

func TestGenerateClashProvider_DefaultGroups(t *testing.T) {
	res, err := GenerateClashProvider(context.Background(), nil, &extconfig.Config{}, fakeFetcher{}, Options{
		ProviderMode: true,
		ProviderURLs: []string{"https://airport.example/sub"},
	})
	if err != nil {
		t.Fatalf("GenerateClashProvider: %v", err)
	}
	out := string(res.Output)
	for _, want := range []string{
		"🚀 节点选择",
		"♻️ 自动选择",
		"MATCH,🚀 节点选择",
		"interval: 86400", // default provider interval
		"type: http",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}
}

// Local share-link nodes are inline nodes, so server-side processing must apply
// to them even in provider mode (the provider payloads stay untouched).
func TestGenerateClashProvider_LocalNodesArePrepared(t *testing.T) {
	nodes, _, err := parseLinks("ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#HK-Test")
	if err != nil {
		t.Fatalf("parse local link: %v", err)
	}
	base := Options{ProviderMode: true, ProviderURLs: []string{"https://airport.example/sub"}}

	// Remarks filter from the external config.
	cfg := &extconfig.Config{ExcludeRemarks: []*regexp.Regexp{regexp.MustCompile("HK")}}
	res, err := GenerateClashProvider(context.Background(), nodes, cfg, fakeFetcher{}, base)
	if err != nil {
		t.Fatal(err)
	}
	if res.Filtered != 1 || res.NodeCount != 0 {
		t.Errorf("Filtered = %d, NodeCount = %d, want 1 and 0", res.Filtered, res.NodeCount)
	}

	// Protocol exclusion.
	opts := base
	opts.ExcludeProtocols = []string{"ss"}
	res, err = GenerateClashProvider(context.Background(), nodes, &extconfig.Config{}, fakeFetcher{}, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExcludedProtocols != 1 || res.NodeCount != 0 {
		t.Errorf("ExcludedProtocols = %d, NodeCount = %d, want 1 and 0", res.ExcludedProtocols, res.NodeCount)
	}
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Proxies) != 0 {
		t.Errorf("excluded local node leaked into proxies: %v", doc.Proxies)
	}
}
