package generator

import (
	"context"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
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
		"use:",
		"- sub-1",
		"- sub-2",
		// url-test group with ".*" selector: use over all providers, no filter
		// (name is .* → all local nodes inlined and joined; here the local ss
		// node must appear both under proxies: and in the group).
		"proxies:",
	} {
		if !strings.Contains(cfgYAML, want) {
			t.Errorf("output missing %q\n%s", want, cfgYAML)
		}
	}
	// Region group: regex selector becomes the group filter.
	if !strings.Contains(cfgYAML, "filter: 港|HK") {
		t.Errorf("region group filter missing\n%s", cfgYAML)
	}
	// Local share-link node is inlined and referenced in the .* group.
	if !strings.Contains(cfgYAML, "type: ss") {
		t.Errorf("local node not inlined\n%s", cfgYAML)
	}
	if strings.Contains(cfgYAML, "proxies: []") {
		t.Errorf("empty proxies list leaked into output\n%s", cfgYAML)
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
