package generator

import (
	"context"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
)

func generateWithBase(t *testing.T, base string) string {
	t.Helper()
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ClashRuleBase:       "https://example.com/base.yml",
		OverwriteRules:      true,
		Rulesets:            []extconfig.Ruleset{{Group: "G", Inline: "FINAL"}},
	}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(base)}, Options{})
	if err != nil {
		t.Fatalf("GenerateClash: %v", err)
	}
	return string(res.Output)
}

func TestBaseYAMLDirectiveAccepted(t *testing.T) {
	out := generateWithBase(t, "%YAML 1.2\n---\nmixed-port: 7890\n")
	if strings.Contains(out, "%YAML") {
		t.Errorf("output kept the %%YAML directive:\n%s", out)
	}
	for _, want := range []string{"mixed-port: 7890", "proxies:", "rules:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestBaseTAGDirectiveAccepted(t *testing.T) {
	const ini = "[custom]\n" +
		"custom_proxy_group=G`select`.*\n" +
		"clash_rule_base=https://example.com/base.yml\n"
	cfg := extconfig.Parse([]byte(ini))
	base := "%TAG !e! tag:example.com,2000:\n---\nmixed-port: 7890\nrules:\n  - MATCH,keep\n"
	opts := Options{ProviderMode: true, ProviderURLs: []string{"https://airport.example/sub"}}
	res, err := GenerateClashProvider(context.Background(), nil, cfg, fakeFetcher{"base.yml": []byte(base)}, opts)
	if err != nil {
		t.Fatalf("GenerateClashProvider: %v", err)
	}
	out := string(res.Output)
	if strings.Contains(out, "%TAG") {
		t.Errorf("output kept the %%TAG directive:\n%s", out)
	}
	for _, want := range []string{"mixed-port: 7890", "proxy-providers:", "rules:\n  - MATCH,keep\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestBaseKeepsFourSpaceIndent(t *testing.T) {
	out := generateWithBase(t, "dns:\n    enable: true\n")
	for _, want := range []string{
		"dns:\n    enable: true\n",
		"proxies:\n    - name: ",
		"\n      type: ss\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestBaseKeepsTwoSpaceIndent(t *testing.T) {
	out := generateWithBase(t, "dns:\n  enable: true\n")
	for _, want := range []string{
		"dns:\n  enable: true\n",
		"proxies:\n  - name: ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestBaseSequenceFirstIndentedLine(t *testing.T) {
	out := generateWithBase(t, "profile:\n  - a\n")
	for _, want := range []string{
		"profile:\n  - a\n",
		"proxies:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}
