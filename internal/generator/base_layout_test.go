package generator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
)

func generateWithBase(t *testing.T, base string) string {
	t.Helper()
	return generateWithBaseOverwrite(t, base, true)
}

func generateWithBaseOverwrite(t *testing.T, base string, overwrite bool) string {
	t.Helper()
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ClashRuleBase:       "https://example.com/base.yml",
		OverwriteRules:      overwrite,
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

func TestBaseBOMYAMLDirectiveAccepted(t *testing.T) {
	out := generateWithBase(t, "\xef\xbb\xbf%YAML 1.2\n---\nmixed-port: 7890\n")
	if strings.Contains(out, "%YAML") || strings.Contains(out, "\xef\xbb\xbf") {
		t.Errorf("output kept the BOM or %%YAML directive:\n%s", out)
	}
	if !strings.Contains(out, "mixed-port: 7890") {
		t.Errorf("output missing mixed-port:\n%s", out)
	}
}

func TestBaseDirectiveValidationErrors(t *testing.T) {
	cases := []struct{ name, base, want string }{
		{"unknown directive", "%FOO bar\n---\nmixed-port: 7890\n", "unsupported directive"},
		{"unsupported version", "%YAML 2.0\n---\nmixed-port: 7890\n", "unsupported YAML version"},
		{"unterminated directives", "%YAML 1.2\nmixed-port: 7890\n", "not terminated"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := &extconfig.Config{
				EnableRuleGenerator: true,
				ClashRuleBase:       "https://example.com/base.yml",
				Rulesets:            []extconfig.Ruleset{{Group: "G", Inline: "FINAL"}},
			}
			_, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{"base.yml": []byte(c.base)}, Options{})
			if !errors.Is(err, ErrConfigInvalid) {
				t.Errorf("err = %v, want ErrConfigInvalid", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want substring %q", err, c.want)
			}
		})
	}
}

func TestBaseTAGDirectiveAccepted(t *testing.T) {
	const ini = "[custom]\n" +
		"custom_proxy_group=G`select`.*\n" +
		"clash_rule_base=https://example.com/base.yml\n"
	cfg := extconfig.Parse([]byte(ini))
	base := "%TAG !e! tag:example.com,2000:\n---\nmixed-port: 7890\ncustom: !e!foo bar\nrules:\n  - MATCH,keep\n"
	opts := Options{ProviderMode: true, ProviderURLs: []string{"https://airport.example/sub"}}
	res, err := GenerateClashProvider(context.Background(), nil, cfg, fakeFetcher{"base.yml": []byte(base)}, opts)
	if err != nil {
		t.Fatalf("GenerateClashProvider: %v", err)
	}
	out := string(res.Output)
	if strings.Contains(out, "%TAG") {
		t.Errorf("output kept the %%TAG directive:\n%s", out)
	}
	for _, want := range []string{"mixed-port: 7890", "custom:", "proxy-providers:", "rules:\n  - MATCH,keep\n"} {
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

func TestBaseOnlyProxiesBlockKeepsFourSpace(t *testing.T) {
	base := "mixed-port: 7890\nproxies:\n    - name: old\n      type: ss\n"
	for _, overwrite := range []bool{true, false} {
		name := "keep rules"
		if overwrite {
			name = "overwrite rules"
		}
		t.Run(name, func(t *testing.T) {
			out := generateWithBaseOverwrite(t, base, overwrite)
			for _, want := range []string{
				"proxies:\n    - name: ",
				"\n      type: ss\n",
				"rules:\n    - MATCH,G\n",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, "proxies:\n  - name:") {
				t.Errorf("proxies fell back to 2-space indent:\n%s", out)
			}
		})
	}
}

func TestBaseAnchoredMappingKeepsFourSpace(t *testing.T) {
	out := generateWithBase(t, "dns: &d\n    enable: true\n")
	for _, want := range []string{
		"dns: &d\n    enable: true\n",
		"proxies:\n    - name: ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestBaseAnchoredSequenceKeepsFourSpace(t *testing.T) {
	out := generateWithBase(t, "profile: &p\n    - a\n")
	for _, want := range []string{
		"profile: &p\n    - a\n",
		"proxies:\n    - name: ",
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

func TestBaseSequenceKeepsFourSpace(t *testing.T) {
	out := generateWithBase(t, "profile:\n    - a\n")
	for _, want := range []string{
		"profile:\n    - a\n",
		"proxies:\n    - name: ",
		"\n      type: ss\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestBaseNineSpaceIndentPreserved(t *testing.T) {
	out := generateWithBase(t, "dns:\n         enable: true\n")
	for _, want := range []string{
		"dns:\n         enable: true\n",
		"proxies:\n         - name: ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestBaseOneSpaceIndentFallsBackToTwo(t *testing.T) {
	out := generateWithBase(t, "dns:\n enable: true\n")
	for _, want := range []string{
		"dns:\n  enable: true\n",
		"proxies:\n  - name: ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}
