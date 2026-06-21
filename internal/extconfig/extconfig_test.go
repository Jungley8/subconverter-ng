package extconfig

import "testing"

const sample = `[custom]
; a comment
# another comment
ruleset=🎯 全球直连,[]GEOIP,CN
ruleset=🐟 漏网之鱼,[]FINAL
ruleset=🚀 节点选择,https://example.com/PROXY.list
ruleset=bad-no-comma
custom_proxy_group=🚀 节点选择` + "`select`" + `[]♻️ 自动选择` + "`" + `[]DIRECT
custom_proxy_group=♻️ 自动选择` + "`url-test`" + `.*` + "`" + `http://www.gstatic.com/generate_204` + "`" + `300,5,50
custom_proxy_group=too-few-fields
exclude_remarks=(到期|过期)
exclude_remarks=[invalid(regex
include_remarks=(HK|US)
enable_rule_generator=true
overwrite_original_rules=true
clash_rule_base=https://example.com/base.yml
rename=美国@US
rename=\[(.+?)\]@\1
unknown_key=ignored
`

func TestParse(t *testing.T) {
	cfg := Parse([]byte(sample))

	if len(cfg.Rulesets) != 3 {
		t.Fatalf("rulesets = %d, want 3 (bad-no-comma dropped)", len(cfg.Rulesets))
	}
	if cfg.Rulesets[0].Inline != "GEOIP,CN" || cfg.Rulesets[0].URL != "" {
		t.Errorf("inline GEOIP parsed wrong: %+v", cfg.Rulesets[0])
	}
	if cfg.Rulesets[1].Inline != "FINAL" {
		t.Errorf("FINAL inline parsed wrong: %+v", cfg.Rulesets[1])
	}
	if cfg.Rulesets[2].URL != "https://example.com/PROXY.list" || cfg.Rulesets[2].Inline != "" {
		t.Errorf("remote ruleset parsed wrong: %+v", cfg.Rulesets[2])
	}

	if len(cfg.ProxyGroups) != 2 {
		t.Fatalf("proxy groups = %d, want 2 (too-few-fields dropped)", len(cfg.ProxyGroups))
	}
	sel := cfg.ProxyGroups[0]
	if sel.Type != "select" || len(sel.Selectors) != 2 {
		t.Errorf("select group wrong: %+v", sel)
	}
	ut := cfg.ProxyGroups[1]
	if ut.Type != "url-test" || ut.TestURL == "" || ut.Interval != 300 || ut.Timeout != 5 || ut.Tolerance != 50 {
		t.Errorf("url-test group interval spec wrong: %+v", ut)
	}
	if len(ut.Selectors) != 1 || ut.Selectors[0] != ".*" {
		t.Errorf("url-test selectors wrong: %+v", ut.Selectors)
	}

	if len(cfg.ExcludeRemarks) != 1 { // invalid regex skipped
		t.Errorf("exclude remarks = %d, want 1 (invalid regex dropped)", len(cfg.ExcludeRemarks))
	}
	if len(cfg.IncludeRemarks) != 1 {
		t.Errorf("include remarks = %d, want 1", len(cfg.IncludeRemarks))
	}
	if !cfg.EnableRuleGenerator || !cfg.OverwriteRules {
		t.Error("bool flags not set")
	}
	if cfg.ClashRuleBase != "https://example.com/base.yml" {
		t.Errorf("clash_rule_base = %q", cfg.ClashRuleBase)
	}
	if len(cfg.RenameRules) != 2 || cfg.RenameRules[0] != "美国@US" || cfg.RenameRules[1] != `\[(.+?)\]@\1` {
		t.Errorf("rename rules parsed wrong: %v", cfg.RenameRules)
	}
}

func TestParseDefaultsRuleGeneratorOn(t *testing.T) {
	cfg := Parse([]byte(""))
	if !cfg.EnableRuleGenerator {
		t.Error("EnableRuleGenerator should default to true")
	}
}

func TestLiteral(t *testing.T) {
	if name, ok := Literal("[]DIRECT"); !ok || name != "DIRECT" {
		t.Errorf("Literal([]DIRECT) = %q,%v", name, ok)
	}
	if _, ok := Literal("(港|HK)"); ok {
		t.Error("regex selector should not be a literal")
	}
}

func TestParseIntervalPartial(t *testing.T) {
	i, to, tol := parseInterval("300")
	if i != 300 || to != 0 || tol != 0 {
		t.Errorf("parseInterval(300) = %d,%d,%d", i, to, tol)
	}
	i, to, tol = parseInterval("300,,50")
	if i != 300 || to != 0 || tol != 50 {
		t.Errorf("parseInterval(300,,50) = %d,%d,%d", i, to, tol)
	}
}

func TestBoolVal(t *testing.T) {
	for _, on := range []string{"true", "1", "yes", "ON"} {
		if !boolVal(on) {
			t.Errorf("boolVal(%q) should be true", on)
		}
	}
	for _, off := range []string{"false", "0", "no", ""} {
		if boolVal(off) {
			t.Errorf("boolVal(%q) should be false", off)
		}
	}
}
