package emoji

import "testing"

func TestRemove(t *testing.T) {
	cases := []struct{ in, want string }{
		{"🇭🇰 香港01", "香港01"},
		{"🇺🇲 US-Test", "US-Test"},
		{"⭐ 高级 节点 🚀", "高级 节点"},
		{"无emoji节点", "无emoji节点"},
		{"🇯🇵日本", "日本"},
		{"🏳️‍🌈 流量", "流量"}, // ZWJ sequence + variation selector
	}
	for _, c := range cases {
		if got := Remove(c.in); got != c.want {
			t.Errorf("Remove(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseRulesAndAdd(t *testing.T) {
	rules := ParseRules([]string{
		"# comment",
		"(?i:HK|香港|港),🇭🇰",
		"(?i:US|美国),🇺🇸",
		"badpattern-no-comma",
		"(?<!x)lookbehind,🚫", // RE2-incompatible -> skipped
	})
	if len(rules) != 2 {
		t.Fatalf("ParseRules = %d rules, want 2 (comment/no-comma/lookbehind skipped)", len(rules))
	}
	if got := Add("香港 01", rules); got != "🇭🇰 香港 01" {
		t.Errorf("Add HK = %q", got)
	}
	if got := Add("US-Node", rules); got != "🇺🇸 US-Node" {
		t.Errorf("Add US = %q", got)
	}
	// No match -> unchanged.
	if got := Add("无匹配", rules); got != "无匹配" {
		t.Errorf("Add no-match = %q, want unchanged", got)
	}
}

func TestDefaultRulesLoaded(t *testing.T) {
	rules := Default()
	if len(rules) < 80 {
		t.Fatalf("default rule set too small: %d", len(rules))
	}
	// Spot-check a few well-known mappings using the bundled rules.
	for _, c := range []struct{ name, wantPrefix string }{
		{"Hong Kong 01", "🇭🇰"},
		{"Tokyo Japan", "🇯🇵"},
		{"美国洛杉矶", "🇺🇸"},
		{"Singapore", "🇸🇬"},
	} {
		if got := Add(c.name, rules); got[:len(c.wantPrefix)] != c.wantPrefix {
			t.Errorf("Add(%q) = %q, want prefix %q", c.name, got, c.wantPrefix)
		}
	}
}
