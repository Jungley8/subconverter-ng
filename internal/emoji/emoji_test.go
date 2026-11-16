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
		"(?<!x)lookbehind,🚫", // PCRE lookbehind: accepted through the fallback
	})
	if len(rules) != 3 {
		t.Fatalf("ParseRules = %d rules, want 3 (comment/no-comma skipped)", len(rules))
	}
	for _, c := range []struct{ name, want string }{
		{"香港 01", "🇭🇰 香港 01"},
		{"US-Node", "🇺🇸 US-Node"},
		{"无匹配", "无匹配"},
	} {
		got, err := Add(c.name, rules)
		if err != nil {
			t.Fatalf("Add(%q): %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("Add(%q) = %q, want %q", c.name, got, c.want)
		}
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
		got, err := Add(c.name, rules)
		if err != nil {
			t.Fatal(err)
		}
		if got[:len(c.wantPrefix)] != c.wantPrefix {
			t.Errorf("Add(%q) = %q, want prefix %q", c.name, got, c.wantPrefix)
		}
	}
}
