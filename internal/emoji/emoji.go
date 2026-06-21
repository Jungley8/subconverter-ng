// Package emoji implements subconverter-compatible emoji handling for node
// names. It mirrors tindy2013/subconverter's model: optionally remove existing
// emoji from a remark, then optionally add a flag emoji chosen by the first
// matching regex rule.
//
//	remove_emoji : strip existing emoji from the name
//	add_emoji    : prepend "<emoji> " using the first matching rule
//
// The default rule set is bundled (default.txt, ported from subconverter's
// snippets/emoji.txt and adjusted for Go's RE2 engine).
package emoji

import (
	_ "embed"
	"regexp"
	"strings"
)

//go:embed default.txt
var defaultRulesText string

// Rule maps a remark pattern to the emoji prepended when it matches.
type Rule struct {
	Pattern *regexp.Regexp
	Emoji   string
}

var defaultRules []Rule

func init() { defaultRules = ParseRules(strings.Split(defaultRulesText, "\n")) }

// Default returns the bundled emoji rule set.
func Default() []Rule { return defaultRules }

// ParseRules parses "<regex>,<emoji>" lines, splitting on the LAST comma so a
// regex containing commas is preserved. Comment/blank lines and uncompilable
// patterns (e.g. PCRE lookbehind unsupported by RE2) are skipped.
func ParseRules(lines []string) []Rule {
	var rules []Rule
	for _, raw := range lines {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		idx := strings.LastIndex(line, ",")
		if idx <= 0 {
			continue
		}
		pattern := strings.TrimSpace(line[:idx])
		em := strings.TrimSpace(line[idx+1:])
		if em == "" {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		rules = append(rules, Rule{Pattern: re, Emoji: em})
	}
	return rules
}

// Remove strips emoji / pictographic runes (country flags, symbols, variation
// selectors, ZWJ) from name and collapses the whitespace left behind. Regular
// text (CJK, latin, digits) is preserved.
//
// This is broader than subconverter's leading-only strip: it removes emoji
// anywhere in the name, which is what clients that cannot render emoji need.
func Remove(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if isEmojiRune(r) {
			continue
		}
		b.WriteRune(r)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// Add prepends "<emoji> " using the first rule whose pattern matches name. If no
// rule matches, name is returned unchanged.
func Add(name string, rules []Rule) string {
	for _, r := range rules {
		if r.Pattern.MatchString(name) {
			return r.Emoji + " " + name
		}
	}
	return name
}

func isEmojiRune(r rune) bool {
	switch {
	case r >= 0x1F1E6 && r <= 0x1F1FF: // regional indicator symbols (country flags)
		return true
	case r >= 0x1F300 && r <= 0x1FAFF: // symbols, pictographs, emoji, supplemental
		return true
	case r >= 0x1F000 && r <= 0x1F02F: // mahjong / dominoes
		return true
	case r >= 0x2600 && r <= 0x27BF: // misc symbols + dingbats
		return true
	case r >= 0x2B00 && r <= 0x2BFF: // misc symbols and arrows (stars ⭐ etc.)
		return true
	case r >= 0xFE00 && r <= 0xFE0F: // variation selectors
		return true
	case r == 0x200D || r == 0x20E3 || r == 0xFEFF: // ZWJ, combining keycap, BOM
		return true
	}
	return false
}
