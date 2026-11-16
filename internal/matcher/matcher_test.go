package matcher

import (
	"strings"
	"testing"
	"time"
)

func TestCompileAccepted(t *testing.T) {
	patterns := []string{
		`港|HK`,
		`(?i)hk.*`,
		`(?P<n>a)`, // RE2-only syntax: must not be handed to regexp2
		`^(?!.*(港|HK|TW|测试)).*$`,
		`(?<=a)b`,
	}
	for _, pattern := range patterns {
		m, err := Compile(pattern)
		if err != nil {
			t.Errorf("Compile(%q): %v", pattern, err)
			continue
		}
		if m.Pattern() != pattern {
			t.Errorf("Pattern() = %q, want %q", m.Pattern(), pattern)
		}
	}
}

func TestCompileInvalid(t *testing.T) {
	for _, pattern := range []string{`^(!`, `(?!`, `[`} {
		if _, err := Compile(pattern); err == nil {
			t.Errorf("Compile(%q) = nil error, want failure", pattern)
		}
	}
}

// CompileClient is what provider-mode filters use: mihomo compiles them with
// regexp2, so RE2-only syntax must be rejected here.
func TestCompileClientRejectsRE2OnlySyntax(t *testing.T) {
	if _, err := Compile(`(?P<n>a)`); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{`(?P<n>a)`, `\Qa\E`} {
		if _, err := CompileClient(pattern); err == nil {
			t.Errorf("CompileClient(%q) = nil error, want failure", pattern)
		}
	}
	if _, err := CompileClient(`^(?!.*(港|HK)).*$`); err != nil {
		t.Errorf("CompileClient rejected a PCRE lookahead: %v", err)
	}
}

func TestMatchPCREExclusion(t *testing.T) {
	m, err := Compile(`^(?!.*(港|(?i)HK|台|(?i)TW|测试|(?i)test)).*$`)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"香港 IPLC 01":  false,
		"台湾 HiNet 01": false,
		"测试 节点":       false,
		"hk node":     false, // inline (?i) applies inside the group
		"HK-02":       false,
		"新加坡 AWS 01":  true,
		"日本 AWS 01":   true,
	}
	for name, want := range cases {
		got, err := m.Match(name)
		if err != nil {
			t.Fatalf("Match(%q): %v", name, err)
		}
		if got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestMatchRE2(t *testing.T) {
	m, err := Compile(`(港|HK)`)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := m.Match("🇭🇰 HK 01"); err != nil || !ok {
		t.Errorf("Match(HK) = %v, %v; want true", ok, err)
	}
	if ok, err := m.Match("日本 01"); err != nil || ok {
		t.Errorf("Match(JP) = %v, %v; want false", ok, err)
	}
}

// A backtracking pattern must stop at the timeout and report it, not silently
// report "no match".
func TestMatchTimeoutIsAnError(t *testing.T) {
	m, err := Compile(`^(a+)+(?=b)`)
	if err != nil {
		t.Fatal(err)
	}
	name := strings.Repeat("a", 40) + "!"
	start := time.Now()
	ok, err := m.Match(name)
	if err == nil {
		t.Fatalf("Match = %v, nil; want a timeout error", ok)
	}
	if ok {
		t.Error("a timed-out match must not report true")
	}
	if strings.Contains(err.Error(), name) {
		t.Errorf("timeout error embeds the node name: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("timeout took %v, want the configured bound", elapsed)
	}
}

func TestReplaceAll(t *testing.T) {
	m, err := Compile(`(?<=HK)-(\d+)`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.ReplaceAll("HK-01x", " $1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "HK 01x" {
		t.Errorf("ReplaceAll = %q, want %q", got, "HK 01x")
	}
}

// The upstream subconverter README documents this exact selector shape.
func TestMatchDocumentedExclusionForm(t *testing.T) {
	m, err := Compile(`(^(?!.*(美国|日本)).*)`)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		"🇺🇸 美国 01":  false,
		"🇯🇵 日本 01":  false,
		"🇸🇬 新加坡 01": true,
	}
	for name, want := range cases {
		got, err := m.Match(name)
		if err != nil {
			t.Fatalf("Match(%q): %v", name, err)
		}
		if got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
}
