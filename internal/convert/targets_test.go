package convert

import (
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/generator"
)

func TestNormalizeTarget(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"clash", "clash"},
		{"Clash", "clash"},
		{"  singbox  ", "singbox"},
		{"clash.meta", "clash"},
		{"ClashMeta", "clash"},
		{"clashr", "clash"},
		{"sing-box", "singbox"},
		{"SING_BOX", "singbox"},
		{"surge", "surge"},
		{"shadow-rocket", "shadowrocket"},
		{"QUANX", "quanx"},
		{"quantumult-x", "quanx"},
		{"loon", "loon"},
		{"v2rayn", "v2ray"},
		{"mixed", "v2ray"},
		{"ss", "v2ray"},
		{"quan", "quan"}, // unknown values pass through unchanged
	}
	for _, c := range cases {
		if got := NormalizeTarget(c.raw); got != c.want {
			t.Errorf("NormalizeTarget(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestParseTarget(t *testing.T) {
	cases := []struct {
		raw  string
		name string
		ver  *generator.Version
		err  string
	}{
		// Plain names, no version part.
		{raw: "clash", name: "clash"},
		{raw: "  SINGBOX  ", name: "singbox"},
		{raw: "Sing-Box", name: "singbox"},
		{raw: "clash.meta", name: "clash"},
		{raw: "1", name: "1"}, // unknown name passes through; caller validates

		// name/version forms.
		{raw: "singbox/1.3.xx", name: "singbox", ver: &generator.Version{Major: 1, Minor: 3, Patch: 0}},
		{raw: "sing-box/1.13.11", name: "singbox", ver: &generator.Version{Major: 1, Minor: 13, Patch: 11}},
		{raw: "clash.meta/1.18", name: "clash", ver: &generator.Version{Major: 1, Minor: 18, Patch: 0}},
		{raw: "SINGBOX/1.2.3.4", name: "singbox", ver: &generator.Version{Major: 1, Minor: 2, Patch: 3}},
		{raw: " singbox / 1.3 ", name: "singbox", ver: &generator.Version{Major: 1, Minor: 3, Patch: 0}},
		{raw: "singbox/1.x", name: "singbox", ver: &generator.Version{Major: 1, Minor: 0, Patch: 0}},

		// Errors: a "/" with no usable numeric segment.
		{raw: "singbox/", err: `invalid target version ""`},
		{raw: "singbox/abc", err: `invalid target version "abc"`},
	}
	for _, c := range cases {
		name, ver, err := ParseTarget(c.raw)
		if c.err != "" {
			if err == nil || err.Error() != c.err {
				t.Errorf("ParseTarget(%q) err = %v, want %q", c.raw, err, c.err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTarget(%q) unexpected error: %v", c.raw, err)
			continue
		}
		if name != c.name {
			t.Errorf("ParseTarget(%q) name = %q, want %q", c.raw, name, c.name)
		}
		if !sameVersion(ver, c.ver) {
			t.Errorf("ParseTarget(%q) version = %+v, want %+v", c.raw, ver, c.ver)
		}
	}
}

func sameVersion(a, b *generator.Version) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func TestVersionAtLeast(t *testing.T) {
	cases := []struct {
		v        generator.Version
		maj, min int
		want     bool
	}{
		{generator.Version{Major: 1, Minor: 3}, 1, 3, true},
		{generator.Version{Major: 1, Minor: 3}, 1, 2, true},
		{generator.Version{Major: 1, Minor: 3}, 1, 4, false},
		{generator.Version{Major: 1, Minor: 3}, 2, 0, false},
		{generator.Version{Major: 1, Minor: 3}, 0, 9, true},
		{generator.Version{Major: 1, Minor: 3, Patch: 9}, 1, 3, true},  // patch ignored
		{generator.Version{Major: 1, Minor: 3, Patch: 9}, 1, 4, false}, // patch ignored
		{generator.Version{Major: 2, Minor: 0}, 1, 99, true},
		{generator.Version{Major: 0, Minor: 9}, 1, 0, false},
	}
	for _, c := range cases {
		if got := c.v.AtLeast(c.maj, c.min); got != c.want {
			t.Errorf("Version{%d,%d,%d}.AtLeast(%d,%d) = %v, want %v",
				c.v.Major, c.v.Minor, c.v.Patch, c.maj, c.min, got, c.want)
		}
	}
}
