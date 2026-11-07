package fetch

import (
	"reflect"
	"testing"
)

func TestUAPreset(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"clash.meta", "clash.meta", "clash.meta/1.18.0 mihomo/1.18.0", true},
		{"clash alias", "clash", "clash.meta/1.18.0 mihomo/1.18.0", true},
		{"mihomo alias", "mihomo", "clash.meta/1.18.0 mihomo/1.18.0", true},
		{"v2ray", "v2ray", "v2rayN/6.45", true},
		{"v2rayn alias", "v2rayn", "v2rayN/6.45", true},
		{"singbox", "singbox", "sing-box/1.3.0", true},
		{"sing-box alias", "sing-box", "sing-box/1.3.0", true},
		{"surge", "surge", "Surge/5.9.0", true},
		{"shadowrocket", "shadowrocket", "Shadowrocket/2.2.50", true},
		{"quanx", "quanx", "Quantumult X/1.0.30", true},
		{"loon", "loon", "Loon/3.2.4", true},
		{"uppercase tolerated", "CLASH.META", "clash.meta/1.18.0 mihomo/1.18.0", true},
		{"case + whitespace tolerated", "  Sing-Box\t", "sing-box/1.3.0", true},
		{"unknown name", "quantumultx", "", false},
		{"empty", "", "", false},
		{"whitespace only", "   ", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := UAPreset(tt.in)
			if ok != tt.ok || got != tt.want {
				t.Errorf("UAPreset(%q) = (%q, %v), want (%q, %v)", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestUAPresetNames(t *testing.T) {
	names := UAPresetNames()
	if len(names) == 0 {
		t.Fatal("UAPresetNames() is empty")
	}
	want := []string{"clash.meta", "loon", "quanx", "shadowrocket", "singbox", "surge", "v2ray"}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("UAPresetNames() = %v, want %v", names, want)
	}
	// The returned slice must be a copy: mutating it must not corrupt state.
	names[0] = "tampered"
	if got := UAPresetNames(); !reflect.DeepEqual(got, want) {
		t.Errorf("UAPresetNames() after caller mutation = %v, want %v", got, want)
	}
}
