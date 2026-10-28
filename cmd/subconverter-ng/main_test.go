package main

import (
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/config"
)

func TestSplitPipe(t *testing.T) {
	got := splitPipe(" a | b |  | c ")
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Errorf("splitPipe = %#v", got)
	}
	if len(splitPipe("")) != 0 {
		t.Error("empty -> no urls")
	}
}

func TestResolveUserAgent(t *testing.T) {
	// Explicit --ua wins over --source.
	if got, err := resolveUserAgent("MyCustomUA/1.0", "clash.meta"); err != nil || got != "MyCustomUA/1.0" {
		t.Errorf("ua priority: got (%q, %v), want (MyCustomUA/1.0, nil)", got, err)
	}
	// --ua is trimmed but otherwise used verbatim.
	if got, err := resolveUserAgent("  My UA/2.0  ", ""); err != nil || got != "My UA/2.0" {
		t.Errorf("ua trim: got (%q, %v), want (My UA/2.0, nil)", got, err)
	}
	// --source maps to its preset UA (trimmed, case-insensitive per fetch.UAPreset).
	if got, err := resolveUserAgent("", " clash.meta "); err != nil || got != "clash.meta/1.18.0 mihomo/1.18.0" {
		t.Errorf("source preset: got (%q, %v), want (clash.meta/1.18.0 mihomo/1.18.0, nil)", got, err)
	}
	// Unknown --source errors and names the supported presets.
	if _, err := resolveUserAgent("", "foo"); err == nil || !strings.Contains(err.Error(), "supported") {
		t.Errorf("unknown source: err = %v, want error mentioning supported presets", err)
	}
	// Both empty leaves the UA unset (fetch.New fills its default).
	if got, err := resolveUserAgent("   ", ""); err != nil || got != "" {
		t.Errorf("both empty: got (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestTriFromString(t *testing.T) {
	for _, on := range []string{"true", "1", "yes", "ON"} {
		if v := triFromString(on); v == nil || !*v {
			t.Errorf("triFromString(%q) should be true", on)
		}
	}
	for _, off := range []string{"false", "0", "no", "OFF"} {
		if v := triFromString(off); v == nil || *v {
			t.Errorf("triFromString(%q) should be false", off)
		}
	}
	for _, none := range []string{"", "maybe", " "} {
		if v := triFromString(none); v != nil {
			t.Errorf("triFromString(%q) should be nil, got %v", none, *v)
		}
	}
}

func TestNewHTTPServer(t *testing.T) {
	cfg := config.Default()
	cfg.Listen = ":12345"
	srv := newHTTPServer(cfg)
	if srv.Addr != ":12345" || srv.Handler == nil {
		t.Errorf("server misconfigured: addr=%q handler=%v", srv.Addr, srv.Handler)
	}
	if srv.ReadHeaderTimeout == 0 || srv.WriteTimeout == 0 {
		t.Error("timeouts not set")
	}
}
