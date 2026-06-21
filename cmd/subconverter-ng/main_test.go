package main

import (
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
