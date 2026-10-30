package main

import (
	"context"
	"os"
	"path/filepath"
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

func TestCLIFetcher_LocalFileAndStdin(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "sub.txt")
	content := []byte("ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTI3LjAuMC4xOjgzODg=#LocalNode\n")
	if err := os.WriteFile(tmpFile, content, 0o644); err != nil {
		t.Fatal(err)
	}

	cf := newCLIFetcher(nil)
	ctx := context.Background()

	// Read relative/absolute path
	got, err := cf.Get(ctx, tmpFile)
	if err != nil {
		t.Fatalf("failed to read local file: %v", err)
	}
	if string(got) != string(content) {
		t.Errorf("got %q, want %q", got, content)
	}

	// Read file:// URI
	gotURI, err := cf.Get(ctx, "file://"+tmpFile)
	if err != nil {
		t.Fatalf("failed to read file://: %v", err)
	}
	if string(gotURI) != string(content) {
		t.Errorf("got %q, want %q", gotURI, content)
	}

	// Stdin simulation
	cfStdin := newCLIFetcher(nil)
	cfStdin.stdinData = []byte("stdin-content")
	cfStdin.stdinRead = true
	gotStdin, err := cfStdin.Get(ctx, "-")
	if err != nil {
		t.Fatalf("failed to read stdin: %v", err)
	}
	if string(gotStdin) != "stdin-content" {
		t.Errorf("got %q, want %q", gotStdin, "stdin-content")
	}
}
