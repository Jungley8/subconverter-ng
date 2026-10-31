package main

import (
	"context"
	"os"
	"path/filepath"
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

	// Non-existent file error
	_, err = cf.Get(ctx, "non_existent_file.txt")
	if err == nil {
		t.Fatal("expected error for non-existent file, got nil")
	}
	if !strings.Contains(err.Error(), "read file non_existent_file.txt:") {
		t.Errorf("error = %q, expected read file prefix", err)
	}
}

func TestCmdConvert_ExcludeProtocol(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "out.yaml")
	shareLinks := "ss://YWVzLTI1Ni1nY206cGFzc3dvcmRAMTI3LjAuMC4xOjgzODg=#NodeSS|trojan://pass@127.0.0.1:443?sni=example.com#NodeTrojan"

	args := []string{
		"--url", shareLinks,
		"--exclude-protocol", "trojan",
		"-o", outPath,
	}
	cmdConvert(args)

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "NodeSS") {
		t.Errorf("expected output to contain NodeSS, got: %s", content)
	}
	if strings.Contains(content, "NodeTrojan") {
		t.Errorf("expected output to exclude NodeTrojan, got: %s", content)
	}

	// Test repeatable flags and alias --filter-type
	outPath2 := filepath.Join(t.TempDir(), "out2.yaml")
	args2 := []string{
		"--url", shareLinks,
		"--exclude-protocol", "trojan",
		"--filter-type", "ss",
		"-o", outPath2,
	}
	cmdConvert(args2)

	data2, err := os.ReadFile(outPath2)
	if err != nil {
		t.Fatalf("failed to read output2 file: %v", err)
	}
	content2 := string(data2)
	if strings.Contains(content2, "NodeSS") || strings.Contains(content2, "NodeTrojan") {
		t.Errorf("expected both nodes to be excluded, got: %s", content2)
	}
}
