package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	c := Default()
	if c.Listen != ":25500" || c.Fetch.Timeout != 30*time.Second {
		t.Errorf("defaults wrong: %+v", c)
	}
}

func TestLoadMissingFileUsesDefaults(t *testing.T) {
	c, err := Load("/nonexistent/path/app.yaml")
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if c.Listen != ":25500" {
		t.Errorf("listen = %q", c.Listen)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.yaml")
	yaml := "listen: \":9999\"\nfetch:\n  proxy: socks5://127.0.0.1:1080\n  flaresolverr_url: http://fs:8191/v1\n  timeout: 15s\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":9999" || c.Fetch.Proxy != "socks5://127.0.0.1:1080" {
		t.Errorf("file not loaded: %+v", c)
	}
	if c.Fetch.Timeout != 15*time.Second || c.Fetch.FlareSolverrURL != "http://fs:8191/v1" {
		t.Errorf("fetch fields wrong: %+v", c.Fetch)
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("SUBNG_LISTEN", ":7000")
	t.Setenv("SUBNG_PROXY", "http://envproxy:8080")
	t.Setenv("SUBNG_FLARESOLVERR_URL", "http://envfs:8191/v1")
	t.Setenv("SUBNG_USER_AGENT", "env-ua")

	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":7000" || c.Fetch.Proxy != "http://envproxy:8080" {
		t.Errorf("env not applied: %+v", c)
	}
	if c.Fetch.FlareSolverrURL != "http://envfs:8191/v1" || c.Fetch.UserAgent != "env-ua" {
		t.Errorf("env fetch not applied: %+v", c.Fetch)
	}
}
