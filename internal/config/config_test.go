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
	if !c.RateLimit.Enabled || c.RateLimit.RequestsPerMinute != 30 || c.RateLimit.Burst != 10 {
		t.Errorf("ratelimit defaults wrong: %+v", c.RateLimit)
	}
	if c.DefaultConfigURL != "" {
		t.Errorf("default config URL should be empty by default, got %q", c.DefaultConfigURL)
	}
}

func TestInsertDefaultsAndEnv(t *testing.T) {
	c := Default()
	if !c.Insert.Enabled || !c.Insert.Prepend || len(c.Insert.URLs) != 0 {
		t.Errorf("insert defaults wrong: %+v", c.Insert)
	}

	t.Setenv("SUBNG_INSERT_URLS", "https://a/x , https://b/y")
	t.Setenv("SUBNG_INSERT_PREPEND", "false")
	t.Setenv("SUBNG_INSERT_ENABLED", "false")
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Insert.Enabled || c.Insert.Prepend {
		t.Errorf("insert env bools not applied: %+v", c.Insert)
	}
	if len(c.Insert.URLs) != 2 || c.Insert.URLs[0] != "https://a/x" || c.Insert.URLs[1] != "https://b/y" {
		t.Errorf("insert URLs env not parsed/trimmed: %+v", c.Insert.URLs)
	}
}

func TestDefaultConfigURLFromFileAndEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.yaml")
	yaml := "default_config_url: https://example.com/config.init\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.DefaultConfigURL != "https://example.com/config.init" {
		t.Errorf("default_config_url from file = %q", c.DefaultConfigURL)
	}

	// Env overrides the file.
	t.Setenv("SUBNG_DEFAULT_CONFIG_URL", "https://env.example.com/other.init")
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.DefaultConfigURL != "https://env.example.com/other.init" {
		t.Errorf("default_config_url from env = %q", c.DefaultConfigURL)
	}

	// Blank/whitespace env must not wipe the file value.
	t.Setenv("SUBNG_DEFAULT_CONFIG_URL", "   ")
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.DefaultConfigURL != "https://example.com/config.init" {
		t.Errorf("blank env wiped file value: %q", c.DefaultConfigURL)
	}
}

func TestRateLimitDefaultsBackfilled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.yaml")
	// Toggle enabled off but omit the numeric fields: defaults must backfill.
	yaml := "ratelimit:\n  enabled: false\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.RateLimit.Enabled {
		t.Error("enabled should be false from file")
	}
	if c.RateLimit.RequestsPerMinute != 30 || c.RateLimit.Burst != 10 {
		t.Errorf("numeric defaults not backfilled: %+v", c.RateLimit)
	}
}

func TestRateLimitFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.yaml")
	yaml := "ratelimit:\n  enabled: true\n  requests_per_minute: 100\n  burst: 25\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.RateLimit.Enabled || c.RateLimit.RequestsPerMinute != 100 || c.RateLimit.Burst != 25 {
		t.Errorf("ratelimit from file wrong: %+v", c.RateLimit)
	}
}

func TestRateLimitEnvOverrides(t *testing.T) {
	t.Setenv("SUBNG_RATELIMIT_ENABLED", "false")
	t.Setenv("SUBNG_RATELIMIT_RPM", "120")
	t.Setenv("SUBNG_RATELIMIT_BURST", "40")

	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.RateLimit.Enabled {
		t.Error("SUBNG_RATELIMIT_ENABLED=false not applied")
	}
	if c.RateLimit.RequestsPerMinute != 120 || c.RateLimit.Burst != 40 {
		t.Errorf("ratelimit env not applied: %+v", c.RateLimit)
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

func TestCacheTTLFromFileAndEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.yaml")
	yaml := "fetch:\n  cache_ttl: 120s\n"
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Fetch.CacheTTL != 120*time.Second {
		t.Errorf("cache_ttl from file = %v, want 120s", c.Fetch.CacheTTL)
	}

	// Env overrides the file.
	t.Setenv("SUBNG_CACHE_TTL", "45s")
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Fetch.CacheTTL != 45*time.Second {
		t.Errorf("cache_ttl from env = %v, want 45s", c.Fetch.CacheTTL)
	}
}

func TestConfig_Validate(t *testing.T) {
	// 1. Default config is valid
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}

	// 2. Empty listen address
	cfg.Listen = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty listen address")
	}
	cfg.Listen = ":25500"

	// 3. Negative timeout
	cfg.Fetch.Timeout = -1
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for negative timeout")
	}
	cfg.Fetch.Timeout = 30 * time.Second

	// 4. Negative rate limit
	cfg.RateLimit.RequestsPerMinute = -1
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for negative RPM")
	}
	cfg.RateLimit.RequestsPerMinute = 30

	// 5. Invalid trusted proxy
	cfg.RateLimit.TrustedProxies = []string{"10.0.0.0/8", "not-an-ip-or-cidr"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid trusted proxy")
	}
	cfg.RateLimit.TrustedProxies = []string{"10.0.0.0/8", "192.168.1.1"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid trusted proxies failed: %v", err)
	}

	// 6. Invalid proxy scheme
	cfg.Fetch.Proxy = "ftp://proxy.com"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for ftp proxy scheme")
	}
	cfg.Fetch.Proxy = "socks5://proxy.com:1080"
	if err := cfg.Validate(); err != nil {
		t.Errorf("socks5 proxy scheme should be valid: %v", err)
	}

	// 7. Invalid flaresolverr URL
	cfg.Fetch.FlareSolverrURL = "ftp://flaresolverr:8191"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for non-http flaresolverr url")
	}
	cfg.Fetch.FlareSolverrURL = "http://flaresolverr:8191/v1"

	// 8. Invalid default config URL
	cfg.DefaultConfigURL = "://bad"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for bad default config url")
	}
}
