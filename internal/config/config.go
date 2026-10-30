// Package config holds the application-level configuration: where the server
// listens and the default fetch (access) settings. It is intentionally small —
// per-request behaviour is driven by URL parameters, not this file.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Fetch struct {
	UserAgent       string        `yaml:"user_agent"`
	Proxy           string        `yaml:"proxy"`            // default upstream proxy for all fetches
	FlareSolverrURL string        `yaml:"flaresolverr_url"` // e.g. http://127.0.0.1:8191/v1
	Timeout         time.Duration `yaml:"timeout"`

	// CacheTTL is the in-memory TTL cache lifetime for successful remote GETs
	// (subscriptions + rulesets), keyed by URL. Default 300s when zero. Set to a
	// negative value to disable caching.
	CacheTTL time.Duration `yaml:"cache_ttl"`

	// AllowPrivateIPs controls SSRF protection. By default (false), requests to
	// private, loopback, multicast, or link-local IPs are blocked, and redirects
	// to them are rejected.
	AllowPrivateIPs bool `yaml:"allow_private_ips"`
}

// RateLimit configures per-client-IP rate limiting on the expensive /sub
// endpoint. When Enabled is false the limiter is a no-op pass-through.
type RateLimit struct {
	Enabled           bool     `yaml:"enabled"`
	RequestsPerMinute int      `yaml:"requests_per_minute"`
	Burst             int      `yaml:"burst"`
	TrustedProxies    []string `yaml:"trusted_proxies"` // CIDRs or IPs of reverse proxies whose XFF/X-Real-IP are trusted
}

// Insert configures the insert_url feature: a fixed set of node URLs the server
// merges into every conversion (subconverter's insert_url). Prepend controls
// ordering relative to the user's subscription nodes; Enabled is the default
// that the &insert= URL param can override per request.
type Insert struct {
	URLs    []string `yaml:"urls"`
	Prepend bool     `yaml:"prepend"`
	Enabled bool     `yaml:"enabled"`
}

type Config struct {
	Listen         string    `yaml:"listen"`
	APIAccessToken string    `yaml:"api_access_token"` // optional token protecting /sub and /flushcache
	Fetch          Fetch     `yaml:"fetch"`
	RateLimit      RateLimit `yaml:"ratelimit"`
	Insert         Insert    `yaml:"insert"`

	// DefaultConfigURL is the remote external INI config (the &config=
	// groups/rules source) used when a /sub request omits &config=. URL only.
	// An explicit &config= param always wins. When set but the fetch fails,
	// the request fails instead of silently falling back to an empty config.
	DefaultConfigURL string `yaml:"default_config_url"`
}

// Default returns a config with sane defaults applied.
func Default() *Config {
	return &Config{
		Listen: ":25500",
		Fetch:  Fetch{Timeout: 30 * time.Second},
		RateLimit: RateLimit{
			Enabled:           true,
			RequestsPerMinute: 30,
			Burst:             10,
		},
		// insert_url defaults: feature on (no-op until URLs are configured),
		// inserted nodes placed before the user's subscription nodes.
		Insert: Insert{
			Prepend: true,
			Enabled: true,
		},
	}
}

// Load reads a YAML config file (if path is non-empty and exists) and then
// applies environment overrides. Missing file is not an error.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	applyEnv(cfg)
	if cfg.Fetch.Timeout == 0 {
		cfg.Fetch.Timeout = 30 * time.Second
	}
	// Backfill rate-limit defaults for values left unset (e.g. a config file
	// that toggles `enabled` but omits the numeric fields).
	if cfg.RateLimit.RequestsPerMinute == 0 {
		cfg.RateLimit.RequestsPerMinute = 30
	}
	if cfg.RateLimit.Burst == 0 {
		cfg.RateLimit.Burst = 10
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks for configuration errors and enforces fail-closed guarantees.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.Listen) == "" {
		return errors.New("config: listen address cannot be empty")
	}
	if c.Fetch.Timeout < 0 {
		return errors.New("config: fetch.timeout cannot be negative")
	}
	if c.RateLimit.RequestsPerMinute < 0 {
		return errors.New("config: ratelimit.requests_per_minute cannot be negative")
	}
	if c.RateLimit.Burst < 0 {
		return errors.New("config: ratelimit.burst cannot be negative")
	}
	for _, raw := range c.RateLimit.TrustedProxies {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if _, err := netip.ParsePrefix(trimmed); err != nil {
			if _, err := netip.ParseAddr(trimmed); err != nil {
				return fmt.Errorf("config: invalid trusted_proxies entry %q: must be valid IP or CIDR", raw)
			}
		}
	}
	if c.Fetch.Proxy != "" {
		u, err := url.Parse(c.Fetch.Proxy)
		if err != nil {
			return fmt.Errorf("config: invalid fetch.proxy: %w", err)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" && scheme != "socks5" && scheme != "socks5h" {
			return fmt.Errorf("config: unsupported scheme %q for fetch.proxy (must be http, https, socks5, or socks5h)", scheme)
		}
	}
	if c.Fetch.FlareSolverrURL != "" {
		u, err := url.Parse(c.Fetch.FlareSolverrURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("config: invalid fetch.flaresolverr_url %q", c.Fetch.FlareSolverrURL)
		}
	}
	if c.DefaultConfigURL != "" {
		u, err := url.Parse(c.DefaultConfigURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("config: invalid default_config_url %q", c.DefaultConfigURL)
		}
	}
	return nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("SUBNG_LISTEN"); v != "" {
		cfg.Listen = v
	}
	if v := os.Getenv("SUBNG_PROXY"); v != "" {
		cfg.Fetch.Proxy = v
	}
	if v := os.Getenv("SUBNG_FLARESOLVERR_URL"); v != "" {
		cfg.Fetch.FlareSolverrURL = v
	}
	if v := os.Getenv("SUBNG_USER_AGENT"); v != "" {
		cfg.Fetch.UserAgent = v
	}
	if v := os.Getenv("SUBNG_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Fetch.CacheTTL = d
		}
	}
	if v := os.Getenv("SUBNG_RATELIMIT_ENABLED"); v != "" {
		if b, err := parseBool(v); err == nil {
			cfg.RateLimit.Enabled = b
		}
	}
	if v := os.Getenv("SUBNG_RATELIMIT_RPM"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.RequestsPerMinute = n
		}
	}
	if v := os.Getenv("SUBNG_RATELIMIT_BURST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.Burst = n
		}
	}
	if v := os.Getenv("SUBNG_INSERT_URLS"); v != "" {
		var urls []string
		for _, u := range strings.Split(v, ",") {
			if u = strings.TrimSpace(u); u != "" {
				urls = append(urls, u)
			}
		}
		cfg.Insert.URLs = urls
	}
	if v := os.Getenv("SUBNG_INSERT_PREPEND"); v != "" {
		if b, err := parseBool(v); err == nil {
			cfg.Insert.Prepend = b
		}
	}
	if v := os.Getenv("SUBNG_INSERT_ENABLED"); v != "" {
		if b, err := parseBool(v); err == nil {
			cfg.Insert.Enabled = b
		}
	}
	if v := os.Getenv("SUBNG_API_ACCESS_TOKEN"); v != "" {
		cfg.APIAccessToken = v
	}
	if v := os.Getenv("SUBNG_ALLOW_PRIVATE_IPS"); v != "" {
		if b, err := parseBool(v); err == nil {
			cfg.Fetch.AllowPrivateIPs = b
		}
	}
	if v := os.Getenv("SUBNG_TRUSTED_PROXIES"); v != "" {
		var proxies []string
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				proxies = append(proxies, p)
			}
		}
		cfg.RateLimit.TrustedProxies = proxies
	}
	if v := strings.TrimSpace(os.Getenv("SUBNG_DEFAULT_CONFIG_URL")); v != "" {
		cfg.DefaultConfigURL = v
	}
}

// parseBool accepts the common truthy/falsey spellings in addition to those
// understood by strconv.ParseBool.
func parseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	}
	return strconv.ParseBool(v)
}
