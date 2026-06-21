// Package config holds the application-level configuration: where the server
// listens and the default fetch (access) settings. It is intentionally small —
// per-request behaviour is driven by URL parameters, not this file.
package config

import (
	"os"
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
}

type Config struct {
	Listen string `yaml:"listen"`
	Fetch  Fetch  `yaml:"fetch"`
}

// Default returns a config with sane defaults applied.
func Default() *Config {
	return &Config{
		Listen: ":25500",
		Fetch:  Fetch{Timeout: 30 * time.Second},
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
	return cfg, nil
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
}
