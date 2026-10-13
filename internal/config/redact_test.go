package config

import (
	"strings"
	"testing"
	"time"
)

func TestRedactURL(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"empty", "", ""},
		{"no secrets", "http://127.0.0.1:7890", "http://127.0.0.1:7890"},
		{"proxy password", "socks5://user:s3cret@127.0.0.1:1080", "socks5://user:***@127.0.0.1:1080"},
		{"username only", "socks5://user@127.0.0.1:1080", "socks5://user@127.0.0.1:1080"},
		{"query token", "https://air.com/api/v1/client/subscribe?token=abc123", "https://air.com/api/v1/client/subscribe?token=***"},
		{"multi query", "https://air.com/sub?token=abc&flag=1", "https://air.com/sub?token=***&flag=***"},
		{"creds and query", "https://u:p@air.com/sub?token=abc", "https://u:***@air.com/sub?token=***"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RedactURL(c.in); got != c.want {
				t.Errorf("RedactURL(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestRedactSubURL(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"path token", "https://relay.example.com/s/MyPrivatePath", "https://relay.example.com/***"},
		{"query token", "https://air.com/api/v1/client/subscribe?token=abc", "https://air.com/***"},
		{"host only", "https://air.com", "https://air.com"},
		{"trailing slash", "https://air.com/", "https://air.com"},
		{"creds in path sub", "https://u:p@air.com/s/tok", "https://u:***@air.com/***"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RedactSubURL(c.in); got != c.want {
				t.Errorf("RedactSubURL(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestRedactSubURLNeverLeaksPathSecret(t *testing.T) {
	const secret = "MyPrivatePath9999"
	for _, in := range []string{
		"https://relay.example.com/s/" + secret,
		"https://air.com/sub/" + secret + "?x=1",
	} {
		if got := RedactSubURL(in); strings.Contains(got, secret) {
			t.Errorf("RedactSubURL(%q) leaked secret: %q", in, got)
		}
	}
}

func TestRedactURLNeverLeaksSecret(t *testing.T) {
	const secret = "s3cretToken9999"
	for _, in := range []string{
		"socks5://user:" + secret + "@host:1080",
		"https://air.com/sub?token=" + secret,
		"not a url " + secret, // unparseable, masked in the middle
	} {
		if got := RedactURL(in); strings.Contains(got, secret) {
			t.Errorf("RedactURL(%q) leaked secret: %q", in, got)
		}
	}
}

func TestSummaryRedactsAndCoversFields(t *testing.T) {
	cfg := Default()
	cfg.Fetch.Proxy = "socks5://user:topsecret@127.0.0.1:1080"
	cfg.Fetch.FlareSolverrURL = "http://flaresolverr:8191/v1"
	cfg.Fetch.Timeout = 30 * time.Second
	cfg.Insert.URLs = []string{"https://air.com/sub?token=leakme"}
	cfg.DefaultConfigURL = "https://rules.example.com/config.init?token=leakme-too"

	out := cfg.Summary()

	if strings.Contains(out, "topsecret") || strings.Contains(out, "leakme") {
		t.Fatalf("Summary leaked a secret:\n%s", out)
	}
	for _, want := range []string{"listen:", "user-agent:", "upstream proxy:", "flaresolverr:", "rate limit:", "insert urls:", "default config:"} {
		if !strings.Contains(out, want) {
			t.Errorf("Summary missing %q field:\n%s", want, out)
		}
	}
}

func TestSummaryDefaultConfigUnset(t *testing.T) {
	// Without a default config URL the banner must say so explicitly, so an
	// operator does not mistake an empty summary for a loaded value.
	out := Default().Summary()
	if !strings.Contains(out, "default config:") {
		t.Fatalf("Summary missing default config line:\n%s", out)
	}
	if !strings.Contains(out, "&config=") {
		t.Errorf("unset default config should hint at per-request &config=:\n%s", out)
	}
}
