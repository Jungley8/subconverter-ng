package config

import (
	"errors"
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
		{"proxy password", "socks5://user:s3cret@127.0.0.1:1080", "socks5://***@127.0.0.1:1080"},
		{"username only", "socks5://user@127.0.0.1:1080", "socks5://***@127.0.0.1:1080"},
		{"query token", "https://air.com/api/v1/client/subscribe?token=abc123", "https://air.com/api/v1/client/subscribe?token=***"},
		{"multi query", "https://air.com/sub?token=abc&flag=1", "https://air.com/sub?token=***&flag=***"},
		{"creds and query", "https://u:p@air.com/sub?token=abc", "https://***@air.com/sub?token=***"},
		{"trojan password", "trojan://mypassword@127.0.0.1:443?peer=example.com", "trojan://***@127.0.0.1:443?peer=***"},
		{"vless uuid", "vless://550e8400-e29b-41d4-a716-446655440000@127.0.0.1:443", "vless://***@127.0.0.1:443"},
		{"hysteria2 auth", "hysteria2://mytoken@127.0.0.1:443", "hysteria2://***@127.0.0.1:443"},
		{"wireguard key", "wireguard://privatekey@127.0.0.1:51820", "wireguard://***@127.0.0.1:51820"},
		{"ss base64", "ss://Y2hhY2hhMjA6cGFzc3dvcmQ@127.0.0.1:8388", "ss://***@127.0.0.1:8388"},
		{"vmess payload", "vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjoiNDQzIn0=", "vmess://***"},
		{"ssr payload", "ssr://ZXhhbXBsZS5jb206ODg4ODpvcmlnaW46bm9uZQ==", "ssr://***"},
		{"password with at", "http://user:p@ssword@host.com/path", "http://***@host.com/path"},
		{"fragment with at", "trojan://1.2.3.4:443#user@domain", "trojan://1.2.3.4:443#user@domain"},
		{"trojan pass with fragment at", "trojan://mypass@1.2.3.4:443#user@domain", "trojan://***@1.2.3.4:443#user@domain"},
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
		{"creds in path sub", "https://u:p@air.com/s/tok", "https://***@air.com/***"},
		{"vmess sub", "vmess://eyJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjoiNDQzIn0=", "vmess://***"},
		{"ssr sub", "ssr://ZXhhbXBsZS5jb206ODg4ODpvcmlnaW46bm9uZQ==", "ssr://***"},
		{"fragment sub", "https://air.com#secret_token", "https://air.com/***"},
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

func TestRedactStringAndError(t *testing.T) {
	rawErr := "fetch https://air.com/sub?token=s3cret: unexpected status 502"
	redacted := RedactString(rawErr)
	if strings.Contains(redacted, "s3cret") {
		t.Fatalf("RedactString leaked secret: %s", redacted)
	}
	if !strings.Contains(redacted, "https://air.com/sub?token=***: unexpected status 502") {
		t.Errorf("unexpected RedactString result: %s", redacted)
	}

	err := RedactError(errors.New("dial https://user:pass@air.com/api?key=123 failed"))
	if strings.Contains(err.Error(), "pass") || strings.Contains(err.Error(), "123") {
		t.Fatalf("RedactError leaked credentials: %v", err)
	}

	socksErr := RedactError(errors.New("dial socks5://myuser:mypassword@proxy.host:1080: connect refused"))
	if strings.Contains(socksErr.Error(), "mypassword") || strings.Contains(socksErr.Error(), "myuser") {
		t.Fatalf("RedactError leaked socks5 credentials: %v", socksErr)
	}
	if !strings.Contains(socksErr.Error(), "socks5://***@proxy.host:1080") {
		t.Errorf("socks5 creds not redacted properly: %v", socksErr)
	}

	trojanErr := RedactError(errors.New("connect trojan://topsecret@proxy.host:443 failed"))
	if strings.Contains(trojanErr.Error(), "topsecret") {
		t.Fatalf("RedactError leaked trojan secret: %v", trojanErr)
	}
	if !strings.Contains(trojanErr.Error(), "trojan://***@proxy.host:443") {
		t.Errorf("trojan creds not redacted properly: %v", trojanErr)
	}

	vmessErr := RedactError(errors.New("connect vmess://eyJhZGQiOiIxMjcuMC4wLjEifQ== failed"))
	if strings.Contains(vmessErr.Error(), "eyJhZGQiOiIxMjcuMC4wLjEifQ==") {
		t.Fatalf("RedactError leaked vmess payload: %v", vmessErr)
	}
	if !strings.Contains(vmessErr.Error(), "vmess://***") {
		t.Errorf("vmess payload not redacted properly: %v", vmessErr)
	}
}

func TestSummaryNewFields(t *testing.T) {
	cfg := Default()
	cfg.APIAccessToken = "my-secret-token"
	cfg.Fetch.AllowPrivateIPs = true
	cfg.RateLimit.TrustedProxies = []string{"10.0.0.0/8", "127.0.0.1"}

	out := cfg.Summary()
	if strings.Contains(out, "my-secret-token") {
		t.Errorf("Summary leaked APIAccessToken: %s", out)
	}
	if !strings.Contains(out, "api token:      configured") {
		t.Errorf("Summary missing api token mention: %s", out)
	}
	if !strings.Contains(out, "private ips:    allowed") {
		t.Errorf("Summary missing private ips mention: %s", out)
	}
	if !strings.Contains(out, "trusted proxies: 10.0.0.0/8, 127.0.0.1") {
		t.Errorf("Summary missing trusted proxies: %s", out)
	}
}
