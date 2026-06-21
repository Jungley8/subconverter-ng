// Package fetch retrieves remote resources (subscriptions, rulesets, base
// configs) with three concerns airports impose on us:
//
//  1. User-Agent gating — many panels only return nodes for a clash-like UA.
//  2. Upstream proxy — some airports are only reachable through a proxy; the
//     converter host itself may be unable to reach them directly.
//  3. Cloudflare challenge — when a "Just a moment" interstitial is detected we
//     fall back to a FlareSolverr instance to obtain a cf_clearance cookie and
//     replay the request through the same egress.
//
// See docs/proxy.md and docs/cloudflare.md.
package fetch

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// Options configures a single Client. Zero values fall back to sensible
// defaults in New.
type Options struct {
	UserAgent      string        // default: clash.meta UA
	Proxy          string        // http(s):// or socks5:// upstream proxy URL
	FlareSolverrURL string       // e.g. http://127.0.0.1:8191/v1 (empty disables)
	Timeout        time.Duration // per-request timeout (default 30s)
	MaxRetries     int           // network retry attempts (default 2)
}

// Client fetches URLs applying the configured access strategy.
type Client struct {
	opts Options
	http *http.Client
}

const defaultUA = "clash.meta/1.18.0 mihomo/1.18.0"

// New builds a Client. proxyOverride, when non-empty, replaces opts.Proxy
// (used for per-request &proxy= overrides).
func New(opts Options) (*Client, error) {
	if opts.UserAgent == "" {
		opts.UserAgent = defaultUA
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.MaxRetries == 0 {
		opts.MaxRetries = 2
	}
	tr := &http.Transport{
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        50,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}
	if opts.Proxy != "" {
		// An explicit proxy (config / SUBNG_PROXY / --proxy / &proxy=) wins and
		// also gets forwarded to FlareSolverr so the egress stays consistent.
		pu, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy %q: %w", opts.Proxy, err)
		}
		tr.Proxy = http.ProxyURL(pu)
	} else {
		// Otherwise honour the standard HTTP_PROXY / HTTPS_PROXY / NO_PROXY
		// (and lowercase) environment variables, like every other Go HTTP tool.
		tr.Proxy = http.ProxyFromEnvironment
	}
	jar, _ := cookiejar.New(nil)
	return &Client{
		opts: opts,
		http: &http.Client{Transport: tr, Timeout: opts.Timeout, Jar: jar},
	}, nil
}

// Get retrieves target, transparently solving a Cloudflare challenge if one is
// detected and a FlareSolverr endpoint is configured.
func (c *Client) Get(ctx context.Context, target string) ([]byte, error) {
	body, status, err := c.do(ctx, target, nil)
	if err == nil && !isCloudflareChallenge(status, body) {
		return body, nil
	}
	if err != nil && c.opts.FlareSolverrURL == "" {
		return nil, err
	}
	if c.opts.FlareSolverrURL == "" {
		return nil, fmt.Errorf("fetch %s: blocked by Cloudflare and no FlareSolverr configured (set fetch.flaresolverr_url; see docs/cloudflare.md)", target)
	}

	// Solve the challenge: obtain cf_clearance cookies + the UA FlareSolverr
	// used, then replay the request ourselves through the same egress.
	cookies, ua, ferr := c.solveCloudflare(ctx, target)
	if ferr != nil {
		return nil, fmt.Errorf("fetch %s: cloudflare solve failed: %w", target, ferr)
	}
	body, _, err = c.do(ctx, target, &replay{cookies: cookies, userAgent: ua})
	if err != nil {
		return nil, fmt.Errorf("fetch %s: replay after solve failed: %w", target, err)
	}
	return body, nil
}

type replay struct {
	cookies   string
	userAgent string
}

func (c *Client) do(ctx context.Context, target string, r *replay) ([]byte, int, error) {
	var lastErr error
	for attempt := 0; attempt <= c.opts.MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, 0, err
		}
		ua := c.opts.UserAgent
		if r != nil {
			if r.userAgent != "" {
				ua = r.userAgent
			}
			if r.cookies != "" {
				req.Header.Set("Cookie", r.cookies)
			}
		}
		req.Header.Set("User-Agent", ua)
		req.Header.Set("Accept", "*/*")

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, rerr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if rerr != nil {
			lastErr = rerr
			continue
		}
		return body, resp.StatusCode, nil
	}
	return nil, 0, lastErr
}

// isCloudflareChallenge detects the JS interstitial / managed-challenge page.
func isCloudflareChallenge(status int, body []byte) bool {
	if status != http.StatusForbidden && status != http.StatusServiceUnavailable {
		// Challenges sometimes return 200 with the interstitial body.
		if status != http.StatusOK {
			return false
		}
	}
	s := string(body)
	if len(s) > 8192 {
		s = s[:8192]
	}
	for _, marker := range []string{
		"Just a moment...",
		"Attention Required! | Cloudflare",
		"cf-browser-verification",
		"_cf_chl_opt",
		"challenge-platform",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}
