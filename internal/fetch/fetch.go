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
	UserAgent       string        // default: clash.meta UA
	Proxy           string        // http(s):// or socks5:// upstream proxy URL
	FlareSolverrURL string        // e.g. http://127.0.0.1:8191/v1 (empty disables)
	Timeout         time.Duration // per-request timeout (default 30s)
	MaxRetries      int           // network retry attempts (default 2)

	// CacheTTL controls the in-memory TTL cache for successful GETs:
	//   0  => use defaultCacheTTL (300s)
	//   <0 => caching disabled
	//   >0 => that TTL
	CacheTTL time.Duration

	// Cache, when non-nil, is a shared cache injected by the caller (e.g. the
	// HTTP server reuses one cache across per-request Clients). When nil, New
	// creates a per-Client cache (unless caching is disabled).
	Cache *Cache
}

// Client fetches URLs applying the configured access strategy.
type Client struct {
	opts  Options
	http  *http.Client
	cache *Cache // nil when caching is disabled
}

const defaultUA = "clash.meta/1.18.0 mihomo/1.18.0"

// defaultCacheTTL is applied when Options.CacheTTL is zero.
const defaultCacheTTL = 300 * time.Second

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
	c := &Client{
		opts: opts,
		http: &http.Client{Transport: tr, Timeout: opts.Timeout, Jar: jar},
	}
	// Wire up caching unless explicitly disabled (CacheTTL < 0).
	if opts.CacheTTL >= 0 {
		ttl := opts.CacheTTL
		if ttl == 0 {
			ttl = defaultCacheTTL
		}
		if opts.Cache != nil {
			c.cache = opts.Cache
		} else {
			c.cache = NewCache(ttl)
		}
		c.cache.ttl = ttl
	}
	return c, nil
}

// Get retrieves target, transparently solving a Cloudflare challenge if one is
// detected and a FlareSolverr endpoint is configured. It honours the TTL cache.
func (c *Client) Get(ctx context.Context, target string) ([]byte, error) {
	body, _, err := c.GetWithMeta(ctx, target)
	return body, err
}

// GetWithMeta is like Get but also returns the response headers of the final
// (origin or FlareSolverr-replay) response. Callers use this to capture
// airport metadata such as the Subscription-Userinfo header.
//
// Caching: successful (200, non-empty) responses are cached by URL. Cached
// entries also retain their headers so repeated reads see Subscription-Userinfo.
// Pass a context value (see NoCache) is not used here; cache bypass is decided
// by the caller wiring a Client with caching disabled or by clearing the cache.
func (c *Client) GetWithMeta(ctx context.Context, target string) ([]byte, http.Header, error) {
	if c.cache != nil {
		if body, hdr, ok := c.cache.get(target); ok {
			return body, hdr, nil
		}
	}

	body, hdr, status, err := c.do(ctx, target, nil)
	if err == nil && !isCloudflareChallenge(status, body) {
		c.maybeCache(target, status, body, hdr)
		return body, hdr, nil
	}
	if err != nil && c.opts.FlareSolverrURL == "" {
		return nil, nil, err
	}
	if c.opts.FlareSolverrURL == "" {
		return nil, nil, fmt.Errorf("fetch %s: blocked by Cloudflare and no FlareSolverr configured (set fetch.flaresolverr_url; see docs/cloudflare.md)", target)
	}

	// Solve the challenge: obtain cf_clearance cookies + the UA FlareSolverr
	// used, then replay the request ourselves through the same egress.
	cookies, ua, ferr := c.solveCloudflare(ctx, target)
	if ferr != nil {
		return nil, nil, fmt.Errorf("fetch %s: cloudflare solve failed: %w", target, ferr)
	}
	body, hdr, status, err = c.do(ctx, target, &replay{cookies: cookies, userAgent: ua})
	if err != nil {
		return nil, nil, fmt.Errorf("fetch %s: replay after solve failed: %w", target, err)
	}
	c.maybeCache(target, status, body, hdr)
	return body, hdr, nil
}

// maybeCache stores successful (200, non-empty) responses if caching is on.
func (c *Client) maybeCache(target string, status int, body []byte, hdr http.Header) {
	if c.cache == nil || status != http.StatusOK || len(body) == 0 {
		return
	}
	c.cache.set(target, body, hdr)
}

// FlushCache clears all cached entries. Safe to call when caching is disabled.
func (c *Client) FlushCache() {
	if c.cache != nil {
		c.cache.Flush()
	}
}

type replay struct {
	cookies   string
	userAgent string
}

func (c *Client) do(ctx context.Context, target string, r *replay) ([]byte, http.Header, int, error) {
	var lastErr error
	for attempt := 0; attempt <= c.opts.MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, nil, 0, err
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
		return body, resp.Header, resp.StatusCode, nil
	}
	return nil, nil, 0, lastErr
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
