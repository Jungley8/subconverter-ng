package config

import (
	"fmt"
	"strings"
)

// RedactURL returns a display-safe form of a URL for logging. It masks the
// password in any user:pass@ credential and replaces every query-parameter
// value with "***" — subscription tokens, API keys and the like live in the
// userinfo and query string. Values without a scheme are treated as opaque and
// masked in the middle, so a stray secret never reaches the logs verbatim.
//
// It works on the raw string (not net/url) on purpose: round-tripping through
// url.URL re-encodes the "***" mask into an unreadable %2A%2A%2A.
func RedactURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		return maskMiddle(raw) // not a URL we can structurally parse
	}
	base, query := raw, ""
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		base, query = raw[:i], raw[i+1:]
	}
	base = redactUserinfo(base)
	if query != "" {
		return base + "?" + maskQuery(query)
	}
	return base
}

// RedactSubURL is a stricter redaction for subscription-style links (insert_url
// sources), where the secret token may sit anywhere in the path or query — not
// just the userinfo/query. It keeps the scheme and host for recognisability and
// masks everything after the host.
func RedactSubURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		return maskMiddle(raw)
	}
	base := raw
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		base = raw[:i]
	}
	base = redactUserinfo(base)
	sep := strings.Index(base, "://")
	rest := base[sep+3:]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		if rest[i:] == "/" { // bare trailing slash carries no secret
			return base[:sep+3] + rest[:i]
		}
		return base[:sep+3] + rest[:i] + "/***"
	}
	if len(base) < len(raw) { // had a query but no path
		return base + "/***"
	}
	return base
}

// redactUserinfo masks the password in a scheme://user:pass@host... prefix,
// leaving the username visible. The '@' must precede the path's first '/'.
func redactUserinfo(base string) string {
	sep := strings.Index(base, "://")
	if sep < 0 {
		return base
	}
	rest := base[sep+3:]
	at := strings.IndexByte(rest, '@')
	if at < 0 {
		return base
	}
	if slash := strings.IndexByte(rest, '/'); slash >= 0 && slash < at {
		return base // '@' lives in the path, not the userinfo
	}
	userinfo := rest[:at]
	if colon := strings.IndexByte(userinfo, ':'); colon >= 0 {
		userinfo = userinfo[:colon+1] + "***"
	}
	return base[:sep+3] + userinfo + rest[at:]
}

// maskQuery replaces each query value with "***", preserving keys and order.
func maskQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	for i, p := range parts {
		if p == "" {
			continue
		}
		if eq := strings.IndexByte(p, '='); eq >= 0 {
			parts[i] = p[:eq+1] + "***"
		}
	}
	return strings.Join(parts, "&")
}

// maskMiddle keeps a short prefix/suffix for recognisability and hides the rest.
func maskMiddle(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "***" + s[len(s)-2:]
}

// Summary returns a multi-line, human-readable view of the effective config
// with secrets redacted (see RedactURL). It is meant for the startup banner;
// each line is indented two spaces and the block ends with a trailing newline.
func (c *Config) Summary() string {
	var b strings.Builder

	ua := c.Fetch.UserAgent
	if ua == "" {
		ua = "(built-in default)"
	}
	fmt.Fprintf(&b, "  listen:         %s\n", c.Listen)
	fmt.Fprintf(&b, "  user-agent:     %s\n", ua)

	if c.Fetch.Proxy != "" {
		fmt.Fprintf(&b, "  upstream proxy: %s\n", RedactURL(c.Fetch.Proxy))
	} else {
		b.WriteString("  upstream proxy: (none, honoring HTTP_PROXY)\n")
	}

	if c.Fetch.FlareSolverrURL != "" {
		fmt.Fprintf(&b, "  flaresolverr:   %s\n", RedactURL(c.Fetch.FlareSolverrURL))
	} else {
		b.WriteString("  flaresolverr:   (disabled)\n")
	}

	fmt.Fprintf(&b, "  fetch timeout:  %s\n", c.Fetch.Timeout)

	switch {
	case c.Fetch.CacheTTL < 0:
		b.WriteString("  fetch cache:    disabled\n")
	case c.Fetch.CacheTTL == 0:
		b.WriteString("  fetch cache:    300s (default)\n")
	default:
		fmt.Fprintf(&b, "  fetch cache:    %s\n", c.Fetch.CacheTTL)
	}

	if c.RateLimit.Enabled {
		fmt.Fprintf(&b, "  rate limit:     %d/min, burst %d\n", c.RateLimit.RequestsPerMinute, c.RateLimit.Burst)
	} else {
		b.WriteString("  rate limit:     disabled\n")
	}

	if len(c.Insert.URLs) > 0 {
		pos := "append"
		if c.Insert.Prepend {
			pos = "prepend"
		}
		state := "enabled"
		if !c.Insert.Enabled {
			state = "off by default"
		}
		fmt.Fprintf(&b, "  insert urls:    %d (%s, %s)\n", len(c.Insert.URLs), state, pos)
		for _, u := range c.Insert.URLs {
			fmt.Fprintf(&b, "    - %s\n", RedactSubURL(u))
		}
	}

	return b.String()
}
