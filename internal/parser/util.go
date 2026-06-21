package parser

import (
	"encoding/base64"
	"net/url"
	"strconv"
	"strings"
)

// b64decode decodes a string trying every common base64 variant. Returns the
// input unchanged on failure so callers can fall back to treating it as plain.
func b64decode(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return string(b), true
		}
	}
	return s, false
}

// fragmentName extracts and URL-unescapes the #fragment of a share link, used
// as the node remark/name. Falls back to fallback when absent.
func fragmentName(u *url.URL, fallback string) string {
	if u.Fragment == "" {
		return fallback
	}
	if name, err := url.QueryUnescape(u.Fragment); err == nil {
		return strings.TrimSpace(name)
	}
	return strings.TrimSpace(u.Fragment)
}

// atoiPort parses a port string, tolerating surrounding whitespace.
func atoiPort(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// anyToInt coerces a JSON value that may be a number or a numeric string into
// an int (vmess JSON producers are inconsistent about this).
func anyToInt(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		return atoiPort(t)
	}
	return 0
}

// boolish reports whether a query flag means "on" (1/true/yes).
func boolish(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// splitHostPort splits "host:port", correctly handling bracketed IPv6 hosts
// like "[2001:db8::1]:443".
func splitHostPort(hostport string) (host string, port int) {
	hostport = strings.TrimSpace(hostport)
	if strings.HasPrefix(hostport, "[") {
		if end := strings.Index(hostport, "]"); end != -1 {
			host = hostport[1:end]
			rest := hostport[end+1:]
			if strings.HasPrefix(rest, ":") {
				port = atoiPort(rest[1:])
			}
			return host, port
		}
	}
	if i := strings.LastIndex(hostport, ":"); i != -1 {
		return hostport[:i], atoiPort(hostport[i+1:])
	}
	return hostport, 0
}
