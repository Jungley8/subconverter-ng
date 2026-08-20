// Package parser turns raw subscription payloads into proxy.Proxy values.
//
// It handles the two payload shapes airports commonly serve:
//
//   - A base64 blob whose decoded body is a newline-separated list of share
//     links (ss://, vmess://, vless://, trojan://, hysteria2://, tuic://).
//   - A ready-made Clash/Clash.Meta YAML document (served when the request
//     carries a clash-like User-Agent). Its `proxies:` list is lifted directly.
package parser

import (
	"encoding/base64"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// lineParser parses a single share link of one protocol.
type lineParser func(uri string) (*proxy.Proxy, error)

// schemeOrder defines schemes checked in descending length order to avoid prefix ambiguities.
var schemeOrder = []string{
	"hysteria2://",
	"hysteria://",
	"wireguard://",
	"socks5h://",
	"socks4a://",
	"socks5://",
	"socks4://",
	"socks://",
	"trojan://",
	"anytls://",
	"vmess://",
	"vless://",
	"tuic://",
	"ssr://",
	"ss://",
	"hy2://",
	"hy://",
	"wg://",
	"tg://socks",
}

// registry maps a URI scheme prefix to its parser.
var registry = map[string]lineParser{
	"ss://":        parseSS,
	"ssr://":       parseSSR,
	"vmess://":     parseVMess,
	"vless://":     parseVLESS,
	"trojan://":    parseTrojan,
	"hysteria2://": parseHysteria2,
	"hy2://":       parseHysteria2,
	"hysteria://":  parseHysteria1,
	"hy://":        parseHysteria1,
	"tuic://":      parseTUIC,
	"socks://":     parseSOCKS,
	"socks5://":    parseSOCKS,
	"socks5h://":   parseSOCKS,
	"socks4://":    parseSOCKS,
	"socks4a://":   parseSOCKS,
	"tg://socks":   parseSOCKS,
	"anytls://":    parseAnyTLS,
	"wireguard://": parseWireGuard,
	"wg://":        parseWireGuard,
}

// matchScheme returns the registry scheme that prefixes s (matched case-insensitively),
// or "" when s is not a share link.
func matchScheme(s string) string {
	lower := strings.ToLower(s)
	for _, scheme := range schemeOrder {
		if strings.HasPrefix(lower, scheme) {
			return scheme
		}
	}
	return ""
}

// IsShareLink reports whether s is a single share link (e.g.
// "vless://uuid@host:443?...#name") rather than a subscription URL to fetch.
// Callers use it to accept node links directly in place of subscription URLs.
func IsShareLink(s string) bool { return matchScheme(s) != "" }

// Parse decodes a subscription payload into proxy nodes. Unparseable or
// unsupported lines are skipped and returned in skipped for diagnostics; a
// non-nil error is only returned for a payload that is neither a node list nor
// a Clash document.
func Parse(payload []byte) (nodes []*proxy.Proxy, skipped []string, err error) {
	text := strings.TrimSpace(string(payload))

	// A Clash YAML document is served verbatim by some airports.
	if looksLikeClashYAML(text) {
		return parseClashYAML(text)
	}

	body := text
	if decoded, ok := tryBase64(text); ok {
		body = decoded
	}

	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := dispatch(line)
		if p == nil {
			skipped = append(skipped, line)
			continue
		}
		nodes = append(nodes, p)
	}
	return nodes, skipped, nil
}

func dispatch(line string) *proxy.Proxy {
	scheme := matchScheme(line)
	if scheme == "" {
		return nil
	}
	p, err := registry[scheme](line)
	if err != nil {
		return nil
	}
	return p
}

// tryBase64 decodes a subscription body that is wrapped in standard or
// URL-safe base64, with or without padding. Returns ok=false when the input is
// not base64 (i.e. it is already a plain node list).
func tryBase64(s string) (string, bool) {
	compact := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(compact); err == nil {
			d := string(b)
			// Guard against false positives: a real node list contains "://".
			if strings.Contains(d, "://") {
				return d, true
			}
		}
	}
	return "", false
}
