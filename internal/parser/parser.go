// Package parser turns raw subscription payloads into proxy.Proxy values.
//
// It handles common subscription payload shapes:
//   - A ready-made Clash/Clash.Meta YAML document.
//   - A sing-box JSON configuration or outbounds array.
//   - A Surge .conf file or [Proxy] node list.
//   - A base64 blob whose decoded body is a newline-separated list of share
//     links (ss://, vmess://, vless://, trojan://, hysteria2://, tuic://, etc.)
//     or one of the structured document formats above.
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
// a recognized subscription document format.
func Parse(payload []byte) (nodes []*proxy.Proxy, skipped []string, err error) {
	text := strings.TrimSpace(string(payload))

	// Direct document formats
	if looksLikeClashYAML(text) {
		return parseClashYAML(text)
	}
	if looksLikeSingboxJSON(text) {
		return parseSingboxJSON(text)
	}
	if looksLikeSurge(text) {
		return parseSurge(text)
	}

	body := text
	if decoded, ok := tryBase64(text); ok {
		body = decoded
		if looksLikeClashYAML(body) {
			return parseClashYAML(body)
		}
		if looksLikeSingboxJSON(body) {
			return parseSingboxJSON(body)
		}
		if looksLikeSurge(body) {
			return parseSurge(body)
		}
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
// not base64 (i.e. it is already a plain node list or unencoded document).
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
			// Guard against false positives: a real subscription contains "://"
			// or matches one of the structured document formats.
			if strings.Contains(d, "://") || looksLikeClashYAML(d) || looksLikeSingboxJSON(d) || looksLikeSurge(d) {
				return d, true
			}
		}
	}
	return "", false
}
