package generator

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/matcher"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// typeNames maps our protocol ids to the names upstream subconverter matches
// with !!TYPE=.
var typeNames = map[string]string{
	"ss":        "SS",
	"ssr":       "SSR",
	"vmess":     "VMESS",
	"vless":     "VLESS",
	"trojan":    "TROJAN",
	"snell":     "SNELL",
	"http":      "HTTP",
	"https":     "HTTPS",
	"socks5":    "SOCKS5",
	"wireguard": "WIREGUARD",
	"hysteria":  "HYSTERIA",
	"hysteria2": "HYSTERIA2",
	"tuic":      "TUIC",
	"anytls":    "ANYTLS",
}

func typeName(t string) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return strings.ToUpper(t)
}

// attrTypeName is the !!TYPE= name for a node. Parsers store TLS HTTP nodes as
// type "http" with Clash tls=true; upstream matches those as HTTPS.
func attrTypeName(n *proxy.Proxy) string {
	if n.Type == "https" {
		return "HTTPS"
	}
	if n.Type == "http" {
		switch tls := n.Clash["tls"].(type) {
		case bool:
			if tls {
				return "HTTPS"
			}
		case string:
			// A Clash source may write tls: "true"; upstream compares the string.
			if tls == "true" {
				return "HTTPS"
			}
		}
	}
	return typeName(n.Type)
}

// attrSelector matches a node by one subconverter attribute matcher:
// !!TYPE=, !!PORT=, !!SERVER=, !!GROUP=, !!GROUPID= or !!INSERT=, each with an
// optional !!<regex> tail applied to the node name.
type attrSelector struct {
	kind string
	re   *matcher.Matcher
	rng  []rangeToken
	tail *matcher.Matcher
}

// parseAttrSelector reports whether sel is an attribute selector. A selector
// starting with "!!" that cannot be parsed is an error, never a plain regex.
func parseAttrSelector(sel string) (*attrSelector, bool, error) {
	if !strings.HasPrefix(sel, "!!") {
		return nil, false, nil
	}
	body := sel[2:]
	eq := strings.IndexByte(body, '=')
	if eq <= 0 {
		return nil, true, fmt.Errorf("attribute selector %q has no value", sel)
	}
	kind := body[:eq]
	arg, tail, _ := strings.Cut(body[eq+1:], "!!")
	if arg == "" {
		return nil, true, fmt.Errorf("attribute selector %q has an empty value", sel)
	}
	a := &attrSelector{kind: kind}
	switch kind {
	case "TYPE", "SERVER", "GROUP":
		pattern := arg
		if kind == "TYPE" {
			// Upstream full-matches the type name, not a substring.
			pattern = "^(?:" + arg + ")$"
		}
		re, err := matcher.Compile(pattern)
		if err != nil {
			return nil, true, fmt.Errorf("!!%s=%s: %w", kind, arg, err)
		}
		a.re = re
	case "PORT", "GROUPID", "INSERT":
		rng, err := parseRange(arg)
		if err != nil {
			return nil, true, fmt.Errorf("!!%s=%s: %w", kind, arg, err)
		}
		a.rng = rng
	case "PROVIDER":
		return nil, true, fmt.Errorf("!!PROVIDER= is not supported: provider names are generated as sub-N")
	default:
		return nil, true, fmt.Errorf("unknown attribute matcher !!%s", kind)
	}
	if tail != "" {
		re, err := matcher.Compile(tail)
		if err != nil {
			return nil, true, fmt.Errorf("!!%s=%s!!%s: %w", kind, arg, tail, err)
		}
		a.tail = re
	}
	return a, true, nil
}

func (a *attrSelector) match(n *proxy.Proxy) (bool, error) {
	var ok bool
	var err error
	switch a.kind {
	case "TYPE":
		ok, err = a.re.Match(attrTypeName(n))
	case "SERVER":
		ok, err = a.re.Match(n.Server)
		// Upstream stores IPv6 servers bracketed; ours are bare.
		if err == nil && !ok && strings.Contains(n.Server, ":") {
			ok, err = a.re.Match("[" + n.Server + "]")
		}
	case "GROUP":
		ok, err = a.re.Match(n.Group)
	case "PORT":
		ok = matchRange(a.rng, n.Port)
	case "GROUPID":
		ok = matchRange(a.rng, n.GroupID)
	case "INSERT":
		ok = matchRange(a.rng, -n.GroupID)
	}
	if err != nil || !ok {
		return false, err
	}
	if a.tail == nil {
		return true, nil
	}
	return a.tail.Match(n.Name)
}

// rangeToken is one entry of an upstream range list. A negated entry means
// "everything except this".
type rangeToken struct {
	neg    bool
	kind   byte // '=' exact, 'r' range, 'l' at most, 'g' at least
	lo, hi int
}

func (t rangeToken) hit(v int) bool {
	switch t.kind {
	case '=':
		return v == t.lo
	case 'r':
		return v >= t.lo && v <= t.hi
	case 'l':
		return v <= t.lo
	case 'g':
		return v >= t.lo
	}
	return false
}

// matchRange applies upstream's matchRange: entries are OR-ed, and a negated
// entry flips the result to false when it hits.
func matchRange(tokens []rangeToken, v int) bool {
	matched := false
	for _, t := range tokens {
		if t.neg {
			matched = true
			if t.hit(v) {
				matched = false
			}
			continue
		}
		if t.hit(v) {
			matched = true
		}
	}
	return matched
}

func parseRange(spec string) ([]rangeToken, error) {
	parts := strings.Split(spec, ",")
	out := make([]rangeToken, 0, len(parts))
	for _, p := range parts {
		t, err := parseRangeToken(strings.TrimSpace(p))
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// parseRangeToken accepts the upstream forms: 443, 1000-2000, 1000-, 1000+,
// each optionally prefixed with ! to exclude.
func parseRangeToken(s string) (rangeToken, error) {
	if s == "" {
		return rangeToken{}, fmt.Errorf("empty range entry")
	}
	t := rangeToken{}
	if strings.HasPrefix(s, "!") {
		t.neg = true
		s = s[1:]
	}
	// Upstream reads these as different forms; reject instead of guessing.
	if t.neg && (strings.HasSuffix(s, "-") || strings.HasSuffix(s, "+")) {
		return t, fmt.Errorf("negated open-ended range %q is not supported", s)
	}
	if strings.HasPrefix(s, "+") {
		return t, fmt.Errorf("bad range entry %q", s)
	}
	switch {
	case strings.HasSuffix(s, "+"):
		n, err := strconv.Atoi(strings.TrimSuffix(s, "+"))
		if err != nil {
			return t, fmt.Errorf("bad range entry %q", s)
		}
		t.kind, t.lo = 'g', n
	case strings.HasSuffix(s, "-"):
		n, err := strconv.Atoi(strings.TrimSuffix(s, "-"))
		if err != nil {
			return t, fmt.Errorf("bad range entry %q", s)
		}
		t.kind, t.lo = 'l', n
	case strings.Contains(s, "-") && !strings.HasPrefix(s, "-"):
		lo, hi, ok := strings.Cut(s, "-")
		if !ok {
			return t, fmt.Errorf("bad range entry %q", s)
		}
		a, err := strconv.Atoi(lo)
		if err != nil {
			return t, fmt.Errorf("bad range entry %q", s)
		}
		b, err := strconv.Atoi(hi)
		if err != nil {
			return t, fmt.Errorf("bad range entry %q", s)
		}
		t.kind, t.lo, t.hi = 'r', a, b
	default:
		n, err := strconv.Atoi(s)
		if err != nil {
			return t, fmt.Errorf("bad range entry %q", s)
		}
		t.kind, t.lo = '=', n
	}
	return t, nil
}
