package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseWireGuard handles WireGuard share links. There is no single official
// URI, so we accept the de-facto form used by several panels, plus awg:// for
// AWG links:
//
//	wireguard://<private-key>@<host>:<port>?address=<v4>[,<v6>]&publickey=<pk>
//	           &presharedkey=<psk>&reserved=<a,b,c>&mtu=<n>#name
//	awg://<private-key>@<host>:<port>?jc=4&jmin=10&jmax=50&s1=1&h1=0x1#name
//
// Query keys are matched case-insensitively and tolerate a few spellings
// (publickey/public-key, presharedkey/pre-shared-key, address/ip). WireGuard
// nodes that arrive inside a Clash YAML subscription are handled by the YAML
// lift in clash.go and do not go through this parser.
func parseWireGuard(uri string) (*proxy.Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	host := u.Hostname()
	port := atoiPort(u.Port())
	priv := u.User.Username()
	if host == "" || port == 0 {
		return nil, fmt.Errorf("wireguard: missing host/port")
	}
	q := lowerQuery(u.Query())
	name := fragmentName(u, fmt.Sprintf("%s:%d", host, port))

	p := proxy.New("wireguard", name, host, port)
	p.Set("private-key", priv)
	p.Set("public-key", firstQ(q, "publickey", "public-key", "peerpublickey"))

	// address=<v4>[,<v6>] (a.k.a. ip / ips); split by family.
	for _, addr := range strings.Split(firstQ(q, "address", "ip", "ips"), ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		addr = strings.TrimSuffix(addr, "/32")
		addr = strings.TrimSuffix(addr, "/128")
		if strings.Contains(addr, ":") {
			p.Set("ipv6", addr)
		} else {
			p.Set("ip", addr)
		}
	}

	p.Set("pre-shared-key", firstQ(q, "presharedkey", "pre-shared-key", "psk"))

	if mtu := firstQ(q, "mtu"); mtu != "" {
		if n, err := strconv.Atoi(mtu); err == nil {
			p.Set("mtu", n)
		}
	}

	// reserved=<a,b,c> -> [a,b,c] (ints).
	if rsv := firstQ(q, "reserved"); rsv != "" {
		var vals []int
		ok := true
		for _, part := range strings.Split(rsv, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(part))
			if err != nil {
				ok = false
				break
			}
			vals = append(vals, n)
		}
		if ok && len(vals) > 0 {
			p.Set("reserved", vals)
		}
	}

	p.SetRaw("udp", true)

	// AWG obfuscation parameters. Only keys present in the link are copied; the
	// object is absent for a plain WireGuard node.
	if opts := awgOptions(q); len(opts) > 0 {
		p.Set("amnezia-wg-option", opts)
	}
	return p, nil
}

// lowerQuery lower-cases query keys so we can match them case-insensitively.
func lowerQuery(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for k, v := range in {
		out[strings.ToLower(k)] = v
	}
	return out
}

// firstQ returns the first non-empty value among the given (already lower-cased)
// keys.
func firstQ(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(q.Get(k)); v != "" {
			return v
		}
	}
	return ""
}

// awgKeyKinds maps the normalized (separator-free) AWG query key to its
// canonical name and value kind. Keys missing here are not AWG options.
var awgKeyKinds = map[string]struct {
	name string
	kind string // "int" | "scalar" | "string" | "bool"
}{
	"version": {"version", "int"},
	"jc":      {"jc", "int"},
	"jmin":    {"jmin", "int"},
	"jmax":    {"jmax", "int"},
	"s1":      {"s1", "int"},
	"s2":      {"s2", "int"},
	"s3":      {"s3", "int"},
	"s4":      {"s4", "int"},
	"h1":      {"h1", "scalar"},
	"h2":      {"h2", "scalar"},
	"h3":      {"h3", "scalar"},
	"h4":      {"h4", "scalar"},
	"i1":      {"i1", "scalar"},
	"i2":      {"i2", "scalar"},
	"i3":      {"i3", "scalar"},
	"i4":      {"i4", "scalar"},
	"i5":      {"i5", "scalar"},
	"j1":      {"j1", "scalar"},
	"j2":      {"j2", "scalar"},
	"j3":      {"j3", "scalar"},
	"itime":   {"itime", "int"},

	"headerprotectionkey":    {"header-protection-key", "string"},
	"contentpaddingaddition": {"content-padding-addition", "string"},
	"rekeyaftertime":         {"rekey-after-time", "int"},
	"rekeytimeout":           {"rekey-timeout", "int"},
	"rejectaftertime":        {"reject-after-time", "int"},
	"keepalivetimeout":       {"keepalive-timeout", "int"},
	"maxhandshakeattempts":   {"max-handshake-attempts", "int"},
	"randomtrailers":         {"random-trailers", "bool"},
	"disablecookies":         {"disable-cookies", "bool"},
}

// awgOptions collects the AWG query keys into the canonical
// amnezia-wg-option object. Hyphen and underscore spellings are equivalent.
func awgOptions(q url.Values) map[string]any {
	var opts map[string]any
	for k, vals := range q {
		if len(vals) == 0 {
			continue
		}
		norm := strings.NewReplacer("-", "", "_", "").Replace(k)
		spec, ok := awgKeyKinds[norm]
		if !ok {
			continue
		}
		val := strings.TrimSpace(vals[0])
		if val == "" {
			continue
		}
		if opts == nil {
			opts = map[string]any{}
		}
		switch spec.kind {
		case "int":
			if n, err := strconv.Atoi(val); err == nil {
				opts[spec.name] = n
			}
		case "scalar":
			if n, err := strconv.Atoi(val); err == nil {
				opts[spec.name] = n
			} else {
				opts[spec.name] = val
			}
		case "bool":
			opts[spec.name] = boolish(val)
		default:
			opts[spec.name] = val
		}
	}
	return opts
}
