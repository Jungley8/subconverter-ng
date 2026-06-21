package parser

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseWireGuard handles WireGuard share links. There is no single official
// URI, so we accept the de-facto form used by several panels:
//
//	wireguard://<private-key>@<host>:<port>?address=<v4>[,<v6>]&publickey=<pk>
//	           &presharedkey=<psk>&reserved=<a,b,c>&mtu=<n>#name
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
