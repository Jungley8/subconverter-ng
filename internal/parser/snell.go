package parser

import (
	"fmt"
	"net/url"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseSnell handles the de-facto snell:// share link.
//
//	snell://<psk>@host:port?version=4&obfs=http&obfs-host=bing.com&obfs-uri=/
//	        &userkey=...&reuse=1&mode=...#name
//
// The psk may sit in the query instead of the userinfo. An absent version
// means Snell v1, the protocol default.
func parseSnell(uri string) (*proxy.Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("snell: %w", err)
	}
	host := u.Hostname()
	port := atoiPort(u.Port())
	if host == "" || port == 0 {
		return nil, fmt.Errorf("snell: missing host/port")
	}
	q := lowerQuery(u.Query())
	psk := u.User.Username()
	if psk == "" {
		psk = firstQ(q, "psk")
	}
	if psk == "" {
		return nil, fmt.Errorf("snell: missing psk")
	}

	version := 1
	if raw := firstQ(q, "version"); raw != "" {
		version = atoiPort(raw)
		if version < 1 || version > 6 {
			return nil, fmt.Errorf("snell: unsupported version %q", raw)
		}
	}
	name := fragmentName(u, fmt.Sprintf("%s:%d", host, port))

	p := proxy.New("snell", name, host, port)
	p.Set("psk", psk)
	p.SetRaw("version", version)
	p.Set("userkey", firstQ(q, "userkey", "user-key"))
	if boolish(firstQ(q, "reuse")) {
		p.SetRaw("reuse", true)
	}
	if boolish(firstQ(q, "udp")) {
		p.SetRaw("udp", true)
	}
	p.Set("mode", firstQ(q, "mode"))
	p.Set("client-fingerprint", firstQ(q, "client-fingerprint", "fingerprint", "fp"))

	if opts := snellObfsOpts(q); len(opts) > 0 {
		p.Set("obfs-opts", opts)
	}
	return p, nil
}

// snellObfsOpts maps the obfs-* query family onto canonical obfs-opts. ShadowTLS
// is an obfs mode, so its separate secret and version come from obfs-<key>
// query names.
func snellObfsOpts(q url.Values) map[string]any {
	mode := firstQ(q, "obfs", "obfs-mode")
	if mode == "" {
		return nil
	}
	opts := map[string]any{"mode": mode}
	if host := firstQ(q, "obfs-host"); host != "" {
		opts["host"] = host
	}
	if mode == "shadow-tls" {
		if pw := firstQ(q, "obfs-password", "obfs-psk"); pw != "" {
			opts["password"] = pw
		}
		if v := firstQ(q, "obfs-version"); v != "" {
			opts["version"] = atoiPort(v)
		}
		if alpn := firstQ(q, "obfs-alpn"); alpn != "" {
			opts["alpn"] = splitALPN(alpn)
		}
		return opts
	}
	if uri := firstQ(q, "obfs-uri"); uri != "" {
		opts["uri"] = uri
	}
	return opts
}
