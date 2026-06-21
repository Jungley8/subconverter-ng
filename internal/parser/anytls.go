package parser

import (
	"fmt"
	"net/url"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseAnyTLS handles anytls:// links.
//
//	anytls://password@host:port?sni=xxx&insecure=1&alpn=h2,http/1.1#name
func parseAnyTLS(uri string) (*proxy.Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("anytls: %w", err)
	}
	host := u.Hostname()
	port := atoiPort(u.Port())
	password := u.User.Username()
	if host == "" || port == 0 || password == "" {
		return nil, fmt.Errorf("anytls: missing password/host/port")
	}
	q := u.Query()
	name := fragmentName(u, fmt.Sprintf("%s:%d", host, port))

	p := proxy.New("anytls", name, host, port)
	p.Set("password", password)
	p.Set("sni", q.Get("sni"))
	if boolish(q.Get("insecure")) || boolish(q.Get("allowInsecure")) {
		p.SetRaw("skip-cert-verify", true)
	}
	if alpn := q.Get("alpn"); alpn != "" {
		p.Set("alpn", splitALPN(alpn))
	}
	p.SetRaw("udp", true)
	return p, nil
}
