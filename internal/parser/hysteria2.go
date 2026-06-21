package parser

import (
	"fmt"
	"net/url"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseHysteria2 handles hysteria2:// and hy2:// links.
//
//	hysteria2://auth@host:port?sni=...&insecure=1&obfs=salamander
//	           &obfs-password=...&alpn=h3#name
func parseHysteria2(uri string) (*proxy.Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}
	host := u.Hostname()
	port := atoiPort(u.Port())
	if host == "" || port == 0 {
		return nil, fmt.Errorf("hysteria2: missing host/port")
	}
	q := u.Query()
	name := fragmentName(u, fmt.Sprintf("%s:%d", host, port))

	p := proxy.New("hysteria2", name, host, port)
	// The auth/password sits in the userinfo for hy2.
	if pw := u.User.Username(); pw != "" {
		p.Set("password", pw)
	} else if auth := q.Get("auth"); auth != "" {
		p.Set("password", auth)
	}
	p.Set("sni", q.Get("sni"))
	if boolish(q.Get("insecure")) || boolish(q.Get("allowInsecure")) {
		p.SetRaw("skip-cert-verify", true)
	}
	if obfs := q.Get("obfs"); obfs != "" {
		p.Set("obfs", obfs)
		p.Set("obfs-password", q.Get("obfs-password"))
	}
	if alpn := q.Get("alpn"); alpn != "" {
		p.Set("alpn", splitALPN(alpn))
	}
	return p, nil
}
