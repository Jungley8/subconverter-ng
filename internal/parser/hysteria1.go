package parser

import (
	"fmt"
	"net/url"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseHysteria1 handles hysteria:// and hy:// (Hysteria v1) links.
//
//	hysteria://host:port?protocol=udp&auth=xxx&peer=sni&insecure=1
//	          &upmbps=100&downmbps=100&obfs=xxx&alpn=h3#name
func parseHysteria1(uri string) (*proxy.Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("hysteria: %w", err)
	}
	host := u.Hostname()
	port := atoiPort(u.Port())
	if host == "" || port == 0 {
		return nil, fmt.Errorf("hysteria: missing host/port")
	}
	q := u.Query()
	name := fragmentName(u, fmt.Sprintf("%s:%d", host, port))

	p := proxy.New("hysteria", name, host, port)

	auth := q.Get("auth")
	if auth == "" {
		auth = q.Get("auth_str")
	}
	p.Set("auth-str", auth)

	p.Set("up", q.Get("upmbps"))
	p.Set("down", q.Get("downmbps"))

	sni := q.Get("peer")
	if sni == "" {
		sni = q.Get("sni")
	}
	p.Set("sni", sni)

	if boolish(q.Get("insecure")) || boolish(q.Get("allowInsecure")) {
		p.SetRaw("skip-cert-verify", true)
	}
	p.Set("obfs", q.Get("obfs"))
	if alpn := q.Get("alpn"); alpn != "" {
		p.Set("alpn", splitALPN(alpn))
	}
	p.Set("protocol", q.Get("protocol"))
	return p, nil
}
