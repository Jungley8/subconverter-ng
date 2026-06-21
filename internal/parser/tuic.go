package parser

import (
	"fmt"
	"net/url"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseTUIC handles TUIC v5 links.
//
//	tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3
//	       &sni=...&allow_insecure=1&udp_relay_mode=native#name
func parseTUIC(uri string) (*proxy.Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	host := u.Hostname()
	port := atoiPort(u.Port())
	uuid := u.User.Username()
	password, _ := u.User.Password()
	if host == "" || port == 0 || uuid == "" {
		return nil, fmt.Errorf("tuic: missing uuid/host/port")
	}
	q := u.Query()
	name := fragmentName(u, fmt.Sprintf("%s:%d", host, port))

	p := proxy.New("tuic", name, host, port)
	p.Set("uuid", uuid)
	p.Set("password", password)
	p.Set("sni", q.Get("sni"))

	cc := q.Get("congestion_control")
	if cc == "" {
		cc = "bbr"
	}
	p.Set("congestion-controller", cc)

	mode := q.Get("udp_relay_mode")
	if mode == "" {
		mode = "native"
	}
	p.Set("udp-relay-mode", mode)

	if alpn := q.Get("alpn"); alpn != "" {
		p.Set("alpn", splitALPN(alpn))
	} else {
		p.Set("alpn", []string{"h3"})
	}
	if boolish(q.Get("allow_insecure")) || boolish(q.Get("insecure")) {
		p.SetRaw("skip-cert-verify", true)
	}
	return p, nil
}
