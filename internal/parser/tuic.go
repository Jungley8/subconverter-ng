package parser

import (
	"fmt"
	"net/url"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseTUIC handles TUIC v5 and v4 links.
//
//	tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3
//	       &sni=...&allow_insecure=1&udp_relay_mode=native#name
//	tuic://<token>@host:port#name
//	tuic://host:port?token=<token>#name
//
// v4 is the token-based handshake. It has no uuid, so a userinfo without a
// password part and no uuid or token in the query means v4; Proxy.Version
// records it.
func parseTUIC(uri string) (*proxy.Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	host := u.Hostname()
	port := atoiPort(u.Port())
	if host == "" || port == 0 {
		return nil, fmt.Errorf("tuic: missing host/port")
	}
	q := u.Query()
	name := fragmentName(u, fmt.Sprintf("%s:%d", host, port))

	username := u.User.Username()
	pass, _ := u.User.Password()
	token := q.Get("token")
	uuidQuery := q.Get("uuid")
	if token == "" && pass == "" && uuidQuery == "" {
		// No password part, no uuid and no token: a v4 token in the userinfo.
		token = username
	}

	if token != "" {
		p := proxy.New("tuic", name, host, port)
		p.Set("password", token)
		p.Version = 4
		p.Set("sni", q.Get("sni"))
		if alpn := q.Get("alpn"); alpn != "" {
			p.Set("alpn", splitALPN(alpn))
		}
		if boolish(q.Get("allow_insecure")) || boolish(q.Get("insecure")) {
			p.SetRaw("skip-cert-verify", true)
		}
		return p, nil
	}

	uuid := firstNonEmptyStr(uuidQuery, username)
	if uuid == "" || pass == "" {
		return nil, fmt.Errorf("tuic: missing uuid/password")
	}
	p := proxy.New("tuic", name, host, port)
	p.Set("uuid", uuid)
	p.Set("password", pass)
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
