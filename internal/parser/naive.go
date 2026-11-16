package parser

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseNaive handles naive+https:// and naive+quic:// links.
//
//	naive+https://user:pass@host:port?sni=...&insecure=1&alpn=h2,http/1.1#name
//	naive+quic://user:pass@host:port?sni=...#name
func parseNaive(uri string) (*proxy.Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("naive: %w", err)
	}
	host := u.Hostname()
	port := atoiPort(u.Port())
	username := u.User.Username()
	pass, _ := u.User.Password()
	if host == "" || port == 0 || username == "" || pass == "" {
		return nil, fmt.Errorf("naive: missing username/pass/host/port")
	}
	q := lowerQuery(u.Query())
	name := fragmentName(u, fmt.Sprintf("%s:%d", host, port))

	p := proxy.New("naive", name, host, port)
	p.Set("username", username)
	p.Set("password", pass)
	p.SetRaw("tls", true)
	if strings.HasPrefix(strings.ToLower(uri), "naive+quic://") {
		p.SetRaw("quic", true)
	}
	p.Set("sni", firstQ(q, "sni", "server-name", "servername"))
	if boolish(firstQ(q, "insecure", "allowinsecure", "skip-cert-verify")) {
		p.SetRaw("skip-cert-verify", true)
	}
	if alpn := firstQ(q, "alpn"); alpn != "" {
		p.Set("alpn", splitALPN(alpn))
	}
	if extra := firstQ(q, "insecure-concurrency", "insecure_concurrency"); extra != "" {
		if n := atoiPort(extra); n > 0 {
			p.Set("insecure-concurrency", n)
		}
	}
	return p, nil
}
