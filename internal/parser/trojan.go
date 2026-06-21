package parser

import (
	"fmt"
	"net/url"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseTrojan handles trojan:// links, including ws/grpc transports.
//
//	trojan://password@host:port?sni=...&type=ws&host=...&path=...&allowInsecure=1#name
func parseTrojan(uri string) (*proxy.Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("trojan: %w", err)
	}
	password := u.User.Username()
	host := u.Hostname()
	port := atoiPort(u.Port())
	if password == "" || host == "" || port == 0 {
		return nil, fmt.Errorf("trojan: missing password/host/port")
	}
	q := u.Query()
	name := fragmentName(u, fmt.Sprintf("%s:%d", host, port))

	p := proxy.New("trojan", name, host, port)
	p.Set("password", password)
	p.SetRaw("udp", true)

	sni := q.Get("sni")
	if sni == "" {
		sni = q.Get("peer")
	}
	p.Set("sni", sni)
	if boolish(q.Get("allowInsecure")) {
		p.SetRaw("skip-cert-verify", true)
	}
	if alpn := q.Get("alpn"); alpn != "" {
		p.Set("alpn", splitALPN(alpn))
	}

	switch q.Get("type") {
	case "ws":
		p.Set("network", "ws")
		applyV2RayTransport(p, "ws", q.Get("host"), q.Get("path"), "")
	case "grpc":
		p.Set("network", "grpc")
		applyV2RayTransport(p, "grpc", q.Get("host"), q.Get("serviceName"), "")
	}
	return p, nil
}
