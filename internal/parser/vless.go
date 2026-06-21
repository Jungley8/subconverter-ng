package parser

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseVLESS handles vless:// links including TLS, XTLS-Vision flow and Reality.
//
//	vless://uuid@host:port?encryption=none&security=reality&sni=...&fp=chrome
//	        &pbk=...&sid=...&flow=xtls-rprx-vision&type=ws&host=...&path=...#name
func parseVLESS(uri string) (*proxy.Proxy, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	uuid := u.User.Username()
	host := u.Hostname()
	port := atoiPort(u.Port())
	if uuid == "" || host == "" || port == 0 {
		return nil, fmt.Errorf("vless: missing uuid/host/port")
	}
	q := u.Query()
	name := fragmentName(u, fmt.Sprintf("%s:%d", host, port))

	p := proxy.New("vless", name, host, port)
	p.Set("uuid", uuid)
	p.SetRaw("udp", true)
	if flow := q.Get("flow"); flow != "" {
		p.Set("flow", flow)
	}

	security := q.Get("security")
	switch security {
	case "tls":
		p.SetRaw("tls", true)
	case "reality":
		p.SetRaw("tls", true)
		ro := map[string]any{}
		if pbk := q.Get("pbk"); pbk != "" {
			ro["public-key"] = pbk
		}
		if sid := q.Get("sid"); sid != "" {
			ro["short-id"] = sid
		}
		p.Set("reality-opts", ro)
	}
	if security == "tls" || security == "reality" {
		sni := q.Get("sni")
		if sni == "" {
			sni = q.Get("peer")
		}
		p.Set("servername", sni)
		fp := q.Get("fp")
		if fp == "" {
			fp = "chrome"
		}
		p.Set("client-fingerprint", fp)
		if boolish(q.Get("allowInsecure")) {
			p.SetRaw("skip-cert-verify", true)
		}
		if alpn := q.Get("alpn"); alpn != "" {
			p.Set("alpn", splitALPN(alpn))
		}
	}

	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	p.Set("network", network)
	switch network {
	case "ws":
		applyV2RayTransport(p, "ws", q.Get("host"), q.Get("path"), "")
	case "grpc":
		applyV2RayTransport(p, "grpc", q.Get("host"), q.Get("serviceName"), "")
	case "h2":
		applyV2RayTransport(p, "h2", q.Get("host"), q.Get("path"), "")
	}
	return p, nil
}

// splitALPN turns a comma-separated alpn string into a Clash list.
func splitALPN(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
