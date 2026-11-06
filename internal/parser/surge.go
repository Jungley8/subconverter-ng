package parser

import (
	"fmt"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

var knownSurgeTypes = map[string]bool{
	"ss":         true,
	"custom":     true,
	"vmess":      true,
	"vless":      true,
	"trojan":     true,
	"hysteria2":  true,
	"hysteria":   true,
	"tuic":       true,
	"snell":      true,
	"socks5":     true,
	"socks5-tls": true,
	"http":       true,
	"https":      true,
	"wireguard":  true,
}

// looksLikeSurge reports whether text appears to be a Surge configuration file
// or a list of Surge [Proxy] lines.
func looksLikeSurge(text string) bool {
	text = strings.TrimSpace(text)
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") && strings.HasPrefix(text, "[\"") {
		return false
	}
	if looksLikeClashYAML(text) {
		return false
	}

	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.ToLower(strings.TrimSpace(line))
		if trimmed == "[proxy]" {
			return true
		}
		if idx := strings.Index(line, "="); idx != -1 {
			rest := strings.TrimSpace(line[idx+1:])
			parts := strings.Split(rest, ",")
			if len(parts) >= 3 {
				typ := strings.ToLower(strings.TrimSpace(parts[0]))
				if knownSurgeTypes[typ] {
					return true
				}
			}
		}
	}
	return false
}

// parseSurge extracts proxy nodes from a Surge .conf or raw [Proxy] lines.
func parseSurge(text string) ([]*proxy.Proxy, []string, error) {
	lines := strings.Split(text, "\n")
	inProxySection := false
	hasSections := false

	// First pass: check if document uses INI-style sections
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			hasSections = true
			break
		}
	}

	var proxyLines []string
	for _, l := range lines {
		line := strings.TrimSpace(strings.TrimRight(l, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}

		if hasSections {
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				sec := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
				inProxySection = (sec == "proxy")
				continue
			}
			if !inProxySection {
				continue
			}
		}

		// Line must contain '=' to define a node
		if strings.Contains(line, "=") {
			proxyLines = append(proxyLines, line)
		}
	}

	var nodes []*proxy.Proxy
	var skipped []string

	for _, line := range proxyLines {
		name, rest, ok := strings.Cut(line, "=")
		if !ok {
			skipped = append(skipped, line)
			continue
		}
		name = strings.TrimSpace(name)
		rawTokens := strings.Split(rest, ",")
		if len(rawTokens) < 3 {
			skipped = append(skipped, line)
			continue
		}

		typ := strings.ToLower(strings.TrimSpace(rawTokens[0]))
		server := strings.TrimSpace(rawTokens[1])
		port := atoiPort(rawTokens[2])

		p, err := parseSurgeLine(typ, name, server, port, rawTokens[3:])
		if err != nil || p == nil {
			skipped = append(skipped, line)
			continue
		}
		nodes = append(nodes, p)
	}

	return nodes, skipped, nil
}

func parseSurgeLine(typ, name, server string, port int, extra []string) (*proxy.Proxy, error) {
	if name == "" || server == "" || port == 0 {
		return nil, fmt.Errorf("missing name/server/port")
	}

	// Parse parameters: both key=value and positional
	params := map[string]string{}
	var posArgs []string
	for _, raw := range extra {
		token := strings.TrimSpace(raw)
		if token == "" {
			continue
		}
		if k, v, ok := strings.Cut(token, "="); ok {
			params[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		} else {
			posArgs = append(posArgs, token)
		}
	}

	switch typ {
	case "ss":
		p := proxy.New("ss", name, server, port)
		p.Set("cipher", params["encrypt-method"])
		p.Set("password", params["password"])
		if boolish(params["udp-relay"]) {
			p.SetRaw("udp", true)
		}
		if boolish(params["tfo"]) {
			p.SetRaw("tfo", true)
		}
		if obfs := params["obfs"]; obfs != "" {
			p.Set("plugin", "obfs")
			p.Set("plugin-opts", map[string]any{
				"mode": obfs,
				"host": params["obfs-host"],
			})
		}
		return p, nil

	case "custom":
		// Surge legacy Shadowsocks format:
		// name = custom, server, port, encrypt-method, password, module-url [, obfs=..., obfs-host=...]
		p := proxy.New("ss", name, server, port)
		if len(posArgs) > 0 {
			p.Set("cipher", posArgs[0])
		}
		if len(posArgs) > 1 {
			p.Set("password", posArgs[1])
		}
		if boolish(params["udp-relay"]) {
			p.SetRaw("udp", true)
		}
		if boolish(params["tfo"]) {
			p.SetRaw("tfo", true)
		}
		if obfs := params["obfs"]; obfs != "" {
			p.Set("plugin", "obfs")
			p.Set("plugin-opts", map[string]any{
				"mode": obfs,
				"host": params["obfs-host"],
			})
		}
		return p, nil

	case "vmess":
		p := proxy.New("vmess", name, server, port)
		p.Set("uuid", firstNonEmptyStr(params["username"], params["uuid"]))
		p.Set("cipher", "auto")
		if boolish(params["tfo"]) {
			p.SetRaw("tfo", true)
		}
		if boolish(params["tls"]) || params["sni"] != "" {
			p.SetRaw("tls", true)
			p.Set("sni", params["sni"])
			if boolish(params["skip-cert-verify"]) {
				p.SetRaw("skip-cert-verify", true)
			}
		}
		if boolish(params["ws"]) {
			p.Set("network", "ws")
			wsOpts := map[string]any{}
			if path := params["ws-path"]; path != "" {
				wsOpts["path"] = path
			}
			if headers := params["ws-headers"]; headers != "" {
				if host, val, ok := strings.Cut(headers, ":"); ok && strings.EqualFold(strings.TrimSpace(host), "host") {
					wsOpts["headers"] = map[string]any{"Host": strings.TrimSpace(val)}
				}
			}
			p.Set("ws-opts", wsOpts)
		}
		return p, nil

	case "vless":
		p := proxy.New("vless", name, server, port)
		p.Set("uuid", firstNonEmptyStr(params["username"], params["uuid"]))
		if flow := params["flow"]; flow != "" {
			p.Set("flow", flow)
		}
		if boolish(params["tfo"]) {
			p.SetRaw("tfo", true)
		}
		if boolish(params["reality"]) {
			p.SetRaw("tls", true)
			p.Set("reality-opts", map[string]any{
				"public-key": params["public-key"],
				"short-id":   params["short-id"],
			})
			if fp := params["fingerprint"]; fp != "" {
				p.Set("client-fingerprint", fp)
			}
		} else if boolish(params["tls"]) || params["sni"] != "" {
			p.SetRaw("tls", true)
		}
		if sni := params["sni"]; sni != "" {
			p.Set("sni", sni)
		}
		if boolish(params["skip-cert-verify"]) {
			p.SetRaw("skip-cert-verify", true)
		}
		if boolish(params["ws"]) {
			p.Set("network", "ws")
			wsOpts := map[string]any{}
			if path := params["ws-path"]; path != "" {
				wsOpts["path"] = path
			}
			if headers := params["ws-headers"]; headers != "" {
				if host, val, ok := strings.Cut(headers, ":"); ok && strings.EqualFold(strings.TrimSpace(host), "host") {
					wsOpts["headers"] = map[string]any{"Host": strings.TrimSpace(val)}
				}
			}
			p.Set("ws-opts", wsOpts)
		}
		return p, nil

	case "trojan":
		p := proxy.New("trojan", name, server, port)
		p.Set("password", params["password"])
		p.SetRaw("udp", true)
		p.SetRaw("tls", true)
		if sni := params["sni"]; sni != "" {
			p.Set("sni", sni)
		}
		if boolish(params["skip-cert-verify"]) {
			p.SetRaw("skip-cert-verify", true)
		}
		if boolish(params["tfo"]) {
			p.SetRaw("tfo", true)
		}
		if boolish(params["ws"]) {
			p.Set("network", "ws")
			wsOpts := map[string]any{}
			if path := params["ws-path"]; path != "" {
				wsOpts["path"] = path
			}
			if headers := params["ws-headers"]; headers != "" {
				if host, val, ok := strings.Cut(headers, ":"); ok && strings.EqualFold(strings.TrimSpace(host), "host") {
					wsOpts["headers"] = map[string]any{"Host": strings.TrimSpace(val)}
				}
			}
			p.Set("ws-opts", wsOpts)
		}
		return p, nil

	case "hysteria2":
		p := proxy.New("hysteria2", name, server, port)
		p.Set("password", params["password"])
		if sni := params["sni"]; sni != "" {
			p.Set("sni", sni)
		}
		if boolish(params["skip-cert-verify"]) {
			p.SetRaw("skip-cert-verify", true)
		}
		return p, nil

	case "hysteria":
		p := proxy.New("hysteria", name, server, port)
		p.Set("auth-str", params["auth"])
		if up := params["upmbps"]; up != "" {
			p.Set("up", up)
		}
		if down := params["downmbps"]; down != "" {
			p.Set("down", down)
		}
		if peer := firstNonEmptyStr(params["peer"], params["sni"]); peer != "" {
			p.Set("sni", peer)
		}
		if obfs := params["obfs"]; obfs != "" {
			p.Set("obfs", obfs)
		}
		if alpn := params["alpn"]; alpn != "" {
			p.Set("alpn", []string{alpn})
		}
		if proto := params["protocol"]; proto != "" {
			p.Set("protocol", proto)
		}
		if boolish(params["skip-cert-verify"]) {
			p.SetRaw("skip-cert-verify", true)
		}
		if boolish(params["tfo"]) {
			p.SetRaw("tfo", true)
		}
		return p, nil

	case "tuic":
		p := proxy.New("tuic", name, server, port)
		p.Set("password", firstNonEmptyStr(params["token"], params["password"]))
		if sni := params["sni"]; sni != "" {
			p.Set("sni", sni)
		}
		if alpn := params["alpn"]; alpn != "" {
			p.Set("alpn", []string{alpn})
		}
		if boolish(params["skip-cert-verify"]) {
			p.SetRaw("skip-cert-verify", true)
		}
		return p, nil

	case "socks5", "socks5-tls":
		p := proxy.New("socks5", name, server, port)
		if len(posArgs) > 0 {
			p.Set("username", posArgs[0])
		}
		if len(posArgs) > 1 {
			p.Set("password", posArgs[1])
		}
		if u := params["username"]; u != "" {
			p.Set("username", u)
		}
		if pw := params["password"]; pw != "" {
			p.Set("password", pw)
		}
		if typ == "socks5-tls" || boolish(params["tls"]) {
			p.SetRaw("tls", true)
			if sni := params["sni"]; sni != "" {
				p.Set("sni", sni)
			}
		}
		return p, nil

	case "http", "https":
		p := proxy.New("http", name, server, port)
		if u := params["username"]; u != "" {
			p.Set("username", u)
		}
		if pw := params["password"]; pw != "" {
			p.Set("password", pw)
		}
		if typ == "https" || boolish(params["tls"]) {
			p.SetRaw("tls", true)
			if sni := params["sni"]; sni != "" {
				p.Set("sni", sni)
			}
		}
		return p, nil

	case "snell":
		p := proxy.New("snell", name, server, port)
		p.Set("psk", params["psk"])
		if obfs := params["obfs"]; obfs != "" {
			p.Set("obfs", obfs)
			if host := params["obfs-host"]; host != "" {
				p.Set("obfs-host", host)
			}
		}
		return p, nil
	}

	return nil, fmt.Errorf("unsupported surge proxy type: %s", typ)
}
