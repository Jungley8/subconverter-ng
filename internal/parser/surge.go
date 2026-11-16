package parser

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

var knownSurgeTypes = map[string]bool{
	"ss":           true,
	"custom":       true,
	"vmess":        true,
	"vless":        true,
	"trojan":       true,
	"hysteria2":    true,
	"hysteria":     true,
	"tuic":         true,
	"tuic-v5":      true,
	"snell":        true,
	"socks5":       true,
	"socks5-tls":   true,
	"http":         true,
	"https":        true,
	"wireguard":    true,
	"anytls":       true,
	"ssh":          true,
	"masque":       true,
	"trust-tunnel": true,
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
			if len(parts) >= 2 {
				typ := strings.ToLower(strings.TrimSpace(parts[0]))
				// A WireGuard policy line points at a [WireGuard <section>]
				// block instead of carrying host and port inline.
				if typ == "wireguard" && strings.Contains(strings.ToLower(parts[1]), "section-name") {
					return true
				}
			}
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
	// [WireGuard <section>] blocks carry the keys and peer of a policy line
	// `name = wireguard, section-name=<section>`.
	wgSections := map[string]map[string]string{}
	inProxySection := false
	currentWG := ""
	for _, l := range lines {
		line := strings.TrimSpace(strings.TrimRight(l, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sec := strings.TrimSpace(line[1 : len(line)-1])
			lower := strings.ToLower(sec)
			switch {
			case lower == "proxy":
				inProxySection = true
				currentWG = ""
			case strings.HasPrefix(lower, "wireguard "):
				currentWG = strings.TrimSpace(sec[len("wireguard "):])
				inProxySection = false
				if currentWG != "" && wgSections[currentWG] == nil {
					wgSections[currentWG] = map[string]string{}
				}
			default:
				inProxySection = false
				currentWG = ""
			}
			continue
		}

		if currentWG != "" {
			if k, v, ok := strings.Cut(line, "="); ok {
				key := strings.ToLower(strings.TrimSpace(k))
				// A node has one endpoint: keep the first peer when a section
				// lists several.
				if key == "peer" {
					if _, exists := wgSections[currentWG][key]; exists {
						continue
					}
				}
				wgSections[currentWG][key] = strings.TrimSpace(v)
			}
			continue
		}
		if hasSections && !inProxySection {
			continue
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
		if len(rawTokens) < 2 {
			skipped = append(skipped, line)
			continue
		}

		typ := strings.ToLower(strings.TrimSpace(rawTokens[0]))

		// Section form has no inline host/port.
		if typ == "wireguard" {
			params, _ := surgeParams(rawTokens[1:])
			if section := params["section-name"]; section != "" {
				p, err := parseSurgeWireGuardSection(name, section, wgSections)
				if err != nil || p == nil {
					skipped = append(skipped, line)
					continue
				}
				nodes = append(nodes, p)
				continue
			}
		}

		if len(rawTokens) < 3 {
			skipped = append(skipped, line)
			continue
		}
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

// surgeParams splits a Surge proxy line's key=value list from its positional
// arguments.
func surgeParams(extra []string) (map[string]string, []string) {
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
	return params, posArgs
}

func parseSurgeLine(typ, name, server string, port int, extra []string) (*proxy.Proxy, error) {
	if name == "" || server == "" || port == 0 {
		return nil, fmt.Errorf("missing name/server/port")
	}

	params, posArgs := surgeParams(extra)

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
		if used, err := applySurgeShadowTLS(p, params); err != nil {
			return nil, err
		} else if used {
			return p, nil
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
		applySurgeWS(p, params)
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
		// Shadowrocket writes reality=true + public-key/short-id; Surge writes
		// reality-public-key/reality-short-id and treats REALITY as its own
		// security mode. Both become the canonical TLS+reality-opts pair.
		pbk := firstNonEmptyStr(params["reality-public-key"], params["public-key"])
		sid := firstNonEmptyStr(params["reality-short-id"], params["short-id"])
		if boolish(params["reality"]) || pbk != "" {
			p.SetRaw("tls", true)
			ro := map[string]any{}
			if pbk != "" {
				ro["public-key"] = pbk
			}
			if sid != "" {
				ro["short-id"] = sid
			}
			if len(ro) > 0 {
				p.Set("reality-opts", ro)
			}
			if fp := firstNonEmptyStr(params["fingerprint"], params["client-fingerprint"]); fp != "" {
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
		switch {
		case boolish(params["grpc"]):
			p.Set("network", "grpc")
			p.Set("grpc-opts", map[string]any{"grpc-service-name": params["grpc-service-name"]})
		case boolish(params["xhttp"]):
			p.Set("network", "xhttp")
			opts := map[string]any{}
			if v := params["xhttp-path"]; v != "" {
				opts["path"] = v
			}
			if v := params["xhttp-host"]; v != "" {
				opts["host"] = v
			}
			if v := params["xhttp-mode"]; v != "" {
				opts["mode"] = v
			}
			if len(opts) > 0 {
				p.Set("xhttp-opts", opts)
			}
		default:
			applySurgeWS(p, params)
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
		applySurgeWS(p, params)
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
		applySurgeHysteria2Obfs(p, params)
		applySurgePositionalObfs(p, posArgs)
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
		// Surge `tuic` is the v4 token handshake.
		p := proxy.New("tuic", name, server, port)
		p.Set("password", firstNonEmptyStr(params["token"], params["password"]))
		p.Version = 4
		applySurgeTUICOptions(p, params)
		return p, nil

	case "tuic-v5":
		p := proxy.New("tuic", name, server, port)
		p.Set("uuid", firstNonEmptyStr(params["uuid"], params["username"]))
		p.Set("password", params["password"])
		applySurgeTUICOptions(p, params)
		return p, nil

	case "snell":
		return parseSurgeSnell(name, server, port, params)

	case "anytls":
		p := proxy.New("anytls", name, server, port)
		p.Set("password", params["password"])
		if sni := params["sni"]; sni != "" {
			p.Set("sni", sni)
		}
		if boolish(params["skip-cert-verify"]) {
			p.SetRaw("skip-cert-verify", true)
		}
		if alpn := params["alpn"]; alpn != "" {
			p.Set("alpn", splitALPN(alpn))
		}
		return p, nil

	case "ssh":
		p := proxy.New("ssh", name, server, port)
		p.Set("username", firstNonEmptyStr(params["username"], params["user"]))
		p.Set("password", params["password"])
		return p, nil

	case "masque":
		p := proxy.New("masque", name, server, port)
		p.Set("username", params["username"])
		p.Set("password", params["password"])
		if sni := params["sni"]; sni != "" {
			p.Set("sni", sni)
		}
		if boolish(params["skip-cert-verify"]) {
			p.SetRaw("skip-cert-verify", true)
		}
		if alpn := params["alpn"]; alpn != "" {
			p.Set("alpn", splitALPN(alpn))
		}
		if v := params["port-hopping"]; v != "" {
			p.Set("port-hopping", v)
		}
		if v := params["port-hopping-interval"]; v != "" {
			p.Set("port-hopping-interval", atoiPort(v))
		}
		return p, nil

	case "trust-tunnel":
		p := proxy.New("trusttunnel", name, server, port)
		p.Set("username", params["username"])
		p.Set("password", params["password"])
		p.Set("sni", params["sni"])
		if boolish(params["skip-cert-verify"]) {
			p.SetRaw("skip-cert-verify", true)
		}
		if alpn := params["alpn"]; alpn != "" {
			p.Set("alpn", splitALPN(alpn))
		}
		p.Set("headers", params["headers"])
		if v := params["max-streams"]; v != "" {
			p.Set("max-streams", atoiPort(v))
		}
		if boolish(params["h3"]) {
			p.SetRaw("h3", true)
		}
		if boolish(params["quic"]) {
			p.SetRaw("quic", true)
		}
		p.Set("congestion-controller", params["congestion-controller"])
		p.Set("bbr-profile", params["bbr-profile"])
		p.Set("client-random-auth-key", params["client-random-auth-key"])
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

	case "wireguard":
		return parseSurgeWireGuardInline(name, server, port, params), nil
	}

	return nil, fmt.Errorf("unsupported surge proxy type: %s", typ)
}

// applySurgeWS maps Surge's ws parameters, including the HTTPUpgrade flag, onto
// the canonical ws shape.
func applySurgeWS(p *proxy.Proxy, params map[string]string) {
	if !boolish(params["ws"]) {
		return
	}
	wsOpts := map[string]any{}
	if path := params["ws-path"]; path != "" {
		wsOpts["path"] = path
	}
	if headers := params["ws-headers"]; headers != "" {
		if host, val, ok := strings.Cut(headers, ":"); ok && strings.EqualFold(strings.TrimSpace(host), "host") {
			wsOpts["headers"] = map[string]any{"Host": strings.TrimSpace(val)}
		}
	}
	if boolish(params["ws-http-upgrade"]) {
		wsOpts["v2ray-http-upgrade"] = true
	}
	p.Set("network", "ws")
	p.Set("ws-opts", wsOpts)
}

// applySurgeTUICOptions copies the TLS options shared by tuic and tuic-v5.
func applySurgeTUICOptions(p *proxy.Proxy, params map[string]string) {
	if sni := params["sni"]; sni != "" {
		p.Set("sni", sni)
	}
	if alpn := params["alpn"]; alpn != "" {
		p.Set("alpn", []string{alpn})
	}
	if boolish(params["skip-cert-verify"]) {
		p.SetRaw("skip-cert-verify", true)
	}
}

// applySurgeShadowTLS turns the shadow-tls-* Surge parameters into the
// Shadowsocks plugin wrapper. It reports whether the node uses ShadowTLS.
func applySurgeShadowTLS(p *proxy.Proxy, params map[string]string) (bool, error) {
	pass := params["shadow-tls-password"]
	version := params["shadow-tls-version"]
	sni := params["shadow-tls-sni"]
	if pass == "" && version == "" && sni == "" {
		return false, nil
	}
	if pass == "" {
		return false, fmt.Errorf("shadow-tls needs shadow-tls-password")
	}
	opts := map[string]any{"password": pass}
	if sni != "" {
		opts["host"] = sni
	}
	if v := atoiPort(version); v > 0 {
		opts["version"] = v
	}
	p.Set("plugin", "shadow-tls")
	p.Set("plugin-opts", opts)
	return true, nil
}

// applySurgeHysteria2Obfs maps Surge's combined salamander-<key> /
// gecko-<key> obfs value to the canonical obfs + obfs-password pair.
func applySurgeHysteria2Obfs(p *proxy.Proxy, params map[string]string) {
	obfs := params["obfs"]
	if obfs == "" {
		return
	}
	if key := params["obfs-password"]; key != "" {
		p.Set("obfs", obfs)
		p.Set("obfs-password", key)
		return
	}
	kind, key, ok := strings.Cut(obfs, "-")
	if ok && (kind == "salamander" || kind == "gecko") {
		p.Set("obfs", kind)
		p.Set("obfs-password", key)
		return
	}
	p.Set("obfs", obfs)
}

// applySurgePositionalObfs reads Surge's salamander-<key> / gecko-<key> flags,
// which are standalone tokens rather than key=value parameters.
func applySurgePositionalObfs(p *proxy.Proxy, posArgs []string) {
	for _, arg := range posArgs {
		kind, key, ok := strings.Cut(arg, "-")
		switch strings.ToLower(kind) {
		case "salamander", "gecko":
			if ok && key != "" {
				p.Set("obfs", strings.ToLower(kind))
				p.Set("obfs-password", key)
				return
			}
		}
	}
}

// parseSurgeSnell maps a Surge snell line. Surge omits the version for v1.
func parseSurgeSnell(name, server string, port int, params map[string]string) (*proxy.Proxy, error) {
	psk := params["psk"]
	if psk == "" {
		return nil, fmt.Errorf("snell: missing psk")
	}
	version := 1
	if v := params["version"]; v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 6 {
			return nil, fmt.Errorf("snell: unsupported version %q", v)
		}
		version = n
	}

	p := proxy.New("snell", name, server, port)
	p.Set("psk", psk)
	p.SetRaw("version", version)
	if boolish(params["reuse"]) {
		p.SetRaw("reuse", true)
	}
	if params["udp-port"] != "" {
		p.SetRaw("udp", true)
		if n := atoiPort(params["udp-port"]); n > 0 {
			p.Set("udp-port", n)
		}
	}
	p.Set("userkey", params["userkey"])
	p.Set("mode", params["mode"])

	opts := map[string]any{}
	stPass := params["shadow-tls-password"]
	if stPass == "" && (params["shadow-tls-version"] != "" || params["shadow-tls-sni"] != "") {
		return nil, fmt.Errorf("snell: shadow-tls needs shadow-tls-password")
	}
	if stPass != "" {
		opts["mode"] = "shadow-tls"
		opts["password"] = stPass
		if sni := params["shadow-tls-sni"]; sni != "" {
			opts["host"] = sni
		}
		if v := atoiPort(params["shadow-tls-version"]); v > 0 {
			opts["version"] = v
		}
	} else if obfs := params["obfs"]; obfs != "" {
		opts["mode"] = obfs
		if host := params["obfs-host"]; host != "" {
			opts["host"] = host
		}
		if uri := params["obfs-uri"]; uri != "" {
			opts["uri"] = uri
		}
	}
	if len(opts) > 0 {
		p.Set("obfs-opts", opts)
	}
	return p, nil
}

// parseSurgeWireGuardSection builds a node from a [WireGuard <section>] block.
func parseSurgeWireGuardSection(name, section string, sections map[string]map[string]string) (*proxy.Proxy, error) {
	fields := sections[section]
	if fields == nil {
		return nil, fmt.Errorf("wireguard: unknown section %q", section)
	}
	peer := parseSurgePeer(fields["peer"])
	host, port := splitHostPort(peer["endpoint"])
	if host == "" || port == 0 {
		return nil, fmt.Errorf("wireguard: section %q has no peer endpoint", section)
	}

	p := proxy.New("wireguard", name, host, port)
	p.Set("private-key", fields["private-key"])
	p.Set("public-key", peer["public-key"])
	p.Set("pre-shared-key", firstNonEmptyStr(peer["preshared-key"], peer["pre-shared-key"]))
	applyWireGuardAddrs(p, fields["self-ip"], fields["self-ip-v6"])
	if mtu := atoiPort(fields["mtu"]); mtu > 0 {
		p.Set("mtu", mtu)
	}
	if dns := fields["dns-server"]; dns != "" {
		p.Set("dns", splitALPN(dns))
	}
	if ka := atoiPort(peer["keepalive"]); ka > 0 {
		p.Set("persistent-keepalive", ka)
	}
	if allowed := peer["allowed-ips"]; allowed != "" {
		p.Set("allowed-ips", splitALPN(allowed))
	}
	p.SetRaw("udp", true)
	return p, nil
}

// parseSurgeWireGuardInline builds a node from the Shadowrocket inline form
// `wireguard, host, port, private-key=..., public-key=..., ip=..., ...`.
func parseSurgeWireGuardInline(name, server string, port int, params map[string]string) *proxy.Proxy {
	p := proxy.New("wireguard", name, server, port)
	p.Set("private-key", params["private-key"])
	p.Set("public-key", firstNonEmptyStr(params["public-key"], params["publickey"]))
	p.Set("pre-shared-key",
		firstNonEmptyStr(params["pre-shared-key"], params["preshared-key"], params["presharedkey"], params["psk"]))
	applyWireGuardAddrs(p,
		firstNonEmptyStr(params["ip"], params["address"], params["self-ip"]),
		firstNonEmptyStr(params["ipv6"], params["self-ip-v6"]))
	if mtu := atoiPort(params["mtu"]); mtu > 0 {
		p.Set("mtu", mtu)
	}
	if reserved := params["reserved"]; reserved != "" {
		var vals []int
		for _, part := range strings.Split(reserved, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				vals = append(vals, n)
			}
		}
		if len(vals) > 0 {
			p.Set("reserved", vals)
		}
	}
	p.SetRaw("udp", true)
	return p
}

// applyWireGuardAddrs splits local addresses into the canonical ip/ipv6 pair
// and drops their CIDR suffix.
func applyWireGuardAddrs(p *proxy.Proxy, v4list, v6 string) {
	for _, addr := range strings.Split(v4list, ",") {
		addr = stripWGAddr(addr)
		if addr == "" {
			continue
		}
		if strings.Contains(addr, ":") {
			p.Set("ipv6", addr)
		} else {
			p.Set("ip", addr)
		}
	}
	if addr := stripWGAddr(v6); addr != "" {
		p.Set("ipv6", addr)
	}
}

func stripWGAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimSuffix(addr, "/32")
	return strings.TrimSuffix(addr, "/128")
}

// parseSurgePeer parses Surge's `peer = (key = value, ...)` form. Quoted
// values (allowed-ips) may contain commas.
func parseSurgePeer(s string) map[string]string {
	out := map[string]string{}
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "(")
	s = strings.TrimSuffix(s, ")")
	for _, part := range splitSurgeQuoted(s) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(k))] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return out
}

func splitSurgeQuoted(s string) []string {
	var out []string
	var b strings.Builder
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
			b.WriteRune(r)
		case r == '"' || r == '\'':
			quote = r
			b.WriteRune(r)
		case r == ',':
			out = append(out, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if v := strings.TrimSpace(b.String()); v != "" {
		out = append(out, v)
	}
	return out
}
