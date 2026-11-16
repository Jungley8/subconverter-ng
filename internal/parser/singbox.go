package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// looksLikeSingboxJSON reports whether text resembles a sing-box JSON configuration
// or an outbounds JSON array.
func looksLikeSingboxJSON(text string) bool {
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "{") && !strings.HasPrefix(text, "[") {
		return false
	}
	// A sing-box config or payload distinctly contains "outbounds" or ("server_port" and "type").
	return strings.Contains(text, `"outbounds"`) ||
		(strings.Contains(text, `"server_port"`) && strings.Contains(text, `"type"`))
}

type singboxDoc struct {
	Outbounds []map[string]any `json:"outbounds"`
}

// nonProxyOutbounds are sing-box internal/routing outbound types that do not represent
// actual proxy server exit nodes.
var nonProxyOutbounds = map[string]bool{
	"direct":   true,
	"block":    true,
	"dns":      true,
	"selector": true,
	"urltest":  true,
}

// parseSingboxJSON extracts proxy nodes from a sing-box JSON configuration document
// or a raw JSON array of outbounds.
func parseSingboxJSON(text string) ([]*proxy.Proxy, []string, error) {
	text = strings.TrimSpace(text)
	var rawOutbounds []map[string]any

	if strings.HasPrefix(text, "[") {
		if err := json.Unmarshal([]byte(text), &rawOutbounds); err != nil {
			return nil, nil, fmt.Errorf("singbox json array: %w", err)
		}
	} else {
		var doc singboxDoc
		if err := json.Unmarshal([]byte(text), &doc); err != nil {
			return nil, nil, fmt.Errorf("singbox json: %w", err)
		}
		rawOutbounds = doc.Outbounds
	}

	var nodes []*proxy.Proxy
	var skipped []string

	// A ShadowTLS setup is two outbounds: the shadowtls outbound dials the
	// camouflage server, and the shadowsocks outbound detours through it. Merge
	// each pair into one canonical ss node before the main pass.
	stOuter := map[string]map[string]any{}
	for _, ob := range rawOutbounds {
		if strings.ToLower(cs(ob, "type")) != "shadowtls" {
			continue
		}
		if tag := cs(ob, "tag"); tag != "" {
			stOuter[tag] = ob
		}
	}
	stInner := map[string]map[string]any{} // shadowtls tag -> its shadowsocks outbound
	mergedSS := map[string]bool{}          // shadowsocks tag consumed by a merge
	for _, ob := range rawOutbounds {
		switch strings.ToLower(cs(ob, "type")) {
		case "shadowsocks", "ss":
			detour := cs(ob, "detour")
			if stOuter[detour] == nil {
				continue
			}
			if _, seen := stInner[detour]; seen {
				continue
			}
			stInner[detour] = ob
			mergedSS[cs(ob, "tag")] = true
		}
	}

	for _, ob := range rawOutbounds {
		typ := strings.ToLower(cs(ob, "type"))
		tag := cs(ob, "tag")

		// Skip internal routing types cleanly.
		if nonProxyOutbounds[typ] {
			continue
		}
		if typ == "shadowtls" {
			if inner := stInner[tag]; inner != nil {
				nodes = append(nodes, mergeSingboxShadowTLS(ob, inner))
			} else {
				skipped = append(skipped, fmt.Sprintf("%v", ob))
			}
			continue
		}
		if mergedSS[tag] {
			continue
		}

		server := cs(ob, "server")
		port := ci(ob, "server_port")

		// Protocol-specific extraction
		p, err := parseSingboxOutbound(typ, tag, server, port, ob)
		if err != nil || p == nil {
			skipped = append(skipped, fmt.Sprintf("%v", ob))
			continue
		}
		nodes = append(nodes, p)
	}

	return nodes, skipped, nil
}

// mergeSingboxShadowTLS joins the shadowtls outbound with the shadowsocks
// outbound it carries into one ss node with the canonical plugin wrapper.
func mergeSingboxShadowTLS(st, ss map[string]any) *proxy.Proxy {
	p := proxy.New("ss", cs(ss, "tag"), cs(st, "server"), ci(st, "server_port"))
	p.Set("cipher", cs(ss, "method"))
	p.Set("password", cs(ss, "password"))
	opts := map[string]any{}
	if sni := cs(cmap(st, "tls"), "server_name"); sni != "" {
		opts["host"] = sni
	}
	if pass := cs(st, "password"); pass != "" {
		opts["password"] = pass
	}
	if version := ci(st, "version"); version > 0 {
		opts["version"] = version
	}
	p.Set("plugin", "shadow-tls")
	p.Set("plugin-opts", opts)
	if cb(ss, "tcp_fast_open") {
		p.SetRaw("tfo", true)
	}
	return p
}

func parseSingboxOutbound(typ, tag, server string, port int, ob map[string]any) (*proxy.Proxy, error) {
	if tag == "" || server == "" || port == 0 {
		// Some local/special nodes (like wireguard without server_port in old schemas) might differ,
		// but standard outbound proxy nodes must have host and port.
		if typ != "wireguard" {
			return nil, fmt.Errorf("missing tag/server/port")
		}
	}

	switch typ {
	case "shadowsocks", "ss":
		p := proxy.New("ss", tag, server, port)
		p.Set("cipher", cs(ob, "method"))
		p.Set("password", cs(ob, "password"))
		if cb(ob, "tcp_fast_open") {
			p.SetRaw("tfo", true)
		}
		plugin := cs(ob, "plugin")
		pluginOpts := cs(ob, "plugin_opts")
		if plugin == "obfs-local" || plugin == "obfs" {
			p.Set("plugin", "obfs")
			opts := map[string]any{}
			for _, part := range strings.Split(pluginOpts, ";") {
				k, v, ok := strings.Cut(part, "=")
				if !ok {
					continue
				}
				k = strings.TrimSpace(k)
				v = strings.TrimSpace(v)
				switch k {
				case "obfs":
					opts["mode"] = v
				case "obfs-host":
					opts["host"] = v
				}
			}
			p.Set("plugin-opts", opts)
		} else if plugin == "v2ray-plugin" {
			p.Set("plugin", "v2ray-plugin")
			opts := map[string]any{}
			for _, part := range strings.Split(pluginOpts, ";") {
				part = strings.TrimSpace(part)
				if part == "tls" {
					opts["tls"] = true
					continue
				}
				k, v, ok := strings.Cut(part, "=")
				if ok {
					opts[strings.TrimSpace(k)] = strings.TrimSpace(v)
				}
			}
			p.Set("plugin-opts", opts)
		}
		return p, nil

	case "vmess":
		p := proxy.New("vmess", tag, server, port)
		p.Set("uuid", cs(ob, "uuid"))
		if aid := ci(ob, "alter_id"); aid >= 0 {
			p.SetRaw("alterId", aid)
		}
		p.Set("cipher", firstNonEmptyStr(cs(ob, "security"), "auto"))
		extractSingboxTLS(p, cmap(ob, "tls"))
		extractSingboxTransport(p, cmap(ob, "transport"))
		if cb(ob, "tcp_fast_open") {
			p.SetRaw("tfo", true)
		}
		return p, nil

	case "vless":
		p := proxy.New("vless", tag, server, port)
		p.Set("uuid", cs(ob, "uuid"))
		if flow := cs(ob, "flow"); flow != "" {
			p.Set("flow", flow)
		}
		extractSingboxTLS(p, cmap(ob, "tls"))
		extractSingboxTransport(p, cmap(ob, "transport"))
		if cb(ob, "tcp_fast_open") {
			p.SetRaw("tfo", true)
		}
		return p, nil

	case "trojan":
		p := proxy.New("trojan", tag, server, port)
		p.Set("password", cs(ob, "password"))
		p.SetRaw("udp", true)
		extractSingboxTLS(p, cmap(ob, "tls"))
		extractSingboxTransport(p, cmap(ob, "transport"))
		if cb(ob, "tcp_fast_open") {
			p.SetRaw("tfo", true)
		}
		return p, nil

	case "hysteria2", "hy2":
		p := proxy.New("hysteria2", tag, server, port)
		p.Set("password", cs(ob, "password"))
		if obfs := cmap(ob, "obfs"); obfs != nil {
			p.Set("obfs", cs(obfs, "type"))
			p.Set("obfs-password", cs(obfs, "password"))
		}
		extractSingboxTLS(p, cmap(ob, "tls"))
		return p, nil

	case "hysteria":
		p := proxy.New("hysteria", tag, server, port)
		p.Set("auth-str", cs(ob, "auth_str"))
		if up := ci(ob, "up_mbps"); up > 0 {
			p.Set("up", fmt.Sprintf("%d", up))
		}
		if down := ci(ob, "down_mbps"); down > 0 {
			p.Set("down", fmt.Sprintf("%d", down))
		}
		p.Set("obfs", cs(ob, "obfs"))
		extractSingboxTLS(p, cmap(ob, "tls"))
		return p, nil

	case "tuic":
		p := proxy.New("tuic", tag, server, port)
		p.Set("uuid", cs(ob, "uuid"))
		p.Set("password", cs(ob, "password"))
		p.Set("congestion-controller", cs(ob, "congestion_control"))
		extractSingboxTLS(p, cmap(ob, "tls"))
		return p, nil

	case "anytls":
		p := proxy.New("anytls", tag, server, port)
		p.Set("password", cs(ob, "password"))
		extractSingboxTLS(p, cmap(ob, "tls"))
		return p, nil

	case "snell":
		psk := cs(ob, "psk")
		if psk == "" {
			return nil, fmt.Errorf("snell: missing psk")
		}
		p := proxy.New("snell", tag, server, port)
		p.Set("psk", psk)
		version := ci(ob, "version")
		if version == 0 {
			version = 1
		}
		p.SetRaw("version", version)
		p.Set("userkey", cs(ob, "userkey"))
		if cb(ob, "reuse") {
			p.SetRaw("reuse", true)
		}
		if cb(ob, "udp") {
			p.SetRaw("udp", true)
		}
		if mode := cs(ob, "obfs_mode"); mode != "" && !strings.EqualFold(mode, "none") {
			opts := map[string]any{"mode": strings.ToLower(mode)}
			if host := cs(ob, "obfs_host"); host != "" {
				opts["host"] = host
			}
			p.Set("obfs-opts", opts)
		}
		p.Set("mode", cs(ob, "mode"))
		return p, nil

	case "ssh":
		p := proxy.New("ssh", tag, server, port)
		p.Set("username", firstNonEmptyStr(cs(ob, "user"), cs(ob, "username")))
		p.Set("password", cs(ob, "password"))
		p.Set("private-key", cs(ob, "private_key"))
		p.Set("private-key-passphrase", cs(ob, "private_key_passphrase"))
		if hostKeys := stringList(ob["host_key"]); len(hostKeys) > 0 {
			p.Set("host-key", hostKeys)
		}
		if algs := stringList(ob["host_key_algorithms"]); len(algs) > 0 {
			p.Set("host-key-algorithms", algs)
		}
		return p, nil

	case "naive":
		p := proxy.New("naive", tag, server, port)
		p.Set("username", cs(ob, "username"))
		p.Set("password", cs(ob, "password"))
		// naive is TLS-only and has no insecure mode; TLS options cover the rest.
		p.SetRaw("tls", true)
		if cb(ob, "quic") {
			p.SetRaw("quic", true)
		}
		extractSingboxTLS(p, cmap(ob, "tls"))
		if v := ci(ob, "insecure_concurrency"); v > 0 {
			p.Set("insecure-concurrency", v)
		}
		return p, nil

	case "socks", "socks5":
		p := proxy.New("socks5", tag, server, port)
		p.Set("username", cs(ob, "username"))
		p.Set("password", cs(ob, "password"))
		return p, nil

	case "http":
		p := proxy.New("http", tag, server, port)
		p.Set("username", cs(ob, "username"))
		p.Set("password", cs(ob, "password"))
		extractSingboxTLS(p, cmap(ob, "tls"))
		return p, nil

	case "wireguard":
		p := proxy.New("wireguard", tag, server, port)
		p.Set("private-key", cs(ob, "private_key"))
		p.Set("public-key", cs(ob, "peer_public_key"))
		p.Set("pre-shared-key", cs(ob, "pre_shared_key"))
		if localAddrs, ok := ob["local_address"].([]any); ok {
			for _, addr := range localAddrs {
				s, _ := addr.(string)
				s = strings.TrimSpace(s)
				if strings.Contains(s, ":") {
					p.Set("ipv6", strings.TrimSuffix(s, "/128"))
				} else if s != "" {
					p.Set("ip", strings.TrimSuffix(s, "/32"))
				}
			}
		}
		if mtu := ci(ob, "mtu"); mtu > 0 {
			p.Set("mtu", mtu)
		}
		if rsv, ok := ob["reserved"].([]any); ok && len(rsv) > 0 {
			var rsvInts []int
			for _, r := range rsv {
				rsvInts = append(rsvInts, anyToInt(r))
			}
			p.Set("reserved", rsvInts)
		}
		return p, nil
	}

	return nil, fmt.Errorf("unsupported singbox outbound type: %s", typ)
}

func extractSingboxTLS(p *proxy.Proxy, tls map[string]any) {
	if tls == nil {
		return
	}
	if cb(tls, "enabled") || cs(tls, "server_name") != "" || len(cmap(tls, "reality")) > 0 {
		p.SetRaw("tls", true)
	}
	if sni := cs(tls, "server_name"); sni != "" {
		p.Set("sni", sni)
	}
	if cb(tls, "insecure") {
		p.SetRaw("skip-cert-verify", true)
	}
	if alpn, ok := tls["alpn"].([]any); ok && len(alpn) > 0 {
		var alpnStrs []string
		for _, a := range alpn {
			if s, ok := a.(string); ok && s != "" {
				alpnStrs = append(alpnStrs, s)
			}
		}
		if len(alpnStrs) > 0 {
			p.Set("alpn", alpnStrs)
		}
	}
	if utls := cmap(tls, "utls"); utls != nil {
		if fp := cs(utls, "fingerprint"); fp != "" {
			p.Set("client-fingerprint", fp)
		}
	}
	if reality := cmap(tls, "reality"); reality != nil {
		ro := map[string]any{}
		if pbk := cs(reality, "public_key"); pbk != "" {
			ro["public-key"] = pbk
		}
		if sid := cs(reality, "short_id"); sid != "" {
			ro["short-id"] = sid
		}
		if len(ro) > 0 {
			p.Set("reality-opts", ro)
		}
	}
}

func extractSingboxTransport(p *proxy.Proxy, tr map[string]any) {
	if tr == nil {
		return
	}
	switch cs(tr, "type") {
	case "ws":
		p.Set("network", "ws")
		wsOpts := map[string]any{}
		if path := cs(tr, "path"); path != "" {
			wsOpts["path"] = path
		}
		if headers := cmap(tr, "headers"); headers != nil {
			if host := cs(headers, "Host"); host != "" {
				wsOpts["headers"] = map[string]any{"Host": host}
			}
		}
		p.Set("ws-opts", wsOpts)

	case "httpupgrade":
		p.Set("network", "ws")
		wsOpts := map[string]any{"v2ray-http-upgrade": true}
		if path := cs(tr, "path"); path != "" {
			wsOpts["path"] = path
		}
		if headers := cmap(tr, "headers"); headers != nil {
			if host := cs(headers, "Host"); host != "" {
				wsOpts["headers"] = map[string]any{"Host": host}
			}
		}
		p.Set("ws-opts", wsOpts)

	case "grpc":
		p.Set("network", "grpc")
		p.Set("grpc-opts", map[string]any{
			"grpc-service-name": cs(tr, "service_name"),
		})

	case "http":
		p.Set("network", "h2")
		h2Opts := map[string]any{}
		if path := cs(tr, "path"); path != "" {
			h2Opts["path"] = path
		}
		if hosts, ok := tr["host"].([]any); ok && len(hosts) > 0 {
			var hStrs []string
			for _, h := range hosts {
				if s, ok := h.(string); ok {
					hStrs = append(hStrs, s)
				}
			}
			h2Opts["host"] = hStrs
		}
		p.Set("h2-opts", h2Opts)
	}
}

// Map helper functions
func cs(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

func ci(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	return anyToInt(m[key])
}

func cb(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	if v, ok := m[key].(bool); ok {
		return v
	}
	return false
}

func cmap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

// stringList converts a JSON array of strings into a []string, dropping
// non-string and empty entries.
func stringList(v any) []string {
	items, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, item := range items {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
