package parser

import (
	"fmt"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// QuanX resources list nodes as "type=host:port, key=value, ..." lines, with the
// node type on the left of the "=" instead of a user-chosen name (Surge puts the
// name there). Airports that only ship a Quantumult X resource otherwise cannot
// be imported at all.
var quanxTypeSet = map[string]bool{
	"shadowsocks":  true,
	"shadowsocksr": true,
	"vmess":        true,
	"trojan":       true,
	"http":         true,
	"socks5":       true,
}

// quanxServerSections are the QuanX sections that hold node definitions.
var quanxServerSections = map[string]bool{
	"server_local":  true,
	"server_remote": true,
	"server":        true,
}

// looksLikeQuanX reports whether text is a QuanX resource or a bare list of
// QuanX node lines.
func looksLikeQuanX(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		if typ, rest, ok := quanxLine(line); ok && quanxTypeSet[typ] && quanxHostPort(rest) {
			return true
		}
	}
	return false
}

// quanxLine splits one "type=rest" line. ok is false for blank lines, comments,
// section headers, and lines without "=".
func quanxLine(line string) (typ, rest string, ok bool) {
	line = strings.TrimSpace(strings.TrimRight(line, "\r"))
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") ||
		strings.HasPrefix(line, "//") || strings.HasPrefix(line, "[") {
		return "", "", false
	}
	key, value, found := strings.Cut(line, "=")
	if !found {
		return "", "", false
	}
	return strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value), true
}

// quanxHostPort reports whether the first comma field of rest is "host:port".
// Surge lines start with a proxy type there ("ss, 1.2.3.4, 8388"), so this is
// what keeps the two formats apart.
func quanxHostPort(rest string) bool {
	first, _, _ := strings.Cut(rest, ",")
	host, port := splitHostPort(first)
	return host != "" && port > 0
}

// parseQuanX extracts nodes from a QuanX resource. With section headers, only
// the server sections are read and everything else (filters, rewrites) is
// ignored; without them, every non-comment line is treated as a node.
func parseQuanX(text string) (nodes []*proxy.Proxy, skipped []string, err error) {
	sectioned := false
	for _, line := range strings.Split(text, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			sectioned = true
			break
		}
	}

	section := ""
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(strings.TrimRight(line, "\r"))
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.ToLower(strings.Trim(trimmed, "[]"))
			continue
		}
		if sectioned && !quanxServerSections[section] {
			continue
		}
		typ, rest, ok := quanxLine(trimmed)
		if !ok {
			if sectioned || trimmed == "" {
				continue
			}
			skipped = append(skipped, trimmed)
			continue
		}
		if !quanxTypeSet[typ] {
			skipped = append(skipped, trimmed)
			continue
		}
		p, perr := parseQuanXNode(typ, rest)
		if perr != nil {
			skipped = append(skipped, trimmed+" ("+perr.Error()+")")
			continue
		}
		nodes = append(nodes, p)
	}
	return nodes, skipped, nil
}

func parseQuanXNode(typ, rest string) (*proxy.Proxy, error) {
	fields := strings.Split(rest, ",")
	host, port := splitHostPort(strings.TrimSpace(fields[0]))
	if host == "" || port == 0 {
		return nil, fmt.Errorf("missing host/port")
	}
	params := map[string]string{}
	for _, raw := range fields[1:] {
		k, v, ok := strings.Cut(raw, "=")
		if !ok {
			continue
		}
		params[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	name := params["tag"]
	if name == "" {
		name = fmt.Sprintf("%s:%d", host, port)
	}
	// QX writes "tls-verification=false" to skip validation; unset means verify.
	skipCert := params["tls-verification"] == "false"

	switch typ {
	case "shadowsocks":
		p := proxy.New("ss", name, host, port)
		p.Set("cipher", params["method"])
		p.Set("password", params["password"])
		if boolish(params["udp-relay"]) {
			p.SetRaw("udp", true)
		}
		if obfs := params["obfs"]; obfs != "" {
			p.Set("plugin", "obfs")
			opts := map[string]any{"mode": obfs}
			if h := params["obfs-host"]; h != "" {
				opts["host"] = h
			}
			p.Set("plugin-opts", opts)
		}
		if cs(p.Clash, "cipher") == "" || cs(p.Clash, "password") == "" {
			return nil, fmt.Errorf("shadowsocks needs method and password)")
		}
		return p, nil

	case "shadowsocksr":
		p := proxy.New("ssr", name, host, port)
		p.Set("cipher", params["method"])
		p.Set("password", params["password"])
		p.Set("protocol", params["protocol"])
		p.Set("protocol-param", params["protocol-param"])
		p.Set("obfs", params["obfs"])
		p.Set("obfs-param", params["obfs-param"])
		if boolish(params["udp-relay"]) {
			p.SetRaw("udp", true)
		}
		if cs(p.Clash, "cipher") == "" || cs(p.Clash, "password") == "" {
			return nil, fmt.Errorf("shadowsocksr needs method and password)")
		}
		return p, nil

	case "vmess":
		p := proxy.New("vmess", name, host, port)
		p.Set("uuid", params["password"])
		p.Set("cipher", firstNonEmptyString(params["method"], "auto"))
		p.SetRaw("alterId", 0)
		applyQuanXVMessTransport(p, params, skipCert)
		if cs(p.Clash, "uuid") == "" {
			return nil, fmt.Errorf("vmess needs password)")
		}
		return p, nil

	case "trojan":
		p := proxy.New("trojan", name, host, port)
		p.Set("password", params["password"])
		p.Set("sni", params["tls-host"])
		p.SetRaw("tls", true)
		if skipCert {
			p.SetRaw("skip-cert-verify", true)
		}
		if cs(p.Clash, "password") == "" {
			return nil, fmt.Errorf("trojan needs password)")
		}
		return p, nil

	case "http":
		p := proxy.New("http", name, host, port)
		p.Set("username", params["username"])
		p.Set("password", params["password"])
		if boolish(params["over-tls"]) {
			p.SetRaw("tls", true)
		}
		if skipCert {
			p.SetRaw("skip-cert-verify", true)
		}
		return p, nil

	case "socks5":
		p := proxy.New("socks5", name, host, port)
		p.Set("username", params["username"])
		p.Set("password", params["password"])
		return p, nil
	}
	return nil, fmt.Errorf("unsupported type %s", typ)
}

// applyQuanXVMessTransport maps QX's obfs/tls options onto Clash transport
// fields. QX spells the transport "obfs" whether it means WebSocket ("ws"),
// WebSocket over TLS ("wss"), or plain TLS ("over-tls").
func applyQuanXVMessTransport(p *proxy.Proxy, params map[string]string, skipCert bool) {
	tls := false
	switch strings.ToLower(params["obfs"]) {
	case "ws":
		p.Set("network", "ws")
	case "wss":
		p.Set("network", "ws")
		tls = true
	case "over-tls":
		tls = true
	}
	if host := params["obfs-host"]; host != "" {
		if cs(p.Clash, "network") == "ws" {
			p.Set("ws-opts", map[string]any{
				"path":    firstNonEmptyString(params["obfs-uri"], "/"),
				"headers": map[string]any{"Host": host},
			})
		}
	}
	if tlsHost := params["tls-host"]; tlsHost != "" {
		p.Set("servername", tlsHost)
	}
	if tls {
		p.SetRaw("tls", true)
		if skipCert {
			p.SetRaw("skip-cert-verify", true)
		}
	}
}
