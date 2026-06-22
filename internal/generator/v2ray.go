package generator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// GenerateV2ray renders nodes as a base64-encoded list of share-links (ss://,
// vmess://, vless://, trojan://, hysteria2://, tuic://). This is the universal
// "v2ray"/"mixed" subscription consumed by v2rayN, NekoBox, Shadowrocket, etc.
// It carries no groups or rules — the client manages those. Protocols without a
// share-link form are skipped and reported in Result.SkippedNodes.
func GenerateV2ray(_ context.Context, nodes []*proxy.Proxy, cfg *extconfig.Config, _ Fetcher, opts Options) (*Result, error) {
	res := &Result{ContentType: ctText}
	nodes = prepareNodes(nodes, cfg, opts, res)

	links := make([]string, 0, len(nodes))
	for _, n := range nodes {
		link, ok := nodeShareLink(n)
		if !ok {
			res.SkippedNodes = append(res.SkippedNodes, n.Name+" ("+n.Type+": no share-link form)")
			continue
		}
		links = append(links, link)
	}

	joined := strings.Join(links, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(joined))
	res.Output = []byte(encoded)
	return res, nil
}

// nodeShareLink renders a single node to its share-link URI, reading from the
// node's Clash field bag. ok is false for protocols with no URI form.
func nodeShareLink(n *proxy.Proxy) (string, bool) {
	c := n.Clash
	host := cs(c, "server")
	port := ci(c, "port")
	hostport := host + ":" + strconv.Itoa(port)
	frag := "#" + encodeFragment(n.Name)

	switch n.Type {
	case "ss":
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(cs(c, "cipher") + ":" + cs(c, "password")))
		link := "ss://" + userinfo + "@" + hostport
		if q := ssPluginQuery(c); q != "" {
			link += "?" + q
		}
		return link + frag, true

	case "vmess":
		j := map[string]any{
			"v":    "2",
			"ps":   n.Name,
			"add":  host,
			"port": strconv.Itoa(port),
			"id":   cs(c, "uuid"),
			"aid":  strconv.Itoa(ci(c, "alterId")),
			"scy":  firstNonEmptyStr(cs(c, "cipher"), "auto"),
			"net":  firstNonEmptyStr(cs(c, "network"), "tcp"),
			"type": "none",
			"tls":  tlsField(c),
		}
		applyVMessTransportJSON(j, c)
		if sni := cs(c, "servername"); sni != "" {
			j["sni"] = sni
		}
		b, _ := json.Marshal(j)
		return "vmess://" + base64.StdEncoding.EncodeToString(b), true

	case "vless":
		q := url.Values{}
		q.Set("encryption", "none")
		ro := cmap(c, "reality-opts")
		switch {
		case len(ro) > 0:
			q.Set("security", "reality")
			if pbk := cs(ro, "public-key"); pbk != "" {
				q.Set("pbk", pbk)
			}
			if sid := cs(ro, "short-id"); sid != "" {
				q.Set("sid", sid)
			}
		case cb(c, "tls"):
			q.Set("security", "tls")
		default:
			q.Set("security", "none")
		}
		if sni := cs(c, "servername"); sni != "" {
			q.Set("sni", sni)
		}
		if fp := cs(c, "client-fingerprint"); fp != "" {
			q.Set("fp", fp)
		}
		if flow := cs(c, "flow"); flow != "" {
			q.Set("flow", flow)
		}
		applyV2RayTransportQuery(q, c)
		return "vless://" + cs(c, "uuid") + "@" + hostport + "?" + q.Encode() + frag, true

	case "trojan":
		q := url.Values{}
		if sni := cs(c, "sni"); sni != "" {
			q.Set("sni", sni)
		}
		if cb(c, "skip-cert-verify") {
			q.Set("allowInsecure", "1")
		}
		applyV2RayTransportQuery(q, c)
		return "trojan://" + cs(c, "password") + "@" + hostport + "?" + q.Encode() + frag, true

	case "hysteria2":
		q := url.Values{}
		if sni := cs(c, "sni"); sni != "" {
			q.Set("sni", sni)
		}
		if cb(c, "skip-cert-verify") {
			q.Set("insecure", "1")
		}
		if obfs := cs(c, "obfs"); obfs != "" {
			q.Set("obfs", obfs)
			q.Set("obfs-password", cs(c, "obfs-password"))
		}
		if alpn := joinAny(c["alpn"]); alpn != "" {
			q.Set("alpn", alpn)
		}
		link := "hysteria2://" + cs(c, "password") + "@" + hostport
		if enc := q.Encode(); enc != "" {
			link += "?" + enc
		}
		return link + frag, true

	case "tuic":
		q := url.Values{}
		if cc := cs(c, "congestion-controller"); cc != "" {
			q.Set("congestion_control", cc)
		}
		if mode := cs(c, "udp-relay-mode"); mode != "" {
			q.Set("udp_relay_mode", mode)
		}
		if sni := cs(c, "sni"); sni != "" {
			q.Set("sni", sni)
		}
		if alpn := joinAny(c["alpn"]); alpn != "" {
			q.Set("alpn", alpn)
		}
		if cb(c, "skip-cert-verify") {
			q.Set("allow_insecure", "1")
		}
		return "tuic://" + cs(c, "uuid") + ":" + cs(c, "password") + "@" + hostport + "?" + q.Encode() + frag, true
	}
	return "", false
}

// ssPluginQuery builds the SIP002 plugin query value for an SS node, or "" when
// the node has no plugin.
func ssPluginQuery(c map[string]any) string {
	plugin := cs(c, "plugin")
	if plugin == "" {
		return ""
	}
	opts := cmap(c, "plugin-opts")
	var parts []string
	switch plugin {
	case "obfs":
		parts = append(parts, "obfs-local", "obfs="+cs(opts, "mode"))
		if h := cs(opts, "host"); h != "" {
			parts = append(parts, "obfs-host="+h)
		}
	case "v2ray-plugin":
		parts = append(parts, "v2ray-plugin", "mode="+firstNonEmptyStr(cs(opts, "mode"), "websocket"))
		if cb(opts, "tls") {
			parts = append(parts, "tls")
		}
		if h := cs(opts, "host"); h != "" {
			parts = append(parts, "host="+h)
		}
		if p := cs(opts, "path"); p != "" {
			parts = append(parts, "path="+p)
		}
	default:
		return ""
	}
	return "plugin=" + url.QueryEscape(strings.Join(parts, ";"))
}

// applyVMessTransportJSON fills net/host/path/type into a vmess share-link JSON
// from the node's Clash transport options.
func applyVMessTransportJSON(j map[string]any, c map[string]any) {
	switch cs(c, "network") {
	case "ws":
		ws := cmap(c, "ws-opts")
		j["path"] = cs(ws, "path")
		if hdr := cmap(ws, "headers"); hdr != nil {
			j["host"] = cs(hdr, "Host")
		}
	case "grpc":
		j["path"] = cs(cmap(c, "grpc-opts"), "grpc-service-name")
	case "h2":
		h2 := cmap(c, "h2-opts")
		j["path"] = cs(h2, "path")
		j["host"] = joinAny(h2["host"])
	}
}

// applyV2RayTransportQuery fills type/host/path/serviceName query params shared
// by vless/trojan share-links.
func applyV2RayTransportQuery(q url.Values, c map[string]any) {
	network := firstNonEmptyStr(cs(c, "network"), "tcp")
	q.Set("type", network)
	switch network {
	case "ws":
		ws := cmap(c, "ws-opts")
		if p := cs(ws, "path"); p != "" {
			q.Set("path", p)
		}
		if hdr := cmap(ws, "headers"); hdr != nil {
			if h := cs(hdr, "Host"); h != "" {
				q.Set("host", h)
			}
		}
	case "grpc":
		if sn := cs(cmap(c, "grpc-opts"), "grpc-service-name"); sn != "" {
			q.Set("serviceName", sn)
		}
	case "h2":
		h2 := cmap(c, "h2-opts")
		if p := cs(h2, "path"); p != "" {
			q.Set("path", p)
		}
		if h := joinAny(h2["host"]); h != "" {
			q.Set("host", h)
		}
	}
}

// tlsField returns "tls" when the node enables TLS, else "".
func tlsField(c map[string]any) string {
	if cb(c, "tls") {
		return "tls"
	}
	return ""
}

// encodeFragment percent-encodes a node name for use in a URI fragment, keeping
// spaces as %20 (url.QueryEscape would turn them into '+').
func encodeFragment(name string) string {
	return strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
}

// --- small typed accessors over the Clash field bag (map[string]any) ---

func cs(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func cb(m map[string]any, k string) bool   { b, _ := m[k].(bool); return b }

func cmap(m map[string]any, k string) map[string]any {
	mm, _ := m[k].(map[string]any)
	return mm
}

// ci reads an int field, tolerating the int/int64/float64 forms a decoded map
// may carry.
func ci(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// joinAny renders a string or []string/[]any value as a comma-separated string
// (used for alpn / h2 host lists).
func joinAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []string:
		return strings.Join(t, ",")
	case []any:
		var parts []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ",")
	}
	return ""
}
