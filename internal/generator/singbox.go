package generator

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// GenerateSingbox renders a sing-box JSON config: one outbound per node, plus
// selector/urltest outbounds for the proxy groups and route rules translated
// from the rulesets. Protocols with no sing-box outbound form are skipped and
// reported in Result.SkippedNodes. A built-in base (log/dns/inbounds) is used.
func GenerateSingbox(ctx context.Context, nodes []*proxy.Proxy, cfg *extconfig.Config, f Fetcher, opts Options) (*Result, error) {
	res := &Result{ContentType: ctJSON}
	nodes = prepareNodes(nodes, cfg, opts, res)

	// Node outbounds.
	var outbounds []map[string]any
	emitted := map[string]bool{}
	allNames := make([]string, 0, len(nodes))
	for _, n := range nodes {
		ob, ok := nodeSingboxOutbound(n)
		if !ok {
			res.SkippedNodes = append(res.SkippedNodes, n.Name+" ("+n.Type+": unsupported by sing-box generator)")
			continue
		}
		outbounds = append(outbounds, ob)
		emitted[n.Name] = true
		allNames = append(allNames, n.Name)
	}

	// list=true: emit only the outbounds list
	if opts.ListOnly {
		b, err := json.MarshalIndent(map[string]any{"outbounds": outbounds}, "", "  ")
		if err != nil {
			return nil, err
		}
		res.Output = b
		return res, nil
	}

	// Group outbounds (selector / urltest). Names of all groups so member refs to
	// other groups survive the emitted-filter.
	groupNames := map[string]bool{}
	for _, d := range cfg.ProxyGroups {
		groupNames[d.Name] = true
	}
	groups := buildGroups(cfg.ProxyGroups, nodes, allNames, res)
	for _, g := range groups {
		outbounds = append(outbounds, singboxGroupOutbound(g, emitted, groupNames))
	}

	// Built-in tail outbounds.
	outbounds = append(outbounds,
		map[string]any{"type": "direct", "tag": "direct"},
		map[string]any{"type": "block", "tag": "block"},
		map[string]any{"type": "dns", "tag": "dns-out"},
	)

	// Route rules from neutral rules.
	neutral, skippedRules := collectRules(ctx, cfg, f, opts)
	routeRules := []map[string]any{{"protocol": "dns", "outbound": "dns-out"}}
	final := "direct"
	for _, r := range neutral {
		if r.IsMatch() {
			final = singboxOutboundRef(r.Group, emitted, groupNames)
			continue
		}
		if rule, ok := singboxRouteRule(r, emitted, groupNames); ok {
			routeRules = append(routeRules, rule)
		} else {
			skippedRules = append(skippedRules, r.Type+","+r.Value)
		}
	}
	res.SkippedRules = skippedRules

	conf := map[string]any{
		"log": map[string]any{"level": "info", "timestamp": true},
		"dns": map[string]any{
			"servers": []map[string]any{
				{"tag": "remote", "address": "tls://8.8.8.8"},
				{"tag": "local", "address": "223.5.5.5", "detour": "direct"},
			},
			"final": "remote",
		},
		"inbounds": []map[string]any{
			{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080},
		},
		"outbounds": outbounds,
		"route": map[string]any{
			"rules":                 routeRules,
			"final":                 final,
			"auto_detect_interface": true,
		},
	}

	b, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		return nil, err
	}
	res.Output = b
	return res, nil
}

// singboxOutboundRef maps a selector member / rule group to a sing-box outbound
// tag (DIRECT->direct, REJECT->block; node tags kept only when emitted).
func singboxOutboundRef(m string, emitted, groupNames map[string]bool) string {
	switch m {
	case "DIRECT":
		return "direct"
	case "REJECT", "REJECT-DROP":
		return "block"
	}
	if groupNames[m] || emitted[m] {
		return m
	}
	return m // group/rule target we can't classify: keep verbatim
}

// singboxGroupOutbound renders a proxy group as a selector or urltest outbound.
func singboxGroupOutbound(g groupOut, emitted, groupNames map[string]bool) map[string]any {
	members := make([]string, 0, len(g.Proxies))
	for _, m := range g.Proxies {
		switch m {
		case "DIRECT":
			members = append(members, "direct")
		case "REJECT", "REJECT-DROP":
			members = append(members, "block")
		default:
			if groupNames[m] || emitted[m] {
				members = append(members, m)
			}
		}
	}
	if len(members) == 0 {
		members = []string{"direct"}
	}
	if g.Type == "select" {
		return map[string]any{"type": "selector", "tag": g.Name, "outbounds": members}
	}
	// url-test / fallback / load-balance / relay -> urltest
	ob := map[string]any{
		"type":      "urltest",
		"tag":       g.Name,
		"outbounds": members,
		"url":       firstNonEmptyStr(g.URL, "https://www.gstatic.com/generate_204"),
	}
	interval := g.Interval
	if interval <= 0 {
		interval = 300
	}
	ob["interval"] = strconv.Itoa(interval) + "s"
	if g.Tolerance > 0 {
		ob["tolerance"] = g.Tolerance
	}
	return ob
}

// singboxRuleField maps a neutral rule type to its sing-box route-rule field
// name. The empty string marks an unsupported type.
var singboxRuleField = map[string]string{
	"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword",
	"DOMAIN-REGEX": "domain_regex", "GEOSITE": "geosite", "GEOIP": "geoip",
	"IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr", "SRC-IP-CIDR": "source_ip_cidr",
	"DST-PORT": "port", "SRC-PORT": "source_port", "IP-ASN": "ip_asn",
	"PROCESS-NAME": "process_name",
}

// singboxRouteRule builds a single route rule object. ok is false for rule types
// sing-box has no field for.
func singboxRouteRule(r Rule, emitted, groupNames map[string]bool) (map[string]any, bool) {
	canon := normalizeRuleType(r.Type)
	field, ok := singboxRuleField[canon]
	if !ok {
		return nil, false
	}
	rule := map[string]any{"outbound": singboxOutboundRef(r.Group, emitted, groupNames)}
	switch field {
	case "port", "source_port":
		if p, err := strconv.Atoi(r.Value); err == nil {
			rule[field] = []int{p}
		} else {
			return nil, false
		}
	case "ip_asn":
		if asn, err := strconv.Atoi(r.Value); err == nil {
			rule[field] = []int{asn}
		} else {
			return nil, false
		}
	case "geoip", "geosite":
		rule[field] = []string{strings.ToLower(r.Value)}
	default:
		rule[field] = []string{r.Value}
	}
	return rule, true
}

// nodeSingboxOutbound builds the sing-box outbound object for one node.
func nodeSingboxOutbound(n *proxy.Proxy) (map[string]any, bool) {
	c := n.Clash
	base := map[string]any{
		"tag":         n.Name,
		"server":      cs(c, "server"),
		"server_port": ci(c, "port"),
	}
	if cb(c, "tfo") {
		switch n.Type {
		case "ss", "vmess", "vless", "trojan", "socks5", "socks":
			base["tcp_fast_open"] = true
		}
	}

	switch n.Type {
	case "ss":
		base["type"] = "shadowsocks"
		base["method"] = cs(c, "cipher")
		base["password"] = cs(c, "password")
		if cs(c, "plugin") == "obfs" {
			o := cmap(c, "plugin-opts")
			parts := []string{"obfs=" + cs(o, "mode")}
			if h := cs(o, "host"); h != "" {
				parts = append(parts, "obfs-host="+h)
			}
			base["plugin"] = "obfs-local"
			base["plugin_opts"] = strings.Join(parts, ";")
		} else if cs(c, "plugin") == "v2ray-plugin" {
			o := cmap(c, "plugin-opts")
			parts := []string{"mode=" + firstNonEmptyStr(cs(o, "mode"), "websocket")}
			if cb(o, "tls") {
				parts = append(parts, "tls")
			}
			if h := cs(o, "host"); h != "" {
				parts = append(parts, "host="+h)
			}
			if p := cs(o, "path"); p != "" {
				parts = append(parts, "path="+p)
			}
			base["plugin"] = "v2ray-plugin"
			base["plugin_opts"] = strings.Join(parts, ";")
		}
		return base, true

	case "vmess":
		base["type"] = "vmess"
		base["uuid"] = cs(c, "uuid")
		base["alter_id"] = ci(c, "alterId")
		base["security"] = firstNonEmptyStr(cs(c, "cipher"), "auto")
		if t := singboxTransport(c); t != nil {
			base["transport"] = t
		}
		if tls := singboxTLS(c, getSNI(c), false); tls != nil {
			base["tls"] = tls
		}
		return base, true

	case "vless":
		base["type"] = "vless"
		base["uuid"] = cs(c, "uuid")
		if flow := cs(c, "flow"); flow != "" {
			base["flow"] = flow
		}
		if t := singboxTransport(c); t != nil {
			base["transport"] = t
		}
		if tls := singboxTLS(c, getSNI(c), false); tls != nil {
			base["tls"] = tls
		}
		return base, true

	case "trojan":
		base["type"] = "trojan"
		base["password"] = cs(c, "password")
		if t := singboxTransport(c); t != nil {
			base["transport"] = t
		}
		base["tls"] = singboxTLS(c, getSNI(c), true)
		return base, true

	case "hysteria2":
		base["type"] = "hysteria2"
		base["password"] = cs(c, "password")
		if obfs := cs(c, "obfs"); obfs != "" {
			base["obfs"] = map[string]any{"type": obfs, "password": cs(c, "obfs-password")}
		}
		base["tls"] = singboxTLS(c, getSNI(c), true)
		return base, true

	case "tuic":
		base["type"] = "tuic"
		base["uuid"] = cs(c, "uuid")
		base["password"] = cs(c, "password")
		if cc := cs(c, "congestion-controller"); cc != "" {
			base["congestion_control"] = cc
		}
		base["tls"] = singboxTLS(c, getSNI(c), true)
		return base, true

	case "socks5", "socks":
		base["type"] = "socks"
		base["version"] = "5"
		if u := cs(c, "username"); u != "" {
			base["username"] = u
		}
		if pw := cs(c, "password"); pw != "" {
			base["password"] = pw
		}
		return base, true

	case "http":
		base["type"] = "http"
		if u := cs(c, "username"); u != "" {
			base["username"] = u
		}
		if pw := cs(c, "password"); pw != "" {
			base["password"] = pw
		}
		if tls := singboxTLS(c, getSNI(c), false); tls != nil {
			base["tls"] = tls
		}
		return base, true

	case "wireguard":
		base["type"] = "wireguard"
		base["private_key"] = cs(c, "private-key")
		base["peer_public_key"] = cs(c, "public-key")
		if psk := cs(c, "pre-shared-key"); psk != "" {
			base["pre_shared_key"] = psk
		}
		var localAddr []string
		if ip := cs(c, "ip"); ip != "" {
			if !strings.Contains(ip, "/") {
				localAddr = append(localAddr, ip+"/32")
			} else {
				localAddr = append(localAddr, ip)
			}
		}
		if ipv6 := cs(c, "ipv6"); ipv6 != "" {
			if !strings.Contains(ipv6, "/") {
				localAddr = append(localAddr, ipv6+"/128")
			} else {
				localAddr = append(localAddr, ipv6)
			}
		}
		if len(localAddr) > 0 {
			base["local_address"] = localAddr
		}
		if mtu := ci(c, "mtu"); mtu > 0 {
			base["mtu"] = mtu
		}
		if rsv := parseReserved(c["reserved"]); len(rsv) > 0 {
			base["reserved"] = rsv
		}
		return base, true

	case "hysteria":
		base["type"] = "hysteria"
		if auth := cs(c, "auth-str"); auth != "" {
			base["auth_str"] = auth
		}
		if up := ci(c, "up"); up > 0 {
			base["up_mbps"] = up
		}
		if down := ci(c, "down"); down > 0 {
			base["down_mbps"] = down
		}
		if obfs := cs(c, "obfs"); obfs != "" {
			base["obfs"] = obfs
		}
		base["tls"] = singboxTLS(c, getSNI(c), true)
		return base, true
	}
	return nil, false
}

// singboxTransport builds the transport object for ws/grpc/http networks, or nil
// for plain tcp.
func singboxTransport(c map[string]any) map[string]any {
	switch cs(c, "network") {
	case "ws":
		ws := cmap(c, "ws-opts")
		t := map[string]any{"type": "ws"}
		if p := cs(ws, "path"); p != "" {
			t["path"] = p
		}
		if hdr := cmap(ws, "headers"); hdr != nil {
			if h := cs(hdr, "Host"); h != "" {
				t["headers"] = map[string]any{"Host": h}
			}
		}
		return t
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": cs(cmap(c, "grpc-opts"), "grpc-service-name")}
	case "h2":
		h2 := cmap(c, "h2-opts")
		t := map[string]any{"type": "http"}
		if p := cs(h2, "path"); p != "" {
			t["path"] = p
		}
		if h := joinAny(h2["host"]); h != "" {
			t["host"] = []string{h}
		}
		return t
	}
	return nil
}

// singboxTLS builds a tls object. always forces enabled for protocols that are
// inherently TLS (trojan/hysteria2/tuic); for vmess/vless it returns nil unless
// the node enables TLS.
func singboxTLS(c map[string]any, serverName string, always bool) map[string]any {
	if !always && !cb(c, "tls") && len(cmap(c, "reality-opts")) == 0 {
		return nil
	}
	tls := map[string]any{"enabled": true}
	if serverName != "" {
		tls["server_name"] = serverName
	}
	if cb(c, "skip-cert-verify") {
		tls["insecure"] = true
	}
	if alpn := splitAny(c["alpn"]); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if fp := cs(c, "client-fingerprint"); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if ro := cmap(c, "reality-opts"); len(ro) > 0 {
		reality := map[string]any{"enabled": true}
		if pbk := cs(ro, "public-key"); pbk != "" {
			reality["public_key"] = pbk
		}
		if sid := cs(ro, "short-id"); sid != "" {
			reality["short_id"] = sid
		}
		tls["reality"] = reality
	}
	return tls
}

// splitAny renders a string or []string/[]any field as a []string (for alpn).
func splitAny(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []string:
		return t
	case []any:
		var out []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
