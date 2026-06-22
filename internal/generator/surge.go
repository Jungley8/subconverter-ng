package generator

import (
	"context"
	"strconv"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// surgeFlavor selects the dialect of the INI "surge family" output. The section
// skeleton, proxy groups and rules are shared; only the per-node proxy line
// syntax differs (Surge/Shadowrocket share one form, Loon has its own).
type surgeFlavor int

const (
	flavorSurge surgeFlavor = iota
	flavorShadowrocket
	flavorLoon
)

// GenerateSurge renders a Surge .conf.
func GenerateSurge(ctx context.Context, nodes []*proxy.Proxy, cfg *extconfig.Config, f Fetcher, opts Options) (*Result, error) {
	return generateSurgeFamily(ctx, flavorSurge, nodes, cfg, f, opts)
}

// GenerateShadowrocket renders a Shadowrocket-flavoured Surge .conf (the managed
// config form Shadowrocket imports).
func GenerateShadowrocket(ctx context.Context, nodes []*proxy.Proxy, cfg *extconfig.Config, f Fetcher, opts Options) (*Result, error) {
	return generateSurgeFamily(ctx, flavorShadowrocket, nodes, cfg, f, opts)
}

// GenerateLoon renders a Loon .conf.
func GenerateLoon(ctx context.Context, nodes []*proxy.Proxy, cfg *extconfig.Config, f Fetcher, opts Options) (*Result, error) {
	return generateSurgeFamily(ctx, flavorLoon, nodes, cfg, f, opts)
}

func generateSurgeFamily(ctx context.Context, flavor surgeFlavor, nodes []*proxy.Proxy, cfg *extconfig.Config, f Fetcher, opts Options) (*Result, error) {
	res := &Result{ContentType: ctText}
	nodes = prepareNodes(nodes, cfg, opts, res)

	var b strings.Builder
	b.WriteString("[General]\n")
	b.WriteString("loglevel = notify\n")
	b.WriteString("dns-server = 223.5.5.5, 119.29.29.29, system\n")
	b.WriteString("skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, localhost, *.local\n")
	b.WriteString("\n[Proxy]\n")

	// Render proxy lines, tracking which node names actually made it in so empty
	// groups (and groups referencing skipped nodes) stay loadable.
	emitted := map[string]bool{}
	allNames := make([]string, 0, len(nodes))
	for _, n := range nodes {
		line, ok := surgeNodeLine(flavor, n)
		if !ok {
			res.SkippedNodes = append(res.SkippedNodes, n.Name+" ("+n.Type+": unsupported by target)")
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
		emitted[n.Name] = true
		allNames = append(allNames, n.Name)
	}

	// Proxy groups: reuse the shared resolver, then drop members that were not
	// emitted as proxies (so a group never points at a missing node line).
	groups := buildGroups(cfg.ProxyGroups, nodes, allNames, res)
	b.WriteString("\n[Proxy Group]\n")
	for _, g := range groups {
		b.WriteString(formatSurgeGroup(g, emitted))
		b.WriteByte('\n')
	}

	// Rules: expand to neutral rules then format in Surge syntax, dropping types
	// the family does not support.
	neutral, skippedRules := collectRules(ctx, cfg, f)
	b.WriteString("\n[Rule]\n")
	for _, r := range neutral {
		if line, ok := formatSurgeRule(r); ok {
			b.WriteString(line)
			b.WriteByte('\n')
		} else {
			skippedRules = append(skippedRules, r.Type+","+r.Value)
		}
	}
	res.SkippedRules = skippedRules

	res.Output = []byte(b.String())
	return res, nil
}

// formatSurgeGroup renders one proxy group line. Members not present in emitted
// (skipped nodes) are filtered out; if that empties the group it falls back to
// DIRECT so the config still loads.
func formatSurgeGroup(g groupOut, emitted map[string]bool) string {
	typ := g.Type
	switch typ {
	case "select", "url-test", "fallback", "load-balance":
		// supported as-is
	default:
		typ = "select" // relay and unknowns degrade to a manual selector
	}
	members := make([]string, 0, len(g.Proxies))
	for _, m := range g.Proxies {
		// Keep builtins/group refs; drop references to nodes we didn't emit.
		if m == "DIRECT" || m == "REJECT" || !isNodeName(m) || emitted[m] {
			members = append(members, m)
		}
	}
	if len(members) == 0 {
		members = []string{"DIRECT"}
	}
	parts := append([]string{typ}, members...)
	if typ != "select" {
		if g.URL != "" {
			parts = append(parts, "url="+g.URL)
		}
		if g.Interval > 0 {
			parts = append(parts, "interval="+strconv.Itoa(g.Interval))
		}
		if g.Tolerance > 0 {
			parts = append(parts, "tolerance="+strconv.Itoa(g.Tolerance))
		}
	}
	return g.Name + " = " + strings.Join(parts, ", ")
}

// isNodeName reports whether m looks like a node/group name rather than a Surge
// builtin policy. Used only to decide whether the emitted-filter applies.
func isNodeName(m string) bool { return m != "DIRECT" && m != "REJECT" && m != "REJECT-DROP" }

// surgeSupportedRuleTypes is the set of rule matchers the surge family accepts.
var surgeSupportedRuleTypes = map[string]string{
	"DOMAIN": "DOMAIN", "DOMAIN-SUFFIX": "DOMAIN-SUFFIX", "DOMAIN-KEYWORD": "DOMAIN-KEYWORD",
	"IP-CIDR": "IP-CIDR", "IP-CIDR6": "IP-CIDR6", "IP-ASN": "IP-ASN", "GEOIP": "GEOIP",
	"DST-PORT": "DEST-PORT", "SRC-PORT": "SRC-PORT", "IN-PORT": "IN-PORT",
	"PROCESS-NAME": "PROCESS-NAME", "USER-AGENT": "USER-AGENT", "RULE-SET": "RULE-SET",
	"AND": "AND", "OR": "OR", "NOT": "NOT",
}

// formatSurgeRule renders a neutral rule as a Surge rule line. ok is false for
// rule types the surge family cannot express (e.g. GEOSITE/IP-SUFFIX).
func formatSurgeRule(r Rule) (string, bool) {
	if r.IsMatch() {
		return "FINAL," + r.Group, true
	}
	typ, ok := surgeSupportedRuleTypes[strings.ToUpper(r.Type)]
	if !ok {
		return "", false
	}
	s := typ + "," + r.Value + "," + r.Group
	if r.Flag != "" {
		s += "," + r.Flag
	}
	return s, true
}

// surgeNodeLine renders one node's proxy line for the given flavor. ok is false
// when the flavor has no representation for the protocol.
func surgeNodeLine(flavor surgeFlavor, n *proxy.Proxy) (string, bool) {
	if flavor == flavorLoon {
		return loonNodeLine(n)
	}
	c := n.Clash
	server := cs(c, "server")
	port := strconv.Itoa(ci(c, "port"))
	head := n.Name + " = "

	switch n.Type {
	case "ss":
		parts := []string{"ss", server, port, "encrypt-method=" + cs(c, "cipher"), "password=" + cs(c, "password")}
		if cb(c, "udp") {
			parts = append(parts, "udp-relay=true")
		}
		if cs(c, "plugin") == "obfs" {
			o := cmap(c, "plugin-opts")
			parts = append(parts, "obfs="+cs(o, "mode"))
			if h := cs(o, "host"); h != "" {
				parts = append(parts, "obfs-host="+h)
			}
		}
		return head + strings.Join(parts, ", "), true

	case "vmess":
		parts := []string{"vmess", server, port, "username=" + cs(c, "uuid")}
		if ci(c, "alterId") == 0 {
			parts = append(parts, "vmess-aead=true")
		}
		parts = append(parts, surgeTLSParts(c)...)
		parts = append(parts, surgeWSParts(c)...)
		if cb(c, "udp") {
			parts = append(parts, "udp-relay=true")
		}
		return head + strings.Join(parts, ", "), true

	case "trojan":
		parts := []string{"trojan", server, port, "password=" + cs(c, "password")}
		if sni := cs(c, "sni"); sni != "" {
			parts = append(parts, "sni="+sni)
		}
		if cb(c, "skip-cert-verify") {
			parts = append(parts, "skip-cert-verify=true")
		}
		parts = append(parts, surgeWSParts(c)...)
		if cb(c, "udp") {
			parts = append(parts, "udp-relay=true")
		}
		return head + strings.Join(parts, ", "), true

	case "hysteria2":
		parts := []string{"hysteria2", server, port, "password=" + cs(c, "password")}
		if sni := cs(c, "sni"); sni != "" {
			parts = append(parts, "sni="+sni)
		}
		if cb(c, "skip-cert-verify") {
			parts = append(parts, "skip-cert-verify=true")
		}
		return head + strings.Join(parts, ", "), true

	case "vless":
		// Surge has no VLESS; Shadowrocket does.
		if flavor != flavorShadowrocket {
			return "", false
		}
		parts := []string{"vless", server, port, "username=" + cs(c, "uuid")}
		parts = append(parts, surgeTLSParts(c)...)
		if flow := cs(c, "flow"); flow != "" {
			parts = append(parts, "flow="+flow)
		}
		parts = append(parts, surgeWSParts(c)...)
		return head + strings.Join(parts, ", "), true
	}
	return "", false
}

// surgeTLSParts emits tls/sni/skip-cert-verify params common to vmess/vless.
func surgeTLSParts(c map[string]any) []string {
	var parts []string
	if cb(c, "tls") {
		parts = append(parts, "tls=true")
		if sni := cs(c, "servername"); sni != "" {
			parts = append(parts, "sni="+sni)
		}
		if cb(c, "skip-cert-verify") {
			parts = append(parts, "skip-cert-verify=true")
		}
	}
	return parts
}

// surgeWSParts emits ws=true/ws-path/ws-headers params when the node uses
// WebSocket transport.
func surgeWSParts(c map[string]any) []string {
	if cs(c, "network") != "ws" {
		return nil
	}
	ws := cmap(c, "ws-opts")
	parts := []string{"ws=true"}
	if p := cs(ws, "path"); p != "" {
		parts = append(parts, "ws-path="+p)
	}
	if hdr := cmap(ws, "headers"); hdr != nil {
		if h := cs(hdr, "Host"); h != "" {
			parts = append(parts, "ws-headers=Host:"+h)
		}
	}
	return parts
}

// loonNodeLine renders a node in Loon's proxy syntax (positional credentials,
// quoted secrets). ok is false for protocols Loon cannot express here.
func loonNodeLine(n *proxy.Proxy) (string, bool) {
	c := n.Clash
	server := cs(c, "server")
	port := strconv.Itoa(ci(c, "port"))
	head := n.Name + " = "

	switch n.Type {
	case "ss":
		parts := []string{"Shadowsocks", server, port, cs(c, "cipher"), q(cs(c, "password"))}
		if cb(c, "udp") {
			parts = append(parts, "udp=true")
		}
		return head + strings.Join(parts, ","), true

	case "vmess":
		parts := []string{"vmess", server, port, firstNonEmptyStr(cs(c, "cipher"), "auto"), q(cs(c, "uuid"))}
		parts = append(parts, "transport="+firstNonEmptyStr(cs(c, "network"), "tcp"))
		parts = append(parts, loonWSParts(c)...)
		parts = append(parts, loonTLSParts(c)...)
		return head + strings.Join(parts, ","), true

	case "trojan":
		parts := []string{"trojan", server, port, q(cs(c, "password"))}
		if sni := cs(c, "sni"); sni != "" {
			parts = append(parts, "tls-name="+sni)
		}
		parts = append(parts, "transport="+firstNonEmptyStr(cs(c, "network"), "tcp"))
		parts = append(parts, loonWSParts(c)...)
		if cb(c, "skip-cert-verify") {
			parts = append(parts, "skip-cert-verify=true")
		}
		return head + strings.Join(parts, ","), true

	case "vless":
		parts := []string{"VLESS", server, port, q(cs(c, "uuid"))}
		parts = append(parts, "transport="+firstNonEmptyStr(cs(c, "network"), "tcp"))
		parts = append(parts, loonWSParts(c)...)
		parts = append(parts, loonTLSParts(c)...)
		if flow := cs(c, "flow"); flow != "" {
			parts = append(parts, "flow="+flow)
		}
		return head + strings.Join(parts, ","), true

	case "hysteria2":
		parts := []string{"Hysteria2", server, port, q(cs(c, "password"))}
		if sni := cs(c, "sni"); sni != "" {
			parts = append(parts, "sni="+sni)
		}
		if cb(c, "skip-cert-verify") {
			parts = append(parts, "skip-cert-verify=true")
		}
		return head + strings.Join(parts, ","), true
	}
	return "", false
}

func loonWSParts(c map[string]any) []string {
	if cs(c, "network") != "ws" {
		return nil
	}
	ws := cmap(c, "ws-opts")
	var parts []string
	if p := cs(ws, "path"); p != "" {
		parts = append(parts, "path="+p)
	}
	if hdr := cmap(ws, "headers"); hdr != nil {
		if h := cs(hdr, "Host"); h != "" {
			parts = append(parts, "host="+h)
		}
	}
	return parts
}

func loonTLSParts(c map[string]any) []string {
	if !cb(c, "tls") {
		return []string{"over-tls=false"}
	}
	parts := []string{"over-tls=true"}
	if sni := cs(c, "servername"); sni != "" {
		parts = append(parts, "tls-name="+sni)
	}
	if cb(c, "skip-cert-verify") {
		parts = append(parts, "skip-cert-verify=true")
	}
	return parts
}

// q wraps a secret in double quotes for Loon's positional credential fields.
func q(s string) string { return "\"" + s + "\"" }
