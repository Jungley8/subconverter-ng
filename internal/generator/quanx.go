package generator

import (
	"context"
	"strconv"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// GenerateQuanX renders a Quantumult X resource config: [server_local] node
// lines, [policy] groups and [filter_local] rules. Protocols QuanX cannot
// express (hysteria2/tuic/...) are skipped and reported in Result.SkippedNodes.
func GenerateQuanX(ctx context.Context, nodes []*proxy.Proxy, cfg *extconfig.Config, f Fetcher, opts Options) (*Result, error) {
	res := &Result{ContentType: ctText}
	nodes = prepareNodes(nodes, cfg, opts, res)

	var b strings.Builder
	b.WriteString("[server_local]\n")
	emitted := map[string]bool{}
	allNames := make([]string, 0, len(nodes))
	for _, n := range nodes {
		line, ok := quanxNodeLine(n)
		if !ok {
			res.SkippedNodes = append(res.SkippedNodes, n.Name+" ("+n.Type+": unsupported by Quantumult X)")
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
		emitted[n.Name] = true
		allNames = append(allNames, n.Name)
	}

	groupNames := map[string]bool{}
	for _, d := range cfg.ProxyGroups {
		groupNames[d.Name] = true
	}
	groups := buildGroups(cfg.ProxyGroups, nodes, allNames, res)
	b.WriteString("\n[policy]\n")
	for _, g := range groups {
		b.WriteString(formatQuanXPolicy(g, emitted, groupNames))
		b.WriteByte('\n')
	}

	neutral, skippedRules := collectRules(ctx, cfg, f)
	b.WriteString("\n[filter_local]\n")
	for _, r := range neutral {
		if line, ok := formatQuanXRule(r); ok {
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

// quanxPolicyRef maps a member to a QuanX policy reference (direct/reject for
// builtins; node/group tags kept when emitted/known).
func quanxPolicyRef(m string, emitted, groupNames map[string]bool) (string, bool) {
	switch m {
	case "DIRECT":
		return "direct", true
	case "REJECT", "REJECT-DROP":
		return "reject", true
	}
	if groupNames[m] || emitted[m] {
		return m, true
	}
	return "", false
}

// formatQuanXPolicy renders one [policy] line.
func formatQuanXPolicy(g groupOut, emitted, groupNames map[string]bool) string {
	typ := "static"
	switch g.Type {
	case "url-test":
		typ = "url-latency-benchmark"
	case "fallback":
		typ = "available"
	case "load-balance":
		typ = "round-robin"
	}
	members := make([]string, 0, len(g.Proxies))
	for _, m := range g.Proxies {
		if ref, ok := quanxPolicyRef(m, emitted, groupNames); ok {
			members = append(members, ref)
		}
	}
	if len(members) == 0 {
		members = []string{"direct"}
	}
	parts := append([]string{g.Name}, members...)
	if typ != "static" && g.Interval > 0 {
		parts = append(parts, "check-interval="+strconv.Itoa(g.Interval))
	}
	return typ + "=" + strings.Join(parts, ", ")
}

// quanxRuleKeyword maps a neutral rule type to its QuanX filter keyword.
var quanxRuleKeyword = map[string]string{
	"DOMAIN": "host", "DOMAIN-SUFFIX": "host-suffix", "DOMAIN-KEYWORD": "host-keyword",
	"IP-CIDR": "ip-cidr", "IP-CIDR6": "ip6-cidr", "GEOIP": "geoip", "USER-AGENT": "user-agent",
}

// formatQuanXRule renders a neutral rule as a QuanX filter line. ok is false for
// rule types QuanX has no keyword for.
func formatQuanXRule(r Rule) (string, bool) {
	if r.IsMatch() {
		return "final, " + r.Group, true
	}
	kw, ok := quanxRuleKeyword[strings.ToUpper(r.Type)]
	if !ok {
		return "", false
	}
	val := r.Value
	if kw == "geoip" {
		val = strings.ToLower(val)
	}
	s := kw + ", " + val + ", " + r.Group
	if r.Flag != "" {
		s += ", " + r.Flag
	}
	return s, true
}

// quanxNodeLine renders one node's [server_local] line. ok is false for
// protocols QuanX cannot express.
func quanxNodeLine(n *proxy.Proxy) (string, bool) {
	c := n.Clash
	addr := cs(c, "server") + ":" + strconv.Itoa(ci(c, "port"))
	tag := "tag=" + n.Name

	switch n.Type {
	case "ss":
		parts := []string{"shadowsocks=" + addr, "method=" + cs(c, "cipher"), "password=" + cs(c, "password")}
		if cs(c, "plugin") == "obfs" {
			o := cmap(c, "plugin-opts")
			parts = append(parts, "obfs="+cs(o, "mode"))
			if h := cs(o, "host"); h != "" {
				parts = append(parts, "obfs-host="+h)
			}
		}
		if cb(c, "udp") {
			parts = append(parts, "udp-relay=true")
		}
		parts = append(parts, tag)
		return strings.Join(parts, ", "), true

	case "vmess":
		parts := []string{"vmess=" + addr, "method=" + quanxVmessMethod(cs(c, "cipher")), "password=" + cs(c, "uuid")}
		parts = append(parts, quanxObfsParts(c, cs(c, "servername"))...)
		if cb(c, "udp") {
			parts = append(parts, "udp-relay=true")
		}
		parts = append(parts, tag)
		return strings.Join(parts, ", "), true

	case "vless":
		parts := []string{"vless=" + addr, "method=none", "password=" + cs(c, "uuid")}
		parts = append(parts, quanxObfsParts(c, cs(c, "servername"))...)
		if flow := cs(c, "flow"); flow != "" {
			parts = append(parts, "flow="+flow)
		}
		parts = append(parts, tag)
		return strings.Join(parts, ", "), true

	case "trojan":
		parts := []string{"trojan=" + addr, "password=" + cs(c, "password"), "over-tls=true"}
		if sni := cs(c, "sni"); sni != "" {
			parts = append(parts, "tls-host="+sni)
		}
		parts = append(parts, "tls-verification="+boolStr(!cb(c, "skip-cert-verify")))
		if cs(c, "network") == "ws" {
			ws := cmap(c, "ws-opts")
			parts = append(parts, "obfs=wss")
			if p := cs(ws, "path"); p != "" {
				parts = append(parts, "obfs-uri="+p)
			}
			if hdr := cmap(ws, "headers"); hdr != nil {
				if h := cs(hdr, "Host"); h != "" {
					parts = append(parts, "obfs-host="+h)
				}
			}
		}
		parts = append(parts, tag)
		return strings.Join(parts, ", "), true
	}
	return "", false
}

// quanxObfs/TLS parts shared by vmess/vless: choose obfs (ws/wss/over-tls) and
// emit tls-host / tls-verification.
func quanxObfsParts(c map[string]any, sni string) []string {
	tls := cb(c, "tls")
	ws := cs(c, "network") == "ws"
	var parts []string
	switch {
	case ws && tls:
		parts = append(parts, "obfs=wss")
	case ws:
		parts = append(parts, "obfs=ws")
	case tls:
		parts = append(parts, "obfs=over-tls")
	}
	if ws {
		wo := cmap(c, "ws-opts")
		if p := cs(wo, "path"); p != "" {
			parts = append(parts, "obfs-uri="+p)
		}
		if hdr := cmap(wo, "headers"); hdr != nil {
			if h := cs(hdr, "Host"); h != "" {
				parts = append(parts, "obfs-host="+h)
			}
		}
	}
	if tls {
		if sni != "" {
			parts = append(parts, "tls-host="+sni)
		}
		parts = append(parts, "tls-verification="+boolStr(!cb(c, "skip-cert-verify")))
	}
	return parts
}

// quanxVmessMethod maps a Clash vmess cipher to a QuanX-accepted method.
func quanxVmessMethod(cipher string) string {
	switch cipher {
	case "none", "aes-128-gcm", "chacha20-ietf-poly1305":
		return cipher
	default: // "auto" and anything unknown
		return "chacha20-ietf-poly1305"
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
