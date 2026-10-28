package generator

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// singboxProtocolFloor maps a clash-style node type to the sing-box release
// (major, minor) that introduced the protocol. Best-effort, based on the
// official release notes; types not listed carry no floor.
var singboxProtocolFloor = map[string][2]int{
	"ss": {1, 0}, "socks5": {1, 0}, "socks": {1, 0}, "vmess": {1, 0},
	"vless": {1, 0}, "trojan": {1, 0}, "wireguard": {1, 0},
	"hysteria": {1, 1}, "tuic": {1, 2}, "hysteria2": {1, 5}, "anytls": {1, 12},
}

// singboxSchema aggregates the schema switches enabled by the declared sing-box
// version (based on the official deprecation notes). A nil schema (no declared
// version) keeps the legacy output byte-identical to before.
type singboxSchema struct {
	actions  bool // >=1.11: hijack-dns/reject rule actions, no block/dns-out outbounds
	newDNS   bool // >=1.12: new DNS server format ({type, server} instead of address URLs)
	ruleSets bool // >=1.12: geosite/geoip inline fields -> remote rule_set references
}

// singboxSchemaFor derives the schema switches from the declared version.
// A nil version returns nil: fully legacy output.
func singboxSchemaFor(opts Options) *singboxSchema {
	ver := opts.TargetVersion
	if ver == nil {
		return nil
	}
	return &singboxSchema{
		actions:  ver.AtLeast(1, 11),
		newDNS:   ver.AtLeast(1, 12),
		ruleSets: ver.AtLeast(1, 12),
	}
}

// ruleSetCollector accumulates the remote rule_set tags referenced by route
// rules, de-duplicated, in first-reference order.
type ruleSetCollector struct {
	seen map[string]bool
	tags []string
}

func (c *ruleSetCollector) add(tag string) {
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if c.seen[tag] {
		return
	}
	c.seen[tag] = true
	c.tags = append(c.tags, tag)
}

// definitions renders the collected tags as top-level rule_set entries
// (remote .srs, binary format). nil when nothing was collected.
func (c *ruleSetCollector) definitions() []map[string]any {
	if c == nil || len(c.tags) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(c.tags))
	for _, tag := range c.tags {
		url := "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/" + tag + ".srs"
		if strings.HasPrefix(tag, "geosite-") {
			url = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/" + tag + ".srs"
		}
		out = append(out, map[string]any{
			"tag": tag, "type": "remote", "format": "binary", "url": url,
		})
	}
	return out
}

// GenerateSingbox renders a sing-box JSON config: one outbound per node, plus
// selector/urltest outbounds for the proxy groups and route rules translated
// from the rulesets. Protocols with no sing-box outbound form are skipped and
// reported in Result.SkippedNodes. A built-in base (log/dns/inbounds) is used.
// A declared TargetVersion additionally switches to the modern sing-box schema
// (rule actions / new DNS format / rule_sets, see singboxSchema).
func GenerateSingbox(ctx context.Context, nodes []*proxy.Proxy, cfg *extconfig.Config, f Fetcher, opts Options) (*Result, error) {
	res := &Result{ContentType: ctJSON}
	nodes = prepareNodes(nodes, cfg, opts, res)
	schema := singboxSchemaFor(opts)

	// Node outbounds.
	outbounds, emitted, allNames := nodeOutbounds(nodes, opts, res)

	// Group outbounds (selector / urltest). Names of all groups so member refs to
	// other groups survive the emitted-filter.
	groupNames := map[string]bool{}
	for _, d := range cfg.ProxyGroups {
		groupNames[d.Name] = true
	}
	groups := buildGroups(cfg.ProxyGroups, nodes, allNames, res)
	for _, g := range groups {
		outbounds = append(outbounds, singboxGroupOutbound(g, emitted, groupNames, schema))
	}

	// Built-in tail outbounds. direct is kept on every sing-box release; the
	// block/dns special outbounds are removed under the action schema
	// (deprecated 1.11, removed 1.13 — migrated to route rule actions).
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})
	if schema == nil || !schema.actions {
		outbounds = append(outbounds,
			map[string]any{"type": "block", "tag": "block"},
			map[string]any{"type": "dns", "tag": "dns-out"},
		)
	}

	// Route rules from neutral rules.
	neutral, skippedRules := collectRules(ctx, cfg, f, opts)
	var collector *ruleSetCollector
	if schema != nil && schema.ruleSets {
		collector = &ruleSetCollector{}
	}
	routeRules := []map[string]any{{"protocol": "dns", "outbound": "dns-out"}}
	if schema != nil && schema.actions {
		routeRules = []map[string]any{{"protocol": "dns", "action": "hijack-dns"}}
	}
	final := "direct"
	for _, r := range neutral {
		if r.IsMatch() {
			final = singboxOutboundRef(r.Group, emitted, groupNames)
			if schema != nil && schema.actions && final == "block" {
				// A REJECT final cannot reference the removed block outbound;
				// degrade to direct so the config still loads.
				final = "direct"
			}
			continue
		}
		if rule, ok := singboxRouteRule(r, emitted, groupNames, schema, collector); ok {
			routeRules = append(routeRules, rule)
		} else {
			skippedRules = append(skippedRules, r.Type+","+r.Value)
		}
	}
	res.SkippedRules = skippedRules

	dnsServers := []map[string]any{
		{"tag": "remote", "address": "tls://8.8.8.8"},
		{"tag": "local", "address": "223.5.5.5", "detour": "direct"},
	}
	if schema != nil && schema.newDNS {
		dnsServers = []map[string]any{
			{"type": "tls", "tag": "remote", "server": "8.8.8.8"},
			{"type": "udp", "tag": "local", "server": "223.5.5.5", "detour": "direct"},
		}
	}

	conf := map[string]any{
		"log": map[string]any{"level": "info", "timestamp": true},
		"dns": map[string]any{
			"servers": dnsServers,
			"final":   "remote",
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
	if defs := collector.definitions(); defs != nil {
		conf["rule_set"] = defs
	}

	b, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		return nil, err
	}
	res.Output = b
	return res, nil
}

// nodeOutbounds renders one sing-box outbound per node, applying the version
// gate and recording unsupported nodes in res. emitted/allNames let the group
// and rule builders skip nodes that never made it into the output.
func nodeOutbounds(nodes []*proxy.Proxy, opts Options, res *Result) (outbounds []map[string]any, emitted map[string]bool, allNames []string) {
	emitted = map[string]bool{}
	allNames = make([]string, 0, len(nodes))
	for _, n := range nodes {
		// Version gate: drop protocols the declared sing-box release cannot
		// render. Skipped nodes stay out of emitted/allNames, so groups and
		// rules never reference them.
		if opts.TargetVersion != nil {
			if floor, ok := singboxProtocolFloor[n.Type]; ok && !opts.TargetVersion.AtLeast(floor[0], floor[1]) {
				res.SkippedNodes = append(res.SkippedNodes,
					fmt.Sprintf("%s (%s: requires sing-box >= %d.%d)", n.Name, n.Type, floor[0], floor[1]))
				continue
			}
		}
		ob, ok := nodeSingboxOutbound(n)
		if !ok {
			res.SkippedNodes = append(res.SkippedNodes, n.Name+" ("+n.Type+": unsupported by sing-box generator)")
			continue
		}
		outbounds = append(outbounds, ob)
		emitted[n.Name] = true
		allNames = append(allNames, n.Name)
	}
	return outbounds, emitted, allNames
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
// Under the action schema (schema.actions) REJECT/REJECT-DROP members are
// dropped: the block outbound they map to no longer exists in the config.
func singboxGroupOutbound(g groupOut, emitted, groupNames map[string]bool, schema *singboxSchema) map[string]any {
	members := make([]string, 0, len(g.Proxies))
	for _, m := range g.Proxies {
		switch m {
		case "DIRECT":
			members = append(members, "direct")
		case "REJECT", "REJECT-DROP":
			if schema != nil && schema.actions {
				continue
			}
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
	"IP-CIDR": "ip_cidr", "IP-CIDR6": "ip_cidr", "DST-PORT": "port", "SRC-PORT": "source_port",
	"PROCESS-NAME": "process_name",
}

// geoipCountryRe matches the two-letter country codes SagerNet/sing-geoip
// publishes as rule sets.
var geoipCountryRe = regexp.MustCompile(`^[a-z]{2}$`)

// geositeAlias maps geosite categories that no longer exist upstream to their
// current sing-geosite equivalents (v2fly renamed google-cn to google@cn).
var geositeAlias = map[string]string{
	"google-cn": "google@cn",
}

// singboxRouteRule builds a single route rule object. ok is false for rule types
// sing-box has no field for. Under the action schema (schema.actions) a
// REJECT/REJECT-DROP target becomes an "action": "reject" rule; under the
// rule_set schema (schema.ruleSets) GEOSITE/GEOIP values are emitted as
// rule_set references (geoip:private -> ip_is_private) and recorded in
// collector. A nil schema keeps the legacy inline fields.
func singboxRouteRule(r Rule, emitted, groupNames map[string]bool, schema *singboxSchema, collector *ruleSetCollector) (map[string]any, bool) {
	field, ok := singboxRuleField[strings.ToUpper(r.Type)]
	if !ok {
		return nil, false
	}
	rule := map[string]any{"outbound": singboxOutboundRef(r.Group, emitted, groupNames)}
	if schema != nil && schema.actions && rule["outbound"] == "block" {
		delete(rule, "outbound")
		rule["action"] = "reject"
	}
	switch field {
	case "port", "source_port":
		if p, err := strconv.Atoi(r.Value); err == nil {
			rule[field] = []int{p}
		} else {
			return nil, false
		}
	case "geoip", "geosite":
		v := strings.ToLower(r.Value)
		if schema != nil && schema.ruleSets {
			if field == "geoip" {
				if v == "private" || v == "lan" {
					// Private-network matching is a built-in rule item, not a
					// rule set; LAN is mihomo's alias for the same thing.
					rule["ip_is_private"] = true
				} else if !geoipCountryRe.MatchString(v) {
					// SagerNet/sing-geoip publishes only two-letter country
					// codes; other categories would 404 and abort startup.
					return nil, false
				} else {
					tag := "geoip-" + v
					rule["rule_set"] = []string{tag}
					collector.add(tag)
				}
			} else {
				if t, ok := geositeAlias[v]; ok {
					v = t
				}
				tag := "geosite-" + v
				rule["rule_set"] = []string{tag}
				collector.add(tag)
			}
		} else {
			rule[field] = []string{v}
		}
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
	switch n.Type {
	case "ss":
		base["type"] = "shadowsocks"
		base["method"] = cs(c, "cipher")
		base["password"] = cs(c, "password")
		return base, true

	case "vmess":
		base["type"] = "vmess"
		base["uuid"] = cs(c, "uuid")
		base["alter_id"] = ci(c, "alterId")
		base["security"] = firstNonEmptyStr(cs(c, "cipher"), "auto")
		if t := singboxTransport(c); t != nil {
			base["transport"] = t
		}
		if tls := singboxTLS(c, cs(c, "servername"), false); tls != nil {
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
		if tls := singboxTLS(c, cs(c, "servername"), false); tls != nil {
			base["tls"] = tls
		}
		return base, true

	case "trojan":
		base["type"] = "trojan"
		base["password"] = cs(c, "password")
		if t := singboxTransport(c); t != nil {
			base["transport"] = t
		}
		base["tls"] = singboxTLS(c, cs(c, "sni"), true)
		return base, true

	case "hysteria2":
		base["type"] = "hysteria2"
		base["password"] = cs(c, "password")
		if obfs := cs(c, "obfs"); obfs != "" {
			base["obfs"] = map[string]any{"type": obfs, "password": cs(c, "obfs-password")}
		}
		base["tls"] = singboxTLS(c, cs(c, "sni"), true)
		return base, true

	case "tuic":
		base["type"] = "tuic"
		base["uuid"] = cs(c, "uuid")
		base["password"] = cs(c, "password")
		if cc := cs(c, "congestion-controller"); cc != "" {
			base["congestion_control"] = cc
		}
		base["tls"] = singboxTLS(c, cs(c, "sni"), true)
		return base, true

	case "anytls":
		base["type"] = "anytls"
		base["password"] = cs(c, "password")
		base["tls"] = singboxTLS(c, cs(c, "sni"), true)
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
	if !always && !cb(c, "tls") {
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
