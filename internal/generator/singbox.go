package generator

import (
	"context"
	"encoding/json"
	"fmt"
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

	// Built-in tail outbound. Rejections are route rule actions in current
	// sing-box releases; the legacy "block" outbound was removed in 1.13.
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})

	// Route rules from neutral rules.
	neutral, skippedRules := collectRules(ctx, cfg, f, opts)
	ruleSetTags := map[string]string{}
	var ruleSets []map[string]any
	usedTags := map[string]bool{}
	for _, r := range neutral {
		kind := strings.ToUpper(strings.TrimSpace(r.Type))
		if kind != "GEOIP" && kind != "GEOSITE" {
			continue
		}
		value := strings.ToLower(strings.TrimSpace(r.Value))
		key := kind + "\x00" + value
		if value == "" || ruleSetTags[key] != "" ||
			(kind == "GEOIP" && (value == "lan" || value == "private" || value == "local")) {
			continue
		}
		baseTag := strings.ToLower(kind) + "-" + singboxTagPart(value)
		tag := baseTag
		for suffix := 2; usedTags[tag]; suffix++ {
			tag = baseTag + "-" + strconv.Itoa(suffix)
		}
		usedTags[tag] = true
		ruleSetTags[key] = tag
		repo := "sing-geoip"
		if kind == "GEOSITE" {
			repo = "sing-geosite"
		}
		ruleSets = append(ruleSets, map[string]any{
			"type":   "remote",
			"tag":    tag,
			"format": "binary",
			"url":    "https://raw.githubusercontent.com/SagerNet/" + repo + "/rule-set/" + baseTag + ".srs",
		})
	}
	routeRules := []map[string]any{
		{"action": "sniff"},
		{"protocol": "dns", "action": "hijack-dns"},
	}
	final := "direct"
	finalReject := false
	for _, r := range neutral {
		if r.IsMatch() {
			if target := singboxOutboundRef(r.Group, emitted, groupNames); target == "block" {
				finalReject = true
				final = "direct"
			} else {
				final = target
			}
			continue
		}
		if rule, ok := singboxRouteRule(r, emitted, groupNames, ruleSetTags); ok {
			routeRules = append(routeRules, rule)
		} else {
			skippedRules = append(skippedRules, r.Type+","+r.Value)
		}
	}
	if finalReject {
		routeRules = append(routeRules, map[string]any{"action": "reject"})
	}
	routeRules, ruleSets = compactSingboxRouteRules(routeRules, ruleSets)
	res.SkippedRules = skippedRules

	ruleSetHTTPClient := map[string]any{
		"tag":             "rule-set-download",
		"domain_resolver": "local",
	}
	if final != "" && final != "direct" {
		ruleSetHTTPClient["detour"] = final
	}

	conf := map[string]any{
		"http_clients": []map[string]any{ruleSetHTTPClient},
		"log":          map[string]any{"level": "info", "timestamp": true},
		"dns": map[string]any{
			"servers": []map[string]any{
				{"type": "tls", "tag": "remote", "server": "8.8.8.8"},
				{"type": "https", "tag": "local", "server": "223.5.5.5", "path": "/dns-query"},
			},
			"final": "remote",
		},
		"inbounds": []map[string]any{
			{
				"type":       "tun",
				"tag":        "tun-in",
				"address":    []string{"172.19.0.1/30"},
				"mtu":        1500,
				"auto_route": true,
				"route_exclude_address": []string{
					"10.0.0.0/8",
					"169.254.0.0/16",
					"172.16.0.0/12",
					"192.168.0.0/16",
				},
			},
			{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080},
		},
		"outbounds": outbounds,
		"route": map[string]any{
			"rules":                   routeRules,
			"rule_set":                ruleSets,
			"final":                   final,
			"auto_detect_interface":   true,
			"default_domain_resolver": "local",
			"default_http_client":     "rule-set-download",
		},
	}

	b, err := json.MarshalIndent(conf, "", "  ")
	if err != nil {
		return nil, err
	}
	res.Output = b
	return res, nil
}

// singboxTagPart converts a GeoIP/GeoSite category into a stable rule-set tag.
func singboxTagPart(value string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	tag := strings.Trim(b.String(), "-")
	if tag == "" {
		return "all"
	}
	return tag
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
			// Reject is a route action, so it cannot be represented as a
			// selector/urltest member.
			continue
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
	"DOMAIN-REGEX": "domain_regex",
	"IP-CIDR":      "ip_cidr", "IP-CIDR6": "ip_cidr", "DST-PORT": "port", "SRC-PORT": "source_port",
	"PROCESS-NAME": "process_name",
}

// singboxRouteRule builds a single route rule object. ok is false for rule types
// sing-box has no field for.
func singboxRouteRule(r Rule, emitted, groupNames map[string]bool, ruleSetTags map[string]string) (map[string]any, bool) {
	ruleType := strings.ToUpper(r.Type)
	field, ok := singboxRuleField[ruleType]
	if !ok && ruleType != "GEOIP" && ruleType != "GEOSITE" {
		return nil, false
	}
	rule := map[string]any{}
	target := singboxOutboundRef(r.Group, emitted, groupNames)
	if target == "block" {
		rule["action"] = "reject"
	} else {
		rule["outbound"] = target
	}
	if ruleType == "GEOIP" || ruleType == "GEOSITE" {
		value := strings.ToLower(strings.TrimSpace(r.Value))
		if ruleType == "GEOIP" && (value == "lan" || value == "private" || value == "local") {
			rule["ip_is_private"] = true
			return rule, true
		}
		tag := ruleSetTags[ruleType+"\x00"+value]
		if tag == "" {
			return nil, false
		}
		rule["rule_set"] = tag
		return rule, true
	}
	switch field {
	case "port", "source_port":
		if p, err := strconv.Atoi(r.Value); err == nil {
			rule[field] = []int{p}
		} else {
			return nil, false
		}
	default:
		rule[field] = []string{r.Value}
	}
	return rule, true
}

var singboxCompactFieldOrder = []string{
	"domain",
	"domain_suffix",
	"domain_keyword",
	"domain_regex",
	"ip_cidr",
	"port",
	"source_port",
	"process_name",
}

// compactSingboxRouteRules groups consecutive rules that share a destination
// into inline rule-sets. Values of the same match type are deduplicated and
// stored in one array, which substantially reduces config size and parsing
// overhead without changing match order or destinations.
func compactSingboxRouteRules(rules []map[string]any, ruleSets []map[string]any) ([]map[string]any, []map[string]any) {
	compacted := make([]map[string]any, 0, len(rules))
	usedTags := make(map[string]bool, len(ruleSets))
	for _, ruleSet := range ruleSets {
		if tag, ok := ruleSet["tag"].(string); ok {
			usedTags[tag] = true
		}
	}
	sequence := 0
	for i := 0; i < len(rules); {
		targetKind, target, firstField, firstValues, ok := singboxCompactComponent(rules[i])
		if !ok {
			compacted = append(compacted, rules[i])
			i++
			continue
		}

		valuesByField := map[string][]any{firstField: firstValues}
		seenByField := map[string]map[string]bool{
			firstField: singboxValueSet(firstValues),
		}
		j := i + 1
		for j < len(rules) {
			nextKind, nextTarget, field, values, nextOK := singboxCompactComponent(rules[j])
			if !nextOK || nextKind != targetKind || nextTarget != target {
				break
			}
			seen := seenByField[field]
			if seen == nil {
				seen = map[string]bool{}
				seenByField[field] = seen
			}
			for _, value := range values {
				key := fmt.Sprintf("%T:%v", value, value)
				if !seen[key] {
					seen[key] = true
					valuesByField[field] = append(valuesByField[field], value)
				}
			}
			j++
		}

		var tag string
		for {
			sequence++
			tag = fmt.Sprintf("acl4ssr-%04d", sequence)
			if !usedTags[tag] {
				usedTags[tag] = true
				break
			}
		}
		headlessRules := make([]map[string]any, 0, len(valuesByField))
		for _, field := range singboxCompactFieldOrder {
			if values := valuesByField[field]; len(values) > 0 {
				headlessRules = append(headlessRules, map[string]any{field: values})
			}
		}
		ruleSets = append(ruleSets, map[string]any{
			"type":  "inline",
			"tag":   tag,
			"rules": headlessRules,
		})
		compacted = append(compacted, map[string]any{
			"rule_set": tag,
			targetKind: target,
		})
		i = j
	}
	return compacted, ruleSets
}

// singboxCompactComponent extracts a single-field rule and its destination.
func singboxCompactComponent(rule map[string]any) (targetKind, target, field string, values []any, ok bool) {
	if value, exists := rule["outbound"].(string); exists && value != "" {
		targetKind, target = "outbound", value
	} else if value, exists := rule["action"].(string); exists && value != "" {
		targetKind, target = "action", value
	} else {
		return "", "", "", nil, false
	}
	for key, value := range rule {
		if key == "outbound" || key == "action" {
			continue
		}
		if field != "" || !singboxCompactField(key) {
			return "", "", "", nil, false
		}
		field = key
		values, ok = singboxCompactValues(value)
		if !ok {
			return "", "", "", nil, false
		}
	}
	if field == "" || len(values) == 0 {
		return "", "", "", nil, false
	}
	return targetKind, target, field, values, true
}

func singboxCompactField(field string) bool {
	for _, candidate := range singboxCompactFieldOrder {
		if field == candidate {
			return true
		}
	}
	return false
}

func singboxCompactValues(value any) ([]any, bool) {
	switch values := value.(type) {
	case []string:
		out := make([]any, 0, len(values))
		for _, item := range values {
			if item != "" {
				out = append(out, item)
			}
		}
		return out, len(out) > 0
	case []int:
		out := make([]any, len(values))
		for i, item := range values {
			out[i] = item
		}
		return out, len(out) > 0
	case []any:
		return values, len(values) > 0
	case string:
		return []any{values}, values != ""
	case int:
		return []any{values}, true
	default:
		return nil, false
	}
}

func singboxValueSet(values []any) map[string]bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		seen[fmt.Sprintf("%T:%v", value, value)] = true
	}
	return seen
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
