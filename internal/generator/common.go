// Package generator: common.go holds target-agnostic building blocks shared by
// every output generator (clash, surge family, sing-box, quanx, v2ray):
//
//   - prepareNodes: the pre-render node pipeline (filter -> fdn -> dedup -> sort
//     -> node-option stamping), identical for all targets.
//   - the neutral Rule model plus ruleset parsing (parseRemoteRuleset /
//     parseInlineRule) and concurrent collection (collectRules). Each target
//     formats Rule values into its own rule syntax; formatClashRule lives here so
//     the Clash generator and the neutral layer agree.
//
// Group resolution (buildGroups/resolveSelectors) is also target-agnostic but
// stays in clash.go for now since it predates this split.
package generator

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

func sanitizeNodeName(name string) string {
	name = strings.ReplaceAll(name, "\r", "")
	name = strings.ReplaceAll(name, "\n", " ")
	return name
}

// prepareNodes runs the target-agnostic node pipeline and records its
// diagnostics (dedup/deprecated counts, final NodeCount) into res. The returned
// slice is the processed node list every generator renders from. Node options
// (udp/tfo/scv, emoji, rename, append_type) are stamped onto each node's Clash
// field bag, which all generators read from.
func prepareNodes(nodes []*proxy.Proxy, cfg *extconfig.Config, opts Options, res *Result) []*proxy.Proxy {
	clean := make([]*proxy.Proxy, 0, len(nodes))
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if strings.ContainsAny(n.Name, "\r\n") {
			n.Rename(sanitizeNodeName(n.Name))
		}
		clean = append(clean, n)
	}
	nodes = clean

	var excludedList []string
	if cfg != nil && len(cfg.ExcludeProtocols) > 0 {
		excludedList = append(excludedList, cfg.ExcludeProtocols...)
	}
	if len(opts.ExcludeProtocols) > 0 {
		excludedList = append(excludedList, opts.ExcludeProtocols...)
	}
	if len(excludedList) > 0 {
		var dropped int
		nodes, dropped = filterProtocols(nodes, ParseProtocolSet(excludedList...))
		res.ExcludedProtocols = dropped
	}

	nodes = filterNodes(nodes, cfg)
	if opts.FilterDeprecated {
		var dropped int
		nodes, dropped = filterDeprecated(nodes)
		res.DeprecatedDropped = dropped
	}
	if opts.Dedup {
		var removed int
		nodes, removed = dedup(nodes)
		res.Duplicates = removed
	}
	if opts.Sort {
		sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	}
	applyNodeOptions(nodes, opts)
	for _, n := range nodes {
		if strings.ContainsAny(n.Name, "\r\n") {
			n.Rename(sanitizeNodeName(n.Name))
		}
	}
	uniquifyNames(nodes)
	res.NodeCount = len(nodes)
	return nodes
}

// uniquifyNames guarantees every node has a distinct display name. Clash (and
// sing-box) reject a config with two proxies sharing a name — a common case
// when a provider injects marker nodes like "流量已耗尽!" or repeats a name
// across regions. Duplicates get a " N" suffix (first duplicate -> "name 2"),
// probing upward until the candidate is free so the suffix itself never
// collides. Runs after applyNodeOptions so renames/emoji are already applied.
func uniquifyNames(nodes []*proxy.Proxy) {
	seen := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if !seen[n.Name] {
			seen[n.Name] = true
			continue
		}
		var candidate string
		for i := 2; ; i++ {
			candidate = n.Name + " " + strconv.Itoa(i)
			if !seen[candidate] {
				break
			}
		}
		seen[candidate] = true
		n.Rename(candidate)
	}
}

// protocolAliases maps accepted protocol abbreviations and common aliases to
// their canonical proxy types.
var protocolAliases = map[string]string{
	"ss":           "ss",
	"shadowsocks":  "ss",
	"ssr":          "ssr",
	"shadowsocksr": "ssr",
	"vmess":        "vmess",
	"vless":        "vless",
	"trojan":       "trojan",
	"hysteria":     "hysteria",
	"hysteria1":    "hysteria",
	"hy":           "hysteria",
	"hy1":          "hysteria",
	"hysteria2":    "hysteria2",
	"hy2":          "hysteria2",
	"tuic":         "tuic",
	"tuic5":        "tuic",
	"tuicv5":       "tuic",
	"wireguard":    "wireguard",
	"wg":           "wireguard",
	"socks":        "socks5",
	"socks5":       "socks5",
	"http":         "http",
	"https":        "http",
	"anytls":       "anytls",
	"snell":        "snell",
}

// CanonicalProtocol normalizes a protocol name or alias to its standard form.
func CanonicalProtocol(raw string) string {
	key := strings.ToLower(strings.TrimSpace(raw))
	key = strings.Trim(key, "()[]\"'")
	if c, ok := protocolAliases[key]; ok {
		return c
	}
	// Try without hyphens and underscores (e.g. hysteria_2, hy-2, shadow_socks, tuic_v5)
	normalized := strings.ReplaceAll(strings.ReplaceAll(key, "-", ""), "_", "")
	if c, ok := protocolAliases[normalized]; ok {
		return c
	}
	return key
}

// ParseProtocols parses raw protocol strings (delimited by comma, pipe, semicolon,
// or whitespace) into a sorted, deduplicated slice of canonical protocol names.
func ParseProtocols(raw ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range raw {
		for _, token := range strings.FieldsFunc(r, func(c rune) bool {
			return c == ',' || c == '|' || c == ';' || c == ' ' || c == '\t' || c == '\n' || c == '\r'
		}) {
			token = strings.TrimSpace(token)
			token = strings.Trim(token, "()[]\"'")
			if token == "" {
				continue
			}
			canon := CanonicalProtocol(token)
			if canon != "" && !seen[canon] {
				seen[canon] = true
				out = append(out, canon)
			}
		}
	}
	sort.Strings(out)
	return out
}

// ParseProtocolSet parses raw protocol strings into a set of canonical protocol names.
func ParseProtocolSet(raw ...string) map[string]bool {
	list := ParseProtocols(raw...)
	m := make(map[string]bool, len(list))
	for _, p := range list {
		m[p] = true
	}
	return m
}

// filterProtocols drops nodes whose protocol or proxy type matches any in the
// excluded set. Protocol aliases (e.g. hy2 -> hysteria2, ss -> shadowsocks) are
// normalized so users can specify common abbreviations.
func filterProtocols(nodes []*proxy.Proxy, excluded map[string]bool) ([]*proxy.Proxy, int) {
	if len(excluded) == 0 {
		return nodes, 0
	}
	out := make([]*proxy.Proxy, 0, len(nodes))
	var dropped int
	for _, n := range nodes {
		if n == nil {
			continue
		}
		rawType := strings.ToLower(strings.TrimSpace(n.Type))
		canon := CanonicalProtocol(rawType)
		if excluded[canon] || excluded[rawType] {
			dropped++
			continue
		}
		out = append(out, n)
	}
	return out, dropped
}

// Rule is a target-neutral routing rule. Type is the upper-case matcher
// (DOMAIN-SUFFIX, IP-CIDR, GEOIP, RULE-SET, ...) or "MATCH" for the catch-all;
// Value is empty for MATCH. Flag is the optional trailing token (e.g.
// "no-resolve") preserved verbatim from the source ruleset.
type Rule struct {
	Type  string
	Value string
	Group string
	Flag  string
}

// IsMatch reports whether r is the catch-all rule.
func (r Rule) IsMatch() bool {
	return strings.EqualFold(r.Type, "MATCH") || strings.EqualFold(r.Type, "FINAL")
}

// normalizeRuleType maps common rule type aliases to their canonical forms.
func normalizeRuleType(typ string) string {
	switch strings.ToUpper(strings.TrimSpace(typ)) {
	case "HOST":
		return "DOMAIN"
	case "HOST-SUFFIX":
		return "DOMAIN-SUFFIX"
	case "HOST-KEYWORD":
		return "DOMAIN-KEYWORD"
	case "HOST-WILDCARD":
		return "DOMAIN-SUFFIX"
	case "DEST-PORT":
		return "DST-PORT"
	case "IP6-CIDR":
		return "IP-CIDR6"
	default:
		return strings.ToUpper(strings.TrimSpace(typ))
	}
}

// formatClashRule renders r as a Clash.Meta rule line. ok is false for a rule
// type Clash.Meta does not accept — this is the Clash-specific gate (mihomo
// rejects the WHOLE config on an unknown type). The neutral parsers keep every
// type so other targets (Surge/Loon URL-REGEX etc.) can still emit theirs; each
// target's formatter filters to what it supports.
func formatClashRule(r Rule) (string, bool) {
	if r.IsMatch() {
		return "MATCH," + r.Group, true
	}
	canon := normalizeRuleType(r.Type)
	if !isValidRuleType(canon) {
		return "", false
	}
	s := canon + "," + r.Value + "," + r.Group
	if r.Flag != "" {
		s += "," + r.Flag
	}
	return s, true
}

// tailscaleRules are prepended to the rule list when Options.Tailscale is true.
var tailscaleRules = []Rule{
	{Type: "IP-CIDR", Value: "100.64.0.0/10", Group: "DIRECT", Flag: "no-resolve"},
	{Type: "IP-CIDR", Value: "fd7a:115c:a1e0::/48", Group: "DIRECT", Flag: "no-resolve"},
}

// collectRules expands every ruleset in declared order into neutral Rule values.
// Remote rulesets are fetched concurrently but assembled in declared order;
// inline rulesets ([]GEOIP,CN, []FINAL) are expanded directly. Entries with an
// unsupported rule type are returned in skipped instead of rules.
// When opts.Tailscale is true, Tailscale direct rules are prepended.
func collectRules(ctx context.Context, cfg *extconfig.Config, f Fetcher, opts Options) (rules []Rule, skipped []string) {
	var tsRules []Rule
	if opts.Tailscale {
		tsRules = append(tsRules, tailscaleRules...)
	}
	if !cfg.EnableRuleGenerator {
		return tsRules, nil
	}
	type fetched struct {
		rules   []Rule
		skipped []string
	}
	results := make([]fetched, len(cfg.Rulesets))
	const maxConcurrentRulesetFetches = 16
	sem := make(chan struct{}, maxConcurrentRulesetFetches)
	var wg sync.WaitGroup
	for i, rs := range cfg.Rulesets {
		if rs.URL == "" {
			continue
		}
		wg.Add(1)
		go func(i int, url, group string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			data, err := f.Get(ctx, url)
			if err != nil {
				return
			}
			results[i].rules, results[i].skipped = parseRemoteRuleset(data, group)
		}(i, rs.URL, rs.Group)
	}
	wg.Wait()

	for i, rs := range cfg.Rulesets {
		if rs.Inline != "" {
			if r, ok := parseInlineRule(rs.Inline, rs.Group); ok {
				rules = append(rules, r)
			} else {
				skipped = append(skipped, rs.Inline+","+rs.Group)
			}
			continue
		}
		rules = append(rules, results[i].rules...)
		skipped = append(skipped, results[i].skipped...)
	}
	return append(tsRules, rules...), skipped
}

// parseInlineRule turns a []inline body into a neutral Rule. Types are kept
// verbatim (target-neutral); ok is false only when the body is not rule-shaped
// (a lone token that is neither FINAL nor MATCH).
//
//	FINAL      -> {Type: MATCH}
//	GEOIP,CN   -> {Type: GEOIP, Value: CN}
//	DOMAIN,x   -> {Type: DOMAIN, Value: x}
//
// The body after the first comma is kept verbatim as Value (it may itself carry
// a trailing flag), matching the legacy behaviour of appending the group last.
func parseInlineRule(body, group string) (Rule, bool) {
	if strings.EqualFold(body, "FINAL") || strings.EqualFold(body, "MATCH") {
		return Rule{Type: "MATCH", Group: group}, true
	}
	typ, val, found := strings.Cut(body, ",")
	if !found {
		return Rule{}, false
	}
	return Rule{Type: typ, Value: val, Group: group}, true
}

// parseRemoteRuleset parses an ACL4SSR-style .list file into neutral Rule
// values, tagging each with group. Rule types are kept verbatim so each target
// can emit what it supports; only lines that are not rule-shaped go to skipped.
func parseRemoteRuleset(data []byte, group string) (out []Rule, skipped []string) {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		// Skip provider-style YAML wrappers if present.
		if strings.HasPrefix(line, "payload:") || strings.HasPrefix(line, "- ") {
			line = strings.TrimPrefix(line, "- ")
			line = strings.Trim(line, "'\"")
			if line == "" || strings.HasPrefix(line, "payload") {
				continue
			}
		}
		fields := strings.Split(line, ",")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		switch len(fields) {
		case 2: // TYPE,VALUE
			out = append(out, Rule{Type: fields[0], Value: fields[1], Group: group})
		case 3: // TYPE,VALUE,flag (e.g. no-resolve)
			out = append(out, Rule{Type: fields[0], Value: fields[1], Group: group, Flag: fields[2]})
		case 1: // bare keyword like FINAL/MATCH
			if strings.EqualFold(fields[0], "FINAL") || strings.EqualFold(fields[0], "MATCH") {
				out = append(out, Rule{Type: "MATCH", Group: group})
			} else {
				skipped = append(skipped, line)
			}
		}
	}
	return out, skipped
}

// --- shared typed accessors over the Clash field bag (map[string]any) ---

// cs extracts a string value from a map, converting numeric types if needed.
func cs(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.Itoa(int(v))
	}
	return ""
}

// cb extracts a boolean value from a map, tolerating string/int representations.
func cb(m map[string]any, k string) bool {
	switch v := m[k].(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "on":
			return true
		}
	case int:
		return v != 0
	}
	return false
}

// cmap extracts a nested map[string]any.
func cmap(m map[string]any, k string) map[string]any {
	mm, _ := m[k].(map[string]any)
	return mm
}

// ci reads an int field, tolerating int/int64/float64 and numeric string representations.
func ci(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return 0
}

// parseReserved parses reserved bytes for WireGuard, tolerating []int, []any, and comma-separated string.
func parseReserved(v any) []int {
	switch val := v.(type) {
	case []int:
		return val
	case []any:
		var res []int
		for _, x := range val {
			switch n := x.(type) {
			case int:
				res = append(res, n)
			case int64:
				res = append(res, int(n))
			case float64:
				res = append(res, int(n))
			case string:
				if i, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
					res = append(res, i)
				}
			}
		}
		return res
	case string:
		var res []int
		for _, part := range strings.Split(val, ",") {
			if i, err := strconv.Atoi(strings.TrimSpace(part)); err == nil {
				res = append(res, i)
			}
		}
		return res
	}
	return nil
}

// getSNI returns the server name or SNI, checking both "servername" and "sni".
func getSNI(c map[string]any) string {
	return firstNonEmptyStr(cs(c, "servername"), cs(c, "sni"))
}
