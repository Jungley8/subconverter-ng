// Package generator renders parsed nodes plus an external config into a target
// client configuration. The MVP targets Clash.Meta (mihomo).
package generator

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/emoji"
	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
	"gopkg.in/yaml.v3"
)

// Fetcher fetches remote rulesets and base configs.
type Fetcher interface {
	Get(ctx context.Context, url string) ([]byte, error)
}

// Options carries the URL flags that influence node rendering.
type Options struct {
	Sort           bool // sort nodes by name
	UDP            bool // force udp:true on every node
	TFO            bool // tcp-fast-open
	SkipCertVerify bool // scv=true

	// Emoji handling (subconverter-compatible). RemoveEmoji strips existing
	// emoji; AddEmoji then prepends a flag using EmojiRules. Applied in that
	// order so AddEmoji matches the cleaned name.
	RemoveEmoji bool
	AddEmoji    bool
	EmojiRules  []emoji.Rule

	// RenameRules rewrite node names via regexp, applied between RemoveEmoji and
	// AddEmoji (order: remove emoji -> rename -> add emoji).
	RenameRules []RenameRule

	// UseRuleProviders emits Clash.Meta rule-providers (one per remote ruleset
	// URL) plus RULE-SET rules instead of inlining every remote rule. It maps to
	// subconverter's expand=false. The default (false) keeps the inline path
	// (expand=true). Inline rules ([]GEOIP,CN, []FINAL) stay direct rules.
	UseRuleProviders bool

	// Dedup drops duplicate nodes — entries identical in every connection field
	// (type/server/port/credentials/transport), ignoring the name. First wins.
	// Maps to &dedup=true.
	Dedup bool

	// FilterDeprecated drops nodes Clash.Meta cannot use (e.g. Shadowsocks with
	// a retired cipher), preventing an unloadable config. Maps to &fdn=true.
	FilterDeprecated bool

	// AppendType prepends "[TYPE] " to each node name. Maps to &append_type=true.
	// Applied before emoji/rename so the rest of the pipeline sees the new name.
	AppendType bool

	// ListOnly emits only the proxies list (the `proxies:` document) with no
	// groups or rules. Maps to &list=true.
	ListOnly bool
}

// RenameRule is a compiled rename= entry: a regex pattern and its replacement.
// Replacement uses Go's $N backref syntax (subconverter's \N is translated at
// compile time).
type RenameRule struct {
	Pattern *regexp.Regexp
	Replace string
}

// backrefSlash matches subconverter-style \N backrefs (\1, \2, ...) in a
// replacement string so they can be translated to Go's $N form.
var backrefSlash = regexp.MustCompile(`\\(\d+)`)

// CompileRenameRules turns raw "pattern@replacement" entries into compiled
// RenameRules. The first "@" separates pattern from replacement; the
// replacement may be empty. Backrefs may be written subconverter-style (\1) or
// Go-style ($1) — \N is translated to $N before use, while existing $N are left
// untouched. Invalid entries (no "@", or a pattern that fails to compile) are
// skipped.
func CompileRenameRules(raw []string) []RenameRule {
	var out []RenameRule
	for _, line := range raw {
		pat, repl, ok := strings.Cut(line, "@")
		if !ok || pat == "" {
			continue
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			continue
		}
		repl = backrefSlash.ReplaceAllString(repl, "$$$1")
		out = append(out, RenameRule{Pattern: re, Replace: repl})
	}
	return out
}

// groupOut is a Clash proxy-group, as a struct so YAML keys stay in a natural
// order rather than the map-alphabetical order yaml.v3 would otherwise emit.
type groupOut struct {
	Name      string   `yaml:"name"`
	Type      string   `yaml:"type"`
	Proxies   []string `yaml:"proxies"`
	URL       string   `yaml:"url,omitempty"`
	Interval  int      `yaml:"interval,omitempty"`
	Timeout   int      `yaml:"timeout,omitempty"`
	Tolerance int      `yaml:"tolerance,omitempty"`
}

type clashOut struct {
	MixedPort          int              `yaml:"mixed-port"`
	AllowLan           bool             `yaml:"allow-lan"`
	Mode               string           `yaml:"mode"`
	LogLevel           string           `yaml:"log-level"`
	ExternalController string           `yaml:"external-controller"`
	DNS                map[string]any   `yaml:"dns"`
	Proxies            []map[string]any `yaml:"proxies"`
	ProxyGroups        []groupOut       `yaml:"proxy-groups"`
	RuleProviders      map[string]any   `yaml:"rule-providers,omitempty"`
	Rules              []string         `yaml:"rules"`
}

// Result is the rendered config plus diagnostics worth surfacing to the user.
type Result struct {
	Output            []byte // rendered config bytes for the chosen target
	ContentType       string // HTTP Content-Type the server should send
	NodeCount         int
	EmptyGroups       []string // groups that matched no nodes (filled with DIRECT)
	SkippedRules      []string // source rules dropped for an unsupported rule type
	SkippedNodes      []string // nodes a target cannot render (name + reason)
	Duplicates        int      // nodes removed by dedup
	DeprecatedDropped int      // nodes removed by filter-deprecated (fdn)
}

// Content types per target family.
const (
	ctYAML = "text/yaml; charset=utf-8"
	ctJSON = "application/json; charset=utf-8"
	ctText = "text/plain; charset=utf-8"
)

// GenerateClash builds a Clash.Meta config.
func GenerateClash(ctx context.Context, nodes []*proxy.Proxy, cfg *extconfig.Config, f Fetcher, opts Options) (*Result, error) {
	res := &Result{ContentType: ctYAML}
	nodes = prepareNodes(nodes, cfg, opts, res)

	proxies := make([]map[string]any, 0, len(nodes))
	names := make([]string, 0, len(nodes))
	for _, n := range nodes {
		proxies = append(proxies, n.Clash)
		names = append(names, n.Name)
	}

	// list=true: emit only the proxies list, no groups/rules.
	if opts.ListOnly {
		y, err := yaml.Marshal(struct {
			Proxies []map[string]any `yaml:"proxies"`
		}{Proxies: proxies})
		if err != nil {
			return nil, err
		}
		res.Output = unescapeUnicode(y)
		return res, nil
	}

	groups := buildGroups(cfg.ProxyGroups, nodes, names, res)

	// Rule output: either inline every rule (default, expand=true) or emit
	// rule-providers + RULE-SET rules (expand=false).
	var rules []string
	var providers map[string]any
	if opts.UseRuleProviders {
		rules, providers, res.SkippedRules = buildRuleProviders(cfg)
	} else {
		var skippedRules []string
		rules, skippedRules = buildRules(ctx, cfg, f)
		res.SkippedRules = skippedRules
	}

	out := defaultBase()
	out.Proxies = proxies
	out.ProxyGroups = groups
	out.RuleProviders = providers
	out.Rules = rules

	// A custom base template (clash_rule_base) overrides the default skeleton;
	// we inject proxies/proxy-groups/rules into it and marshal that instead.
	if cfg.ClashRuleBase != "" {
		if data, err := f.Get(ctx, cfg.ClashRuleBase); err == nil {
			var base map[string]any
			if yaml.Unmarshal(data, &base) == nil && base != nil {
				base["proxies"] = proxies
				base["proxy-groups"] = groups
				if providers != nil {
					base["rule-providers"] = providers
				}
				if cfg.OverwriteRules || base["rules"] == nil {
					base["rules"] = rules
				}
				y, err := yaml.Marshal(base)
				if err != nil {
					return nil, err
				}
				res.Output = unescapeUnicode(y)
				return res, nil
			}
		}
		// On any failure we fall through to the default base rather than erroring.
	}

	y, err := yaml.Marshal(out)
	if err != nil {
		return nil, err
	}
	res.Output = unescapeUnicode(y)
	return res, nil
}

// unescapeUnicode rewrites \uXXXX and \U00XXXXXX escape sequences that yaml.v3
// emits for non-ASCII characters (notably emoji, which live outside the BMP and
// which yaml.v3 conservatively escapes) back into raw UTF-8. Real Clash configs
// carry literal emoji in node/group names, and clients display them as-is.
//
// Only non-ASCII code points are unescaped, so genuine control-character
// escapes are preserved and never reintroduced as raw bytes. A literal "\\"
// is passed through untouched so "\\U..." is not misread as an escape.
func unescapeUnicode(b []byte) []byte {
	s := string(b)
	var sb strings.Builder
	sb.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\':
				sb.WriteString(`\\`)
				i += 2
				continue
			case 'U':
				if i+10 <= len(s) {
					if r, err := strconv.ParseInt(s[i+2:i+10], 16, 32); err == nil && r >= 0x80 {
						sb.WriteRune(rune(r))
						i += 10
						continue
					}
				}
			case 'u':
				if i+6 <= len(s) {
					if r, err := strconv.ParseInt(s[i+2:i+6], 16, 32); err == nil && r >= 0x80 {
						sb.WriteRune(rune(r))
						i += 6
						continue
					}
				}
			}
		}
		sb.WriteByte(s[i])
		i++
	}
	return []byte(sb.String())
}

// filterNodes drops nodes whose name matches any exclude_remarks regex, and —
// when include_remarks is set — keeps only those matching at least one.
func filterNodes(nodes []*proxy.Proxy, cfg *extconfig.Config) []*proxy.Proxy {
	out := nodes[:0:0]
	for _, n := range nodes {
		if matchesAny(cfg.ExcludeRemarks, n.Name) {
			continue
		}
		if len(cfg.IncludeRemarks) > 0 && !matchesAny(cfg.IncludeRemarks, n.Name) {
			continue
		}
		out = append(out, n)
	}
	return out
}

// dedup removes nodes that are identical in every connection field, ignoring
// the display name. The first occurrence of each distinct node is kept, so
// order is preserved. The signature is the node's Clash map (minus "name")
// marshalled to YAML, which yaml.v3 emits with deterministically sorted keys.
func dedup(nodes []*proxy.Proxy) (out []*proxy.Proxy, removed int) {
	seen := make(map[string]bool, len(nodes))
	out = make([]*proxy.Proxy, 0, len(nodes))
	for _, n := range nodes {
		sig := nodeSignature(n)
		if seen[sig] {
			removed++
			continue
		}
		seen[sig] = true
		out = append(out, n)
	}
	return out, removed
}

func nodeSignature(n *proxy.Proxy) string {
	clone := make(map[string]any, len(n.Clash))
	for k, v := range n.Clash {
		if k == "name" {
			continue
		}
		clone[k] = v
	}
	b, err := yaml.Marshal(clone)
	if err != nil {
		// Fall back to a coarse signature; collisions only cost a missed dedup.
		return n.Type + "|" + n.Server + "|" + strconv.Itoa(n.Port)
	}
	return string(b)
}

// supportedSSCiphers is the set of Shadowsocks ciphers Clash.Meta accepts. SS
// nodes using anything else make mihomo reject the whole config, so fdn drops
// them.
var supportedSSCiphers = map[string]bool{
	"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true,
	"aes-128-cfb": true, "aes-192-cfb": true, "aes-256-cfb": true,
	"aes-128-ctr": true, "aes-192-ctr": true, "aes-256-ctr": true,
	"rc4-md5": true, "chacha20-ietf": true, "xchacha20": true,
	"chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true,
	"2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true,
	"2022-blake3-chacha20-poly1305": true, "none": true,
}

// filterDeprecated drops nodes Clash.Meta cannot load. Currently this is
// Shadowsocks nodes with a cipher outside supportedSSCiphers; other protocols
// are passed through (the parser only emits types mihomo understands).
func filterDeprecated(nodes []*proxy.Proxy) (out []*proxy.Proxy, dropped int) {
	out = make([]*proxy.Proxy, 0, len(nodes))
	for _, n := range nodes {
		if n.Type == "ss" {
			cipher, _ := n.Clash["cipher"].(string)
			if cipher != "" && !supportedSSCiphers[strings.ToLower(cipher)] {
				dropped++
				continue
			}
		}
		out = append(out, n)
	}
	return out, dropped
}

func matchesAny(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// applyNodeOptions stamps URL-flag-driven fields onto every node and applies
// emoji processing (remove existing, then add per rules). Renames happen here —
// before group/rule assembly — so proxy-group member lists stay in sync.
func applyNodeOptions(nodes []*proxy.Proxy, opts Options) {
	for _, n := range nodes {
		if opts.AppendType && n.Type != "" {
			n.Rename("[" + strings.ToUpper(n.Type) + "] " + n.Name)
		}
		if opts.RemoveEmoji {
			n.Rename(emoji.Remove(n.Name))
		}
		for _, rr := range opts.RenameRules {
			n.Rename(rr.Pattern.ReplaceAllString(n.Name, rr.Replace))
		}
		if opts.AddEmoji {
			n.Rename(emoji.Add(n.Name, opts.EmojiRules))
		}
		if opts.UDP {
			n.Clash["udp"] = true
		}
		if opts.TFO {
			n.Clash["tfo"] = true
		}
		if opts.SkipCertVerify {
			// Only meaningful for TLS-bearing protocols, but harmless elsewhere.
			n.Clash["skip-cert-verify"] = true
		}
	}
}

// buildGroups resolves each custom_proxy_group's selectors against the node
// list. Empty groups are filled with DIRECT to keep the config loadable.
func buildGroups(defs []extconfig.ProxyGroup, nodes []*proxy.Proxy, allNames []string, res *Result) []groupOut {
	groups := make([]groupOut, 0, len(defs))
	for _, d := range defs {
		members := resolveSelectors(d.Selectors, nodes, allNames)
		if len(members) == 0 {
			members = []string{"DIRECT"}
			res.EmptyGroups = append(res.EmptyGroups, d.Name)
		}
		g := groupOut{
			Name:      d.Name,
			Type:      d.Type,
			Proxies:   members,
			URL:       d.TestURL,
			Interval:  d.Interval,
			Timeout:   d.Timeout,
			Tolerance: d.Tolerance,
		}
		groups = append(groups, g)
	}
	return groups
}

// resolveSelectors expands []Literal references and regex/.* node matchers into
// an ordered, de-duplicated member list.
func resolveSelectors(selectors []string, nodes []*proxy.Proxy, allNames []string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(name string) {
		if name != "" && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	for _, sel := range selectors {
		if name, ok := extconfig.Literal(sel); ok {
			add(name)
			continue
		}
		if sel == ".*" {
			for _, n := range allNames {
				add(n)
			}
			continue
		}
		re, err := regexp.Compile(sel)
		if err != nil {
			continue
		}
		for _, n := range nodes {
			if re.MatchString(n.Name) {
				add(n.Name)
			}
		}
	}
	return out
}

// buildRules expands all rulesets in declared order into Clash rule lines. The
// concurrent fetch + neutral parsing lives in collectRules (common.go); this
// just formats each neutral Rule as a Clash rule string.
func buildRules(ctx context.Context, cfg *extconfig.Config, f Fetcher) (rules, skipped []string) {
	neutral, skipped := collectRules(ctx, cfg, f)
	for _, r := range neutral {
		rules = append(rules, formatClashRule(r))
	}
	return rules, skipped
}

// buildRuleProviders implements subconverter's expand=false output. Instead of
// fetching and inlining every remote rule, it emits one Clash.Meta rule-provider
// per distinct remote ruleset URL and a RULE-SET rule pointing each provider at
// its group. Inline rulesets ([]GEOIP,CN, []FINAL) stay direct rules so MATCH
// and inline matchers still work. Providers are deduped by URL: a URL reused
// across groups yields one provider but a RULE-SET line per (provider,group).
func buildRuleProviders(cfg *extconfig.Config) (rules []string, providers map[string]any, skipped []string) {
	if !cfg.EnableRuleGenerator {
		return nil, nil, nil
	}
	providerByURL := map[string]string{} // url -> provider key
	seenRuleSet := map[string]bool{}     // "provider\x00group" -> emitted
	for _, rs := range cfg.Rulesets {
		if rs.Inline != "" {
			if rule, ok := expandInlineRule(rs.Inline, rs.Group); ok {
				rules = append(rules, rule)
			} else {
				skipped = append(skipped, rs.Inline+","+rs.Group)
			}
			continue
		}
		if rs.URL == "" {
			continue
		}
		name, ok := providerByURL[rs.URL]
		if !ok {
			name = "provider_" + strconv.Itoa(len(providerByURL)+1)
			providerByURL[rs.URL] = name
			if providers == nil {
				providers = map[string]any{}
			}
			providers[name] = map[string]any{
				"type":     "http",
				"behavior": "classical",
				"url":      rs.URL,
				"path":     "./ruleset/" + name + ".list",
				"interval": 86400,
				"format":   "text",
			}
		}
		key := name + "\x00" + rs.Group
		if seenRuleSet[key] {
			continue // same (provider,group) already emitted
		}
		seenRuleSet[key] = true
		rules = append(rules, "RULE-SET,"+name+","+rs.Group)
	}
	return rules, providers, skipped
}

// validRuleTypes is the set of rule types Clash.Meta (mihomo) accepts. Rules
// whose type is not in this set make mihomo reject the WHOLE config at load
// time, so we drop unknown types (e.g. a typo'd "DIRECT-SUFFIX" in a source
// ruleset) and report them instead of emitting an unloadable config.
var validRuleTypes = map[string]bool{
	"DOMAIN": true, "DOMAIN-SUFFIX": true, "DOMAIN-KEYWORD": true, "DOMAIN-REGEX": true,
	"GEOSITE": true, "IP-CIDR": true, "IP-CIDR6": true, "IP-SUFFIX": true, "IP-ASN": true,
	"GEOIP": true, "SRC-GEOIP": true, "SRC-IP-CIDR": true, "SRC-IP-SUFFIX": true, "SRC-IP-ASN": true,
	"DST-PORT": true, "SRC-PORT": true, "IN-PORT": true, "IN-TYPE": true, "IN-USER": true, "IN-NAME": true,
	"PROCESS-NAME": true, "PROCESS-PATH": true, "PROCESS-NAME-REGEX": true, "PROCESS-PATH-REGEX": true,
	"NETWORK": true, "DSCP": true, "UID": true, "RULE-SET": true,
	"AND": true, "OR": true, "NOT": true, "SUB-RULE": true, "MATCH": true,
}

func isValidRuleType(typ string) bool {
	return validRuleTypes[strings.ToUpper(strings.TrimSpace(typ))]
}

// expandInlineRule turns a []inline body into a Clash rule for group (a thin
// Clash formatter over parseInlineRule). ok is false when the rule type is not
// recognised by Clash.Meta.
//
//	FINAL      -> MATCH,<group>
//	GEOIP,CN   -> GEOIP,CN,<group>
//	DOMAIN,x   -> DOMAIN,x,<group>
func expandInlineRule(body, group string) (string, bool) {
	r, ok := parseInlineRule(body, group)
	if !ok {
		return "", false
	}
	return formatClashRule(r), true
}

// expandRemoteRuleset parses an ACL4SSR-style .list file into Clash rule lines
// for group (a thin Clash formatter over parseRemoteRuleset). Lines with an
// unsupported rule type are collected into skipped rather than emitted.
func expandRemoteRuleset(data []byte, group string) (out, skipped []string) {
	rules, skipped := parseRemoteRuleset(data, group)
	for _, r := range rules {
		out = append(out, formatClashRule(r))
	}
	return out, skipped
}

// defaultBase is the Clash.Meta skeleton used when no clash_rule_base is set.
func defaultBase() *clashOut {
	return &clashOut{
		MixedPort:          7890,
		AllowLan:           true,
		Mode:               "rule",
		LogLevel:           "info",
		ExternalController: "127.0.0.1:9090",
		DNS: map[string]any{
			"enable":        true,
			"ipv6":          false,
			"enhanced-mode": "fake-ip",
			"nameserver":    []string{"223.5.5.5", "119.29.29.29"},
			"fallback":      []string{"8.8.8.8", "1.1.1.1"},
		},
	}
}
