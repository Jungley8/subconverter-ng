// Package generator renders parsed nodes plus an external config into a target
// client configuration. The MVP targets Clash.Meta (mihomo).
package generator

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

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
	MixedPort          int            `yaml:"mixed-port"`
	AllowLan           bool           `yaml:"allow-lan"`
	Mode               string         `yaml:"mode"`
	LogLevel           string         `yaml:"log-level"`
	ExternalController string         `yaml:"external-controller"`
	DNS                map[string]any `yaml:"dns"`
	Proxies            []map[string]any `yaml:"proxies"`
	ProxyGroups        []groupOut       `yaml:"proxy-groups"`
	Rules              []string         `yaml:"rules"`
}

// Result is the rendered config plus diagnostics worth surfacing to the user.
type Result struct {
	YAML        []byte
	NodeCount   int
	EmptyGroups []string // groups that matched no nodes (filled with DIRECT)
}

// GenerateClash builds a Clash.Meta config.
func GenerateClash(ctx context.Context, nodes []*proxy.Proxy, cfg *extconfig.Config, f Fetcher, opts Options) (*Result, error) {
	nodes = filterNodes(nodes, cfg)
	if opts.Sort {
		sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	}
	applyNodeOptions(nodes, opts)

	res := &Result{NodeCount: len(nodes)}
	proxies := make([]map[string]any, 0, len(nodes))
	names := make([]string, 0, len(nodes))
	for _, n := range nodes {
		proxies = append(proxies, n.Clash)
		names = append(names, n.Name)
	}

	groups := buildGroups(cfg.ProxyGroups, nodes, names, res)
	rules := buildRules(ctx, cfg, f)

	out := defaultBase()
	out.Proxies = proxies
	out.ProxyGroups = groups
	out.Rules = rules

	// A custom base template (clash_rule_base) overrides the default skeleton;
	// we inject proxies/proxy-groups/rules into it and marshal that instead.
	if cfg.ClashRuleBase != "" {
		if data, err := f.Get(ctx, cfg.ClashRuleBase); err == nil {
			var base map[string]any
			if yaml.Unmarshal(data, &base) == nil && base != nil {
				base["proxies"] = proxies
				base["proxy-groups"] = groups
				if cfg.OverwriteRules || base["rules"] == nil {
					base["rules"] = rules
				}
				y, err := yaml.Marshal(base)
				if err != nil {
					return nil, err
				}
				res.YAML = unescapeUnicode(y)
				return res, nil
			}
		}
		// On any failure we fall through to the default base rather than erroring.
	}

	y, err := yaml.Marshal(out)
	if err != nil {
		return nil, err
	}
	res.YAML = unescapeUnicode(y)
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

func matchesAny(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// applyNodeOptions stamps URL-flag-driven fields onto every node.
func applyNodeOptions(nodes []*proxy.Proxy, opts Options) {
	for _, n := range nodes {
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

// buildRules expands all rulesets in declared order. Remote rulesets are
// fetched concurrently but assembled in order. A trailing MATCH (from []FINAL)
// is honoured wherever it appears.
func buildRules(ctx context.Context, cfg *extconfig.Config, f Fetcher) []string {
	if !cfg.EnableRuleGenerator {
		return nil
	}
	type fetched struct {
		lines []string
	}
	results := make([]fetched, len(cfg.Rulesets))
	var wg sync.WaitGroup
	for i, rs := range cfg.Rulesets {
		if rs.URL == "" {
			continue
		}
		wg.Add(1)
		go func(i int, url, group string) {
			defer wg.Done()
			data, err := f.Get(ctx, url)
			if err != nil {
				return
			}
			results[i].lines = expandRemoteRuleset(data, group)
		}(i, rs.URL, rs.Group)
	}
	wg.Wait()

	var rules []string
	for i, rs := range cfg.Rulesets {
		if rs.Inline != "" {
			rules = append(rules, expandInlineRule(rs.Inline, rs.Group))
			continue
		}
		rules = append(rules, results[i].lines...)
	}
	return rules
}

// expandInlineRule turns a []inline body into a Clash rule for group.
//
//	FINAL      -> MATCH,<group>
//	GEOIP,CN   -> GEOIP,CN,<group>
//	DOMAIN,x   -> DOMAIN,x,<group>
func expandInlineRule(body, group string) string {
	if strings.EqualFold(body, "FINAL") {
		return "MATCH," + group
	}
	return body + "," + group
}

// expandRemoteRuleset parses an ACL4SSR-style .list file and appends the policy
// group to each rule, preserving an optional trailing no-resolve.
func expandRemoteRuleset(data []byte, group string) []string {
	var out []string
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
			out = append(out, fields[0]+","+fields[1]+","+group)
		case 3: // TYPE,VALUE,no-resolve  (insert group before the flag)
			out = append(out, fields[0]+","+fields[1]+","+group+","+fields[2])
		case 1: // bare keyword like FINAL/MATCH
			if strings.EqualFold(fields[0], "FINAL") || strings.EqualFold(fields[0], "MATCH") {
				out = append(out, "MATCH,"+group)
			}
		}
	}
	return out
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
