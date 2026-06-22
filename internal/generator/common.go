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
	"strings"
	"sync"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// prepareNodes runs the target-agnostic node pipeline and records its
// diagnostics (dedup/deprecated counts, final NodeCount) into res. The returned
// slice is the processed node list every generator renders from. Node options
// (udp/tfo/scv, emoji, rename, append_type) are stamped onto each node's Clash
// field bag, which all generators read from.
func prepareNodes(nodes []*proxy.Proxy, cfg *extconfig.Config, opts Options, res *Result) []*proxy.Proxy {
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
	res.NodeCount = len(nodes)
	return nodes
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

// formatClashRule renders r as a Clash.Meta rule line.
func formatClashRule(r Rule) string {
	if r.IsMatch() {
		return "MATCH," + r.Group
	}
	s := r.Type + "," + r.Value + "," + r.Group
	if r.Flag != "" {
		s += "," + r.Flag
	}
	return s
}

// collectRules expands every ruleset in declared order into neutral Rule values.
// Remote rulesets are fetched concurrently but assembled in declared order;
// inline rulesets ([]GEOIP,CN, []FINAL) are expanded directly. Entries with an
// unsupported rule type are returned in skipped instead of rules.
func collectRules(ctx context.Context, cfg *extconfig.Config, f Fetcher) (rules []Rule, skipped []string) {
	if !cfg.EnableRuleGenerator {
		return nil, nil
	}
	type fetched struct {
		rules   []Rule
		skipped []string
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
	return rules, skipped
}

// parseInlineRule turns a []inline body into a neutral Rule. ok is false when
// the rule type is not a recognised Clash.Meta type.
//
//	FINAL      -> {Type: MATCH}
//	GEOIP,CN   -> {Type: GEOIP, Value: CN}
//	DOMAIN,x   -> {Type: DOMAIN, Value: x}
//
// The body after the first comma is kept verbatim as Value (it may itself carry
// a trailing flag), matching the legacy behaviour of appending the group last.
func parseInlineRule(body, group string) (Rule, bool) {
	if strings.EqualFold(body, "FINAL") {
		return Rule{Type: "MATCH", Group: group}, true
	}
	typ, val, _ := strings.Cut(body, ",")
	if !isValidRuleType(typ) {
		return Rule{}, false
	}
	return Rule{Type: typ, Value: val, Group: group}, true
}

// parseRemoteRuleset parses an ACL4SSR-style .list file into neutral Rule
// values, tagging each with group. Lines with an unsupported rule type are
// collected into skipped rather than emitted.
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
			if !isValidRuleType(fields[0]) {
				skipped = append(skipped, line)
				continue
			}
			out = append(out, Rule{Type: fields[0], Value: fields[1], Group: group})
		case 3: // TYPE,VALUE,flag (e.g. no-resolve)
			if !isValidRuleType(fields[0]) {
				skipped = append(skipped, line)
				continue
			}
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
