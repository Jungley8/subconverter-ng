package generator

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
	"gopkg.in/yaml.v3"
)

// Provider health-check defaults (mihomo proxy-provider fields).
const (
	providerHealthURL      = "https://www.gstatic.com/generate_204"
	providerHealthInterval = 300
	defaultProviderIntvl   = 86400
)

// GenerateClashProvider renders a Clash.Meta config in proxy-provider mode:
// each http(s) subscription URL becomes a mihomo proxy-provider that the client
// refreshes on its own interval, while the converter only emits the skeleton —
// proxy-providers, template groups (use:/filter), and rules. Share-link url=
// entries are still fetched-free parsed and inlined as local proxies.
//
// Server-side node processing (emoji, rename, fdn, dedup) does NOT apply to
// provider payloads: the client sees the airport's raw nodes, filtered only by
// the provider's filter/exclude-filter. This is the documented tradeoff of
// delegating node fetching to mihomo.
func GenerateClashProvider(ctx context.Context, localNodes []*proxy.Proxy, cfg *extconfig.Config, f Fetcher, opts Options) (*Result, error) {
	res := &Result{ContentType: ctYAML}

	if opts.ProviderInterval <= 0 {
		opts.ProviderInterval = defaultProviderIntvl
	}

	proxies := make([]map[string]any, 0, len(localNodes))
	localNames := make([]string, 0, len(localNodes))
	for _, n := range localNodes {
		proxies = append(proxies, n.Clash)
		localNames = append(localNames, n.Name)
	}
	res.NodeCount = len(localNodes)

	providerNames := make([]string, 0, len(opts.ProviderURLs))
	providers := make(map[string]any, len(opts.ProviderURLs))
	for i, u := range opts.ProviderURLs {
		name := fmt.Sprintf("sub-%d", i+1)
		providerNames = append(providerNames, name)
		entry := map[string]any{
			"type":     "http",
			"url":      u,
			"interval": opts.ProviderInterval,
			"health-check": map[string]any{
				"enable":   true,
				"url":      providerHealthURL,
				"interval": providerHealthInterval,
				"lazy":     true,
			},
		}
		if opts.ProviderUA != "" {
			entry["header"] = map[string]any{"User-Agent": []string{opts.ProviderUA}}
		}
		if opts.ProviderInclude != "" {
			entry["filter"] = opts.ProviderInclude
		}
		if opts.ProviderExclude != "" {
			entry["exclude-filter"] = opts.ProviderExclude
		}
		override := map[string]any{}
		if opts.UDP {
			override["udp"] = true
		}
		if opts.SkipCertVerify {
			override["skip-cert-verify"] = true
		}
		if len(override) > 0 {
			entry["override"] = override
		}
		providers[name] = entry
	}

	groups := buildGroupsProvider(cfg.ProxyGroups, providerNames, localNames, res)
	var rules []string
	if len(groups) == 0 {
		// No external config: without a group the config is unroutable, so
		// synthesize the minimal select + url-test pair over the providers.
		groups = defaultProviderGroups(providerNames)
		rules = []string{"MATCH,🚀 节点选择"}
	} else {
		var skipped []string
		rules, skipped = buildRules(ctx, cfg, f, opts)
		res.SkippedRules = skipped
	}

	out := defaultBase()
	out.Proxies = proxies
	out.ProxyProviders = providers
	out.ProxyGroups = groups
	out.Rules = rules

	if cfg.ClashRuleBase != "" {
		if data, err := f.Get(ctx, cfg.ClashRuleBase); err == nil {
			var base map[string]any
			if yaml.Unmarshal(data, &base) == nil && base != nil {
				base["proxies"] = proxies
				base["proxy-providers"] = providers
				base["proxy-groups"] = groups
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
	}

	y, err := yaml.Marshal(out)
	if err != nil {
		return nil, err
	}
	res.Output = unescapeUnicode(y)
	return res, nil
}

// buildGroupsProvider maps INI proxy-group definitions onto provider-mode
// groups: []Literal selectors stay in `proxies`, regex selectors become the
// group's `filter` over the referenced providers (`use:`), and are also matched
// against local inline nodes so share-link entries still join their groups.
func buildGroupsProvider(defs []extconfig.ProxyGroup, providers, localNames []string, res *Result) []groupOut {
	groups := make([]groupOut, 0, len(defs))
	for _, d := range defs {
		g := groupOut{
			Name:      d.Name,
			Type:      d.Type,
			URL:       d.TestURL,
			Interval:  d.Interval,
			Timeout:   d.Timeout,
			Tolerance: d.Tolerance,
		}
		var filters []string
		seen := map[string]bool{}
		add := func(name string) {
			if name != "" && !seen[name] {
				seen[name] = true
				g.Proxies = append(g.Proxies, name)
			}
		}
		for _, sel := range d.Selectors {
			if name, ok := extconfig.Literal(sel); ok {
				add(name)
				continue
			}
			if sel == ".*" {
				for _, n := range localNames {
					add(n)
				}
				continue
			}
			filters = append(filters, sel)
			// Local nodes matching this selector join the group inline.
			if re, err := regexp.Compile(sel); err == nil {
				for _, n := range localNames {
					if re.MatchString(n) {
						add(n)
					}
				}
			}
		}
		if len(filters) > 0 {
			g.Filter = strings.Join(filters, "|")
		}
		if len(filters) > 0 && len(providers) > 0 {
			g.Use = providers
		}
		if len(g.Proxies) == 0 && len(g.Use) == 0 {
			g.Proxies = []string{"DIRECT"}
			res.EmptyGroups = append(res.EmptyGroups, d.Name)
		}
		groups = append(groups, g)
	}
	return groups
}

// defaultProviderGroups is the fallback group set when no external config
// defines any groups.
func defaultProviderGroups(providers []string) []groupOut {
	return []groupOut{
		{
			Name:    "🚀 节点选择",
			Type:    "select",
			Proxies: []string{"♻️ 自动选择", "DIRECT"},
			Use:     providers,
		},
		{
			Name:     "♻️ 自动选择",
			Type:     "url-test",
			Use:      providers,
			URL:      providerHealthURL,
			Interval: providerHealthInterval,
		},
	}
}
