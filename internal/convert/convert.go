// Package convert orchestrates a full conversion: fetch subscription(s) and the
// external config, parse nodes, then render the target output. It is shared by
// the HTTP server and the CLI so both behave identically.
package convert

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/Jungley8/subconverter-ng/internal/emoji"
	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/generator"
	"github.com/Jungley8/subconverter-ng/internal/matcher"
	"github.com/Jungley8/subconverter-ng/internal/parser"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// ErrNoNodes is returned when a subscription fetched successfully but yielded no
// usable nodes. It signals a subscription-content problem (empty sub, all lines
// unparseable) rather than a gateway/fetch failure, so callers can respond with
// a readable hint instead of a generic upstream-failure response. Test with errors.Is.
var ErrNoNodes = errors.New("no usable nodes parsed from subscription(s)")

// ErrBadRequest marks a failure caused by the request itself — an unknown
// target, provider mode without a subscription URL, a template that cannot be
// used — as opposed to an upstream failure. The HTTP layer answers 400 for
// these and 424 (upstream dependency failed) for everything else. Test with
// errors.Is.
var ErrBadRequest = errors.New("invalid request")

// badRequest builds an ErrBadRequest with a user-facing message.
func badRequest(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBadRequest, fmt.Sprintf(format, args...))
}

// renderError classifies a generator failure. A broken external config (bad
// clash_rule_base, uncompilable selector) is the user's file to fix, so it is a
// 400; anything else stays an upstream-failure error.
func renderError(err error) error {
	if errors.Is(err, generator.ErrConfigInvalid) {
		return badRequest("%s", err)
	}
	return err
}

// Fetcher is the subset of fetch.Client convert needs (kept as an interface for
// testability).
type Fetcher interface {
	Get(ctx context.Context, url string) ([]byte, error)
}

// MetaFetcher is an optional capability: a Fetcher that can also return the
// response headers. fetch.Client implements it. convert type-asserts for it and
// falls back to plain Get (with empty headers) for fakes that don't.
type MetaFetcher interface {
	GetWithMeta(ctx context.Context, url string) ([]byte, http.Header, error)
}

// getWithMeta calls f.GetWithMeta when available, else plain Get with nil headers.
func getWithMeta(ctx context.Context, f Fetcher, url string) ([]byte, http.Header, error) {
	if mf, ok := f.(MetaFetcher); ok {
		return mf.GetWithMeta(ctx, url)
	}
	body, err := f.Get(ctx, url)
	return body, nil, err
}

// Request describes one conversion.
type Request struct {
	Target    string   // currently only "clash"
	SubURLs   []string // subscription URLs (the &url= param, split on |)
	ConfigURL string   // external INI config (the &config= param)

	// Template, when non-empty, is an http(s) URL to a sing-box JSON template.
	// The nodes are rendered into that template instead of a bare config.
	// See generator.GenerateSingboxTemplate.
	Template string
	Gen      generator.Options

	// Provider switches target=clash to proxy-provider output (&provider=true):
	// http(s) subscription URLs become mihomo proxy-providers the client
	// refreshes itself; only share-link entries are parsed and inlined locally.
	// ProviderInterval is the providers' update interval in seconds (0 = 86400).
	// UserAgent is the UA the providers should fetch with (&ua=).
	Provider         bool
	ProviderInterval int
	UserAgent        string

	// Emoji intent from URL params, as tribools (nil = unspecified). Emoji is
	// the subconverter shortcut: when set it drives add_emoji and forces
	// remove_emoji=true. Resolved against the external config + defaults below.
	Emoji       *bool
	AddEmoji    *bool
	RemoveEmoji *bool

	// NoCache, when true, signals the server to bypass the shared fetch cache
	// for this request (the &nocache=1 param). It is informational to convert;
	// the actual bypass is wired by the server constructing the Fetcher.
	NoCache bool

	// InsertURLs are extra node-source URLs (the configured insert_url list) to
	// merge into the conversion. The caller resolves the enable/disable decision
	// (server default + &insert= override): an empty slice means no insertion.
	// InsertPrepend places these nodes before the subscription nodes when true.
	InsertURLs    []string
	InsertPrepend bool

	// IncludeRemarks / ExcludeRemarks are per-request node-name filters (the
	// &include= / &exclude= URL params, or CLI --include / --exclude). When set
	// they OVERRIDE the external config's include_remarks / exclude_remarks,
	// matching original subconverter semantics. Use CompileRemarks to build them.
	IncludeRemarks []*matcher.Matcher
	ExcludeRemarks []*matcher.Matcher
}

// CompileRemarks turns one include/exclude spec into a single compiled regex.
// An empty spec yields nil (no filtering). The spec is matched as ONE regex:
// alternation belongs inside it, e.g. "(?i)(弃用)|(到期)" — no splitting on "|",
// which would break regexes whose groups contain alternation.
func CompileRemarks(spec string) ([]*matcher.Matcher, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	re, err := matcher.Compile(spec)
	if err != nil {
		return nil, badRequest("invalid remarks regex %q: %v", spec, err)
	}
	return []*matcher.Matcher{re}, nil
}

// Diagnostics captures non-fatal information about a conversion.
type Diagnostics struct {
	NodeCount         int
	SkippedLines      []string // subscription lines that did not parse into a node
	EmptyGroups       []string // proxy-groups that matched no nodes (filled with DIRECT)
	SkippedRules      []string // ruleset entries dropped for an unsupported rule type
	SkippedNodes      []string // nodes the chosen target cannot render
	Duplicates        int      // nodes removed by dedup (&dedup=true)
	Deprecated        int      // nodes removed by filter-deprecated (&fdn=true)
	Filtered          int      // nodes removed by include/exclude remarks filters
	ExcludedProtocols int      // nodes removed by protocol exclusion (&exclude_protocol=...)

	// ContentType is the HTTP Content-Type the rendered output should be served
	// with (varies by target: YAML for clash, JSON for sing-box, etc.).
	ContentType string

	// SubscriptionUserinfo is the airport's Subscription-Userinfo response
	// header from the FIRST subscription fetch (empty if absent). Clash clients
	// use it to display traffic/expiry.
	SubscriptionUserinfo string
}

// Run performs the conversion and returns the rendered config bytes.
func Run(ctx context.Context, f Fetcher, req Request) ([]byte, *Diagnostics, error) {
	name, ver, err := ParseTarget(req.Target)
	if err != nil {
		return nil, nil, badRequest("%s", err)
	}
	if !supportedTargets[name] {
		return nil, nil, badRequest("unsupported target %q (supported: %s)", describeTarget(name, ver), supportedList())
	}
	if len(req.SubURLs) == 0 {
		return nil, nil, badRequest("no subscription url provided")
	}

	var cfg *extconfig.Config
	if req.ConfigURL != "" {
		data, err := f.Get(ctx, req.ConfigURL)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch external config: %w", err)
		}
		cfg = extconfig.Parse(data)
		if invalid := stillInvalid(cfg.Invalid, req); len(invalid) > 0 {
			return nil, nil, badRequest("invalid external config: %s", strings.Join(invalid, ", "))
		}
	} else {
		cfg = &extconfig.Config{EnableRuleGenerator: true}
	}

	// Provider mode (&provider=true): delegate node fetching to the mihomo
	// client. The server never touches the subscription payloads — each http(s)
	// url= entry becomes a proxy-provider; share-link entries are parsed and
	// inlined as local nodes.
	if req.Provider {
		if name != "clash" {
			return nil, nil, badRequest("provider mode is only available with target=clash (got %s)", describeTarget(name, ver))
		}
		var subs, links []string
		for _, raw := range req.SubURLs {
			group, link := splitSource(raw)
			if group != "" {
				// A tag only feeds !!GROUP=, and no !! selector can be expressed
				// in a provider filter.
				return nil, nil, badRequest("provider mode does not support tag:<group>, sources")
			}
			if parser.IsShareLink(link) {
				links = append(links, link)
			} else {
				subs = append(subs, link)
			}
		}
		if len(subs) == 0 {
			return nil, nil, badRequest("provider mode needs at least one http(s) subscription url")
		}
		var localNodes []*proxy.Proxy
		var skipped []string
		for _, l := range links {
			ns, sk, err := parser.Parse([]byte(l))
			if err != nil {
				return nil, nil, fmt.Errorf("parse local node link: %w", err)
			}
			localNodes = append(localNodes, ns...)
			skipped = append(skipped, sk...)
		}
		gen := buildGen(cfg, req, ver)
		gen.ProviderMode = true
		gen.ProviderURLs = subs
		gen.ProviderUA = req.UserAgent
		gen.ProviderInterval = req.ProviderInterval
		if gen.ProviderInterval <= 0 {
			gen.ProviderInterval = 86400
		}
		// The provider's filter is compiled by mihomo with regexp2, so a
		// request regex must pass that engine as well as ours.
		if len(req.IncludeRemarks) > 0 {
			client, err := matcher.CompileClient(req.IncludeRemarks[0].Pattern())
			if err != nil {
				return nil, nil, badRequest("invalid include regex for provider mode: %v", err)
			}
			gen.ProviderInclude = req.IncludeRemarks[0].Pattern()
			cfg.IncludeRemarks = []*matcher.Matcher{client}
		}
		if len(req.ExcludeRemarks) > 0 {
			client, err := matcher.CompileClient(req.ExcludeRemarks[0].Pattern())
			if err != nil {
				return nil, nil, badRequest("invalid exclude regex for provider mode: %v", err)
			}
			gen.ProviderExclude = req.ExcludeRemarks[0].Pattern()
			cfg.ExcludeRemarks = []*matcher.Matcher{client}
		}
		result, err := generator.GenerateClashProvider(ctx, localNodes, cfg, f, gen)
		if err != nil {
			return nil, nil, renderError(err)
		}
		return result.Output, diagnosticsFor(result, skipped, ""), nil
	}

	nodes, skipped, userinfo, err := fetchAndParseAll(ctx, f, req.SubURLs, func(i int) int { return i })
	if err != nil {
		return nil, nil, err
	}

	// insert_url: merge configured insert nodes. Failures are non-fatal (the
	// user's own subscription must still convert); the userinfo header is taken
	// from the subscription only, so we discard the insert sources' headers.
	if len(req.InsertURLs) > 0 {
		if insNodes, _, _, ierr := fetchAndParseAll(ctx, f, req.InsertURLs, func(i int) int { return -(i + 1) }); ierr == nil && len(insNodes) > 0 {
			if req.InsertPrepend {
				nodes = append(insNodes, nodes...)
			} else {
				nodes = append(nodes, insNodes...)
			}
		}
	}

	if len(nodes) == 0 {
		// A successful fetch that yields zero nodes almost always means the
		// airport returned a notice/error page instead of a node list (e.g. the
		// sub is only reachable from a given region, or the UA was rejected).
		// Surface a snippet of what came back so the cause is diagnosable
		// instead of opaque — the raw body is far more useful than a bare count.
		return nil, nil, fmt.Errorf("%w; %d lines skipped%s", ErrNoNodes, len(skipped), skippedHint(skipped))
	}

	gen := buildGen(cfg, req, ver)

	if req.Template != "" {
		tmpl, err := resolveTemplate(ctx, f, req.Template)
		if err != nil {
			return nil, nil, err
		}
		result, err := generator.GenerateSingboxTemplate(ctx, nodes, cfg, tmpl, gen)
		if err != nil {
			// A template the user supplied failed to render: their file, their
			// fix, not an upstream outage.
			if errors.Is(err, generator.ErrTemplateInvalid) {
				return nil, nil, badRequest("%s", err)
			}
			return nil, nil, renderError(err)
		}
		return result.Output, diagnosticsFor(result, skipped, userinfo), nil
	}

	result, err := render(ctx, name, nodes, cfg, f, gen)
	if err != nil {
		// The subscription parsed fine; this target just cannot encode any of
		// it. That is the same user-facing situation as an empty subscription.
		if errors.Is(err, generator.ErrTargetNodes) {
			return nil, nil, fmt.Errorf("%w: %s", ErrNoNodes, err)
		}
		return nil, nil, renderError(err)
	}
	return result.Output, diagnosticsFor(result, skipped, userinfo), nil
}

// stillInvalid drops remark entries that a request-level &include= / &exclude=
// replaces, so an unused broken entry does not reject the request.
func stillInvalid(invalid []string, req Request) []string {
	out := make([]string, 0, len(invalid))
	for _, entry := range invalid {
		if req.IncludeRemarks != nil && strings.HasPrefix(entry, "include_remarks=") {
			continue
		}
		if req.ExcludeRemarks != nil && strings.HasPrefix(entry, "exclude_remarks=") {
			continue
		}
		out = append(out, entry)
	}
	return out
}

// buildGen resolves the per-request generator options against the external
// config: declared target version, rename rules, remarks filters and emoji
// rules. The provider path uses it too, so local share-link nodes get the same
// treatment as inlined subscription nodes.
func buildGen(cfg *extconfig.Config, req Request, ver *generator.Version) generator.Options {
	gen := req.Gen
	gen.TargetVersion = ver
	gen.RenameRules = generator.CompileRenameRules(cfg.RenameRules)
	// Per-request &include= / &exclude= override the external config's
	// include_remarks / exclude_remarks (original subconverter semantics).
	if req.IncludeRemarks != nil {
		cfg.IncludeRemarks = req.IncludeRemarks
	}
	if req.ExcludeRemarks != nil {
		cfg.ExcludeRemarks = req.ExcludeRemarks
	}
	gen.RemoveEmoji, gen.AddEmoji = resolveEmoji(cfg, req)
	if gen.AddEmoji {
		if len(cfg.EmojiRules) > 0 {
			gen.EmojiRules = emoji.ParseRules(cfg.EmojiRules)
		} else {
			gen.EmojiRules = emoji.Default()
		}
	}
	return gen
}

// diagnosticsFor assembles the Diagnostics returned alongside a rendered config,
// shared by the regular and template render paths.
func diagnosticsFor(result *generator.Result, skipped []string, userinfo string) *Diagnostics {
	return &Diagnostics{
		NodeCount:            result.NodeCount,
		SkippedLines:         skipped,
		EmptyGroups:          result.EmptyGroups,
		SkippedRules:         result.SkippedRules,
		SkippedNodes:         result.SkippedNodes,
		Duplicates:           result.Duplicates,
		Deprecated:           result.DeprecatedDropped,
		Filtered:             result.Filtered,
		ExcludedProtocols:    result.ExcludedProtocols,
		ContentType:          result.ContentType,
		SubscriptionUserinfo: userinfo,
	}
}

// resolveTemplate loads the &template= value. It must be an http(s) URL that
// returns a sing-box JSON template; there is no built-in template name.
func resolveTemplate(ctx context.Context, f Fetcher, spec string) ([]byte, error) {
	spec = strings.TrimSpace(spec)
	if !strings.HasPrefix(spec, "http://") && !strings.HasPrefix(spec, "https://") {
		return nil, badRequest("template %q must be an http(s) URL to a sing-box JSON template", spec)
	}
	return f.Get(ctx, spec)
}

// resolveEmoji decides remove/add emoji flags using subconverter's precedence:
// global default (both true) < external config < URL add_emoji/remove_emoji <
// the `emoji` shortcut (which sets add_emoji and forces remove_emoji=true).
func resolveEmoji(cfg *extconfig.Config, req Request) (remove, add bool) {
	add, remove = true, true // subconverter global defaults

	if cfg.AddEmoji != nil {
		add = *cfg.AddEmoji
	}
	if cfg.RemoveOldEmoji != nil {
		remove = *cfg.RemoveOldEmoji
	}
	if req.AddEmoji != nil {
		add = *req.AddEmoji
	}
	if req.RemoveEmoji != nil {
		remove = *req.RemoveEmoji
	}
	if req.Emoji != nil {
		add = *req.Emoji
		remove = true
	}
	return remove, add
}

// skippedHint returns a short ": <snippet>" describing the first unparsed line,
// or "" when there is nothing to show. It helps distinguish a region-blocked /
// UA-rejected notice page from a genuinely empty subscription. The snippet is
// truncated and whitespace-collapsed so it stays on one line in logs and the
// HTTP hint.
func skippedHint(skipped []string) string {
	for _, line := range skipped {
		s := strings.TrimSpace(line)
		if s == "" {
			continue
		}
		s = strings.Join(strings.Fields(s), " ")
		const max = 200
		if len(s) > max {
			s = s[:max] + "…"
		}
		return ": first skipped line: " + s
	}
	return ""
}

// splitSource separates a subconverter tag:<name>,<link> source entry. A source
// without the prefix keeps an empty group.
func splitSource(raw string) (group, link string) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(raw), "tag:")
	if !ok {
		return "", raw
	}
	if i := strings.Index(rest, ","); i >= 0 {
		return strings.TrimSpace(rest[:i]), strings.TrimSpace(rest[i+1:])
	}
	return "", raw
}

// fetchAndParseAll fetches every subscription concurrently and concatenates the
// parsed nodes, preserving subscription order. It also returns the
// Subscription-Userinfo header captured from the FIRST subscription URL. idFor
// assigns each source's GroupID (url= counts up, insert_url counts down).
func fetchAndParseAll(ctx context.Context, f Fetcher, urls []string, idFor func(i int) int) ([]*proxy.Proxy, []string, string, error) {
	type out struct {
		nodes    []*proxy.Proxy
		skipped  []string
		userinfo string
		group    string
		err      error
	}
	results := make([]out, len(urls))
	var wg sync.WaitGroup
	for i, u := range urls {
		group, link := splitSource(u)
		wg.Add(1)
		go func(i int, link, group string) {
			defer wg.Done()
			// A raw share link (vless://, ss://, …) is node content, not a URL
			// to fetch: parse it inline. The &url= param and the CLI --url flag
			// both accept node links directly, so a single node can be
			// converted without a subscription.
			if parser.IsShareLink(link) {
				nodes, skipped, err := parser.Parse([]byte(link))
				results[i] = out{nodes: nodes, skipped: skipped, group: group, err: err}
				return
			}
			data, hdr, err := getWithMeta(ctx, f, link)
			if err != nil {
				results[i].err = err
				return
			}
			nodes, skipped, err := parser.Parse(data)
			results[i] = out{
				nodes:    nodes,
				skipped:  skipped,
				userinfo: hdr.Get("Subscription-Userinfo"),
				group:    group,
				err:      err,
			}
		}(i, link, group)
	}
	wg.Wait()

	var allNodes []*proxy.Proxy
	var allSkipped []string
	for i, r := range results {
		if r.err != nil {
			return nil, nil, "", fmt.Errorf("subscription %d: %w", i+1, r.err)
		}
		for _, n := range r.nodes {
			n.GroupID = idFor(i)
			n.Group = r.group
		}
		allNodes = append(allNodes, r.nodes...)
		allSkipped = append(allSkipped, r.skipped...)
	}
	// Userinfo comes from the first subscription URL only.
	userinfo := ""
	if len(results) > 0 {
		userinfo = results[0].userinfo
	}
	return allNodes, allSkipped, userinfo, nil
}
