// Package convert orchestrates a full conversion: fetch subscription(s) and the
// external config, parse nodes, then render the target output. It is shared by
// the HTTP server and the CLI so both behave identically.
package convert

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"github.com/Jungley8/subconverter-ng/internal/emoji"
	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/generator"
	"github.com/Jungley8/subconverter-ng/internal/parser"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

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
	Gen       generator.Options

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
}

// Diagnostics captures non-fatal information about a conversion.
type Diagnostics struct {
	NodeCount    int
	SkippedLines []string // subscription lines that did not parse into a node
	EmptyGroups  []string // proxy-groups that matched no nodes (filled with DIRECT)
	SkippedRules []string // ruleset entries dropped for an unsupported rule type

	// SubscriptionUserinfo is the airport's Subscription-Userinfo response
	// header from the FIRST subscription fetch (empty if absent). Clash clients
	// use it to display traffic/expiry.
	SubscriptionUserinfo string
}

// Run performs the conversion and returns the rendered config bytes.
func Run(ctx context.Context, f Fetcher, req Request) ([]byte, *Diagnostics, error) {
	if req.Target != "clash" {
		return nil, nil, fmt.Errorf("unsupported target %q (MVP supports: clash)", req.Target)
	}
	if len(req.SubURLs) == 0 {
		return nil, nil, fmt.Errorf("no subscription url provided")
	}

	nodes, skipped, userinfo, err := fetchAndParseAll(ctx, f, req.SubURLs)
	if err != nil {
		return nil, nil, err
	}
	if len(nodes) == 0 {
		return nil, nil, fmt.Errorf("no usable nodes parsed from subscription(s); %d lines skipped", len(skipped))
	}

	var cfg *extconfig.Config
	if req.ConfigURL != "" {
		data, err := f.Get(ctx, req.ConfigURL)
		if err != nil {
			return nil, nil, fmt.Errorf("fetch external config: %w", err)
		}
		cfg = extconfig.Parse(data)
	} else {
		cfg = &extconfig.Config{EnableRuleGenerator: true}
	}

	gen := req.Gen
	gen.RenameRules = generator.CompileRenameRules(cfg.RenameRules)
	gen.RemoveEmoji, gen.AddEmoji = resolveEmoji(cfg, req)
	if gen.AddEmoji {
		if len(cfg.EmojiRules) > 0 {
			gen.EmojiRules = emoji.ParseRules(cfg.EmojiRules)
		} else {
			gen.EmojiRules = emoji.Default()
		}
	}

	result, err := generator.GenerateClash(ctx, nodes, cfg, f, gen)
	if err != nil {
		return nil, nil, err
	}
	return result.YAML, &Diagnostics{
		NodeCount:            result.NodeCount,
		SkippedLines:         skipped,
		EmptyGroups:          result.EmptyGroups,
		SkippedRules:         result.SkippedRules,
		SubscriptionUserinfo: userinfo,
	}, nil
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

// fetchAndParseAll fetches every subscription concurrently and concatenates the
// parsed nodes, preserving subscription order. It also returns the
// Subscription-Userinfo header captured from the FIRST subscription URL.
func fetchAndParseAll(ctx context.Context, f Fetcher, urls []string) ([]*proxy.Proxy, []string, string, error) {
	type out struct {
		nodes    []*proxy.Proxy
		skipped  []string
		userinfo string
		err      error
	}
	results := make([]out, len(urls))
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			data, hdr, err := getWithMeta(ctx, f, u)
			if err != nil {
				results[i].err = err
				return
			}
			nodes, skipped, err := parser.Parse(data)
			results[i] = out{
				nodes:    nodes,
				skipped:  skipped,
				userinfo: hdr.Get("Subscription-Userinfo"),
				err:      err,
			}
		}(i, u)
	}
	wg.Wait()

	var allNodes []*proxy.Proxy
	var allSkipped []string
	for i, r := range results {
		if r.err != nil {
			return nil, nil, "", fmt.Errorf("subscription %d: %w", i+1, r.err)
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
