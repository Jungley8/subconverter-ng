// Package convert orchestrates a full conversion: fetch subscription(s) and the
// external config, parse nodes, then render the target output. It is shared by
// the HTTP server and the CLI so both behave identically.
package convert

import (
	"context"
	"fmt"
	"sync"

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

// Request describes one conversion.
type Request struct {
	Target    string   // currently only "clash"
	SubURLs   []string // subscription URLs (the &url= param, split on |)
	ConfigURL string   // external INI config (the &config= param)
	Gen       generator.Options
}

// Diagnostics captures non-fatal information about a conversion.
type Diagnostics struct {
	NodeCount    int
	SkippedLines []string // subscription lines that did not parse into a node
	EmptyGroups  []string // proxy-groups that matched no nodes (filled with DIRECT)
	SkippedRules []string // ruleset entries dropped for an unsupported rule type
}

// Run performs the conversion and returns the rendered config bytes.
func Run(ctx context.Context, f Fetcher, req Request) ([]byte, *Diagnostics, error) {
	if req.Target != "clash" {
		return nil, nil, fmt.Errorf("unsupported target %q (MVP supports: clash)", req.Target)
	}
	if len(req.SubURLs) == 0 {
		return nil, nil, fmt.Errorf("no subscription url provided")
	}

	nodes, skipped, err := fetchAndParseAll(ctx, f, req.SubURLs)
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

	result, err := generator.GenerateClash(ctx, nodes, cfg, f, req.Gen)
	if err != nil {
		return nil, nil, err
	}
	return result.YAML, &Diagnostics{
		NodeCount:    result.NodeCount,
		SkippedLines: skipped,
		EmptyGroups:  result.EmptyGroups,
		SkippedRules: result.SkippedRules,
	}, nil
}

// fetchAndParseAll fetches every subscription concurrently and concatenates the
// parsed nodes, preserving subscription order.
func fetchAndParseAll(ctx context.Context, f Fetcher, urls []string) ([]*proxy.Proxy, []string, error) {
	type out struct {
		nodes   []*proxy.Proxy
		skipped []string
		err     error
	}
	results := make([]out, len(urls))
	var wg sync.WaitGroup
	for i, u := range urls {
		wg.Add(1)
		go func(i int, u string) {
			defer wg.Done()
			data, err := f.Get(ctx, u)
			if err != nil {
				results[i].err = err
				return
			}
			nodes, skipped, err := parser.Parse(data)
			results[i] = out{nodes: nodes, skipped: skipped, err: err}
		}(i, u)
	}
	wg.Wait()

	var allNodes []*proxy.Proxy
	var allSkipped []string
	for i, r := range results {
		if r.err != nil {
			return nil, nil, fmt.Errorf("subscription %d: %w", i+1, r.err)
		}
		allNodes = append(allNodes, r.nodes...)
		allSkipped = append(allSkipped, r.skipped...)
	}
	return allNodes, allSkipped, nil
}
