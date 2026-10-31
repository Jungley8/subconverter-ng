// Command subconverter-ng is a Go reimplementation of subconverter focused on
// modern proxy protocols. It runs either as an HTTP service (drop-in for the
// subconverter /sub API) or as a one-shot CLI converter.
//
//	subconverter-ng serve   [--config app.yaml] [--listen :25500]
//	subconverter-ng convert  --url <sub-url> [--config <ini-url>] [-o out.yaml]
//
// License: GPL-3.0-or-later.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Jungley8/subconverter-ng/internal/config"
	"github.com/Jungley8/subconverter-ng/internal/convert"
	"github.com/Jungley8/subconverter-ng/internal/fetch"
	"github.com/Jungley8/subconverter-ng/internal/generator"
	"github.com/Jungley8/subconverter-ng/internal/server"
)

// newHTTPServer constructs the HTTP server with conservative timeouts.
func newHTTPServer(cfg *config.Config) *http.Server {
	return &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.New(cfg).WithVersion(version).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// Conversions fan out to remote fetches (subscription + rulesets), so
		// the write timeout is generous.
		WriteTimeout: 4 * time.Minute,
	}
}

// version is injected at build time via -ldflags "-X main.version=..."
// (see .goreleaser.yaml). Defaults to "dev" for local builds.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		cmdServe(os.Args[2:])
	case "convert":
		cmdConvert(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("subconverter-ng", version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `subconverter-ng %s — modern subscription converter

Usage:
  subconverter-ng serve   [--config app.yaml] [--listen :25500]
  subconverter-ng convert  --url <sub-url> [--config <ini-url>] [flags]

Run "subconverter-ng serve -h" or "convert -h" for flags.
`, version)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to app config YAML (optional)")
	listen := fs.String("listen", "", "listen address (overrides config), e.g. :25500")
	if err := fs.Parse(args); err != nil {
		fatal("parse flags: %v", err)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("load config: %v", err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if err := cfg.Validate(); err != nil {
		fatal("invalid config: %v", err)
	}

	srv := newHTTPServer(cfg)
	fmt.Printf("subconverter-ng %s\n", version)
	fmt.Print(cfg.Summary()) // effective config, secrets redacted
	slog.Info("starting server", "addr", cfg.Listen, "version", version)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		fatal("server: %v", err)
	case sig := <-stop:
		slog.Info("shutting down server", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			slog.Error("server shutdown error", "error", err)
		} else {
			slog.Info("server stopped gracefully")
		}
	}
}

// cliFetcher wraps a remote Fetcher to support reading local files and stdin ('-') for CLI commands.
type cliFetcher struct {
	remote    convert.Fetcher
	stdinData []byte
	stdinRead bool
}

var _ convert.Fetcher = (*cliFetcher)(nil)
var _ convert.MetaFetcher = (*cliFetcher)(nil)

func newCLIFetcher(remote convert.Fetcher) *cliFetcher {
	return &cliFetcher{remote: remote}
}

func (f *cliFetcher) Get(ctx context.Context, target string) ([]byte, error) {
	data, _, err := f.GetWithMeta(ctx, target)
	return data, err
}

func (f *cliFetcher) GetWithMeta(ctx context.Context, target string) ([]byte, http.Header, error) {
	target = strings.TrimSpace(target)
	if target == "-" {
		if !f.stdinRead {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				return nil, nil, fmt.Errorf("read stdin: %w", err)
			}
			f.stdinData = data
			f.stdinRead = true
		}
		return f.stdinData, nil, nil
	}

	if strings.HasPrefix(target, "file://") {
		path := strings.TrimPrefix(target, "file://")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("read file %s: %w", path, err)
		}
		return data, nil, nil
	}

	// If target is not a URL, treat it as a local file path
	isURL := strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://")
	if !isURL {
		data, err := os.ReadFile(target)
		if err != nil {
			return nil, nil, fmt.Errorf("read file %s: %w", target, err)
		}
		return data, nil, nil
	}

	if mf, ok := f.remote.(convert.MetaFetcher); ok {
		return mf.GetWithMeta(ctx, target)
	}
	body, err := f.remote.Get(ctx, target)
	return body, nil, err
}

func cmdConvert(args []string) {
	fs := flag.NewFlagSet("convert", flag.ExitOnError)
	url := fs.String("url", "", "subscription URL(s), file path, or '-' for stdin, '|'-separated (required)")
	cfgURL := fs.String("config", "", "external INI config URL, file path, or '-' for stdin")
	target := fs.String("target", "clash", "output target: clash|singbox|surge|shadowrocket|quanx|loon|v2ray")
	out := fs.String("o", "", "output file (default: stdout)")
	proxy := fs.String("proxy", "", "upstream proxy URL (http/socks5)")
	flaresolverr := fs.String("flaresolverr", "", "FlareSolverr endpoint, e.g. http://127.0.0.1:8191/v1")
	ua := fs.String("ua", "", "User-Agent for fetches")
	sortNodes := fs.Bool("sort", false, "sort nodes by name")
	udp := fs.Bool("udp", false, "force udp on all nodes")
	tfo := fs.Bool("tfo", false, "enable tcp-fast-open")
	scv := fs.Bool("scv", false, "skip-cert-verify")
	emoji := fs.String("emoji", "", "emoji shortcut (true=normalize, false=strip); empty=default")
	addEmoji := fs.String("add-emoji", "", "add flag emoji by rules (true/false); empty=default")
	removeEmoji := fs.String("remove-emoji", "", "remove existing emoji (true/false); empty=default")
	expand := fs.Bool("expand", true, "inline rules (true) or emit rule-providers (false)")
	dedup := fs.Bool("dedup", false, "remove duplicate nodes")
	fdn := fs.Bool("fdn", false, "filter nodes Clash.Meta cannot use")
	list := fs.Bool("list", false, "output only the node list (no groups/rules)")
	appendType := fs.Bool("append-type", false, "prepend [TYPE] to node names")
	tailscale := fs.Bool("tailscale", false, "prepend Tailscale DIRECT rules (100.64.0.0/10, fd7a:115c:a1e0::/48)")
	insert := fs.String("insert", "", "insert_url: extra node source URL(s), '|'-separated, merged into the output")
	insertPrepend := fs.Bool("insert-prepend", true, "place inserted nodes before subscription nodes")
	var excludeProtocols stringsFlag
	fs.Var(&excludeProtocols, "exclude-protocol", "exclude nodes by protocol or type (e.g. hysteria2, tuic)")
	fs.Var(&excludeProtocols, "exclude-protocols", "alias for --exclude-protocol")
	fs.Var(&excludeProtocols, "exclude-type", "alias for --exclude-protocol")
	fs.Var(&excludeProtocols, "exclude-types", "alias for --exclude-protocol")
	fs.Var(&excludeProtocols, "filter-protocol", "alias for --exclude-protocol")
	fs.Var(&excludeProtocols, "filter-protocols", "alias for --exclude-protocol")
	fs.Var(&excludeProtocols, "filter-type", "alias for --exclude-protocol")
	fs.Var(&excludeProtocols, "filter-types", "alias for --exclude-protocol")
	timeout := fs.Duration("timeout", 30*time.Second, "per-fetch timeout")
	cacheTTL := fs.Duration("cache-ttl", 0, "TTL for the in-memory fetch cache (0=default 300s, negative=disabled)")
	if err := fs.Parse(args); err != nil {
		fatal("parse flags: %v", err)
	}

	if *url == "" {
		fatal("--url is required")
	}

	remoteClient, err := fetch.New(fetch.Options{
		UserAgent:       *ua,
		Proxy:           *proxy,
		FlareSolverrURL: *flaresolverr,
		Timeout:         *timeout,
		CacheTTL:        *cacheTTL,
	})
	if err != nil {
		fatal("fetch client: %v", config.RedactError(err))
	}

	client := newCLIFetcher(remoteClient)

	req := convert.Request{
		Target:        *target,
		SubURLs:       splitPipe(*url),
		ConfigURL:     *cfgURL,
		InsertURLs:    splitPipe(*insert),
		InsertPrepend: *insertPrepend,
		Gen: generator.Options{
			Sort: *sortNodes, UDP: *udp, TFO: *tfo, SkipCertVerify: *scv,
			UseRuleProviders: !*expand,
			Dedup:            *dedup,
			FilterDeprecated: *fdn,
			AppendType:       *appendType,
			ListOnly:         *list,
			Tailscale:        *tailscale,
			ExcludeProtocols: generator.ParseProtocols(excludeProtocols...),
		},
		Emoji:       triFromString(*emoji),
		AddEmoji:    triFromString(*addEmoji),
		RemoveEmoji: triFromString(*removeEmoji),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	data, diag, err := convert.Run(ctx, client, req)
	if err != nil {
		fatal("convert: %v", config.RedactError(err))
	}
	fmt.Fprintf(os.Stderr, "ok: %d nodes, %d unparsed lines, %d dup, %d deprecated, %d excluded by protocol, %d nodes unsupported by target, %d empty groups, %d rules dropped (unsupported type)\n",
		diag.NodeCount, len(diag.SkippedLines), diag.Duplicates, diag.Deprecated, diag.ExcludedProtocols, len(diag.SkippedNodes), len(diag.EmptyGroups), len(diag.SkippedRules))
	for _, r := range diag.SkippedRules {
		fmt.Fprintf(os.Stderr, "  dropped rule (unsupported type): %s\n", r)
	}
	for _, n := range diag.SkippedNodes {
		fmt.Fprintf(os.Stderr, "  node unsupported by target: %s\n", n)
	}

	if *out == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			fatal("write stdout: %v", err)
		}
		return
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fatal("write %s: %v", *out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
}

// triFromString parses an optional bool flag into a tribool (nil when empty).
func triFromString(v string) *bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		b := true
		return &b
	case "false", "0", "no", "off":
		b := false
		return &b
	}
	return nil
}

func splitPipe(raw string) []string {
	var out []string
	for _, u := range strings.Split(raw, "|") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}

type stringsFlag []string

func (s *stringsFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringsFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}
