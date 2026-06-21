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
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
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
		Handler:           server.New(cfg).Handler(),
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
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("load config: %v", err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}

	srv := newHTTPServer(cfg)
	fmt.Printf("subconverter-ng %s listening on %s\n", version, cfg.Listen)
	if cfg.Fetch.Proxy != "" {
		fmt.Printf("  upstream proxy: %s\n", cfg.Fetch.Proxy)
	}
	if cfg.Fetch.FlareSolverrURL != "" {
		fmt.Printf("  flaresolverr:   %s\n", cfg.Fetch.FlareSolverrURL)
	}
	if err := srv.ListenAndServe(); err != nil {
		fatal("server: %v", err)
	}
}

func cmdConvert(args []string) {
	fs := flag.NewFlagSet("convert", flag.ExitOnError)
	url := fs.String("url", "", "subscription URL(s), '|'-separated (required)")
	cfgURL := fs.String("config", "", "external INI config URL")
	target := fs.String("target", "clash", "output target (clash)")
	out := fs.String("o", "", "output file (default: stdout)")
	proxy := fs.String("proxy", "", "upstream proxy URL (http/socks5)")
	flaresolverr := fs.String("flaresolverr", "", "FlareSolverr endpoint, e.g. http://127.0.0.1:8191/v1")
	ua := fs.String("ua", "", "User-Agent for fetches")
	sortNodes := fs.Bool("sort", false, "sort nodes by name")
	udp := fs.Bool("udp", false, "force udp on all nodes")
	tfo := fs.Bool("tfo", false, "enable tcp-fast-open")
	scv := fs.Bool("scv", false, "skip-cert-verify")
	timeout := fs.Duration("timeout", 30*time.Second, "per-fetch timeout")
	fs.Parse(args)

	if *url == "" {
		fatal("--url is required")
	}

	client, err := fetch.New(fetch.Options{
		UserAgent:       *ua,
		Proxy:           *proxy,
		FlareSolverrURL: *flaresolverr,
		Timeout:         *timeout,
	})
	if err != nil {
		fatal("fetch client: %v", err)
	}

	req := convert.Request{
		Target:    *target,
		SubURLs:   splitPipe(*url),
		ConfigURL: *cfgURL,
		Gen: generator.Options{
			Sort: *sortNodes, UDP: *udp, TFO: *tfo, SkipCertVerify: *scv,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	data, diag, err := convert.Run(ctx, client, req)
	if err != nil {
		fatal("convert: %v", err)
	}
	fmt.Fprintf(os.Stderr, "ok: %d nodes, %d skipped lines, empty groups: %v\n",
		diag.NodeCount, len(diag.SkippedLines), diag.EmptyGroups)

	if *out == "" {
		os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fatal("write %s: %v", *out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
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
