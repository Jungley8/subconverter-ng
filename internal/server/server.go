// Package server exposes the subconverter-compatible HTTP API. The MVP serves
// GET /sub?target=clash&url=...&config=..., mirroring tindy2013/subconverter's
// query interface so existing clients keep working unchanged.
package server

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Jungley8/subconverter-ng/internal/config"
	"github.com/Jungley8/subconverter-ng/internal/convert"
	"github.com/Jungley8/subconverter-ng/internal/fetch"
	"github.com/Jungley8/subconverter-ng/internal/generator"
	"github.com/Jungley8/subconverter-ng/internal/web"
)

// Server wires the HTTP handlers to the application config.
type Server struct {
	cfg *config.Config
}

func New(cfg *config.Config) *Server { return &Server{cfg: cfg} }

// Handler returns the root mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/sub", s.handleSub)
	mux.HandleFunc("/version", s.handleVersion)
	mux.Handle("/", web.Handler())
	return logging(mux)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("subconverter-ng (MVP)\n"))
}

func (s *Server) handleSub(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	target := q.Get("target")
	if target == "" {
		target = "clash"
	}
	rawURL := q.Get("url")
	if rawURL == "" {
		http.Error(w, "missing required parameter: url", http.StatusBadRequest)
		return
	}

	// Build a fetch client, allowing a per-request &proxy= override of the
	// configured upstream proxy.
	client, err := fetch.New(fetch.Options{
		UserAgent:       s.cfg.Fetch.UserAgent,
		Proxy:           firstNonEmpty(q.Get("proxy"), s.cfg.Fetch.Proxy),
		FlareSolverrURL: s.cfg.Fetch.FlareSolverrURL,
		Timeout:         s.cfg.Fetch.Timeout,
	})
	if err != nil {
		http.Error(w, "fetch client: "+err.Error(), http.StatusInternalServerError)
		return
	}

	req := convert.Request{
		Target:    target,
		SubURLs:   splitURLs(rawURL),
		ConfigURL: q.Get("config"),
		Gen: generator.Options{
			Sort:           boolParam(q.Get("sort"), false),
			UDP:            boolParam(q.Get("udp"), false),
			TFO:            boolParam(q.Get("tfo"), false),
			SkipCertVerify: boolParam(q.Get("scv"), false),
		},
		// Emoji tribools (nil when the param is absent) resolved in convert.
		Emoji:       boolTri(q.Get("emoji")),
		AddEmoji:    boolTri(q.Get("add_emoji")),
		RemoveEmoji: boolTri(q.Get("remove_emoji")),
	}

	out, diag, err := convert.Run(r.Context(), client, req)
	if err != nil {
		log.Printf("convert error: %v", err)
		http.Error(w, "conversion failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	log.Printf("converted: %d nodes, %d unparsed lines, empty groups: %v, %d rules dropped (unsupported type)",
		diag.NodeCount, len(diag.SkippedLines), diag.EmptyGroups, len(diag.SkippedRules))
	if len(diag.SkippedRules) > 0 {
		log.Printf("dropped rules (unsupported type): %v", diag.SkippedRules)
	}

	// Clash clients expect YAML; this content type matches subconverter.
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Profile-Update-Interval", "24")
	w.Write(out)
}

// splitURLs splits the &url= value on the "|" multi-subscription separator.
func splitURLs(raw string) []string {
	var out []string
	for _, u := range strings.Split(raw, "|") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

// boolTri parses an optional boolean query param into a tribool: nil when the
// param is absent/unrecognised, else a pointer to the parsed value.
func boolTri(v string) *bool {
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

func boolParam(v string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	}
	return def
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}
