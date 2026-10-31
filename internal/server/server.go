// Package server exposes the subconverter-compatible HTTP API. The MVP serves
// GET /sub?target=clash&url=...&config=..., mirroring tindy2013/subconverter's
// query interface so existing clients keep working unchanged.
package server

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Jungley8/subconverter-ng/internal/config"
	"github.com/Jungley8/subconverter-ng/internal/convert"
	"github.com/Jungley8/subconverter-ng/internal/fetch"
	"github.com/Jungley8/subconverter-ng/internal/generator"
	"github.com/Jungley8/subconverter-ng/internal/ratelimit"
	"github.com/Jungley8/subconverter-ng/internal/web"
	"golang.org/x/sync/singleflight"
)

// Server wires the HTTP handlers to the application config.
type Server struct {
	cfg          *config.Config
	version      string              // build version, surfaced by GET /version; "dev" when unset
	cache        *fetch.Cache        // shared across requests so the TTL cache survives; nil when caching disabled
	group        *singleflight.Group // shared singleflight request deduplicator across requests
	limiter      *ratelimit.Limiter  // shared per-IP rate limiter across endpoints; nil when disabled
	trustedCIDRs []netip.Prefix
	trustedIPs   []netip.Addr
}

func New(cfg *config.Config) *Server {
	s := &Server{
		cfg:     cfg,
		version: "dev",
		group:   new(singleflight.Group),
	}
	if cfg.RateLimit.Enabled {
		s.limiter = ratelimit.New(cfg.RateLimit.RequestsPerMinute, cfg.RateLimit.Burst)
	}
	// A shared cache lives on the Server so repeated /sub requests reuse cached
	// ruleset/subscription fetches. CacheTTL < 0 disables caching entirely.
	if cfg.Fetch.CacheTTL >= 0 {
		ttl := cfg.Fetch.CacheTTL // 0 => NewCache applies the default
		s.cache = fetch.NewCache(ttl)
	}
	for _, raw := range cfg.RateLimit.TrustedProxies {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			s.trustedCIDRs = append(s.trustedCIDRs, prefix)
		} else if addr, err := netip.ParseAddr(raw); err == nil {
			s.trustedIPs = append(s.trustedIPs, addr)
		} else {
			// Fail-closed on invalid configuration per Pre-v1.0 architecture rules
			panic(fmt.Sprintf("server: invalid trusted_proxies entry %q", raw))
		}
	}
	return s
}

// WithVersion sets the build version reported by GET /version. Returns the
// receiver for chaining: server.New(cfg).WithVersion(v).Handler().
func (s *Server) WithVersion(v string) *Server {
	if v != "" {
		s.version = v
	}
	return s
}

// Handler returns the root mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/sub", s.authenticate(s.rateLimit(http.HandlerFunc(s.handleSub))))
	mux.Handle("/flushcache", s.authenticate(s.rateLimit(http.HandlerFunc(s.handleFlushCache))))
	mux.HandleFunc("/version", s.handleVersion)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.Handle("/", web.Handler())
	return s.logging(mux)
}

// authenticate checks optional API token authorization.
func (s *Server) authenticate(next http.Handler) http.Handler {
	if s.cfg.APIAccessToken == "" {
		return next
	}
	expected := []byte(s.cfg.APIAccessToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			if auth := r.Header.Get("Authorization"); auth != "" {
				if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
					token = strings.TrimSpace(auth[7:])
				} else {
					token = strings.TrimSpace(auth)
				}
			}
		}
		if token == "" {
			token = r.Header.Get("X-API-Token")
		}

		if token == "" || subtle.ConstantTimeCompare([]byte(token), expected) != 1 {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized: invalid or missing API token\n"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimit wraps next with per-client-IP token-bucket rate limiting. When the
// limiter is disabled in config it returns next unchanged (no-op pass-through).
func (s *Server) rateLimit(next http.Handler) http.Handler {
	if s.limiter == nil {
		return next
	}
	rl := s.cfg.RateLimit
	// Retry-After advertises the worst-case wait for one token to refill.
	retryAfter := "1"
	if rl.RequestsPerMinute > 0 {
		if secs := 60 / rl.RequestsPerMinute; secs > 1 {
			retryAfter = strconv.Itoa(secs)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.Allow(s.clientIP(r)) {
			w.Header().Set("Retry-After", retryAfter)
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isTrustedProxy reports whether host is within configured trusted reverse proxy IPs/subnets.
func (s *Server) isTrustedProxy(host string) bool {
	if len(s.trustedCIDRs) == 0 && len(s.trustedIPs) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, ip := range s.trustedIPs {
		if ip.Unmap() == addr {
			return true
		}
	}
	for _, cidr := range s.trustedCIDRs {
		if cidr.Contains(addr) {
			return true
		}
	}
	return false
}

// clientIP derives the originating client IP. Reverse-proxy headers (X-Forwarded-For,
// X-Real-IP) are honoured ONLY when the connection comes from a configured trusted proxy;
// otherwise the connection's direct remote host is used to prevent header spoofing.
func (s *Server) clientIP(r *http.Request) string {
	remoteHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteHost = r.RemoteAddr
	}

	if s.isTrustedProxy(remoteHost) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
			if first != "" {
				return first
			}
		}
		if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
			return xrip
		}
	}
	return remoteHost
}

// handleFlushCache clears the shared fetch cache.
func (s *Server) handleFlushCache(w http.ResponseWriter, r *http.Request) {
	if s.cache != nil {
		s.cache.Flush()
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("cache flushed\n"))
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("subconverter-ng " + s.version + "\n"))
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ready\n"))
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

	// &flushcache=1 clears the whole shared cache before serving this request.
	if boolParam(q.Get("flushcache"), false) && s.cache != nil {
		s.cache.Flush()
	}

	// &nocache=1 bypasses the cache for this request only. We do that by giving
	// this per-request client a disabled cache (CacheTTL < 0) instead of the
	// shared one.
	noCache := boolParam(q.Get("nocache"), false)

	// Build a fetch client, allowing a per-request &proxy= override of the
	// configured upstream proxy.
	userProxy := q.Get("proxy")
	if userProxy != "" && !s.cfg.Fetch.AllowPrivateIPs {
		if err := fetch.ValidateProxyURL(userProxy, false); err != nil {
			http.Error(w, "invalid proxy parameter: "+config.RedactString(err.Error()), http.StatusBadRequest)
			return
		}
	}

	opts := fetch.Options{
		UserAgent:       s.cfg.Fetch.UserAgent,
		Proxy:           firstNonEmpty(userProxy, s.cfg.Fetch.Proxy),
		TrustedProxy:    s.cfg.Fetch.Proxy,
		FlareSolverrURL: s.cfg.Fetch.FlareSolverrURL,
		Timeout:         s.cfg.Fetch.Timeout,
		AllowPrivateIPs: s.cfg.Fetch.AllowPrivateIPs,
		Group:           s.group,
	}
	if noCache || s.cache == nil {
		opts.CacheTTL = -1 // disable caching for this request
	} else {
		opts.Cache = s.cache
		opts.CacheTTL = s.cfg.Fetch.CacheTTL
	}
	client, err := fetch.New(opts)
	if err != nil {
		http.Error(w, "fetch client: "+config.RedactString(err.Error()), http.StatusBadRequest)
		return
	}

	// insert_url: the &insert= param overrides the server default
	// (cfg.Insert.Enabled). When enabled and the server has insert URLs
	// configured, they are merged into the conversion (prepended by default).
	var insertURLs []string
	if boolParam(q.Get("insert"), s.cfg.Insert.Enabled) {
		insertURLs = s.cfg.Insert.URLs
	}

	req := convert.Request{
		Target:        target,
		SubURLs:       splitURLs(rawURL),
		ConfigURL:     firstNonEmpty(q.Get("config"), s.cfg.DefaultConfigURL),
		InsertURLs:    insertURLs,
		InsertPrepend: s.cfg.Insert.Prepend,
		Gen: generator.Options{
			Sort:           boolParam(q.Get("sort"), false),
			UDP:            boolParam(q.Get("udp"), false),
			TFO:            boolParam(q.Get("tfo"), false),
			SkipCertVerify: boolParam(q.Get("scv"), false),
			// expand=true (default) inlines every rule; expand=false emits
			// rule-providers instead.
			UseRuleProviders: !boolParam(q.Get("expand"), true),
			Dedup:            boolParam(q.Get("dedup"), false),
			FilterDeprecated: boolParam(q.Get("fdn"), false),
			AppendType:       boolParam(q.Get("append_type"), false),
			ListOnly:         boolParam(q.Get("list"), false),
			Tailscale:        boolParam(q.Get("tailscale"), false),
			ExcludeProtocols: parseProtocolParams(q),
		},
		// Emoji tribools (nil when the param is absent) resolved in convert.
		Emoji:       boolTri(q.Get("emoji")),
		AddEmoji:    boolTri(q.Get("add_emoji")),
		RemoveEmoji: boolTri(q.Get("remove_emoji")),
		NoCache:     noCache,
	}

	out, diag, err := convert.Run(r.Context(), client, req)
	if err != nil {
		slog.Error("convert failed", "error", config.RedactString(err.Error()))
		writeUserError(w, err)
		return
	}
	slog.Info("converted subscription",
		"target", convert.NormalizeTarget(target),
		"nodes", diag.NodeCount,
		"unparsed_lines", len(diag.SkippedLines),
		"duplicates", diag.Duplicates,
		"deprecated", diag.Deprecated,
		"excluded_protocols", diag.ExcludedProtocols,
		"unsupported_nodes", len(diag.SkippedNodes),
		"empty_groups", len(diag.EmptyGroups),
		"dropped_rules", len(diag.SkippedRules),
	)

	// Content-Type varies by target (YAML for clash, JSON for sing-box, plain
	// text for surge/quanx/loon/v2ray). The generator reports the right one.
	contentType := diag.ContentType
	if contentType == "" {
		contentType = "text/yaml; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)

	// &interval=<hours> overrides the client's profile auto-update interval.
	updateInterval := "24"
	if iv := q.Get("interval"); iv != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(iv)); err == nil && n > 0 {
			updateInterval = strconv.Itoa(n)
		}
	}
	w.Header().Set("Profile-Update-Interval", updateInterval)

	// &filename=<name> sets the download filename clients save the profile as.
	if fn := strings.TrimSpace(q.Get("filename")); fn != "" {
		w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(fn)+"\"")
	}

	// Pass through the airport's traffic/expiry metadata so Clash clients can
	// display it.
	if diag.SubscriptionUserinfo != "" {
		w.Header().Set("Subscription-Userinfo", diag.SubscriptionUserinfo)
	}
	_, _ = w.Write(out)
}

// writeUserError renders a conversion failure with an appropriate HTTP error status
// (422 for unprocessable content such as no usable nodes, 502 for upstream fetch failure)
// along with plain-text comments detailing the cause with secrets redacted.
func writeUserError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	redactedMsg := config.RedactString(err.Error())
	if errors.Is(err, convert.ErrNoNodes) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = fmt.Fprintf(w, "# subconverter-ng: %s\n# 订阅无可用节点，请检查订阅链接或订阅内容是否有效。\n", redactedMsg)
		return
	}
	w.WriteHeader(http.StatusBadGateway)
	_, _ = fmt.Fprintf(w, "# subconverter-ng: 转换失败 / conversion failed\n# %s\n", redactedMsg)
}

// parseProtocolParams extracts excluded protocols from query parameters,
// supporting common aliases (&exclude_protocol=, &exclude_protocols=, &exclude_types=, etc.).
func parseProtocolParams(q url.Values) []string {
	keys := []string{
		"exclude_protocol", "exclude_protocols",
		"exclude-protocol", "exclude-protocols",
		"exclude_type", "exclude_types",
		"exclude-type", "exclude-types",
		"filter_protocol", "filter_protocols",
		"filter-protocol", "filter-protocols",
		"filter_type", "filter_types",
		"filter-type", "filter-types",
	}
	var raw []string
	for _, k := range keys {
		if vals, ok := q[k]; ok {
			raw = append(raw, vals...)
		}
	}
	return generator.ParseProtocols(raw...)
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

// sanitizeFilename strips characters that could break (or inject into) the
// Content-Disposition header.
func sanitizeFilename(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '"', '\\', '\r', '\n', '/':
			return -1
		}
		return r
	}, s)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		slog.Info("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"client_ip", s.clientIP(r),
		)
	})
}
