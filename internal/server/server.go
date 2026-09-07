// Package server exposes the subconverter-compatible HTTP API. The MVP serves
// GET /sub?target=clash&url=...&config=..., mirroring tindy2013/subconverter's
// query interface so existing clients keep working unchanged.
package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Jungley8/subconverter-ng/internal/config"
	"github.com/Jungley8/subconverter-ng/internal/convert"
	"github.com/Jungley8/subconverter-ng/internal/fetch"
	"github.com/Jungley8/subconverter-ng/internal/generator"
	"github.com/Jungley8/subconverter-ng/internal/ratelimit"
	"github.com/Jungley8/subconverter-ng/internal/web"
)

// Server wires the HTTP handlers to the application config.
type Server struct {
	cfg     *config.Config
	version string       // build version, surfaced by GET /version; "dev" when unset
	cache   *fetch.Cache // shared across requests so the TTL cache survives; nil when caching disabled
	now     func() time.Time

	profilesMu sync.RWMutex
	profiles   map[string]config.AccessProfile
}

func New(cfg *config.Config) *Server {
	s := &Server{
		cfg: cfg, version: "dev", now: time.Now,
		profiles: make(map[string]config.AccessProfile),
	}
	// A shared cache lives on the Server so repeated /sub requests reuse cached
	// ruleset/subscription fetches. CacheTTL < 0 disables caching entirely.
	if cfg.Fetch.CacheTTL >= 0 {
		ttl := cfg.Fetch.CacheTTL // 0 => NewCache applies the default
		s.cache = fetch.NewCache(ttl)
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

// Handler returns the root mux. Rate limiting is applied only to /sub, the
// expensive endpoint that triggers upstream fetches; /version and the web UI
// are left unthrottled.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/sub", s.rateLimit(http.HandlerFunc(s.handleSub)))
	mux.Handle("/access/create", s.rateLimit(http.HandlerFunc(s.handleCreateAccess)))
	mux.HandleFunc("/flushcache", s.handleFlushCache)
	mux.HandleFunc("/version", s.handleVersion)
	mux.Handle("/", web.Handler())
	return logging(mux)
}

// rateLimit wraps next with per-client-IP token-bucket rate limiting. When the
// limiter is disabled in config it returns next unchanged (no-op pass-through).
func (s *Server) rateLimit(next http.Handler) http.Handler {
	rl := s.cfg.RateLimit
	if !rl.Enabled {
		return next
	}
	limiter := ratelimit.New(rl.RequestsPerMinute, rl.Burst)
	// Retry-After advertises the worst-case wait for one token to refill.
	retryAfter := "1"
	if rl.RequestsPerMinute > 0 {
		if secs := 60 / rl.RequestsPerMinute; secs > 1 {
			retryAfter = strconv.Itoa(secs)
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow(clientIP(r)) {
			w.Header().Set("Retry-After", retryAfter)
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP derives the originating client IP, honouring reverse-proxy headers
// (the service runs behind Cloudflare / nginx). X-Forwarded-For's first hop
// wins, then X-Real-IP, falling back to the connection's RemoteAddr host.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
		if first != "" {
			return first
		}
	}
	if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
		return xrip
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// handleFlushCache clears the shared fetch cache.
func (s *Server) handleFlushCache(w http.ResponseWriter, r *http.Request) {
	if s.cache != nil {
		s.cache.Flush()
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("cache flushed\n"))
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("subconverter-ng " + s.version + "\n"))
}

func (s *Server) handleSub(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	target := q.Get("target")
	if target == "" {
		target = "clash"
	}
	rawURL := q.Get("url")
	configURL := q.Get("config")
	proxyURL := firstNonEmpty(q.Get("proxy"), s.cfg.Fetch.Proxy)
	noCache := boolParam(q.Get("nocache"), false)
	var accessProfile *config.AccessProfile
	if s.cfg.Access.Enabled || q.Get("token") != "" {
		p := s.findAccessProfile(q.Get("token"))
		if p == nil {
			http.Error(w, "missing or invalid subscription token", http.StatusUnauthorized)
			return
		}
		if !p.Enabled || !s.now().Before(p.ExpiresAt.Time) {
			if convert.NormalizeTarget(target) == "clash" {
				expiry := p.ExpiresAt.Unix()
				if now := s.now().Unix(); now < expiry || !p.Enabled {
					expiry = now
				}
				writeExpiredClash(w, expiry)
			} else {
				http.Error(w, "subscription expired or revoked", http.StatusGone)
			}
			return
		}
		for _, blocked := range []string{"url", "config", "proxy", "nocache", "flushcache"} {
			if q.Has(blocked) {
				http.Error(w, "parameter not allowed for managed subscriptions: "+blocked, http.StatusBadRequest)
				return
			}
		}
		accessProfile = p
		rawURL = strings.Join(p.URLs, "|")
		configURL = p.ConfigURL
		proxyURL = s.cfg.Fetch.Proxy
		noCache = false
	}
	if rawURL == "" {
		http.Error(w, "missing required parameter: url", http.StatusBadRequest)
		return
	}

	// &flushcache=1 clears the whole shared cache before serving this request.
	if boolParam(q.Get("flushcache"), false) && s.cache != nil {
		s.cache.Flush()
	}

	// Build a fetch client, allowing a per-request &proxy= override of the
	// configured upstream proxy. The shared cache is injected so cached
	// ruleset/subscription fetches persist across requests (keyed by URL only;
	// per-request proxy differences are intentionally ignored).
	opts := fetch.Options{
		UserAgent:       s.cfg.Fetch.UserAgent,
		Proxy:           proxyURL,
		FlareSolverrURL: s.cfg.Fetch.FlareSolverrURL,
		Timeout:         s.cfg.Fetch.Timeout,
	}
	if noCache || s.cache == nil {
		opts.CacheTTL = -1 // disable caching for this request
	} else {
		opts.Cache = s.cache
		opts.CacheTTL = s.cfg.Fetch.CacheTTL
	}
	client, err := fetch.New(opts)
	if err != nil {
		http.Error(w, "fetch client: "+err.Error(), http.StatusInternalServerError)
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
		ConfigURL:     configURL,
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
		},
		// Emoji tribools (nil when the param is absent) resolved in convert.
		Emoji:       boolTri(q.Get("emoji")),
		AddEmoji:    boolTri(q.Get("add_emoji")),
		RemoveEmoji: boolTri(q.Get("remove_emoji")),
		NoCache:     noCache,
	}

	// `insert` is handled above (insert_url). `new_name` is accepted for
	// compatibility but has no effect: our node naming is already the "new" style.

	out, diag, err := convert.Run(r.Context(), client, req)
	if err != nil {
		log.Printf("convert error: %v", err)
		// Never respond with a 5xx here: Cloudflare (and similar proxies)
		// replace origin 502/504 with their own error page, so the real cause
		// never reaches the user. Return 200 with a readable plain-text hint
		// instead — the subscription client surfaces the message verbatim.
		writeUserError(w, err)
		return
	}
	log.Printf("converted (%s): %d nodes, %d unparsed lines, %d dup, %d deprecated, %d nodes unsupported by target, empty groups: %v, %d rules dropped (unsupported type)",
		convert.NormalizeTarget(target), diag.NodeCount, len(diag.SkippedLines), diag.Duplicates, diag.Deprecated, len(diag.SkippedNodes), diag.EmptyGroups, len(diag.SkippedRules))
	if len(diag.SkippedRules) > 0 {
		log.Printf("dropped rules (unsupported type): %v", diag.SkippedRules)
	}
	if len(diag.SkippedNodes) > 0 {
		log.Printf("nodes unsupported by target %q: %v", target, diag.SkippedNodes)
	}

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
	userinfo := diag.SubscriptionUserinfo
	if accessProfile != nil {
		userinfo = withExpiry(userinfo, accessProfile.ExpiresAt.Unix())
	}
	if userinfo != "" {
		w.Header().Set("Subscription-Userinfo", userinfo)
	}
	w.Write(out)
}

func (s *Server) findAccessProfile(token string) *config.AccessProfile {
	if token == "" {
		return nil
	}
	if s.cfg.Access.Enabled {
		for i := range s.cfg.Access.Profiles {
			if subtle.ConstantTimeCompare([]byte(s.cfg.Access.Profiles[i].Token), []byte(token)) == 1 {
				return &s.cfg.Access.Profiles[i]
			}
		}
	}
	s.profilesMu.RLock()
	p, ok := s.profiles[token]
	s.profilesMu.RUnlock()
	if ok {
		return &p
	}
	return nil
}

type createAccessRequest struct {
	URLs      []string `json:"urls"`
	ConfigURL string   `json:"config_url"`
	ExpiresAt string   `json:"expires_at"`
}

type createAccessResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	Path      string `json:"path"`
}

// handleCreateAccess creates an in-memory managed profile for the web UI.
// This endpoint intentionally has no administrator authentication yet; callers
// should disable public access to it at their reverse proxy if needed.
func (s *Server) handleCreateAccess(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req createAccessRequest
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON request", http.StatusBadRequest)
		return
	}
	if len(req.URLs) == 0 {
		http.Error(w, "at least one subscription URL is required", http.StatusBadRequest)
		return
	}
	for _, u := range req.URLs {
		if strings.TrimSpace(u) == "" {
			http.Error(w, "subscription URLs cannot be empty", http.StatusBadRequest)
			return
		}
	}
	expires, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		http.Error(w, "expires_at must be RFC3339 with a timezone", http.StatusBadRequest)
		return
	}
	if !s.now().Before(expires) {
		http.Error(w, "expires_at must be in the future", http.StatusBadRequest)
		return
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		http.Error(w, "could not generate access token", http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(tokenBytes)
	profile := config.AccessProfile{
		Name: "web-generated", Token: token, Enabled: true,
		ExpiresAt: config.ExpiryTime{Time: expires},
		URLs:      append([]string(nil), req.URLs...),
		ConfigURL: req.ConfigURL,
	}
	s.profilesMu.Lock()
	s.profiles[token] = profile
	s.profilesMu.Unlock()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createAccessResponse{
		Token: token, ExpiresAt: expires.Format(time.RFC3339),
		Path: "/sub?token=" + token,
	})
}

// withExpiry preserves upstream traffic fields while replacing any existing
// expire field with the managed profile's authoritative expiry timestamp.
func withExpiry(userinfo string, unix int64) string {
	parts := strings.Split(userinfo, ";")
	out := make([]string, 0, len(parts)+1)
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, _, _ := strings.Cut(part, "=")
		if strings.EqualFold(strings.TrimSpace(key), "expire") {
			continue
		}
		out = append(out, part)
	}
	out = append(out, "expire="+strconv.FormatInt(unix, 10))
	return strings.Join(out, "; ")
}

// writeExpiredClash returns a valid replacement profile with no proxy nodes.
// Clients that refresh successfully can replace their cached subscription
// instead of retaining the last good profile after an HTTP error.
func writeExpiredClash(w http.ResponseWriter, unix int64) {
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Profile-Update-Interval", "1")
	w.Header().Set("Subscription-Userinfo", "expire="+strconv.FormatInt(unix, 10))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("mode: rule\nproxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n"))
}

// writeUserError renders a conversion failure as a 200 plain-text hint rather
// than a 5xx status. A 502/504 would be swallowed by Cloudflare's own error
// page, hiding the real cause from the user; a 200 body reaches the client
// intact. The message is prefixed with "#" so a client that still tries to
// parse it as a config sees only comment lines.
func writeUserError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if errors.Is(err, convert.ErrNoNodes) {
		fmt.Fprintf(w, "# subconverter-ng: %s\n# 订阅无可用节点，请检查订阅链接或订阅内容是否有效。\n", err.Error())
		return
	}
	fmt.Fprintf(w, "# subconverter-ng: 转换失败 / conversion failed\n# %s\n", err.Error())
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

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}
