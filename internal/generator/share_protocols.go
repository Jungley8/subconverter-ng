package generator

import (
	"encoding/json"
	"net"
	"net/url"
	"strconv"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// shareSnell renders a snell:// link. The de facto form carries the PSK in the
// userinfo and obfs settings in the query. Absent version means 1, so it is
// omitted rather than written.
func shareSnell(n *proxy.Proxy) string {
	c := n.Clash
	q := url.Values{}
	if v := ci(c, "version"); v > 0 {
		q.Set("version", strconv.Itoa(v))
	}
	opts := cmap(c, "obfs-opts")
	if mode := cs(opts, "mode"); mode != "" {
		q.Set("obfs", mode)
	}
	if h := cs(opts, "host"); h != "" {
		q.Set("obfs-host", h)
	}
	if uri := firstNonEmptyStr(cs(opts, "uri"), cs(opts, "obfs-uri")); uri != "" {
		q.Set("obfs-uri", uri)
	}
	if uk := cs(c, "userkey"); uk != "" {
		q.Set("userkey", uk)
	}
	if cb(c, "reuse") {
		q.Set("reuse", "1")
	}
	if cb(c, "udp") {
		q.Set("udp", "1")
	}
	if mode := cs(c, "mode"); mode != "" {
		q.Set("mode", mode)
	}
	// The snell URI has no standard ShadowTLS keys. Keep the wrapper's secret
	// and version in the link under the parser's obfs-* names so the node
	// round-trips.
	if isShadowTLS(c) {
		if _, pass, version := shadowTLSOpts(c); pass != "" {
			q.Set("obfs-psk", pass)
			if version > 0 {
				q.Set("obfs-version", strconv.Itoa(version))
			}
		}
	}
	link := "snell://" + url.User(cs(c, "psk")).String() + "@" + hostPort(c)
	if enc := q.Encode(); enc != "" {
		link += "?" + enc
	}
	return link + "#" + encodeFragment(n.Name)
}

// shareSSH renders this project's ssh:// form (no official URI exists). The
// private key material travels in the query; the password in the userinfo.
func shareSSH(n *proxy.Proxy) string {
	c := n.Clash
	q := url.Values{}
	if v := cs(c, "private-key"); v != "" {
		q.Set("private-key", v)
	}
	if v := cs(c, "private-key-passphrase"); v != "" {
		q.Set("private-key-passphrase", v)
	}
	if v := joinAny(c["host-key"]); v != "" {
		q.Set("host-key", v)
	}
	if v := joinAny(c["host-key-algorithms"]); v != "" {
		q.Set("host-key-algorithms", v)
	}
	user, pw := cs(c, "username"), cs(c, "password")
	link := "ssh://"
	if user != "" || pw != "" {
		link += url.UserPassword(user, pw).String() + "@"
	}
	link += hostPort(c)
	if enc := q.Encode(); enc != "" {
		link += "?" + enc
	}
	return link + "#" + encodeFragment(n.Name)
}

// shareNaive renders naive+https:// or naive+quic://. The quic flag selects the
// scheme; insecure and alpn are HTTPS-only settings.
func shareNaive(n *proxy.Proxy) string {
	c := n.Clash
	q := url.Values{}
	if sni := cs(c, "sni"); sni != "" {
		q.Set("sni", sni)
	}
	scheme := "naive+https"
	if cb(c, "quic") {
		scheme = "naive+quic"
	} else {
		if cb(c, "skip-cert-verify") {
			q.Set("insecure", "1")
		}
		if alpn := joinAny(c["alpn"]); alpn != "" {
			q.Set("alpn", alpn)
		}
	}
	link := scheme + "://" + url.UserPassword(cs(c, "username"), cs(c, "password")).String() + "@" + hostPort(c)
	if enc := q.Encode(); enc != "" {
		link += "?" + enc
	}
	return link + "#" + encodeFragment(n.Name)
}

// shareAnyTLS renders an anytls:// link.
func shareAnyTLS(n *proxy.Proxy) string {
	c := n.Clash
	q := url.Values{}
	if sni := cs(c, "sni"); sni != "" {
		q.Set("sni", sni)
	}
	if cb(c, "skip-cert-verify") {
		q.Set("insecure", "1")
	}
	if alpn := joinAny(c["alpn"]); alpn != "" {
		q.Set("alpn", alpn)
	}
	link := "anytls://" + url.User(cs(c, "password")).String() + "@" + hostPort(c)
	if enc := q.Encode(); enc != "" {
		link += "?" + enc
	}
	return link + "#" + encodeFragment(n.Name)
}

// awgQueryKeys are the AmneziaWG keys the share-link query carries. It matches
// the set the parser accepts so a link round-trips.
var awgQueryKeys = []string{
	"jc", "jmin", "jmax",
	"s1", "s2", "s3", "s4",
	"h1", "h2", "h3", "h4",
	"i1", "i2", "i3", "i4", "i5",
	"j1", "j2", "j3",
	"itime", "version",
	"header-protection-key", "content-padding-addition",
	"rekey-after-time", "rekey-timeout", "reject-after-time",
	"keepalive-timeout", "max-handshake-attempts",
	"random-trailers", "disable-cookies",
}

// appendAmneziaWGQuery adds the amnezia-wg-option values present on a WireGuard
// node. Missing keys stay missing: the server side has no default to invent.
func appendAmneziaWGQuery(q url.Values, c map[string]any) {
	awg := cmap(c, "amnezia-wg-option")
	if len(awg) == 0 {
		return
	}
	for _, k := range awgQueryKeys {
		v, ok := awg[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" {
				q.Set(k, t)
			}
		case int:
			q.Set(k, strconv.Itoa(t))
		case int64:
			q.Set(k, strconv.FormatInt(t, 10))
		case float64:
			q.Set(k, strconv.Itoa(int(t)))
		case bool:
			q.Set(k, strconv.FormatBool(t))
		}
	}
}

// xhttpExtraJSON serializes the xhttp-opts keys the URI cannot carry as named
// query parameters (everything beyond path/host/mode). It returns "" when there
// is nothing extra.
func xhttpExtraJSON(xo map[string]any) string {
	extra := make(map[string]any, len(xo))
	for k, v := range xo {
		switch k {
		case "path", "host", "mode":
			continue
		}
		extra[k] = v
	}
	if len(extra) == 0 {
		return ""
	}
	b, err := json.Marshal(extra)
	if err != nil {
		return ""
	}
	return string(b)
}

func hostPort(c map[string]any) string {
	return net.JoinHostPort(cs(c, "server"), strconv.Itoa(ci(c, "port")))
}
