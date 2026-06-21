package parser

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// parseSS handles Shadowsocks share links in both the SIP002 form
//
//	ss://base64(method:password)@host:port?plugin=...#name
//
// and the legacy fully-base64 form
//
//	ss://base64(method:password@host:port)#name
func parseSS(uri string) (*proxy.Proxy, error) {
	rest := strings.TrimPrefix(uri, "ss://")

	// Split off the #fragment (name) first so base64 bodies don't swallow it.
	name := ""
	if i := strings.Index(rest, "#"); i != -1 {
		if n, err := url.QueryUnescape(rest[i+1:]); err == nil {
			name = strings.TrimSpace(n)
		}
		rest = rest[:i]
	}

	var method, password, host string
	var port int
	var query url.Values

	if at := strings.LastIndex(rest, "@"); at != -1 {
		// SIP002: userinfo @ host:port ?query
		userinfo := rest[:at]
		hostpart := rest[at+1:]
		if q := strings.Index(hostpart, "?"); q != -1 {
			query, _ = url.ParseQuery(hostpart[q+1:])
			hostpart = hostpart[:q]
		}
		host, port = splitHostPort(hostpart)
		if dec, ok := b64decode(userinfo); ok {
			method, password = splitCred(dec)
		} else {
			method, password = splitCred(userinfo)
		}
	} else {
		// Legacy: everything base64. May carry ?query after the base64 body.
		if q := strings.Index(rest, "?"); q != -1 {
			query, _ = url.ParseQuery(rest[q+1:])
			rest = rest[:q]
		}
		dec, _ := b64decode(rest)
		at := strings.LastIndex(dec, "@")
		if at == -1 {
			return nil, fmt.Errorf("ss: malformed legacy link")
		}
		method, password = splitCred(dec[:at])
		host, port = splitHostPort(dec[at+1:])
	}

	if host == "" || port == 0 || method == "" {
		return nil, fmt.Errorf("ss: missing host/port/cipher")
	}
	if name == "" {
		name = fmt.Sprintf("%s:%d", host, port)
	}

	p := proxy.New("ss", name, host, port)
	p.Set("cipher", method)
	p.Set("password", password)
	p.SetRaw("udp", true)

	// SIP003 plugins (obfs / v2ray-plugin) carried in ?plugin=
	if plugin := query.Get("plugin"); plugin != "" {
		applySSPlugin(p, plugin)
	}
	return p, nil
}

func splitCred(s string) (method, password string) {
	if i := strings.Index(s, ":"); i != -1 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// applySSPlugin maps a SIP003 plugin spec ("obfs-local;obfs=http;obfs-host=x")
// onto Clash.Meta's plugin/plugin-opts fields.
func applySSPlugin(p *proxy.Proxy, spec string) {
	parts := strings.Split(spec, ";")
	name := parts[0]
	opts := map[string]any{}
	for _, kv := range parts[1:] {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "obfs":
			opts["mode"] = v
		case "obfs-host":
			opts["host"] = v
		case "mode":
			opts["mode"] = v
		case "host":
			opts["host"] = v
		case "path":
			opts["path"] = v
		case "tls":
			opts["tls"] = true
		}
	}
	switch {
	case strings.Contains(name, "obfs"):
		p.Set("plugin", "obfs")
		p.Set("plugin-opts", opts)
	case strings.Contains(name, "v2ray"):
		p.Set("plugin", "v2ray-plugin")
		p.Set("plugin-opts", opts)
	}
}
