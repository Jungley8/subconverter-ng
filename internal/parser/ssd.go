package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// ssdPrefix marks a ShadowSocksDroid subscription: an ssd:// URI whose body is
// base64 JSON. Old airports still hand these out, and a client that accepts the
// URI cannot turn it into nodes without this decoder.
const ssdPrefix = "ssd://"

// ssdDoc is the ShadowSocksDroid subscription document. Per-server fields
// override the document-level defaults, which is how airports share one
// encryption/password pair across every server.
type ssdDoc struct {
	Airport    string      `json:"airport"`
	Port       int         `json:"port"`
	Encryption string      `json:"encryption"`
	Password   string      `json:"password"`
	Servers    []ssdServer `json:"servers"`
}

type ssdServer struct {
	Server        string `json:"server"`
	Port          int    `json:"port"`
	Encryption    string `json:"encryption"`
	Password      string `json:"password"`
	Plugin        string `json:"plugin"`
	PluginOptions string `json:"plugin_options"`
	Remarks       string `json:"remarks"`
}

// looksLikeSSD reports whether s is an ssd:// subscription URI.
func looksLikeSSD(s string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(s)), ssdPrefix)
}

// parseSSD decodes an ssd:// URI into Shadowsocks nodes. ok is false when the
// input is not an SSD URI at all; a malformed SSD body returns ok with a
// skipped entry, so the caller reports it instead of trying to fetch it.
func parseSSD(uri string) (nodes []*proxy.Proxy, skipped []string, ok bool) {
	uri = strings.TrimSpace(uri)
	if !looksLikeSSD(uri) {
		return nil, nil, false
	}
	body, decoded := b64decode(uri[len(ssdPrefix):])
	if !decoded {
		return nil, []string{"ssd:// (body is not base64)"}, true
	}
	var doc ssdDoc
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return nil, []string{"ssd:// (body is not SSD JSON)"}, true
	}
	if len(doc.Servers) == 0 {
		return nil, []string{"ssd:// (no servers)"}, true
	}

	airport := strings.TrimSpace(doc.Airport)
	for i, s := range doc.Servers {
		name := strings.TrimSpace(s.Remarks)
		if name == "" {
			if airport != "" {
				name = fmt.Sprintf("%s %d", airport, i+1)
			} else {
				name = fmt.Sprintf("%s:%d", s.Server, s.Port)
			}
		}
		enc := firstNonEmptyString(s.Encryption, doc.Encryption)
		pw := firstNonEmptyString(s.Password, doc.Password)
		port := s.Port
		if port == 0 {
			port = doc.Port
		}
		host := strings.TrimSpace(s.Server)
		if host == "" || port <= 0 || enc == "" || pw == "" {
			skipped = append(skipped, "ssd:// server "+name+" (missing host, port, cipher, or password)")
			continue
		}
		p := proxy.New("ss", name, host, port)
		p.Set("cipher", enc)
		p.Set("password", pw)
		p.SetRaw("udp", true)
		if s.Plugin != "" {
			spec := s.Plugin
			if s.PluginOptions != "" {
				spec += ";" + s.PluginOptions
			}
			applySSPlugin(p, spec)
		}
		nodes = append(nodes, p)
	}
	return nodes, skipped, true
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}
