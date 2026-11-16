package parser

import (
	"fmt"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
	"gopkg.in/yaml.v3"
)

// looksLikeClashYAML detects a Clash/Clash.Meta document so we can lift its
// proxies instead of trying to base64-decode it. A top-level `proxies:` key is
// enough: neither a base64 blob nor a share-link list contains a line starting
// with "proxies:", so there is no false positive to guard against — and keying
// only on it avoids missing configs whose proxy-groups/rules sit far past the
// header (previously a fixed 4096-byte window with a required secondary marker
// dropped those). Anchored to line start so a substring inside a node name
// can't trip it.
func looksLikeClashYAML(text string) bool {
	return strings.HasPrefix(text, "proxies:") || strings.Contains(text, "\nproxies:")
}

type clashDoc struct {
	Proxies []map[string]any `yaml:"proxies"`
}

// parseClashYAML extracts the proxies list from a ready-made Clash document.
func parseClashYAML(text string) ([]*proxy.Proxy, []string, error) {
	var doc clashDoc
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		return nil, nil, fmt.Errorf("clash yaml: %w", err)
	}
	var nodes []*proxy.Proxy
	var skipped []string
	for _, m := range doc.Proxies {
		name, _ := m["name"].(string)
		typ, _ := m["type"].(string)
		if name == "" || typ == "" {
			skipped = append(skipped, fmt.Sprintf("%v", m))
			continue
		}
		server, _ := m["server"].(string)
		port := anyToInt(m["port"])
		p := &proxy.Proxy{
			Name:   name,
			Type:   typ,
			Server: server,
			Port:   port,
			Clash:  m,
		}
		if typ == "tuic" {
			normalizeClashTUIC(p, m)
		}
		nodes = append(nodes, p)
	}
	return nodes, skipped, nil
}

// normalizeClashTUIC marks a v4 node (token-based, no uuid) and moves its token
// to the canonical password key. mihomo cannot load v4 nodes, so generators
// branch on Proxy.Version to skip or emit a v4 line.
func normalizeClashTUIC(p *proxy.Proxy, m map[string]any) {
	if s, ok := m["uuid"].(string); ok && strings.TrimSpace(s) != "" {
		return
	}
	p.Version = 4
	if token, ok := m["token"].(string); ok && strings.TrimSpace(token) != "" {
		m["password"] = token
	}
	delete(m, "token")
}
