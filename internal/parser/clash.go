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
		nodes = append(nodes, &proxy.Proxy{
			Name:   name,
			Type:   typ,
			Server: server,
			Port:   port,
			Clash:  m,
		})
	}
	return nodes, skipped, nil
}
