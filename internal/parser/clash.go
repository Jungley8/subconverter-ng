package parser

import (
	"fmt"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
	"gopkg.in/yaml.v3"
)

// looksLikeClashYAML heuristically detects a Clash/Clash.Meta document so we
// can lift its proxies instead of trying to base64-decode it.
func looksLikeClashYAML(text string) bool {
	head := text
	if len(head) > 4096 {
		head = head[:4096]
	}
	return strings.Contains(head, "proxies:") &&
		(strings.Contains(head, "proxy-groups:") ||
			strings.Contains(head, "rules:") ||
			strings.Contains(head, "port:") ||
			strings.Contains(head, "mixed-port:"))
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
