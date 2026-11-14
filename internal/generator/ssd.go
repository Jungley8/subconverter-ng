package generator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// ErrTargetNodes reports that the input had nodes, but none the target can
// encode (e.g. target=ssd with a vmess-only subscription). convert maps it to
// ErrNoNodes so the server answers 422 with the usual hint instead of blaming
// an upstream.
var ErrTargetNodes = errors.New("no nodes the target can encode")

// ssdAirportName is the document-level name; SSD has no field to carry the
// user's own airport name through a conversion.
const ssdAirportName = "subconverter-ng"

// GenerateSSD renders an SSD subscription: an ssd:// URI whose base64 JSON body
// lists Shadowsocks servers. SSD carries method and password per
// server, so no other protocol can be represented; those nodes are reported in
// Result.SkippedNodes.
//
// The document-level port/encryption/password repeat the first
// server: the SSD spec defines them as defaults, and clients differ in whether
// they require the keys to be present.
func GenerateSSD(_ context.Context, nodes []*proxy.Proxy, cfg *extconfig.Config, _ Fetcher, opts Options) (*Result, error) {
	res := &Result{ContentType: ctText}
	nodes = prepareNodes(nodes, cfg, opts, res)

	servers := make([]map[string]any, 0, len(nodes))
	var defaults map[string]any
	for _, n := range nodes {
		if n.Type != "ss" {
			res.SkippedNodes = append(res.SkippedNodes, n.Name+" ("+n.Type+": ssd carries Shadowsocks only)")
			continue
		}
		c := n.Clash
		enc, pw := cs(c, "cipher"), cs(c, "password")
		port := ci(c, "port")
		if enc == "" || pw == "" || port <= 0 || cs(c, "server") == "" {
			res.SkippedNodes = append(res.SkippedNodes, n.Name+" (incomplete ss fields)")
			continue
		}
		srv := map[string]any{
			"server":     cs(c, "server"),
			"port":       port,
			"encryption": enc,
			"password":   pw,
			"remarks":    n.Name,
		}
		if spec := ssPluginSpec(c); spec != "" {
			name, pluginOpts, _ := strings.Cut(spec, ";")
			srv["plugin"] = name
			if pluginOpts != "" {
				srv["plugin_options"] = pluginOpts
			}
		}
		if defaults == nil {
			defaults = map[string]any{"port": port, "encryption": enc, "password": pw}
		}
		servers = append(servers, srv)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("%w: target ssd needs Shadowsocks nodes", ErrTargetNodes)
	}

	res.NodeCount = len(servers)
	doc := map[string]any{"airport": ssdAirportName, "servers": servers}
	for k, v := range defaults {
		doc[k] = v
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	res.Output = []byte("ssd://" + base64.StdEncoding.EncodeToString(body))
	return res, nil
}
