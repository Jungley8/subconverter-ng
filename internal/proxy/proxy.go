// Package proxy defines the intermediate proxy-node model used across the
// converter. Each subscription entry is parsed into a Proxy; generators then
// render Proxy values into a target client format (Clash.Meta for the MVP).
package proxy

// Proxy is a single proxy node, decoupled from any subscription URI format and
// from any target output format.
//
// Clash holds the full Clash.Meta proxy mapping (the exact map that will be
// emitted under the top-level `proxies:` list). The promoted fields (Name,
// Type, Server, Port) are kept alongside it so node-selection logic
// (renaming, dedup, regex group matching, exclude/include filters) does not
// have to reach into the map.
type Proxy struct {
	Name   string
	Type   string // ss | vmess | vless | trojan | hysteria2 | tuic
	Server string
	Port   int

	// Clash is the rendered Clash.Meta proxy entry. It always contains at
	// least name/type/server/port mirroring the fields above.
	Clash map[string]any
}

// New builds a Proxy and seeds its Clash map with the common fields. Callers
// add protocol-specific keys to the returned map.
func New(typ, name, server string, port int) *Proxy {
	p := &Proxy{Name: name, Type: typ, Server: server, Port: port}
	p.Clash = map[string]any{
		"name":   name,
		"type":   typ,
		"server": server,
		"port":   port,
	}
	return p
}

// Rename updates both the promoted name and the Clash map in lockstep.
func (p *Proxy) Rename(name string) {
	p.Name = name
	p.Clash["name"] = name
}

// Set adds a Clash field when v is non-empty/non-zero. It keeps the rendered
// config tidy by skipping default-valued keys.
func (p *Proxy) Set(key string, v any) {
	switch t := v.(type) {
	case string:
		if t == "" {
			return
		}
	case nil:
		return
	}
	p.Clash[key] = v
}

// SetRaw always sets the field, even for zero values (use when the zero value
// is meaningful, e.g. alterId: 0).
func (p *Proxy) SetRaw(key string, v any) {
	p.Clash[key] = v
}
