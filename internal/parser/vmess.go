package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// vmessJSON is the v2rayN base64-JSON share format carried by vmess:// links.
// Fields are strings or numbers depending on the producer, so the numeric ones
// are decoded permissively via json.Number-ish handling below.
type vmessJSON struct {
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port any    `json:"port"`
	ID   string `json:"id"`
	Aid  any    `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
	FP   string `json:"fp"`
}

func parseVMess(uri string) (*proxy.Proxy, error) {
	body := strings.TrimPrefix(uri, "vmess://")
	dec, ok := b64decode(body)
	if !ok {
		return nil, fmt.Errorf("vmess: not base64")
	}
	var v vmessJSON
	if err := json.Unmarshal([]byte(dec), &v); err != nil {
		return nil, fmt.Errorf("vmess: bad json: %w", err)
	}

	port := anyToInt(v.Port)
	if v.Add == "" || port == 0 || v.ID == "" {
		return nil, fmt.Errorf("vmess: missing add/port/id")
	}
	name := v.PS
	if name == "" {
		name = fmt.Sprintf("%s:%d", v.Add, port)
	}

	p := proxy.New("vmess", name, v.Add, port)
	p.Set("uuid", v.ID)
	p.SetRaw("alterId", anyToInt(v.Aid))
	cipher := v.Scy
	if cipher == "" {
		cipher = "auto"
	}
	p.Set("cipher", cipher)
	p.SetRaw("udp", true)

	if strings.EqualFold(v.TLS, "tls") {
		p.SetRaw("tls", true)
		sni := v.SNI
		if sni == "" {
			sni = v.Host
		}
		p.Set("servername", sni)
		if v.FP != "" {
			p.Set("client-fingerprint", v.FP)
		}
	}

	network := v.Net
	if network == "" {
		network = "tcp"
	}
	p.Set("network", network)
	applyV2RayTransport(p, network, v.Host, v.Path, v.Type)
	return p, nil
}

// applyV2RayTransport fills ws-opts/grpc-opts/h2-opts shared by vmess/vless.
func applyV2RayTransport(p *proxy.Proxy, network, host, path, headerType string) {
	switch network {
	case "ws":
		opts := map[string]any{}
		if path != "" {
			opts["path"] = path
		}
		if host != "" {
			opts["headers"] = map[string]any{"Host": host}
		}
		if len(opts) > 0 {
			p.Set("ws-opts", opts)
		}
	case "grpc":
		if path != "" {
			p.Set("grpc-opts", map[string]any{"grpc-service-name": path})
		}
	case "h2":
		opts := map[string]any{}
		if path != "" {
			opts["path"] = path
		}
		if host != "" {
			opts["host"] = []string{host}
		}
		if len(opts) > 0 {
			p.Set("h2-opts", opts)
		}
	}
}
