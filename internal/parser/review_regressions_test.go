package parser

import (
	"strings"
	"testing"
)

func TestParseTrojanModernTransports(t *testing.T) {
	p, err := parseTrojan("trojan://pw@h.example.com:443?type=httpupgrade&host=up.example.com&path=/up#T")
	if err != nil {
		t.Fatal(err)
	}
	ws, _ := p.Clash["ws-opts"].(map[string]any)
	if p.Clash["network"] != "ws" || ws["v2ray-http-upgrade"] != true ||
		ws["path"] != "/up" || ws["headers"].(map[string]any)["Host"] != "up.example.com" {
		t.Errorf("trojan httpupgrade lost: %v", p.Clash)
	}

	p, err = parseTrojan("trojan://pw@h.example.com:443?type=xhttp&host=x.example.com&path=/x&mode=auto#T")
	if err != nil {
		t.Fatal(err)
	}
	xo, _ := p.Clash["xhttp-opts"].(map[string]any)
	if p.Clash["network"] != "xhttp" || xo["path"] != "/x" || xo["host"] != "x.example.com" || xo["mode"] != "auto" {
		t.Errorf("trojan xhttp lost: %v", p.Clash)
	}
}

func TestParseXHTTPInvalidExtra(t *testing.T) {
	for _, uri := range []string{
		"vless://u@h.example.com:443?type=xhttp&extra=not-json",
		"trojan://pw@h.example.com:443?type=xhttp&extra={bad",
	} {
		var err error
		if strings.HasPrefix(uri, "vless") {
			_, err = parseVLESS(uri)
		} else {
			_, err = parseTrojan(uri)
		}
		if err == nil {
			t.Errorf("%s: invalid extra must fail closed", uri)
		}
	}
}

func TestParseSingboxHTTPUpgradeHost(t *testing.T) {
	doc := `{"outbounds":[{"tag":"H","type":"vless","server":"h.example.com","server_port":443,` +
		`"uuid":"11111111-2222-3333-4444-555555555555",` +
		`"transport":{"type":"httpupgrade","path":"/up","host":"up.example.com"}}]}`
	nodes, skipped, err := parseSingboxJSON(doc)
	if err != nil || len(nodes) != 1 || len(skipped) != 0 {
		t.Fatalf("parse: nodes=%d skipped=%v err=%v", len(nodes), skipped, err)
	}
	ws, _ := nodes[0].Clash["ws-opts"].(map[string]any)
	headers, _ := ws["headers"].(map[string]any)
	if ws["v2ray-http-upgrade"] != true || headers["Host"] != "up.example.com" {
		t.Errorf("httpupgrade host lost: %v", nodes[0].Clash)
	}
}

func TestParseSurgeWireGuardFirstPeer(t *testing.T) {
	text := `[Proxy]
WG = wireguard, section-name=wg1

[WireGuard wg1]
private-key = priv
self-ip = 10.0.0.2
peer = (public-key = pub1, allowed-ips = "0.0.0.0/0", endpoint = 1.1.1.1:51820)
peer = (public-key = pub2, allowed-ips = "0.0.0.0/0", endpoint = 2.2.2.2:51821)
`
	nodes, skipped, err := parseSurge(text)
	if err != nil || len(nodes) != 1 || len(skipped) != 0 {
		t.Fatalf("parse: nodes=%d skipped=%v err=%v", len(nodes), skipped, err)
	}
	n := nodes[0]
	if n.Server != "1.1.1.1" || n.Port != 51820 || n.Clash["public-key"] != "pub1" {
		t.Errorf("must keep the first peer: %+v", n)
	}
	allowed, _ := n.Clash["allowed-ips"].([]string)
	if len(allowed) != 1 || allowed[0] != "0.0.0.0/0" {
		t.Errorf("allowed-ips = %v, want a string slice", n.Clash["allowed-ips"])
	}
}

func TestParseSurgeShadowTLSRequiresSecret(t *testing.T) {
	for _, text := range []string{
		`[Proxy]
SS = ss, 1.2.3.4, 8388, encrypt-method=aes-128-gcm, password=pw, shadow-tls-version=3`,
		`[Proxy]
SN = snell, 1.2.3.4, 443, psk=psk, version=4, shadow-tls-version=3`,
	} {
		nodes, skipped, err := parseSurge(text)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if len(nodes) != 0 || len(skipped) != 1 {
			t.Errorf("ShadowTLS without a secret must skip: nodes=%d skipped=%v", len(nodes), skipped)
		}
	}
}

func TestParseTUICV4KeepsTLSOptions(t *testing.T) {
	p, err := parseTUIC("tuic://tok4@h.example.com:443?sni=t.example.com&alpn=h3&allow_insecure=1")
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 4 || p.Clash["sni"] != "t.example.com" || p.Clash["skip-cert-verify"] != true {
		t.Errorf("v4 TLS options lost: %v", p.Clash)
	}
	alpn, _ := p.Clash["alpn"].([]string)
	if len(alpn) != 1 || alpn[0] != "h3" {
		t.Errorf("v4 alpn lost: %v", p.Clash["alpn"])
	}
}
