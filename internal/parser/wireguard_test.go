package parser

import "testing"

func TestParseWireGuard_Full(t *testing.T) {
	uri := "wireguard://cHJpdmtleQ==@wg.example.com:51820?address=10.0.0.2/32,fd00::2/128&publickey=cHVia2V5&presharedkey=cHNr&reserved=1,2,3&mtu=1408#🇺🇸 WG"
	p, err := parseWireGuard(uri)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != "wireguard" || p.Server != "wg.example.com" || p.Port != 51820 {
		t.Errorf("base fields wrong: %+v", p)
	}
	if p.Name != "🇺🇸 WG" {
		t.Errorf("name = %q", p.Name)
	}
	if p.Clash["private-key"] != "cHJpdmtleQ==" || p.Clash["public-key"] != "cHVia2V5" {
		t.Errorf("keys wrong: %v", p.Clash)
	}
	if p.Clash["ip"] != "10.0.0.2" || p.Clash["ipv6"] != "fd00::2" {
		t.Errorf("addresses wrong: ip=%v ipv6=%v", p.Clash["ip"], p.Clash["ipv6"])
	}
	if p.Clash["pre-shared-key"] != "cHNr" || p.Clash["mtu"] != 1408 {
		t.Errorf("psk/mtu wrong: %v", p.Clash)
	}
	rsv, ok := p.Clash["reserved"].([]int)
	if !ok || len(rsv) != 3 || rsv[2] != 3 {
		t.Errorf("reserved wrong: %v", p.Clash["reserved"])
	}
	if p.Clash["udp"] != true {
		t.Error("udp should be true")
	}
}

func TestParseWireGuard_MinimalAndAliases(t *testing.T) {
	// wg:// alias, public-key spelling variant, ip= alias, no reserved/mtu.
	p, err := parseWireGuard("wg://priv@1.2.3.4:51820?public-key=pk&ip=10.0.0.5")
	if err != nil {
		t.Fatal(err)
	}
	if p.Clash["public-key"] != "pk" || p.Clash["ip"] != "10.0.0.5" {
		t.Errorf("alias keys not honored: %v", p.Clash)
	}
	if _, ok := p.Clash["reserved"]; ok {
		t.Error("reserved should be absent")
	}
}

func TestParseWireGuard_MissingHostPort(t *testing.T) {
	if _, err := parseWireGuard("wireguard://priv@host"); err == nil {
		t.Error("expected error for missing port")
	}
}

func TestParse_WireGuardViaDispatch(t *testing.T) {
	body := b64("wireguard://priv@1.2.3.4:51820?publickey=pk&address=10.0.0.2#WG")
	nodes, _, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Type != "wireguard" {
		t.Fatalf("dispatch failed: %+v", nodes)
	}
}

func TestParseWireGuardAWG(t *testing.T) {
	uri := "awg://priv@wg.example.com:51820?publickey=pk&address=10.0.0.2&jc=4&jmin=10&jmax=50&s1=1&s2=2&h1=123456&h2=0xabcdef&i1=45&j1=3&itime=30&version=2&header-protection-key=HPK&content-padding-addition=CPA&random-trailers=1&disable-cookies=true&max-handshake-attempts=5&keepalive-timeout=10#AWG"
	p, err := parseWireGuard(uri)
	if err != nil {
		t.Fatal(err)
	}
	opts, ok := p.Clash["amnezia-wg-option"].(map[string]any)
	if !ok {
		t.Fatalf("amnezia-wg-option missing: %v", p.Clash)
	}
	want := map[string]any{
		"jc":                       4,
		"jmin":                     10,
		"jmax":                     50,
		"s1":                       1,
		"s2":                       2,
		"h1":                       123456,
		"h2":                       "0xabcdef",
		"i1":                       45,
		"j1":                       3,
		"itime":                    30,
		"version":                  2,
		"header-protection-key":    "HPK",
		"content-padding-addition": "CPA",
		"random-trailers":          true,
		"disable-cookies":          true,
		"max-handshake-attempts":   5,
		"keepalive-timeout":        10,
	}
	for k, v := range want {
		if opts[k] != v {
			t.Errorf("amnezia-wg-option[%q] = %#v, want %#v", k, opts[k], v)
		}
	}
	if len(opts) != len(want) {
		t.Errorf("amnezia-wg-option has %d keys, want %d: %v", len(opts), len(want), opts)
	}
}

func TestParseWireGuard_AWGOptionsOnlyWhenPresent(t *testing.T) {
	p, err := parseWireGuard("wireguard://priv@wg.example.com:51820?publickey=pk&jc=3")
	if err != nil {
		t.Fatal(err)
	}
	opts, ok := p.Clash["amnezia-wg-option"].(map[string]any)
	if !ok || len(opts) != 1 || opts["jc"] != 3 {
		t.Errorf("amnezia-wg-option = %#v", p.Clash["amnezia-wg-option"])
	}

	plain, err := parseWireGuard("wireguard://priv@wg.example.com:51820?publickey=pk")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plain.Clash["amnezia-wg-option"]; ok {
		t.Error("plain WireGuard node should have no amnezia-wg-option")
	}
}

func TestParse_AWGViaDispatch(t *testing.T) {
	nodes, skipped, err := Parse([]byte("awg://priv@1.2.3.4:51820?publickey=pk&jc=4#AWG"))
	if err != nil || len(skipped) != 0 || len(nodes) != 1 {
		t.Fatalf("dispatch failed: nodes=%v skipped=%v err=%v", nodes, skipped, err)
	}
	if nodes[0].Type != "wireguard" || nodes[0].Name != "AWG" {
		t.Errorf("unexpected node: %+v", nodes[0])
	}
}
