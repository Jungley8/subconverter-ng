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
