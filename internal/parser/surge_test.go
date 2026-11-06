package parser

import (
	"testing"
)

func TestParseSurge_FullConf(t *testing.T) {
	conf := `[General]
loglevel = notify
skip-proxy = 127.0.0.1, 192.168.0.0/16

[Proxy]
🇭🇰 HK-SS = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=ss-secret, udp-relay=true, obfs=http, obfs-host=cdn.example.com
🇯🇵 JP-VMess = vmess, 2.3.4.5, 443, username=vmess-uuid, ws=true, ws-path=/ws, ws-headers=Host:jp.example.com, tls=true, sni=jp.example.com
🇺🇸 US-Trojan = trojan, 3.4.5.6, 443, password=trojan-pass, sni=tr.example.com, skip-cert-verify=true
🇸🇬 SG-Hy2 = hysteria2, 4.5.6.7, 8443, password=hy2-pass, sni=hy2.example.com

[Proxy Group]
🚀 PROXY = select, 🇭🇰 HK-SS, 🇯🇵 JP-VMess

[Rule]
FINAL, DIRECT
`

	if !looksLikeSurge(conf) {
		t.Fatalf("looksLikeSurge failed on full conf")
	}

	nodes, skipped, err := parseSurge(conf)
	if err != nil {
		t.Fatalf("parseSurge error: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("unexpected skipped lines: %v", skipped)
	}
	if len(nodes) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(nodes))
	}

	// SS
	ss := nodes[0]
	if ss.Name != "🇭🇰 HK-SS" || ss.Type != "ss" || ss.Server != "1.2.3.4" || ss.Port != 8388 {
		t.Errorf("bad ss: %+v", ss)
	}
	if ss.Clash["cipher"] != "aes-256-gcm" || ss.Clash["password"] != "ss-secret" || ss.Clash["udp"] != true {
		t.Errorf("bad ss clash: %v", ss.Clash)
	}
	if ss.Clash["plugin"] != "obfs" {
		t.Errorf("bad ss plugin: %v", ss.Clash["plugin"])
	}

	// VMess
	vm := nodes[1]
	if vm.Name != "🇯🇵 JP-VMess" || vm.Type != "vmess" || vm.Clash["uuid"] != "vmess-uuid" {
		t.Errorf("bad vmess: %+v", vm)
	}
	if vm.Clash["network"] != "ws" || vm.Clash["tls"] != true || vm.Clash["sni"] != "jp.example.com" {
		t.Errorf("bad vmess opts: %v", vm.Clash)
	}
	wsOpts, _ := vm.Clash["ws-opts"].(map[string]any)
	if wsOpts["path"] != "/ws" {
		t.Errorf("bad ws path: %v", wsOpts)
	}
	hdr, _ := wsOpts["headers"].(map[string]any)
	if hdr["Host"] != "jp.example.com" {
		t.Errorf("bad ws Host header: %v", hdr)
	}

	// Trojan
	tr := nodes[2]
	if tr.Name != "🇺🇸 US-Trojan" || tr.Type != "trojan" || tr.Clash["password"] != "trojan-pass" || tr.Clash["skip-cert-verify"] != true {
		t.Errorf("bad trojan: %+v", tr)
	}

	// Hy2
	hy2 := nodes[3]
	if hy2.Name != "🇸🇬 SG-Hy2" || hy2.Type != "hysteria2" || hy2.Clash["password"] != "hy2-pass" || hy2.Clash["sni"] != "hy2.example.com" {
		t.Errorf("bad hy2: %+v", hy2)
	}
}

func TestParseSurge_RawListAndOtherProtocols(t *testing.T) {
	rawList := `# Surge managed proxy list
VLESS-Reality = vless, 1.1.1.1, 443, username=vless-uuid, reality=true, public-key=pk123, short-id=sid123, fingerprint=chrome, sni=reality.example.com
Custom-SS = custom, 2.2.2.2, 8388, chacha20-ietf-poly1305, custompass, http://example.com/module, udp-relay=true
TUIC-Node = tuic, 3.3.3.3, 10443, token=tuic-token, sni=tuic.example.com, alpn=h3
SOCKS5-Node = socks5, 4.4.4.4, 1080, username=user, password=pass
`

	if !looksLikeSurge(rawList) {
		t.Fatalf("looksLikeSurge failed on raw list")
	}

	nodes, skipped, err := parseSurge(rawList)
	if err != nil {
		t.Fatalf("parseSurge error: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("unexpected skipped: %v", skipped)
	}
	if len(nodes) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(nodes))
	}

	// VLESS Reality
	vl := nodes[0]
	if vl.Name != "VLESS-Reality" || vl.Type != "vless" || vl.Clash["uuid"] != "vless-uuid" || vl.Clash["client-fingerprint"] != "chrome" {
		t.Errorf("bad vless: %+v", vl)
	}
	ro, _ := vl.Clash["reality-opts"].(map[string]any)
	if ro["public-key"] != "pk123" || ro["short-id"] != "sid123" {
		t.Errorf("bad reality-opts: %v", ro)
	}

	// Custom SS
	cs := nodes[1]
	if cs.Name != "Custom-SS" || cs.Type != "ss" || cs.Clash["cipher"] != "chacha20-ietf-poly1305" || cs.Clash["password"] != "custompass" || cs.Clash["udp"] != true {
		t.Errorf("bad custom ss: %+v", cs)
	}

	// TUIC
	tuic := nodes[2]
	if tuic.Name != "TUIC-Node" || tuic.Type != "tuic" || tuic.Clash["password"] != "tuic-token" {
		t.Errorf("bad tuic: %+v", tuic)
	}

	// SOCKS5
	socks := nodes[3]
	if socks.Name != "SOCKS5-Node" || socks.Type != "socks5" || socks.Clash["username"] != "user" || socks.Clash["password"] != "pass" {
		t.Errorf("bad socks5: %+v", socks)
	}
}
