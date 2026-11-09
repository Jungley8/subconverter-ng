package parser

import (
	"testing"
)

func TestParseSingboxJSON_Doc(t *testing.T) {
	jsonDoc := `{
		"outbounds": [
			{
				"tag": "🇭🇰 HK SS",
				"type": "shadowsocks",
				"server": "1.2.3.4",
				"server_port": 8388,
				"method": "aes-256-gcm",
				"password": "secret_password",
				"tcp_fast_open": true
			},
			{
				"tag": "🇯🇵 JP VMess",
				"type": "vmess",
				"server": "2.3.4.5",
				"server_port": 443,
				"uuid": "a1b2c3d4-e5f6-7890-1234-56789abcdef0",
				"alter_id": 0,
				"security": "auto",
				"tls": {
					"enabled": true,
					"server_name": "jp.example.com",
					"insecure": true,
					"alpn": ["h2", "http/1.1"]
				},
				"transport": {
					"type": "ws",
					"path": "/vmess-ws",
					"headers": {
						"Host": "jp.example.com"
					}
				}
			},
			{
				"tag": "🇺🇸 US VLESS Reality",
				"type": "vless",
				"server": "3.4.5.6",
				"server_port": 443,
				"uuid": "b2c3d4e5-f6a7-8901-2345-6789abcdef01",
				"flow": "xtls-rprx-vision",
				"tls": {
					"enabled": true,
					"server_name": "reality.example.com",
					"utls": {
						"enabled": true,
						"fingerprint": "chrome"
					},
					"reality": {
						"enabled": true,
						"public_key": "my_public_key",
						"short_id": "abcd1234"
					}
				}
			},
			{
				"tag": "🚀 Direct",
				"type": "direct"
			},
			{
				"tag": "🛑 Block",
				"type": "block"
			},
			{
				"tag": "dns-out",
				"type": "dns"
			},
			{
				"tag": "Auto",
				"type": "urltest",
				"outbounds": ["🇭🇰 HK SS", "🇯🇵 JP VMess"]
			}
		]
	}`

	if !looksLikeSingboxJSON(jsonDoc) {
		t.Fatalf("looksLikeSingboxJSON failed on doc")
	}

	nodes, skipped, err := parseSingboxJSON(jsonDoc)
	if err != nil {
		t.Fatalf("parseSingboxJSON error: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("unexpected skipped outbounds: %v", skipped)
	}
	if len(nodes) != 3 {
		t.Fatalf("expected 3 proxy nodes, got %d", len(nodes))
	}

	// Verify SS
	ssNode := nodes[0]
	if ssNode.Name != "🇭🇰 HK SS" || ssNode.Type != "ss" || ssNode.Server != "1.2.3.4" || ssNode.Port != 8388 {
		t.Errorf("unexpected ss node: %+v", ssNode)
	}
	if ssNode.Clash["cipher"] != "aes-256-gcm" || ssNode.Clash["password"] != "secret_password" || ssNode.Clash["tfo"] != true {
		t.Errorf("unexpected ss clash fields: %v", ssNode.Clash)
	}

	// Verify VMess
	vmNode := nodes[1]
	if vmNode.Name != "🇯🇵 JP VMess" || vmNode.Type != "vmess" || vmNode.Server != "2.3.4.5" || vmNode.Port != 443 {
		t.Errorf("unexpected vmess node: %+v", vmNode)
	}
	if vmNode.Clash["uuid"] != "a1b2c3d4-e5f6-7890-1234-56789abcdef0" || vmNode.Clash["alterId"] != 0 {
		t.Errorf("unexpected vmess uuid/alterId: %v", vmNode.Clash)
	}
	if vmNode.Clash["tls"] != true || vmNode.Clash["sni"] != "jp.example.com" || vmNode.Clash["skip-cert-verify"] != true {
		t.Errorf("unexpected vmess tls: %v", vmNode.Clash)
	}
	if vmNode.Clash["network"] != "ws" {
		t.Errorf("unexpected vmess network: %v", vmNode.Clash["network"])
	}
	wsOpts, _ := vmNode.Clash["ws-opts"].(map[string]any)
	if wsOpts["path"] != "/vmess-ws" {
		t.Errorf("unexpected ws-opts: %v", wsOpts)
	}

	// Verify VLESS Reality
	vlessNode := nodes[2]
	if vlessNode.Name != "🇺🇸 US VLESS Reality" || vlessNode.Type != "vless" {
		t.Errorf("unexpected vless node: %+v", vlessNode)
	}
	if vlessNode.Clash["flow"] != "xtls-rprx-vision" || vlessNode.Clash["client-fingerprint"] != "chrome" {
		t.Errorf("unexpected vless flow/fp: %v", vlessNode.Clash)
	}
	ro, _ := vlessNode.Clash["reality-opts"].(map[string]any)
	if ro["public-key"] != "my_public_key" || ro["short-id"] != "abcd1234" {
		t.Errorf("unexpected reality-opts: %v", ro)
	}
}

func TestParseSingboxJSON_ArrayAndOtherProtocols(t *testing.T) {
	jsonArray := `[
		{
			"tag": "Trojan-Node",
			"type": "trojan",
			"server": "tr.example.com",
			"server_port": 443,
			"password": "trojan_password",
			"tls": {
				"enabled": true,
				"server_name": "tr.example.com"
			},
			"transport": {
				"type": "grpc",
				"service_name": "tr-grpc"
			}
		},
		{
			"tag": "Hy2-Node",
			"type": "hysteria2",
			"server": "hy2.example.com",
			"server_port": 8443,
			"password": "hy2_password",
			"obfs": {
				"type": "salamander",
				"password": "obfs_secret"
			},
			"tls": {
				"enabled": true,
				"server_name": "hy2.example.com"
			}
		},
		{
			"tag": "TUIC-Node",
			"type": "tuic",
			"server": "tuic.example.com",
			"server_port": 10443,
			"uuid": "tuic-uuid",
			"password": "tuic-password",
			"congestion_control": "bbr",
			"tls": {
				"enabled": true,
				"server_name": "tuic.example.com"
			}
		},
		{
			"tag": "WG-Node",
			"type": "wireguard",
			"server": "wg.example.com",
			"server_port": 51820,
			"private_key": "privkey",
			"peer_public_key": "pubkey",
			"pre_shared_key": "psk",
			"local_address": ["10.0.0.2/32", "fc00::2/128"],
			"mtu": 1420,
			"reserved": [1, 2, 3]
		}
	]`

	if !looksLikeSingboxJSON(jsonArray) {
		t.Fatalf("looksLikeSingboxJSON failed on array")
	}

	nodes, skipped, err := parseSingboxJSON(jsonArray)
	if err != nil {
		t.Fatalf("parseSingboxJSON array error: %v", err)
	}
	if len(skipped) != 0 {
		t.Errorf("unexpected skipped: %v", skipped)
	}
	if len(nodes) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(nodes))
	}

	// Trojan
	tr := nodes[0]
	if tr.Type != "trojan" || tr.Clash["password"] != "trojan_password" || tr.Clash["network"] != "grpc" {
		t.Errorf("bad trojan: %v", tr.Clash)
	}

	// Hy2
	hy2 := nodes[1]
	if hy2.Type != "hysteria2" || hy2.Clash["obfs"] != "salamander" || hy2.Clash["obfs-password"] != "obfs_secret" {
		t.Errorf("bad hy2: %v", hy2.Clash)
	}

	// TUIC
	tuic := nodes[2]
	if tuic.Type != "tuic" || tuic.Clash["congestion-controller"] != "bbr" {
		t.Errorf("bad tuic: %v", tuic.Clash)
	}

	// WireGuard
	wg := nodes[3]
	if wg.Type != "wireguard" || wg.Clash["private-key"] != "privkey" || wg.Clash["ip"] != "10.0.0.2" || wg.Clash["ipv6"] != "fc00::2" {
		t.Errorf("bad wg: %v", wg.Clash)
	}
	rsv, _ := wg.Clash["reserved"].([]int)
	if len(rsv) != 3 || rsv[0] != 1 || rsv[1] != 2 || rsv[2] != 3 {
		t.Errorf("bad wg reserved: %v", wg.Clash["reserved"])
	}
}
