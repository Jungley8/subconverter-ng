package parser

import "testing"

func TestParseSingboxJSON_ModernOutbounds(t *testing.T) {
	doc := `{
		"outbounds": [
			{
				"tag": "SN4",
				"type": "snell",
				"server": "sn.example.com",
				"server_port": 8388,
				"psk": "snpsk",
				"version": 4,
				"userkey": "uk",
				"reuse": true,
				"obfs_mode": "http",
				"obfs_host": "bing.com"
			},
			{
				"tag": "SN6",
				"type": "snell",
				"server": "sn6.example.com",
				"server_port": 443,
				"psk": "p6",
				"version": 6,
				"mode": "unshaped"
			},
			{
				"tag": "SSH",
				"type": "ssh",
				"server": "ssh.example.com",
				"server_port": 22,
				"user": "alice",
				"password": "alicepw",
				"private_key": "KEY",
				"private_key_passphrase": "PP",
				"host_key": ["hk1", "hk2"],
				"host_key_algorithms": ["ed25519"]
			},
			{
				"tag": "NV",
				"type": "naive",
				"server": "n.example.com",
				"server_port": 443,
				"username": "nu",
				"password": "np",
				"quic": true,
				"tls": {
					"enabled": true,
					"server_name": "n.example.com",
					"alpn": ["h2"]
				}
			},
			{
				"tag": "SS-ST",
				"type": "shadowsocks",
				"server": "inner.example.com",
				"server_port": 8388,
				"method": "aes-256-gcm",
				"password": "ssp",
				"detour": "st-out"
			},
			{
				"tag": "st-out",
				"type": "shadowtls",
				"server": "camouflage.example.com",
				"server_port": 443,
				"version": 3,
				"password": "stp",
				"tls": {
					"enabled": true,
					"server_name": "bing.com"
				}
			},
			{
				"tag": "HU",
				"type": "vless",
				"server": "hu.example.com",
				"server_port": 443,
				"uuid": "uuid-1",
				"transport": {
					"type": "httpupgrade",
					"path": "/up",
					"headers": {
						"Host": "up.example.com"
					}
				}
			}
		]
	}`

	nodes, skipped, err := parseSingboxJSON(doc)
	if err != nil || len(skipped) != 0 {
		t.Fatalf("parse failed: skipped=%v err=%v", skipped, err)
	}
	if len(nodes) != 6 {
		t.Fatalf("got %d nodes, want 6", len(nodes))
	}

	checkClash(t, nodes[0], map[string]any{
		"type":    "snell",
		"psk":     "snpsk",
		"version": 4,
		"userkey": "uk",
		"reuse":   true,
		"obfs-opts": map[string]any{
			"mode": "http",
			"host": "bing.com",
		},
	})
	checkClash(t, nodes[1], map[string]any{
		"type":    "snell",
		"version": 6,
		"mode":    "unshaped",
	})
	if _, ok := nodes[1].Clash["obfs-opts"]; ok {
		t.Error("SN6 should have no obfs-opts")
	}
	checkClash(t, nodes[2], map[string]any{
		"type":                   "ssh",
		"username":               "alice",
		"password":               "alicepw",
		"private-key":            "KEY",
		"private-key-passphrase": "PP",
		"host-key":               []string{"hk1", "hk2"},
		"host-key-algorithms":    []string{"ed25519"},
	})
	checkClash(t, nodes[3], map[string]any{
		"type":     "naive",
		"username": "nu",
		"password": "np",
		"quic":     true,
		"tls":      true,
		"sni":      "n.example.com",
		"alpn":     []string{"h2"},
	})
	checkClash(t, nodes[4], map[string]any{
		"type":     "ss",
		"name":     "SS-ST",
		"server":   "camouflage.example.com",
		"port":     443,
		"cipher":   "aes-256-gcm",
		"password": "ssp",
		"plugin":   "shadow-tls",
		"plugin-opts": map[string]any{
			"host":     "bing.com",
			"password": "stp",
			"version":  3,
		},
	})
	checkClash(t, nodes[5], map[string]any{
		"type":    "vless",
		"network": "ws",
		"ws-opts": map[string]any{
			"path":               "/up",
			"headers":            map[string]any{"Host": "up.example.com"},
			"v2ray-http-upgrade": true,
		},
	})
}

func TestParseSingboxJSON_SnellMissingPSK(t *testing.T) {
	doc := `[{"tag":"bad","type":"snell","server":"h.example.com","server_port":443}]`
	nodes, skipped, err := parseSingboxJSON(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 || len(skipped) != 1 {
		t.Errorf("nodes=%d skipped=%v, want 0/1", len(nodes), skipped)
	}
}

func TestParseSingboxJSON_ShadowTLSWithoutInner(t *testing.T) {
	doc := `[{"tag":"st","type":"shadowtls","server":"h.example.com","server_port":443,"version":3,"password":"p"}]`
	nodes, skipped, err := parseSingboxJSON(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 || len(skipped) != 1 {
		t.Errorf("nodes=%d skipped=%v, want 0/1", len(nodes), skipped)
	}
}
