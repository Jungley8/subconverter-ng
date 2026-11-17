package parser

import "testing"

func TestParseSurge_NewProtocols(t *testing.T) {
	conf := `[Proxy]
SN = snell, sn.example.com, 8388, psk=snpsk, version=4, obfs=http, obfs-host=bing.com, obfs-uri=/, reuse=true, udp-port=1234, mode=unshaped, userkey=ukey
ST-Snell = snell, st.example.com, 443, psk=p2, version=4, shadow-tls-password=stp, shadow-tls-version=3, shadow-tls-sni=cdn.example.com
ST-SS = ss, ss.example.com, 8388, encrypt-method=aes-256-gcm, password=ssp, shadow-tls-password=stp, shadow-tls-version=2, shadow-tls-sni=cdn.example.com
AT = anytls, at.example.com, 443, password=atp, sni=at.example.com, skip-cert-verify=true, alpn=h2
SSH = ssh, ssh.example.com, 2222, username=alice, password=alicepw
MQ = masque, mq.example.com, 443, username=mu, password=mp, port-hopping=1000-2000, port-hopping-interval=30, sni=mq.example.com, skip-cert-verify=true, alpn=h2
TT = trust-tunnel, tt.example.com, 443, username=tu, password=tp, headers=x-a:1, max-streams=8, h3=true, client-random-auth-key=k
T4 = tuic, t4.example.com, 443, token=v4tok, sni=t4.example.com
T5 = tuic-v5, t5.example.com, 443, uuid=uuid-5, password=t5p, sni=t5.example.com
HY2 = hysteria2, hy2.example.com, 8443, password=hy2p, salamander-password=key123, sni=hy2.example.com
HY2G = hysteria2, hy2g.example.com, 8443, password=hy2gp, gecko-password=key456
WG = wireguard, section-name=WG1
VLX = vless, vl.example.com, 443, username=vlu, xhttp=true, xhttp-path=/x, xhttp-host=cdn.example.com, xhttp-mode=stream-one, sni=vl.example.com, tls=true
VLG = vless, vlg.example.com, 443, username=vlg, grpc=true, grpc-service-name=svc
VHU = vless, vhu.example.com, 443, username=vhu, ws=true, ws-path=/up, ws-headers=Host:up.example.com, ws-http-upgrade=true
MHU = vmess, mhu.example.com, 443, username=muuid, ws=true, ws-path=/up2, ws-http-upgrade=true
THU = trojan, thu.example.com, 443, password=tpw, ws=true, ws-http-upgrade=true, sni=thu.example.com

[wireguard WG1]
private-key = privkey
self-ip = 172.16.0.2
self-ip-v6 = fd01::2
mtu = 1280
dns-server = 1.1.1.1
peer = (public-key = pubkey, allowed-ips = "0.0.0.0/0, ::/0", endpoint = wg.example.com:51820, keepalive = 30, preshared-key = psk)
`
	nodes, skipped, err := parseSurge(conf)
	if err != nil || len(skipped) != 0 {
		t.Fatalf("parse failed: skipped=%v err=%v", skipped, err)
	}
	if len(nodes) != 17 {
		t.Fatalf("got %d nodes, want 17", len(nodes))
	}

	checkClash(t, nodes[0], map[string]any{
		"type":    "snell",
		"psk":     "snpsk",
		"version": 4,
		"reuse":   true,
		"udp":     true,
		"mode":    "unshaped",
		"userkey": "ukey",
		"obfs-opts": map[string]any{
			"mode": "http",
			"host": "bing.com",
			"uri":  "/",
		},
	})
	checkClash(t, nodes[1], map[string]any{
		"type": "snell",
		"obfs-opts": map[string]any{
			"mode":     "shadow-tls",
			"host":     "cdn.example.com",
			"password": "stp",
			"version":  3,
		},
	})
	checkClash(t, nodes[2], map[string]any{
		"type":   "ss",
		"plugin": "shadow-tls",
		"plugin-opts": map[string]any{
			"host":     "cdn.example.com",
			"password": "stp",
			"version":  2,
		},
	})
	checkClash(t, nodes[3], map[string]any{
		"type":             "anytls",
		"password":         "atp",
		"sni":              "at.example.com",
		"skip-cert-verify": true,
		"alpn":             []string{"h2"},
	})
	checkClash(t, nodes[4], map[string]any{
		"type":     "ssh",
		"username": "alice",
		"password": "alicepw",
	})
	checkClash(t, nodes[5], map[string]any{
		"type":                  "masque",
		"username":              "mu",
		"password":              "mp",
		"port-hopping":          "1000-2000",
		"port-hopping-interval": 30,
		"sni":                   "mq.example.com",
		"skip-cert-verify":      true,
		"alpn":                  []string{"h2"},
	})
	checkClash(t, nodes[6], map[string]any{
		"type":                   "trusttunnel",
		"username":               "tu",
		"password":               "tp",
		"headers":                "x-a:1",
		"max-streams":            8,
		"h3":                     true,
		"client-random-auth-key": "k",
	})
	if nodes[7].Version != 4 || nodes[7].Clash["password"] != "v4tok" {
		t.Errorf("TUIC v4 wrong: version=%d clash=%v", nodes[7].Version, nodes[7].Clash)
	}
	if _, ok := nodes[7].Clash["uuid"]; ok {
		t.Error("TUIC v4 should have no uuid")
	}
	if nodes[8].Version != 0 || nodes[8].Clash["uuid"] != "uuid-5" {
		t.Errorf("TUIC v5 wrong: version=%d clash=%v", nodes[8].Version, nodes[8].Clash)
	}
	checkClash(t, nodes[9], map[string]any{
		"type":          "hysteria2",
		"obfs":          "salamander",
		"obfs-password": "key123",
	})
	checkClash(t, nodes[10], map[string]any{
		"type":          "hysteria2",
		"obfs":          "gecko",
		"obfs-password": "key456",
	})
	checkClash(t, nodes[11], map[string]any{
		"type":                 "wireguard",
		"server":               "wg.example.com",
		"port":                 51820,
		"private-key":          "privkey",
		"public-key":           "pubkey",
		"pre-shared-key":       "psk",
		"ip":                   "172.16.0.2",
		"ipv6":                 "fd01::2",
		"mtu":                  1280,
		"dns":                  []string{"1.1.1.1"},
		"persistent-keepalive": 30,
		"allowed-ips":          []string{"0.0.0.0/0", "::/0"},
		"udp":                  true,
	})
	checkClash(t, nodes[12], map[string]any{
		"type":    "vless",
		"network": "xhttp",
		"xhttp-opts": map[string]any{
			"path": "/x",
			"host": "cdn.example.com",
			"mode": "stream-one",
		},
	})
	checkClash(t, nodes[13], map[string]any{
		"type":      "vless",
		"network":   "grpc",
		"grpc-opts": map[string]any{"grpc-service-name": "svc"},
	})
	checkClash(t, nodes[14], map[string]any{
		"type":    "vless",
		"network": "ws",
		"ws-opts": map[string]any{
			"path":               "/up",
			"headers":            map[string]any{"Host": "up.example.com"},
			"v2ray-http-upgrade": true,
		},
	})
	checkClash(t, nodes[15], map[string]any{
		"type":    "vmess",
		"network": "ws",
		"ws-opts": map[string]any{
			"path":               "/up2",
			"v2ray-http-upgrade": true,
		},
	})
	checkClash(t, nodes[16], map[string]any{
		"type":    "trojan",
		"network": "ws",
		"ws-opts": map[string]any{
			"v2ray-http-upgrade": true,
		},
	})
}

func TestParseSurge_WireGuardInline(t *testing.T) {
	line := `WG-Inline = wireguard, wg.example.com, 2408, private-key=privkey, public-key=pubkey, ip=10.0.0.2/32, ipv6=fd00::2/128, mtu=1420, reserved=1, preshared-key=psk`
	nodes, skipped, err := parseSurge(line)
	if err != nil || len(skipped) != 0 || len(nodes) != 1 {
		t.Fatalf("parse failed: nodes=%v skipped=%v err=%v", nodes, skipped, err)
	}
	checkClash(t, nodes[0], map[string]any{
		"type":           "wireguard",
		"server":         "wg.example.com",
		"port":           2408,
		"private-key":    "privkey",
		"public-key":     "pubkey",
		"pre-shared-key": "psk",
		"ip":             "10.0.0.2",
		"ipv6":           "fd00::2",
		"mtu":            1420,
		"reserved":       []int{1},
		"udp":            true,
	})
}

func TestParseSurge_SectionNameMissing(t *testing.T) {
	conf := "[Proxy]\nWG = wireguard, section-name=Nope\n"
	nodes, skipped, err := parseSurge(conf)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 0 || len(skipped) != 1 {
		t.Errorf("nodes=%d skipped=%v, want 0/1", len(nodes), skipped)
	}
}
