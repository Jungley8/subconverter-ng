package generator

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

func sbProtocolNode(typ, name string, fields map[string]any) *proxy.Proxy {
	p := proxy.New(typ, name, name+".example.com", 443)
	for k, v := range fields {
		p.Clash[k] = v
	}
	return p
}

// sbRender renders nodes through the sing-box generator and returns the parsed
// outbounds keyed by tag.
func sbRender(t *testing.T, nodes []*proxy.Proxy, ver *Version) (*Result, map[string]map[string]any) {
	t.Helper()
	cfg := &extconfig.Config{
		ProxyGroups: []extconfig.ProxyGroup{{Name: "Proxy", Type: "select", Selectors: []string{".*"}}},
	}
	res, err := GenerateSingbox(context.Background(), nodes, cfg, fakeFetcher{}, Options{TargetVersion: ver})
	if err != nil {
		t.Fatalf("GenerateSingbox: %v", err)
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	tags := make(map[string]map[string]any, len(doc.Outbounds))
	for _, ob := range doc.Outbounds {
		tag, _ := ob["tag"].(string)
		tags[tag] = ob
	}
	return res, tags
}

func sbJSONInt(m map[string]any, k string) int {
	f, _ := m[k].(float64)
	return int(f)
}

func TestGenerateSingboxSnell(t *testing.T) {
	nodes := []*proxy.Proxy{
		sbProtocolNode("snell", "Snell4", map[string]any{
			"psk": "snell-pass", "version": 4, "reuse": true,
			"obfs-opts": map[string]any{"mode": "http", "host": "bing.com"},
		}),
		sbProtocolNode("snell", "Snell6", map[string]any{
			"psk": "snell-pass", "version": 6, "userkey": "uk-1", "mode": "unshaped",
			"obfs-opts": map[string]any{"mode": "http", "host": "v4-only.example.com"},
		}),
	}
	_, tags := sbRender(t, nodes, nil)

	v4 := tags["Snell4"]
	if v4 == nil {
		t.Fatal("Snell4 outbound missing")
	}
	if v4["type"] != "snell" || v4["psk"] != "snell-pass" {
		t.Errorf("Snell4 = %v, want type snell with psk", v4)
	}
	if got := sbJSONInt(v4, "version"); got != 4 {
		t.Errorf("Snell4 version = %d, want 4", got)
	}
	if v4["obfs_mode"] != "http" || v4["obfs_host"] != "bing.com" {
		t.Errorf("Snell4 obfs = %v/%v, want http/bing.com", v4["obfs_mode"], v4["obfs_host"])
	}
	if v4["reuse"] != true {
		t.Errorf("Snell4 reuse = %v, want true", v4["reuse"])
	}
	if _, ok := v4["mode"]; ok {
		t.Errorf("Snell4 must not carry the v6 mode: %v", v4)
	}

	v6 := tags["Snell6"]
	if v6 == nil {
		t.Fatal("Snell6 outbound missing")
	}
	if got := sbJSONInt(v6, "version"); got != 6 {
		t.Errorf("Snell6 version = %d, want 6", got)
	}
	if v6["userkey"] != "uk-1" || v6["mode"] != "unshaped" {
		t.Errorf("Snell6 userkey/mode = %v/%v, want uk-1/unshaped", v6["userkey"], v6["mode"])
	}
	if _, ok := v6["obfs_mode"]; ok {
		t.Errorf("Snell6 must not carry v4 obfs: %v", v6)
	}
	if _, ok := v6["obfs_host"]; ok {
		t.Errorf("Snell6 must not carry v4 obfs host: %v", v6)
	}
}

func TestGenerateSingboxSnellVersionGate(t *testing.T) {
	// Only versions 4 and 6 exist in sing-box; an absent version means 1.
	for _, v := range []int{0, 1, 2, 3, 5} {
		fields := map[string]any{"psk": "p"}
		if v > 0 {
			fields["version"] = v
		}
		res, tags := sbRender(t, []*proxy.Proxy{sbProtocolNode("snell", "S", fields)}, nil)
		if tags["S"] != nil {
			t.Errorf("version %d must not be emitted: %v", v, tags["S"])
		}
		if want := "S (snell: requires snell version 4 or 6)"; !strings.Contains(strings.Join(res.SkippedNodes, "\n"), want) {
			t.Errorf("version %d: skipped nodes = %v, want %q", v, res.SkippedNodes, want)
		}
	}
}

func TestGenerateSingboxSnellUnsupportedObfs(t *testing.T) {
	// ShadowTLS is handled as a chain only for shadowsocks; a snell wrapper has
	// no sing-box equivalent.
	res, tags := sbRender(t, []*proxy.Proxy{sbProtocolNode("snell", "SnellTLS", map[string]any{
		"psk": "p", "version": 4,
		"obfs-opts": map[string]any{"mode": "shadow-tls", "host": "cam.example.com", "password": "tlspass", "version": 3},
	})}, nil)
	if tags["SnellTLS"] != nil {
		t.Errorf("snell shadow-tls must not be emitted: %v", tags["SnellTLS"])
	}
	if want := "SnellTLS (snell: snell shadow-tls: unsupported by sing-box)"; !strings.Contains(strings.Join(res.SkippedNodes, "\n"), want) {
		t.Errorf("skipped nodes = %v, want %q", res.SkippedNodes, want)
	}

	res, tags = sbRender(t, []*proxy.Proxy{sbProtocolNode("snell", "SnellObfsTLS", map[string]any{
		"psk": "p", "version": 4,
		"obfs-opts": map[string]any{"mode": "tls", "host": "cam.example.com"},
	})}, nil)
	if tags["SnellObfsTLS"] != nil {
		t.Errorf("snell tls obfs must not be emitted: %v", tags["SnellObfsTLS"])
	}
	if want := "SnellObfsTLS (snell: snell obfs tls is not supported by sing-box)"; !strings.Contains(strings.Join(res.SkippedNodes, "\n"), want) {
		t.Errorf("skipped nodes = %v, want %q", res.SkippedNodes, want)
	}
}

func TestGenerateSingboxSSH(t *testing.T) {
	nodes := []*proxy.Proxy{
		sbProtocolNode("ssh", "SSHKey", map[string]any{
			"username":               "root",
			"private-key":            "PRIVATE-KEY",
			"private-key-passphrase": "key-pass",
			"host-key":               []string{"ssh-ed25519 AAAA"},
		}),
		sbProtocolNode("ssh", "SSHPass", map[string]any{
			"username": "user", "password": "ssh-pass",
		}),
	}
	_, tags := sbRender(t, nodes, nil)

	key := tags["SSHKey"]
	if key == nil {
		t.Fatal("SSHKey outbound missing")
	}
	if key["type"] != "ssh" || key["user"] != "root" {
		t.Errorf("SSHKey = %v, want type ssh user root", key)
	}
	if key["private_key"] != "PRIVATE-KEY" || key["private_key_passphrase"] != "key-pass" {
		t.Errorf("SSHKey key fields = %v/%v", key["private_key"], key["private_key_passphrase"])
	}
	hk, _ := key["host_key"].([]any)
	if len(hk) != 1 || hk[0] != "ssh-ed25519 AAAA" {
		t.Errorf("SSHKey host_key = %v", key["host_key"])
	}

	pw := tags["SSHPass"]
	if pw == nil {
		t.Fatal("SSHPass outbound missing")
	}
	if pw["password"] != "ssh-pass" {
		t.Errorf("SSHPass password = %v, want ssh-pass", pw["password"])
	}
	if _, ok := pw["private_key"]; ok {
		t.Errorf("SSHPass must not invent a private key: %v", pw)
	}
}

func TestGenerateSingboxNaive(t *testing.T) {
	nodes := []*proxy.Proxy{
		sbProtocolNode("naive", "NaiveQUIC", map[string]any{
			"username": "u", "password": "p", "sni": "cam.example.com",
			"alpn": []string{"h2", "http/1.1"}, "skip-cert-verify": true, "quic": true,
		}),
		sbProtocolNode("naive", "NaiveTCP", map[string]any{
			"username": "u", "password": "p",
		}),
	}
	_, tags := sbRender(t, nodes, nil)

	quic := tags["NaiveQUIC"]
	if quic == nil {
		t.Fatal("NaiveQUIC outbound missing")
	}
	if quic["type"] != "naive" || quic["username"] != "u" {
		t.Errorf("NaiveQUIC = %v, want type naive username u", quic)
	}
	if quic["quic"] != true {
		t.Errorf("NaiveQUIC quic = %v, want true", quic["quic"])
	}
	tls, _ := quic["tls"].(map[string]any)
	if tls == nil || tls["enabled"] != true {
		t.Fatalf("NaiveQUIC tls = %v, want enabled", quic["tls"])
	}
	if tls["server_name"] != "cam.example.com" {
		t.Errorf("NaiveQUIC tls.server_name = %v", tls["server_name"])
	}
	if _, ok := tls["alpn"]; ok {
		t.Errorf("naive tls must not carry alpn: %v", tls)
	}
	// sing-box naive TLS has no insecure switch, so skip-cert-verify is dropped.
	if _, ok := tls["insecure"]; ok {
		t.Errorf("naive tls must not carry insecure: %v", tls)
	}

	tcp := tags["NaiveTCP"]
	if tcp == nil {
		t.Fatal("NaiveTCP outbound missing")
	}
	if _, ok := tcp["quic"]; ok {
		t.Errorf("NaiveTCP must not set quic: %v", tcp)
	}
}

func TestGenerateSingboxShadowTLSChain(t *testing.T) {
	t.Run("unique tag", func(t *testing.T) {
		n := shadowTLSNode("HK")
		_, tags := sbRender(t, []*proxy.Proxy{n}, nil)

		inner := tags["HK"]
		if inner == nil || inner["type"] != "shadowsocks" {
			t.Fatalf("inner ss outbound = %v", inner)
		}
		if inner["detour"] != "HK-shadowtls" {
			t.Errorf("inner detour = %v, want HK-shadowtls", inner["detour"])
		}
		if inner["method"] != "aes-256-gcm" {
			t.Errorf("inner method = %v", inner["method"])
		}
		if _, ok := inner["plugin"]; ok {
			t.Errorf("inner ss must not carry a plugin: %v", inner)
		}

		wrapper := tags["HK-shadowtls"]
		if wrapper == nil {
			t.Fatal("shadowtls wrapper outbound missing")
		}
		if wrapper["type"] != "shadowtls" {
			t.Errorf("wrapper type = %v, want shadowtls", wrapper["type"])
		}
		if got := sbJSONInt(wrapper, "version"); got != 3 {
			t.Errorf("wrapper version = %d, want 3", got)
		}
		if wrapper["password"] != "tls-pass" {
			t.Errorf("wrapper password = %v, want tls-pass", wrapper["password"])
		}
		if wrapper["server"] != "HK.example.com" {
			t.Errorf("wrapper server = %v", wrapper["server"])
		}
		tls, _ := wrapper["tls"].(map[string]any)
		if tls == nil || tls["enabled"] != true {
			t.Fatalf("wrapper tls = %v, want enabled", wrapper["tls"])
		}
		if tls["server_name"] != "cam.example.com" {
			t.Errorf("wrapper tls.server_name = %v", tls["server_name"])
		}
		utls, _ := tls["utls"].(map[string]any)
		if utls == nil || utls["fingerprint"] != "chrome" {
			t.Errorf("wrapper tls.utls = %v, want chrome", tls["utls"])
		}
	})

	t.Run("collision appends suffix", func(t *testing.T) {
		// A real node already owns the derived tag, so the wrapper must move.
		decoy := proxy.New("ss", "HK-shadowtls", "decoy.example.com", 8388)
		decoy.Clash["cipher"] = "aes-256-gcm"
		decoy.Clash["password"] = "decoy-pass"
		_, tags := sbRender(t, []*proxy.Proxy{shadowTLSNode("HK"), decoy}, nil)

		if tags["HK"]["detour"] != "HK-shadowtls-2" {
			t.Errorf("inner detour = %v, want HK-shadowtls-2", tags["HK"]["detour"])
		}
		wrapper := tags["HK-shadowtls-2"]
		if wrapper == nil || wrapper["type"] != "shadowtls" {
			t.Fatalf("wrapper = %v, want shadowtls at HK-shadowtls-2", wrapper)
		}
		if decoy := tags["HK-shadowtls"]; decoy == nil || decoy["type"] != "shadowsocks" {
			t.Errorf("decoy node lost its own tag: %v", decoy)
		}
	})
}

func shadowTLSNode(name string) *proxy.Proxy {
	return sbProtocolNode("ss", name, map[string]any{
		"cipher": "aes-256-gcm", "password": "ss-pass",
		"plugin": "shadow-tls",
		"plugin-opts": map[string]any{
			"host": "cam.example.com", "password": "tls-pass", "version": 3,
		},
		"client-fingerprint": "chrome",
	})
}

func TestGenerateSingboxHTTPUpgrade(t *testing.T) {
	upgradeOpts := func() map[string]any {
		return map[string]any{
			"path":               "/up",
			"headers":            map[string]any{"Host": "up.example.com"},
			"v2ray-http-upgrade": true,
		}
	}
	nodes := []*proxy.Proxy{
		sbProtocolNode("vmess", "VM", map[string]any{
			"uuid": "u1", "alterId": 0, "network": "ws", "ws-opts": upgradeOpts(),
		}),
		sbProtocolNode("vless", "VL", map[string]any{
			"uuid": "u2", "network": "ws", "ws-opts": upgradeOpts(),
		}),
		sbProtocolNode("vmess", "PlainWS", map[string]any{
			"uuid": "u3", "alterId": 0, "network": "ws",
			"ws-opts": map[string]any{"path": "/plain"},
		}),
	}
	_, tags := sbRender(t, nodes, nil)

	for _, tag := range []string{"VM", "VL"} {
		tr, _ := tags[tag]["transport"].(map[string]any)
		if tr == nil {
			t.Errorf("%s transport missing", tag)
			continue
		}
		if tr["type"] != "httpupgrade" {
			t.Errorf("%s transport type = %v, want httpupgrade", tag, tr["type"])
		}
		if tr["path"] != "/up" {
			t.Errorf("%s transport path = %v", tag, tr["path"])
		}
		if tr["host"] != "up.example.com" {
			t.Errorf("%s transport host = %v, want up.example.com", tag, tr["host"])
		}
		hdr, _ := tr["headers"].(map[string]any)
		if hdr == nil || hdr["Host"] != "up.example.com" {
			t.Errorf("%s transport headers = %v", tag, tr["headers"])
		}
		// sing-box rejects the ws-only flag as an unknown field.
		if _, ok := tr["v2ray_http_upgrade"]; ok {
			t.Errorf("%s transport must not carry v2ray_http_upgrade: %v", tag, tr)
		}
	}

	tr, _ := tags["PlainWS"]["transport"].(map[string]any)
	if tr == nil || tr["type"] != "ws" {
		t.Fatalf("PlainWS transport = %v", tags["PlainWS"]["transport"])
	}
	if tr["path"] != "/plain" {
		t.Errorf("PlainWS transport path = %v", tr["path"])
	}
	if _, ok := tr["v2ray_http_upgrade"]; ok {
		t.Errorf("plain ws must not set v2ray_http_upgrade: %v", tr)
	}
	if _, ok := tr["host"]; ok {
		t.Errorf("plain ws must not carry the httpupgrade host field: %v", tr)
	}
}

func TestGenerateSingboxNewProtocolFloors(t *testing.T) {
	nodes := func() []*proxy.Proxy {
		return []*proxy.Proxy{
			sbProtocolNode("ssh", "SSH", map[string]any{"username": "u"}),
			sbProtocolNode("naive", "NAIVE", map[string]any{"username": "u"}),
			sbProtocolNode("snell", "SNELL", map[string]any{"psk": "p", "version": 4}),
			sbProtocolNode("ss", "SS", map[string]any{"cipher": "aes-256-gcm", "password": "p"}),
		}
	}
	cases := []struct {
		version     Version
		blocked     []string
		reasonFloor [2]string // tag, "requires sing-box >=" fragment
	}{
		{Version{Major: 1, Minor: 4}, []string{"SSH", "NAIVE", "SNELL"}, [2]string{"SSH", "requires sing-box >= 1.5"}},
		{Version{Major: 1, Minor: 5}, []string{"NAIVE", "SNELL"}, [2]string{"NAIVE", "requires sing-box >= 1.13"}},
		{Version{Major: 1, Minor: 13}, []string{"SNELL"}, [2]string{"SNELL", "requires sing-box >= 1.14"}},
		{Version{Major: 1, Minor: 14}, nil, [2]string{"", ""}},
	}
	for _, tc := range cases {
		v := tc.version
		res, tags := sbRender(t, nodes(), &v)
		skipped := strings.Join(res.SkippedNodes, "\n")
		for _, tag := range tc.blocked {
			if tags[tag] != nil {
				t.Errorf("sing-box %d.%d: %s must be gated out", v.Major, v.Minor, tag)
			}
		}
		if tc.reasonFloor[0] != "" && !strings.Contains(skipped, tc.reasonFloor[1]) {
			t.Errorf("sing-box %d.%d: skipped = %v, want reason %q", v.Major, v.Minor, res.SkippedNodes, tc.reasonFloor[1])
		}
		// ss carries no floor and is always emitted.
		if tags["SS"] == nil {
			t.Errorf("sing-box %d.%d: ss must be emitted", v.Major, v.Minor)
		}
	}
}

func TestGenerateSingboxShadowTLSVersionFloor(t *testing.T) {
	mk := func(version int) []*proxy.Proxy {
		return []*proxy.Proxy{sbProtocolNode("ss", "HK", map[string]any{
			"cipher": "aes-256-gcm", "password": "p",
			"plugin":      "shadow-tls",
			"plugin-opts": map[string]any{"host": "cam.example.com", "password": "tls", "version": version},
		})}
	}

	// v3 needs the 1.3 handshake.
	res, tags := sbRender(t, mk(3), &Version{Major: 1, Minor: 2})
	if tags["HK"] != nil || tags["HK-shadowtls"] != nil {
		t.Errorf("shadowtls v3 must be gated below sing-box 1.3: %v", tags)
	}
	if want := "HK (ss: shadowtls version 3 requires sing-box >= 1.3)"; !strings.Contains(strings.Join(res.SkippedNodes, "\n"), want) {
		t.Errorf("skipped = %v, want %q", res.SkippedNodes, want)
	}

	// v2 exists since 1.0, so it passes 1.2.
	_, tags = sbRender(t, mk(2), &Version{Major: 1, Minor: 2})
	if tags["HK"] == nil || tags["HK-shadowtls"] == nil {
		t.Errorf("shadowtls v2 must be emitted on sing-box 1.2: %v", tags)
	}

	_, tags = sbRender(t, mk(3), &Version{Major: 1, Minor: 3})
	if tags["HK"] == nil || tags["HK-shadowtls"] == nil {
		t.Errorf("shadowtls v3 must be emitted on sing-box 1.3: %v", tags)
	}
}

func TestGenerateSingboxProtocolSkips(t *testing.T) {
	awg := sbProtocolNode("wireguard", "WG", map[string]any{
		"private-key": "priv", "public-key": "pub",
		"amnezia-wg-option": map[string]any{"jc": 3},
	})
	tuic4 := sbProtocolNode("tuic", "T4", map[string]any{"password": "token"})
	tuic4.Version = 4

	nodes := []*proxy.Proxy{
		sbProtocolNode("vless", "VX", map[string]any{"uuid": "u1", "network": "xhttp"}),
		awg,
		sbProtocolNode("masque", "MQ", nil),
		sbProtocolNode("trusttunnel", "TT", nil),
		sbProtocolNode("mieru", "MR", nil),
		tuic4,
		sbProtocolNode("ss", "OK", map[string]any{"cipher": "aes-256-gcm", "password": "p"}),
	}
	res, tags := sbRender(t, nodes, nil)
	skipped := strings.Join(res.SkippedNodes, "\n")

	want := []string{
		"VX (vless: xhttp transport is not supported by sing-box)",
		"WG (wireguard: AmneziaWG is not supported by sing-box)",
		"MQ (masque: masque is an endpoint in sing-box, not an outbound)",
		"TT (trusttunnel: trusttunnel is not supported by sing-box)",
		"MR (mieru: mieru is not supported by sing-box)",
		"T4 (tuic: TUIC v4 is not supported by sing-box)",
	}
	for _, w := range want {
		if !strings.Contains(skipped, w) {
			t.Errorf("skipped nodes missing %q: %v", w, res.SkippedNodes)
		}
	}
	for _, tag := range []string{"VX", "WG", "MQ", "TT", "MR", "T4"} {
		if tags[tag] != nil {
			t.Errorf("skipped node %q was emitted: %v", tag, tags[tag])
		}
	}
	if tags["OK"] == nil {
		t.Fatal("supported ss node must still be emitted")
	}
	// The catch-all group must only reference emitted nodes.
	group, _ := tags["Proxy"]["outbounds"].([]any)
	if len(group) != 1 || group[0] != "OK" {
		t.Errorf("Proxy members = %v, want [OK]", group)
	}
}
