package parser

import "testing"

// The QuanX type sits on the left of "=", while Surge puts the node name
// there. A Surge line must not be read as QuanX and vice versa.
func TestParseQuanX_Detection(t *testing.T) {
	quanx := "shadowsocks=1.2.3.4:8388, method=aes-128-gcm, password=pw, tag=HK\n"
	surge := "HK = ss, 1.2.3.4, 8388, encrypt-method=aes-128-gcm, password=pw\n"

	if !looksLikeQuanX(quanx) {
		t.Error("QuanX node line not detected")
	}
	if looksLikeQuanX(surge) {
		t.Error("Surge [Proxy] line detected as QuanX")
	}
	if looksLikeSurge(quanx) {
		t.Error("QuanX node line detected as Surge")
	}

	nodes, skipped, err := Parse([]byte(surge))
	if err != nil || len(nodes) != 1 || len(skipped) != 0 {
		t.Fatalf("Surge parsing regressed: nodes=%d skipped=%v err=%v", len(nodes), skipped, err)
	}
}

func TestParseQuanX_Shadowsocks(t *testing.T) {
	text := "shadowsocks=1.2.3.4:8388, method=aes-128-gcm, password=pw, obfs=http, obfs-host=bing.com, udp-relay=true, tag=HK 01\n"
	nodes, _, err := Parse([]byte(text))
	if err != nil || len(nodes) != 1 {
		t.Fatalf("nodes=%d err=%v", len(nodes), err)
	}
	p := nodes[0]
	if p.Type != "ss" || p.Name != "HK 01" || p.Server != "1.2.3.4" || p.Port != 8388 {
		t.Errorf("node = %+v", p)
	}
	if p.Clash["cipher"] != "aes-128-gcm" || p.Clash["password"] != "pw" {
		t.Errorf("credentials = %v", p.Clash)
	}
	if p.Clash["udp"] != true {
		t.Error("udp-relay=true did not map to udp: true")
	}
	opts, _ := p.Clash["plugin-opts"].(map[string]any)
	if p.Clash["plugin"] != "obfs" || opts["mode"] != "http" || opts["host"] != "bing.com" {
		t.Errorf("obfs mapping = %v %v", p.Clash["plugin"], opts)
	}
}

func TestParseQuanX_ShadowsocksR(t *testing.T) {
	text := "shadowsocksr=6.6.6.6:8388, method=aes-128-cfb, password=pw, protocol=auth_sha1_v4, protocol-param=abc, obfs=http_simple, obfs-param=def, tag=SSR\n"
	nodes, _, err := Parse([]byte(text))
	if err != nil || len(nodes) != 1 {
		t.Fatalf("nodes=%d err=%v", len(nodes), err)
	}
	p := nodes[0]
	if p.Type != "ssr" {
		t.Errorf("type = %q, want ssr", p.Type)
	}
	for k, want := range map[string]any{
		"cipher": "aes-128-cfb", "protocol": "auth_sha1_v4", "protocol-param": "abc",
		"obfs": "http_simple", "obfs-param": "def",
	} {
		if p.Clash[k] != want {
			t.Errorf("%s = %v, want %v", k, p.Clash[k], want)
		}
	}
}

func TestParseQuanX_VMess(t *testing.T) {
	text := "vmess=2.2.2.2:443, method=chacha20-poly1305, password=uuid-x, obfs=wss, obfs-host=example.com, obfs-uri=/ws, tls-verification=false, tag=US\n"
	nodes, _, err := Parse([]byte(text))
	if err != nil || len(nodes) != 1 {
		t.Fatalf("nodes=%d err=%v", len(nodes), err)
	}
	p := nodes[0]
	if p.Type != "vmess" || p.Clash["uuid"] != "uuid-x" {
		t.Errorf("node = %+v", p.Clash)
	}
	if p.Clash["network"] != "ws" || p.Clash["tls"] != true {
		t.Errorf("obfs=wss must be ws + tls: %v", p.Clash)
	}
	if p.Clash["skip-cert-verify"] != true {
		t.Error("tls-verification=false did not map to skip-cert-verify: true")
	}
	opts, _ := p.Clash["ws-opts"].(map[string]any)
	if opts["path"] != "/ws" {
		t.Errorf("ws path = %v, want /ws", opts["path"])
	}
	headers, _ := opts["headers"].(map[string]any)
	if headers["Host"] != "example.com" {
		t.Errorf("ws Host header = %v", headers)
	}
}

func TestParseQuanX_TrojanHTTPAndSocks(t *testing.T) {
	text := "trojan=3.3.3.3:443, password=pw, tls-host=t.example.com, tag=JP\n" +
		"http=4.4.4.4:8080, username=u, password=p, tag=Proxy\n" +
		"socks5=5.5.5.5:1080, username=u, password=p, tag=Socks\n"
	nodes, skipped, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 || len(skipped) != 0 {
		t.Fatalf("nodes=%d skipped=%v", len(nodes), skipped)
	}
	if nodes[0].Type != "trojan" || nodes[0].Clash["sni"] != "t.example.com" {
		t.Errorf("trojan = %+v", nodes[0].Clash)
	}
	if nodes[1].Type != "http" || nodes[1].Clash["username"] != "u" {
		t.Errorf("http = %+v", nodes[1].Clash)
	}
	if nodes[2].Type != "socks5" {
		t.Errorf("socks5 type = %q", nodes[2].Type)
	}
}

// A full QuanX resource carries filters and rewrites. Only the server sections
// are nodes; the rest must not become skipped-line noise.
func TestParseQuanX_Sections(t *testing.T) {
	text := `[server_local]
shadowsocks=1.2.3.4:8388, method=aes-128-gcm, password=pw, tag=HK

[filter_local]
geoip, cn, direct
final, proxy

[rewrite_local]
^https?://example\.com url reject
`
	nodes, skipped, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Name != "HK" {
		t.Fatalf("nodes = %+v, want only the server", nodes)
	}
	if len(skipped) != 0 {
		t.Errorf("skipped = %v, want nothing: other sections are not node lines", skipped)
	}
}

func TestParseQuanX_SkipsIncomplete(t *testing.T) {
	text := "shadowsocks=1.2.3.4:8388, password=pw, tag=no-method\n" +
		"wireguard=7.7.7.7:51820, password=x, tag=unknown\n" +
		"shadowsocks=8.8.8.8:8388, method=aes-128-gcm, password=pw, tag=good\n"
	nodes, skipped, err := Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Name != "good" {
		t.Fatalf("nodes = %+v, want only the valid line", nodes)
	}
	if len(skipped) != 2 {
		t.Errorf("skipped = %v, want 2 reasons", skipped)
	}
}
