package parser

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestParseSS_SIP002WithPlugin(t *testing.T) {
	plugin := url.QueryEscape("obfs-local;obfs=http;obfs-host=cdn.example.com")
	uri := "ss://" + b64("aes-256-gcm:secret") + "@1.2.3.4:8388?plugin=" + plugin + "#🇭🇰 HK"
	p, err := parseSS(uri)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "🇭🇰 HK" || p.Server != "1.2.3.4" || p.Port != 8388 {
		t.Errorf("bad ss fields: %+v", p)
	}
	if p.Clash["cipher"] != "aes-256-gcm" || p.Clash["password"] != "secret" {
		t.Errorf("bad cred: %v", p.Clash)
	}
	if p.Clash["plugin"] != "obfs" {
		t.Errorf("plugin = %v, want obfs", p.Clash["plugin"])
	}
	opts := p.Clash["plugin-opts"].(map[string]any)
	if opts["mode"] != "http" || opts["host"] != "cdn.example.com" {
		t.Errorf("plugin-opts = %v", opts)
	}
}

func TestParseSS_LegacyForm(t *testing.T) {
	uri := "ss://" + b64("aes-128-gcm:pw@5.6.7.8:1234") + "#legacy"
	p, err := parseSS(uri)
	if err != nil {
		t.Fatal(err)
	}
	if p.Server != "5.6.7.8" || p.Port != 1234 || p.Clash["cipher"] != "aes-128-gcm" {
		t.Errorf("legacy parse wrong: %+v / %v", p, p.Clash)
	}
}

func TestParseSS_V2RayPlugin(t *testing.T) {
	plugin := url.QueryEscape("v2ray-plugin;tls;host=a.com;path=/ws")
	uri := "ss://" + b64("chacha20-ietf-poly1305:pw") + "@h:443?plugin=" + plugin + "#n"
	p, _ := parseSS(uri)
	if p.Clash["plugin"] != "v2ray-plugin" {
		t.Fatalf("plugin = %v", p.Clash["plugin"])
	}
	opts := p.Clash["plugin-opts"].(map[string]any)
	if opts["tls"] != true || opts["path"] != "/ws" {
		t.Errorf("v2ray opts = %v", opts)
	}
}

func TestParseVMess_WS_TLS(t *testing.T) {
	j := `{"v":"2","ps":"JP","add":"jp.com","port":"443","id":"uuid","aid":"0","net":"ws","host":"jp.com","path":"/p","tls":"tls","sni":"jp.com","fp":"chrome"}`
	p, err := parseVMess("vmess://" + b64(j))
	if err != nil {
		t.Fatal(err)
	}
	if p.Clash["tls"] != true || p.Clash["servername"] != "jp.com" || p.Clash["network"] != "ws" {
		t.Errorf("vmess tls/ws wrong: %v", p.Clash)
	}
	if p.Clash["client-fingerprint"] != "chrome" {
		t.Errorf("fp not set: %v", p.Clash)
	}
	ws := p.Clash["ws-opts"].(map[string]any)
	if ws["path"] != "/p" {
		t.Errorf("ws-opts = %v", ws)
	}
}

func TestParseVMess_GRPC_NoTLS(t *testing.T) {
	j := `{"ps":"G","add":"g.com","port":443,"id":"u","aid":0,"net":"grpc","path":"svc"}`
	p, err := parseVMess("vmess://" + b64(j))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Clash["tls"]; ok {
		t.Error("non-tls vmess should not set tls")
	}
	g := p.Clash["grpc-opts"].(map[string]any)
	if g["grpc-service-name"] != "svc" {
		t.Errorf("grpc-opts = %v", g)
	}
}

func TestParseVLESS_RealityAndTLS(t *testing.T) {
	reality := "vless://uuid@us.com:443?security=reality&sni=ms.com&fp=chrome&pbk=KEY&sid=ab&flow=xtls-rprx-vision&type=tcp#US"
	p, err := parseVLESS(reality)
	if err != nil {
		t.Fatal(err)
	}
	if p.Clash["flow"] != "xtls-rprx-vision" || p.Clash["tls"] != true {
		t.Errorf("vless reality wrong: %v", p.Clash)
	}
	ro := p.Clash["reality-opts"].(map[string]any)
	if ro["public-key"] != "KEY" || ro["short-id"] != "ab" {
		t.Errorf("reality-opts = %v", ro)
	}

	tlsWS := "vless://uuid@h:443?security=tls&sni=h&type=ws&host=h&path=/w&allowInsecure=1&alpn=h2,http/1.1#x"
	p2, _ := parseVLESS(tlsWS)
	if p2.Clash["skip-cert-verify"] != true {
		t.Error("allowInsecure should set skip-cert-verify")
	}
	if alpn, ok := p2.Clash["alpn"].([]string); !ok || len(alpn) != 2 {
		t.Errorf("alpn = %v", p2.Clash["alpn"])
	}
}

func TestParseTrojan_GRPCAndWS(t *testing.T) {
	p, err := parseTrojan("trojan://pw@h:443?sni=h&type=grpc&serviceName=gs&allowInsecure=1#T")
	if err != nil {
		t.Fatal(err)
	}
	if p.Clash["password"] != "pw" || p.Clash["network"] != "grpc" {
		t.Errorf("trojan grpc wrong: %v", p.Clash)
	}
	if p.Clash["skip-cert-verify"] != true {
		t.Error("allowInsecure not honored")
	}
}

func TestParseHysteria2_AuthInUserinfoAndQuery(t *testing.T) {
	p, err := parseHysteria2("hysteria2://mypw@h:443?sni=h&insecure=1&obfs=salamander&obfs-password=op#H")
	if err != nil {
		t.Fatal(err)
	}
	if p.Clash["password"] != "mypw" || p.Clash["obfs"] != "salamander" {
		t.Errorf("hy2 userinfo wrong: %v", p.Clash)
	}
	// hy2:// alias with auth in query
	p2, _ := parseHysteria2("hy2://h2.com:8443?auth=qpw&sni=h2.com")
	if p2.Clash["password"] != "qpw" {
		t.Errorf("hy2 query auth wrong: %v", p2.Clash)
	}
}

func TestParseTUIC(t *testing.T) {
	p, err := parseTUIC("tuic://uuid:pass@h:443?congestion_control=bbr&sni=h&alpn=h3#TU")
	if err != nil {
		t.Fatal(err)
	}
	if p.Clash["uuid"] != "uuid" || p.Clash["password"] != "pass" {
		t.Errorf("tuic cred wrong: %v", p.Clash)
	}
	if p.Clash["congestion-controller"] != "bbr" || p.Clash["udp-relay-mode"] != "native" {
		t.Errorf("tuic defaults wrong: %v", p.Clash)
	}
}

func TestParse_DispatchSkipsUnknown(t *testing.T) {
	body := "ss://" + b64("aes-256-gcm:p") + "@h:443#ok\nunknown://garbage\n\n# comment line"
	nodes, skipped, err := Parse([]byte(b64(body)))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Errorf("nodes = %d, want 1", len(nodes))
	}
	if len(skipped) != 1 {
		t.Errorf("skipped = %d, want 1 (unknown scheme)", len(skipped))
	}
}

func TestParse_PlainNoBase64(t *testing.T) {
	// Not base64-wrapped: a raw newline list.
	plain := "trojan://pw@h:443?sni=h#T"
	nodes, _, err := Parse([]byte(plain))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Type != "trojan" {
		t.Errorf("plain list parse failed: %+v", nodes)
	}
}

func TestParse_ClashYAMLPayload(t *testing.T) {
	doc := `
proxies:
  - name: A
    type: ss
    server: 1.1.1.1
    port: 8388
    cipher: aes-256-gcm
    password: p
  - name: B
    type: vmess
    server: 2.2.2.2
    port: 443
rules:
  - MATCH,DIRECT
`
	nodes, _, err := Parse([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 || nodes[0].Name != "A" || nodes[1].Server != "2.2.2.2" {
		t.Errorf("clash yaml lift failed: %+v", nodes)
	}
}

func TestLooksLikeClashYAML(t *testing.T) {
	if !looksLikeClashYAML("proxies:\n  - {}\nrules: []") {
		t.Error("should detect clash yaml")
	}
	if looksLikeClashYAML("ss://abc\nvmess://def") {
		t.Error("node list misdetected as clash yaml")
	}
}
