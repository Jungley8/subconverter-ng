package parser

import (
	"strings"
	"testing"
)

func TestParseHysteria1(t *testing.T) {
	uri := "hysteria://h.example.com:8443?protocol=udp&auth=secretauth&peer=sni.example.com&insecure=1&upmbps=100&downmbps=200&obfs=xplus&alpn=h3#HY1"
	p, err := parseHysteria1(uri)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != "hysteria" || p.Server != "h.example.com" || p.Port != 8443 {
		t.Errorf("bad hysteria fields: %+v", p)
	}
	if p.Clash["auth-str"] != "secretauth" {
		t.Errorf("auth-str = %v", p.Clash["auth-str"])
	}
	if p.Clash["up"] != "100" || p.Clash["down"] != "200" {
		t.Errorf("up/down = %v/%v", p.Clash["up"], p.Clash["down"])
	}
	if p.Clash["sni"] != "sni.example.com" || p.Clash["obfs"] != "xplus" {
		t.Errorf("sni/obfs = %v/%v", p.Clash["sni"], p.Clash["obfs"])
	}
	if p.Clash["protocol"] != "udp" || p.Clash["skip-cert-verify"] != true {
		t.Errorf("protocol/skip = %v/%v", p.Clash["protocol"], p.Clash["skip-cert-verify"])
	}
	if alpn, ok := p.Clash["alpn"].([]string); !ok || len(alpn) != 1 || alpn[0] != "h3" {
		t.Errorf("alpn = %v", p.Clash["alpn"])
	}
	if p.Name != "HY1" {
		t.Errorf("name = %v", p.Name)
	}
}

func TestParseSSR(t *testing.T) {
	pass := b64("ssrpass")
	obfsParam := b64("breakwa11.moe")
	protoParam := b64("64")
	remarks := b64("SSR Node")
	body := "ssr.example.com:1234:auth_aes128_md5:aes-256-cfb:tls1.2_ticket_auth:" + pass +
		"/?obfsparam=" + obfsParam + "&protoparam=" + protoParam + "&remarks=" + remarks + "&group=" + b64("g")
	uri := "ssr://" + b64(body)

	p, err := parseSSR(uri)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != "ssr" || p.Server != "ssr.example.com" || p.Port != 1234 {
		t.Errorf("bad ssr fields: %+v", p)
	}
	if p.Clash["cipher"] != "aes-256-cfb" || p.Clash["password"] != "ssrpass" {
		t.Errorf("cipher/password = %v/%v", p.Clash["cipher"], p.Clash["password"])
	}
	if p.Clash["protocol"] != "auth_aes128_md5" || p.Clash["obfs"] != "tls1.2_ticket_auth" {
		t.Errorf("protocol/obfs = %v/%v", p.Clash["protocol"], p.Clash["obfs"])
	}
	if p.Clash["protocol-param"] != "64" || p.Clash["obfs-param"] != "breakwa11.moe" {
		t.Errorf("proto/obfs param = %v/%v", p.Clash["protocol-param"], p.Clash["obfs-param"])
	}
	if p.Name != "SSR Node" || p.Clash["udp"] != true {
		t.Errorf("name/udp = %v/%v", p.Name, p.Clash["udp"])
	}
}

func TestParseSOCKS_PlainAndBase64(t *testing.T) {
	p, err := parseSOCKS("socks5://user:pass@s.example.com:1080#SK")
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != "socks5" || p.Server != "s.example.com" || p.Port != 1080 {
		t.Errorf("bad socks fields: %+v", p)
	}
	if p.Clash["username"] != "user" || p.Clash["password"] != "pass" {
		t.Errorf("user/pass = %v/%v", p.Clash["username"], p.Clash["password"])
	}
	if p.Clash["udp"] != true || p.Name != "SK" {
		t.Errorf("udp/name = %v/%v", p.Clash["udp"], p.Name)
	}

	// base64(user:pass) in userinfo, via socks:// alias.
	creds := b64("alice:s3cret")
	p2, err := parseSOCKS("socks://" + creds + "@h2.example.com:7891#S2")
	if err != nil {
		t.Fatal(err)
	}
	if p2.Clash["username"] != "alice" || p2.Clash["password"] != "s3cret" {
		t.Errorf("decoded user/pass = %v/%v", p2.Clash["username"], p2.Clash["password"])
	}

	// No auth socks5 link (like Tailscale node).
	p3, err := parseSOCKS("socks5://100.106.251.111:1080#Tailscale")
	if err != nil {
		t.Fatal(err)
	}
	if p3.Type != "socks5" || p3.Server != "100.106.251.111" || p3.Port != 1080 || p3.Name != "Tailscale" {
		t.Errorf("bad socks5 no-auth fields: %+v", p3)
	}
	if _, ok := p3.Clash["username"]; ok {
		t.Errorf("username should not be set when empty")
	}

	// Full base64 host part.
	fullB64 := b64("myuser:mypass@100.106.251.111:1080")
	p4, err := parseSOCKS("socks5://" + fullB64 + "#B64Tailscale")
	if err != nil {
		t.Fatal(err)
	}
	if p4.Server != "100.106.251.111" || p4.Port != 1080 || p4.Name != "B64Tailscale" {
		t.Errorf("bad socks5 full-b64 fields: %+v", p4)
	}
	if p4.Clash["username"] != "myuser" || p4.Clash["password"] != "mypass" {
		t.Errorf("bad socks5 full-b64 creds: %v/%v", p4.Clash["username"], p4.Clash["password"])
	}

	// tg://socks format.
	p5, err := parseSOCKS("tg://socks?server=100.106.251.111&port=1080&user=tguser&pass=tgpass#TGSocks")
	if err != nil {
		t.Fatal(err)
	}
	if p5.Server != "100.106.251.111" || p5.Port != 1080 || p5.Name != "TGSocks" {
		t.Errorf("bad tg://socks fields: %+v", p5)
	}
	if p5.Clash["username"] != "tguser" || p5.Clash["password"] != "tgpass" {
		t.Errorf("bad tg://socks creds: %v/%v", p5.Clash["username"], p5.Clash["password"])
	}
}

func TestParseAnyTLS(t *testing.T) {
	uri := "anytls://mypassword@a.example.com:8443?sni=sni.example.com&insecure=1&alpn=h2,http/1.1#AT"
	p, err := parseAnyTLS(uri)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != "anytls" || p.Server != "a.example.com" || p.Port != 8443 {
		t.Errorf("bad anytls fields: %+v", p)
	}
	if p.Clash["password"] != "mypassword" || p.Clash["sni"] != "sni.example.com" {
		t.Errorf("password/sni = %v/%v", p.Clash["password"], p.Clash["sni"])
	}
	if p.Clash["skip-cert-verify"] != true || p.Clash["udp"] != true {
		t.Errorf("skip/udp = %v/%v", p.Clash["skip-cert-verify"], p.Clash["udp"])
	}
	if alpn, ok := p.Clash["alpn"].([]string); !ok || len(alpn) != 2 {
		t.Errorf("alpn = %v", p.Clash["alpn"])
	}
}

func TestParse_DispatchesNewSchemes(t *testing.T) {
	ssrBody := "ssr.h:443:origin:aes-128-cfb:plain:" + b64("pw") +
		"/?remarks=" + b64("R")
	lines := []string{
		"hysteria://h.h:8443?auth=a&peer=s",
		"ssr://" + b64(ssrBody),
		"socks5://u:p@h.h:1080",
		"anytls://pw@h.h:8443?sni=s",
	}
	sub := b64(strings.Join(lines, "\n"))

	nodes, skipped, err := Parse([]byte(sub))
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 0 {
		t.Errorf("unexpected skipped: %v", skipped)
	}
	got := map[string]bool{}
	for _, n := range nodes {
		got[n.Type] = true
	}
	for _, want := range []string{"hysteria", "ssr", "socks5", "anytls"} {
		if !got[want] {
			t.Errorf("Parse did not dispatch %q; got %d nodes %v", want, len(nodes), got)
		}
	}
}
