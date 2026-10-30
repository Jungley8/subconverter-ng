package generator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/parser"
)

func TestGenerateSingbox(t *testing.T) {
	links := []string{
		"ss://" + b64("aes-256-gcm:pass") + "@1.2.3.4:8388#HK",
		"vmess://" + b64(`{"v":"2","ps":"JP","add":"jp.example.com","port":"443","id":"uuid-1","aid":"0","scy":"auto","net":"ws","host":"jp.example.com","path":"/path","tls":"tls","sni":"jp.example.com"}`),
		"vless://uuid-2@us.example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=ab&flow=xtls-rprx-vision&type=tcp#US",
		"trojan://pass@sg.example.com:443?sni=sg.example.com#SG",
		"hysteria2://authpass@hk2.example.com:443?sni=hk2.example.com&insecure=1&obfs=salamander&obfs-password=xyz#HK2",
	}
	sub := []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
	nodes, _, err := parser.Parse(sub)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups: []extconfig.ProxyGroup{
			{Name: "Proxy", Type: "select", Selectors: []string{".*", "[]DIRECT"}},
			{Name: "Auto", Type: "url-test", Selectors: []string{".*"}, TestURL: "http://t/204", Interval: 300},
		},
		Rulesets: []extconfig.Ruleset{
			{Group: "Proxy", URL: "https://rules/PROXY.list"},
			{Group: "Proxy", Inline: "GEOIP,CN"},
			{Group: "Proxy", Inline: "FINAL"},
		},
	}
	f := fakeFetcher{"PROXY.list": []byte("DOMAIN-SUFFIX,google.com\nIP-CIDR,8.8.8.8/32,no-resolve\nGEOSITE,google\n")}

	res, err := GenerateSingbox(context.Background(), nodes, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ContentType != ctJSON {
		t.Errorf("content type = %q", res.ContentType)
	}

	// Must be valid JSON.
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("invalid sing-box JSON: %v", err)
	}

	tags := map[string]map[string]any{}
	for _, ob := range doc.Outbounds {
		tags[ob["tag"].(string)] = ob
	}
	// Node outbounds present with correct types.
	for tag, wantType := range map[string]string{
		"HK": "shadowsocks", "JP": "vmess", "US": "vless", "SG": "trojan", "HK2": "hysteria2",
	} {
		ob, ok := tags[tag]
		if !ok {
			t.Errorf("missing outbound %q", tag)
			continue
		}
		if ob["type"] != wantType {
			t.Errorf("outbound %q type = %v, want %s", tag, ob["type"], wantType)
		}
	}
	// Group outbounds.
	if tags["Proxy"]["type"] != "selector" {
		t.Errorf("Proxy group type = %v, want selector", tags["Proxy"]["type"])
	}
	if tags["Auto"]["type"] != "urltest" {
		t.Errorf("Auto group type = %v, want urltest", tags["Auto"]["type"])
	}
	// Builtins.
	if tags["direct"] == nil || tags["block"] == nil {
		t.Error("missing direct/block builtins")
	}
	// VLESS reality + utls carried into tls.
	vlessTLS, _ := tags["US"]["tls"].(map[string]any)
	if vlessTLS == nil || vlessTLS["reality"] == nil || vlessTLS["utls"] == nil {
		t.Errorf("vless tls missing reality/utls: %v", tags["US"]["tls"])
	}
	// Route: FINAL -> route.final = Proxy; dns/domain_suffix/geosite rules present.
	if doc.Route.Final != "Proxy" {
		t.Errorf("route.final = %q, want Proxy", doc.Route.Final)
	}
	var sawDomainSuffix, sawDNS, sawGeosite bool
	for _, r := range doc.Route.Rules {
		if r["protocol"] == "dns" {
			sawDNS = true
		}
		if _, ok := r["domain_suffix"]; ok {
			sawDomainSuffix = true
		}
		if _, ok := r["geosite"]; ok {
			sawGeosite = true
		}
	}
	if !sawDNS || !sawDomainSuffix || !sawGeosite {
		t.Errorf("route rules missing dns/domain_suffix/geosite: %+v", doc.Route.Rules)
	}
}

func TestGenerateSingbox_Enhancements(t *testing.T) {
	links := []string{
		"wireguard://privkey@wg.example.com:51820?publickey=pubkey&address=10.0.0.2&presharedkey=psk&mtu=1420&reserved=1,2,3#WG",
		"hysteria://hy.example.com:443?auth=authpass&peer=hy.example.com&insecure=1&upmbps=100&downmbps=50&obfs=hyobfs#HY",
		"ss://" + b64("aes-256-gcm:pass") + "@1.2.3.4:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#SS-OBFS",
	}
	sub := []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
	nodes, _, err := parser.Parse(sub)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups: []extconfig.ProxyGroup{
			{Name: "Proxy", Type: "select", Selectors: []string{".*"}},
		},
		Rulesets: []extconfig.Ruleset{
			{Group: "Proxy", Inline: "IP-ASN,13335"},
			{Group: "Proxy", Inline: "SRC-IP-CIDR,192.168.1.0/24"},
			{Group: "Proxy", Inline: "FINAL"},
		},
	}

	res, err := GenerateSingbox(context.Background(), nodes, cfg, fakeFetcher{}, Options{TFO: true})
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("unmarshal singbox JSON: %v", err)
	}

	tags := map[string]map[string]any{}
	for _, ob := range doc.Outbounds {
		tags[ob["tag"].(string)] = ob
	}

	// WireGuard outbound check
	wg, ok := tags["WG"]
	if !ok || wg["type"] != "wireguard" {
		t.Fatalf("missing or wrong WG outbound: %v", wg)
	}
	if wg["private_key"] != "privkey" || wg["peer_public_key"] != "pubkey" || wg["pre_shared_key"] != "psk" {
		t.Errorf("WG keys mismatch: %v", wg)
	}
	if addrs, ok := wg["local_address"].([]any); !ok || len(addrs) != 1 || addrs[0] != "10.0.0.2/32" {
		t.Errorf("WG local_address mismatch: %v", wg["local_address"])
	}

	// Hysteria v1 check
	hy, ok := tags["HY"]
	if !ok || hy["type"] != "hysteria" {
		t.Fatalf("missing or wrong HY outbound: %v", hy)
	}
	if hy["auth_str"] != "authpass" || hy["up_mbps"] != float64(100) || hy["down_mbps"] != float64(50) {
		t.Errorf("HY speed/auth mismatch: %v", hy)
	}

	// SS with obfs-local and TFO
	ss, ok := tags["SS-OBFS"]
	if !ok || ss["type"] != "shadowsocks" {
		t.Fatalf("missing or wrong SS outbound: %v", ss)
	}
	if ss["plugin"] != "obfs-local" {
		t.Errorf("SS plugin mismatch: %v", ss["plugin"])
	}
	if ss["tcp_fast_open"] != true {
		t.Errorf("SS tcp_fast_open should be true: %v", ss["tcp_fast_open"])
	}

	// Rules check: ip_asn and source_ip_cidr
	var sawASN, sawSrcCIDR bool
	for _, r := range doc.Route.Rules {
		if asn, ok := r["ip_asn"].([]any); ok && len(asn) > 0 && asn[0] == float64(13335) {
			sawASN = true
		}
		if src, ok := r["source_ip_cidr"].([]any); ok && len(src) > 0 && src[0] == "192.168.1.0/24" {
			sawSrcCIDR = true
		}
	}
	if !sawASN || !sawSrcCIDR {
		t.Errorf("missing ip_asn or source_ip_cidr in rules: %+v", doc.Route.Rules)
	}
}

func TestGenerateSingbox_ListOnly(t *testing.T) {
	links := []string{
		"ss://" + b64("aes-256-gcm:pass") + "@1.2.3.4:8388#HK",
	}
	sub := []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
	nodes, _, err := parser.Parse(sub)
	if err != nil {
		t.Fatal(err)
	}

	res, err := GenerateSingbox(context.Background(), nodes, &extconfig.Config{}, fakeFetcher{}, Options{ListOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc["outbounds"] == nil {
		t.Error("singbox list output missing outbounds")
	}
	if doc["route"] != nil || doc["dns"] != nil || doc["inbounds"] != nil {
		t.Errorf("singbox list output must omit route/dns/inbounds: %v", doc)
	}
}
