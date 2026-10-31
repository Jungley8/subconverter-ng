package generator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
	"gopkg.in/yaml.v3"
)

func ssNode(name, server string, port int, cipher string) *proxy.Proxy {
	p := proxy.New("ss", name, server, port)
	p.Set("cipher", cipher)
	p.Set("password", "pw")
	return p
}

func TestDedup(t *testing.T) {
	// Two identical nodes differing only by name -> one removed.
	a := ssNode("HK-1", "1.1.1.1", 8388, "aes-256-gcm")
	b := ssNode("HK-1-dup", "1.1.1.1", 8388, "aes-256-gcm")
	c := ssNode("US", "2.2.2.2", 8388, "aes-256-gcm") // distinct (server)
	out, removed := dedup([]*proxy.Proxy{a, b, c})
	if removed != 1 || len(out) != 2 {
		t.Fatalf("dedup removed=%d len=%d, want 1 and 2", removed, len(out))
	}
	if out[0].Name != "HK-1" || out[1].Name != "US" {
		t.Errorf("dedup kept wrong/first: %q %q", out[0].Name, out[1].Name)
	}
}

func TestUniquifyNames(t *testing.T) {
	// Three nodes share a name; a fourth already occupies the " 2" slot.
	a := ssNode("流量已耗尽!", "1.1.1.1", 8388, "aes-256-gcm")
	b := ssNode("流量已耗尽!", "2.2.2.2", 8388, "aes-256-gcm")
	c := ssNode("流量已耗尽! 2", "3.3.3.3", 8388, "aes-256-gcm")
	d := ssNode("流量已耗尽!", "4.4.4.4", 8388, "aes-256-gcm")
	nodes := []*proxy.Proxy{a, b, c, d}
	uniquifyNames(nodes)

	seen := map[string]bool{}
	for _, n := range nodes {
		if seen[n.Name] {
			t.Fatalf("duplicate name after uniquify: %q", n.Name)
		}
		seen[n.Name] = true
		// Rename must keep the Clash bag in sync so every generator agrees.
		if n.Clash["name"] != n.Name {
			t.Errorf("Clash[name]=%v out of sync with Name=%q", n.Clash["name"], n.Name)
		}
	}
	if b.Name != "流量已耗尽! 2" && b.Name != "流量已耗尽! 3" {
		// b is the first duplicate; it should have taken " 2" but c already
		// held it, so it must probe upward to " 3".
		t.Errorf("unexpected rename for b: %q", b.Name)
	}
}

func TestFilterDeprecated(t *testing.T) {
	good := ssNode("good", "1.1.1.1", 8388, "aes-256-gcm")
	bad := ssNode("bad", "2.2.2.2", 8388, "rc4") // unsupported cipher
	vm := proxy.New("vmess", "vm", "3.3.3.3", 443)
	out, dropped := filterDeprecated([]*proxy.Proxy{good, bad, vm})
	if dropped != 1 || len(out) != 2 {
		t.Fatalf("filterDeprecated dropped=%d len=%d, want 1 and 2", dropped, len(out))
	}
	for _, n := range out {
		if n.Name == "bad" {
			t.Error("deprecated node should have been dropped")
		}
	}
}

func TestGenerateClash_ListOnly(t *testing.T) {
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups:         []extconfig.ProxyGroup{{Name: "G", Type: "select", Selectors: []string{".*"}}},
		Rulesets:            []extconfig.Ruleset{{Group: "G", Inline: "FINAL"}},
	}
	res, err := GenerateClash(context.Background(), mkNodes(), cfg, fakeFetcher{}, Options{ListOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["proxies"] == nil {
		t.Error("list output missing proxies")
	}
	if doc["proxy-groups"] != nil || doc["rules"] != nil {
		t.Error("list output must NOT contain groups/rules")
	}
}

func TestGenerateClash_DedupAndFdnCounted(t *testing.T) {
	nodes := []*proxy.Proxy{
		ssNode("A", "1.1.1.1", 8388, "aes-256-gcm"),
		ssNode("A-dup", "1.1.1.1", 8388, "aes-256-gcm"), // duplicate
		ssNode("legacy", "2.2.2.2", 8388, "rc4"),        // deprecated
	}
	cfg := &extconfig.Config{EnableRuleGenerator: true}
	res, err := GenerateClash(context.Background(), nodes, cfg, fakeFetcher{}, Options{Dedup: true, FilterDeprecated: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.DeprecatedDropped != 1 {
		t.Errorf("DeprecatedDropped = %d, want 1", res.DeprecatedDropped)
	}
	if res.Duplicates != 1 {
		t.Errorf("Duplicates = %d, want 1", res.Duplicates)
	}
	if res.NodeCount != 1 {
		t.Errorf("NodeCount = %d, want 1", res.NodeCount)
	}
}

func TestApplyNodeOptions_AppendType(t *testing.T) {
	nodes := mkNodes() // ss "🇭🇰 HK", vmess "🇺🇲 US"
	applyNodeOptions(nodes, Options{AppendType: true})
	if !strings.HasPrefix(nodes[0].Name, "[SS] ") {
		t.Errorf("append_type ss = %q", nodes[0].Name)
	}
	if !strings.HasPrefix(nodes[1].Name, "[VMESS] ") {
		t.Errorf("append_type vmess = %q", nodes[1].Name)
	}
	if nodes[0].Clash["name"] != nodes[0].Name {
		t.Error("append_type did not sync Clash[name]")
	}
}

func TestGenerateSocks5AllTargets(t *testing.T) {
	node := proxy.New("socks5", "Tailscale", "100.106.251.111", 1080)
	node.Set("username", "myuser")
	node.Set("password", "mypass")
	node.SetRaw("udp", true)

	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups:         []extconfig.ProxyGroup{{Name: "Proxy", Type: "select", Selectors: []string{".*"}}},
		Rulesets:            []extconfig.Ruleset{{Group: "Proxy", Inline: "FINAL"}},
	}
	f := fakeFetcher{}

	// Clash
	clash, err := GenerateClash(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(clash.Output), "type: socks5") {
		t.Fatalf("clash socks5 failed: %v\n%s", err, clash.Output)
	}

	// Singbox
	singbox, err := GenerateSingbox(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(singbox.Output), `"type": "socks"`) {
		t.Fatalf("singbox socks5 failed: %v\n%s", err, singbox.Output)
	}

	// Surge
	surge, err := GenerateSurge(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(surge.Output), "socks5, 100.106.251.111, 1080") {
		t.Fatalf("surge socks5 failed: %v\n%s", err, surge.Output)
	}

	// Loon
	loon, err := GenerateLoon(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(loon.Output), "SOCKS5,100.106.251.111,1080") {
		t.Fatalf("loon socks5 failed: %v\n%s", err, loon.Output)
	}

	// QuanX
	quanx, err := GenerateQuanX(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(quanx.Output), "socks5=100.106.251.111:1080") {
		t.Fatalf("quanx socks5 failed: %v\n%s", err, quanx.Output)
	}

	// V2Ray
	v2ray, err := GenerateV2ray(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil {
		t.Fatalf("v2ray socks5 failed: %v", err)
	}
	v2decoded, _ := base64.StdEncoding.DecodeString(string(v2ray.Output))
	if !strings.Contains(string(v2decoded), "socks5://myuser:mypass@100.106.251.111:1080#Tailscale") {
		t.Fatalf("v2ray socks5 share link mismatch: %s", v2decoded)
	}
}

func TestGenerateTailscaleRules(t *testing.T) {
	nodes := mkNodes()
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups:         []extconfig.ProxyGroup{{Name: "Proxy", Type: "select", Selectors: []string{".*"}}},
		Rulesets:            []extconfig.Ruleset{{Group: "Proxy", Inline: "FINAL"}},
	}
	f := fakeFetcher{}

	// Clash (Inline)
	clash, err := GenerateClash(context.Background(), nodes, cfg, f, Options{Tailscale: true})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(clash.Output, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) < 3 {
		t.Fatalf("clash rules len=%d, want >=3", len(doc.Rules))
	}
	if doc.Rules[0] != "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve" || doc.Rules[1] != "IP-CIDR,fd7a:115c:a1e0::/48,DIRECT,no-resolve" {
		t.Errorf("clash rules[0..1] mismatch: %v", doc.Rules[:2])
	}

	// Clash (RuleProviders)
	clashRP, err := GenerateClash(context.Background(), nodes, cfg, f, Options{Tailscale: true, UseRuleProviders: true})
	if err != nil {
		t.Fatal(err)
	}
	var docRP struct {
		Rules []string `yaml:"rules"`
	}
	if err := yaml.Unmarshal(clashRP.Output, &docRP); err != nil {
		t.Fatal(err)
	}
	if len(docRP.Rules) < 2 {
		t.Fatalf("clashRP rules len=%d, want >=2", len(docRP.Rules))
	}
	if docRP.Rules[0] != "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve" || docRP.Rules[1] != "IP-CIDR,fd7a:115c:a1e0::/48,DIRECT,no-resolve" {
		t.Errorf("clashRP rules[0..1] mismatch: %v", docRP.Rules[:2])
	}

	// Surge
	surge, err := GenerateSurge(context.Background(), nodes, cfg, f, Options{Tailscale: true})
	if err != nil {
		t.Fatal(err)
	}
	s := string(surge.Output)
	ruleIdx := strings.Index(s, "[Rule]\n")
	if ruleIdx == -1 {
		t.Fatal("surge missing [Rule]")
	}
	ruleSection := s[ruleIdx+len("[Rule]\n"):]
	if !strings.HasPrefix(ruleSection, "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve\nIP-CIDR,fd7a:115c:a1e0::/48,DIRECT,no-resolve\n") {
		t.Errorf("surge rule section does not start with tailscale rules:\n%s", ruleSection)
	}

	// Singbox
	singbox, err := GenerateSingbox(context.Background(), nodes, cfg, f, Options{Tailscale: true})
	if err != nil {
		t.Fatal(err)
	}
	var sbDoc struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(singbox.Output, &sbDoc); err != nil {
		t.Fatal(err)
	}
	if len(sbDoc.Route.Rules) < 3 {
		t.Fatalf("singbox rules len=%d, want >= 3", len(sbDoc.Route.Rules))
	}
	// rule 0 is dns, rule 1 is tailscale v4, rule 2 is tailscale v6
	r1, r2 := sbDoc.Route.Rules[1], sbDoc.Route.Rules[2]
	if r1["outbound"] != "direct" || r2["outbound"] != "direct" {
		t.Errorf("singbox tailscale outbound mismatch: %v %v", r1, r2)
	}

	// Loon
	loon, err := GenerateLoon(context.Background(), nodes, cfg, f, Options{Tailscale: true})
	if err != nil {
		t.Fatal(err)
	}
	ls := string(loon.Output)
	if !strings.Contains(ls, "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve") || !strings.Contains(ls, "IP-CIDR,fd7a:115c:a1e0::/48,DIRECT,no-resolve") {
		t.Errorf("loon missing tailscale rules: %s", ls)
	}
}

func TestGenerateListOnlyAllTargets(t *testing.T) {
	nodes := mkNodes()
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups:         []extconfig.ProxyGroup{{Name: "Proxy", Type: "select", Selectors: []string{".*"}}},
		Rulesets:            []extconfig.Ruleset{{Group: "Proxy", Inline: "FINAL"}},
	}
	f := fakeFetcher{}

	// 1. Clash
	clash, err := GenerateClash(context.Background(), nodes, cfg, f, Options{ListOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(clash.Output), "proxy-groups:") || strings.Contains(string(clash.Output), "rules:") {
		t.Errorf("clash list should not contain groups/rules: %s", clash.Output)
	}

	// 2. Singbox
	singbox, err := GenerateSingbox(context.Background(), nodes, cfg, f, Options{ListOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(singbox.Output), `"route":`) || strings.Contains(string(singbox.Output), `"dns":`) {
		t.Errorf("singbox list should not contain route/dns: %s", singbox.Output)
	}

	// 3. Surge
	surge, err := GenerateSurge(context.Background(), nodes, cfg, f, Options{ListOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(surge.Output), "[Proxy Group]") || strings.Contains(string(surge.Output), "[Rule]") {
		t.Errorf("surge list should not contain groups/rules: %s", surge.Output)
	}

	// 4. Shadowrocket
	sr, err := GenerateShadowrocket(context.Background(), nodes, cfg, f, Options{ListOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sr.Output), "[Proxy Group]") || strings.Contains(string(sr.Output), "[Rule]") {
		t.Errorf("shadowrocket list should not contain groups/rules: %s", sr.Output)
	}

	// 5. Loon
	loon, err := GenerateLoon(context.Background(), nodes, cfg, f, Options{ListOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(loon.Output), "[Proxy Group]") || strings.Contains(string(loon.Output), "[Rule]") {
		t.Errorf("loon list should not contain groups/rules: %s", loon.Output)
	}

	// 6. QuanX
	quanx, err := GenerateQuanX(context.Background(), nodes, cfg, f, Options{ListOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(quanx.Output), "[policy]") || strings.Contains(string(quanx.Output), "[filter_local]") {
		t.Errorf("quanx list should not contain policy/filter: %s", quanx.Output)
	}
}

func TestWireguardAllTargets(t *testing.T) {
	node := proxy.New("wireguard", "WG-Node", "1.2.3.4", 51820)
	node.Set("private-key", "privkey")
	node.Set("public-key", "pubkey")
	node.Set("pre-shared-key", "psk")
	node.Set("ip", "10.0.0.2")
	node.Set("ipv6", "fd00::2")
	node.Set("mtu", 1420)
	node.Set("reserved", []int{1, 2, 3})
	node.SetRaw("udp", true)

	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups:         []extconfig.ProxyGroup{{Name: "Proxy", Type: "select", Selectors: []string{".*"}}},
		Rulesets:            []extconfig.Ruleset{{Group: "Proxy", Inline: "FINAL"}},
	}
	f := fakeFetcher{}

	// Clash
	clash, err := GenerateClash(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(clash.Output), "type: wireguard") {
		t.Fatalf("clash wireguard failed: %v\n%s", err, clash.Output)
	}

	// Singbox
	singbox, err := GenerateSingbox(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(singbox.Output), `"type": "wireguard"`) {
		t.Fatalf("singbox wireguard failed: %v\n%s", err, singbox.Output)
	}

	// Loon
	loon, err := GenerateLoon(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(loon.Output), `WireGuard,1.2.3.4,51820,private-key="privkey",public-key="pubkey"`) {
		t.Fatalf("loon wireguard failed: %v\n%s", err, loon.Output)
	}
	if !strings.Contains(string(loon.Output), `reserved=1,2,3`) {
		t.Errorf("loon wireguard missing reserved: %s", loon.Output)
	}

	// Shadowrocket supports native wireguard
	sr, err := GenerateShadowrocket(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sr.Output), `wireguard, 1.2.3.4, 51820, private-key=privkey, public-key=pubkey, ip=10.0.0.2, ipv6=fd00::2, preshared-key=psk, mtu=1420, reserved=1,2,3`) {
		t.Fatalf("shadowrocket wireguard line wrong: %s", sr.Output)
	}

	// V2Ray share link
	v2ray, err := GenerateV2ray(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil {
		t.Fatalf("v2ray wireguard failed: %v", err)
	}
	v2decoded, _ := base64.StdEncoding.DecodeString(string(v2ray.Output))
	if !strings.Contains(string(v2decoded), "wireguard://privkey@1.2.3.4:51820") || !strings.Contains(string(v2decoded), "reserved=1%2C2%2C3") {
		t.Fatalf("v2ray wireguard share link mismatch: %s", v2decoded)
	}

	// Surge skips wireguard (not supported inline)
	surge, err := GenerateSurge(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(surge.SkippedNodes) != 1 {
		t.Errorf("surge should skip unsupported wireguard: %v", surge.SkippedNodes)
	}
}

func TestWireguard_ReservedFromClashYAML(t *testing.T) {
	// In YAML, [1, 2, 3] unmarshals as []any
	node := proxy.New("wireguard", "WG-YAML", "1.2.3.4", 51820)
	node.Set("private-key", "privkey")
	node.Set("public-key", "pubkey")
	node.Set("ip", "10.0.0.2")
	node.Set("reserved", []any{1, 2, 3}) // []any from yaml.Unmarshal

	cfg := &extconfig.Config{EnableRuleGenerator: true}
	f := fakeFetcher{}

	// Singbox
	sb, err := GenerateSingbox(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sb.Output), `"reserved": [`) {
		t.Errorf("singbox did not handle []any reserved from YAML: %s", sb.Output)
	}

	// V2Ray
	v2, err := GenerateV2ray(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	dec, _ := base64.StdEncoding.DecodeString(string(v2.Output))
	if !strings.Contains(string(dec), "reserved=1%2C2%2C3") {
		t.Errorf("v2ray did not handle []any reserved from YAML: %s", dec)
	}
}

func TestHysteria1_AllTargets(t *testing.T) {
	node := proxy.New("hysteria", "HY1", "hy.example.com", 8443)
	node.Set("auth-str", "secretpass")
	node.Set("up", 100)   // integer, as parsed from Clash YAML
	node.Set("down", 200) // integer
	node.Set("sni", "hy.example.com")
	node.SetRaw("skip-cert-verify", true)

	cfg := &extconfig.Config{EnableRuleGenerator: true}
	f := fakeFetcher{}

	// 1. Singbox
	sb, err := GenerateSingbox(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sb.Output), `"type": "hysteria"`) ||
		!strings.Contains(string(sb.Output), `"up_mbps": 100`) ||
		!strings.Contains(string(sb.Output), `"down_mbps": 200`) {
		t.Errorf("singbox hysteria1 output mismatch:\n%s", sb.Output)
	}

	// 2. Shadowrocket
	sr, err := GenerateShadowrocket(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sr.Output), `hysteria, hy.example.com, 8443, auth=secretpass, upmbps=100, downmbps=200, peer=hy.example.com, skip-cert-verify=true`) {
		t.Errorf("shadowrocket hysteria1 output mismatch:\n%s", sr.Output)
	}

	// 3. Loon
	ln, err := GenerateLoon(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ln.Output), `Hysteria,hy.example.com,8443,auth="secretpass",peer="hy.example.com",upmbps=100,downmbps=200,skip-cert-verify=true`) {
		t.Errorf("loon hysteria1 output mismatch:\n%s", ln.Output)
	}

	// 4. V2Ray share link
	v2, err := GenerateV2ray(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	dec, _ := base64.StdEncoding.DecodeString(string(v2.Output))
	if !strings.Contains(string(dec), "hysteria://hy.example.com:8443?") ||
		!strings.Contains(string(dec), "auth=secretpass") ||
		!strings.Contains(string(dec), "upmbps=100") ||
		!strings.Contains(string(dec), "downmbps=200") {
		t.Errorf("v2ray hysteria1 link mismatch: %s", dec)
	}

	// 5. Surge skips Hysteria 1
	surge, err := GenerateSurge(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(surge.SkippedNodes) != 1 {
		t.Errorf("surge should skip hysteria 1: %v", surge.SkippedNodes)
	}
}

func TestHTTPProxyAllTargets(t *testing.T) {
	node := proxy.New("http", "HTTP-Proxy", "proxy.example.com", 8080)
	node.Set("username", "user1")
	node.Set("password", "pass1")
	node.SetRaw("tls", true)
	node.Set("sni", "proxy.example.com")
	node.SetRaw("skip-cert-verify", true)

	cfg := &extconfig.Config{EnableRuleGenerator: true}
	f := fakeFetcher{}

	// Clash
	clash, err := GenerateClash(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(clash.Output), "type: http") {
		t.Errorf("clash http proxy failed: %v", err)
	}

	// Singbox
	sb, err := GenerateSingbox(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(sb.Output), `"type": "http"`) {
		t.Errorf("singbox http proxy failed: %v", err)
	}

	// Surge
	surge, err := GenerateSurge(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(surge.Output), "https, proxy.example.com, 8080, username=user1, password=pass1") {
		t.Errorf("surge http proxy failed: %v\n%s", err, surge.Output)
	}

	// Shadowrocket
	sr, err := GenerateShadowrocket(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(sr.Output), "https, proxy.example.com, 8080, username=user1, password=pass1") {
		t.Errorf("shadowrocket http proxy failed: %v\n%s", err, sr.Output)
	}

	// Loon
	ln, err := GenerateLoon(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(ln.Output), `http,proxy.example.com,8080,"user1","pass1",over-tls=true`) {
		t.Errorf("loon http proxy failed: %v\n%s", err, ln.Output)
	}

	// QuanX
	qx, err := GenerateQuanX(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil || !strings.Contains(string(qx.Output), "http=proxy.example.com:8080, username=user1, password=pass1, over-tls=true") {
		t.Errorf("quanx http proxy failed: %v\n%s", err, qx.Output)
	}

	// V2Ray
	v2, err := GenerateV2ray(context.Background(), []*proxy.Proxy{node}, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	dec, _ := base64.StdEncoding.DecodeString(string(v2.Output))
	if !strings.Contains(string(dec), "https://user1:pass1@proxy.example.com:8080") {
		t.Errorf("v2ray http proxy link mismatch: %s", dec)
	}
}

func TestRuleTypeNormalization_AllTargets(t *testing.T) {
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups:         []extconfig.ProxyGroup{{Name: "Proxy", Type: "select", Selectors: []string{".*"}}},
		Rulesets: []extconfig.Ruleset{
			{Group: "Proxy", Inline: "DEST-PORT,443"},
			{Group: "Proxy", Inline: "HOST,domain.com"},
			{Group: "Proxy", Inline: "HOST-SUFFIX,google.com"},
			{Group: "Proxy", Inline: "HOST-KEYWORD,keyword"},
			{Group: "Proxy", Inline: "IP6-CIDR,2001:db8::/32"},
			{Group: "DIRECT", Inline: "SRC-IP-CIDR,192.168.1.0/24"},
			{Group: "DIRECT", Inline: "FINAL"},
		},
	}
	nodes := mkNodes()
	f := fakeFetcher{}

	// Clash: DEST-PORT -> DST-PORT, HOST* -> DOMAIN*, IP6-CIDR -> IP-CIDR6
	clash, err := GenerateClash(context.Background(), nodes, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	cs := string(clash.Output)
	for _, want := range []string{
		"DST-PORT,443,Proxy",
		"DOMAIN,domain.com,Proxy",
		"DOMAIN-SUFFIX,google.com,Proxy",
		"DOMAIN-KEYWORD,keyword,Proxy",
		"IP-CIDR6,2001:db8::/32,Proxy",
		"SRC-IP-CIDR,192.168.1.0/24,DIRECT",
		"MATCH,DIRECT",
	} {
		if !strings.Contains(cs, want) {
			t.Errorf("clash missing normalized rule %q:\n%s", want, cs)
		}
	}

	// Singbox: port, domain, domain_suffix, domain_keyword, ip_cidr, source_ip_cidr
	sb, err := GenerateSingbox(context.Background(), nodes, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	sbs := string(sb.Output)
	for _, want := range []string{
		`"port": [`,
		`"domain": [`,
		`"domain_suffix": [`,
		`"domain_keyword": [`,
		`"source_ip_cidr": [`,
	} {
		if !strings.Contains(sbs, want) {
			t.Errorf("singbox missing route rule field %q:\n%s", want, sbs)
		}
	}

	// Surge: DEST-PORT, DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR6, SRC-IP-CIDR
	surge, err := GenerateSurge(context.Background(), nodes, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	sgs := string(surge.Output)
	for _, want := range []string{
		"DEST-PORT,443,Proxy",
		"DOMAIN,domain.com,Proxy",
		"DOMAIN-SUFFIX,google.com,Proxy",
		"DOMAIN-KEYWORD,keyword,Proxy",
		"IP-CIDR6,2001:db8::/32,Proxy",
		"SRC-IP-CIDR,192.168.1.0/24,DIRECT",
		"FINAL,DIRECT",
	} {
		if !strings.Contains(sgs, want) {
			t.Errorf("surge missing normalized rule %q:\n%s", want, sgs)
		}
	}

	// QuanX: dest-port, host, host-suffix, host-keyword, ip6-cidr, final, direct
	qx, err := GenerateQuanX(context.Background(), nodes, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	qxs := string(qx.Output)
	for _, want := range []string{
		"dest-port, 443, Proxy",
		"host, domain.com, Proxy",
		"host-suffix, google.com, Proxy",
		"host-keyword, keyword, Proxy",
		"ip6-cidr, 2001:db8::/32, Proxy",
		"final, direct",
	} {
		if !strings.Contains(qxs, want) {
			t.Errorf("quanx missing normalized rule %q:\n%s", want, qxs)
		}
	}
}

func TestQuanX_DirectAndRejectLowercase(t *testing.T) {
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		Rulesets: []extconfig.Ruleset{
			{Group: "DIRECT", Inline: "DOMAIN-SUFFIX,cn"},
			{Group: "REJECT", Inline: "DOMAIN-SUFFIX,ad.com"},
			{Group: "REJECT-DROP", Inline: "DOMAIN-SUFFIX,drop.com"},
			{Group: "DIRECT", Inline: "FINAL"},
		},
	}
	res, err := GenerateQuanX(context.Background(), mkNodes(), cfg, fakeFetcher{}, Options{Tailscale: true})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	for _, want := range []string{
		"host-suffix, cn, direct",
		"host-suffix, ad.com, reject",
		"host-suffix, drop.com, reject",
		"final, direct",
		"ip-cidr, 100.64.0.0/10, direct, no-resolve",
		"ip6-cidr, fd7a:115c:a1e0::/48, direct, no-resolve",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("quanx missing lowercase rule %q:\n%s", want, out)
		}
	}
}

func TestPrepareNodes_SanitizesNewlines(t *testing.T) {
	node := ssNode("HK 01\r\n[Rule]\nDOMAIN,evil.com,REJECT", "1.1.1.1", 8388, "aes-256-gcm")
	cfg := &extconfig.Config{}
	var res Result
	prepared := prepareNodes([]*proxy.Proxy{node}, cfg, Options{}, &res)

	if len(prepared) != 1 {
		t.Fatalf("expected 1 node, got %d", len(prepared))
	}
	name := prepared[0].Name
	if strings.ContainsAny(name, "\r\n") {
		t.Fatalf("prepared node name contains newlines: %q", name)
	}
	if prepared[0].Clash["name"] != name {
		t.Fatalf("Clash['name'] not in sync: %v vs %q", prepared[0].Clash["name"], name)
	}
	if name != "HK 01 [Rule] DOMAIN,evil.com,REJECT" {
		t.Errorf("unexpected sanitized name: %q", name)
	}
}

func TestPrepareNodes_NilSafe(t *testing.T) {
	cfg := &extconfig.Config{}
	var res Result
	prepared := prepareNodes([]*proxy.Proxy{nil}, cfg, Options{}, &res)
	if len(prepared) != 0 {
		t.Fatalf("expected 0 nodes, got %d", len(prepared))
	}
}

type concurrencyTrackingFetcher struct {
	mu          sync.Mutex
	current     int
	maxObserved int
}

func (f *concurrencyTrackingFetcher) Get(ctx context.Context, target string) ([]byte, error) {
	f.mu.Lock()
	f.current++
	if f.current > f.maxObserved {
		f.maxObserved = f.current
	}
	f.mu.Unlock()

	// Sleep slightly to allow concurrency to build up
	time.Sleep(20 * time.Millisecond)

	f.mu.Lock()
	f.current--
	f.mu.Unlock()

	return []byte("DOMAIN-SUFFIX,google.com"), nil
}

func TestCollectRules_SemaphoreConcurrency(t *testing.T) {
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
	}
	for i := 0; i < 32; i++ {
		cfg.Rulesets = append(cfg.Rulesets, extconfig.Ruleset{
			URL:   "http://rules.example.com/test.list",
			Group: "PROXY",
		})
	}
	tracker := &concurrencyTrackingFetcher{}
	rules, _ := collectRules(context.Background(), cfg, tracker, Options{})
	if len(rules) != 32 {
		t.Fatalf("expected 32 rules, got %d", len(rules))
	}
	if tracker.maxObserved > 16 {
		t.Fatalf("max concurrent fetches observed %d exceeded semaphore limit 16", tracker.maxObserved)
	}
}
