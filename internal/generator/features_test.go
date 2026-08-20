package generator

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

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
