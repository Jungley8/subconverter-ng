package generator

import (
	"context"
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
	if err := yaml.Unmarshal(res.YAML, &doc); err != nil {
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
