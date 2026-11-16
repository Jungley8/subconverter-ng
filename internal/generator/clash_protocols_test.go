package generator

import (
	"context"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
	"gopkg.in/yaml.v3"
)

type clashDoc struct {
	Proxies []map[string]any `yaml:"proxies"`
	Groups  []struct {
		Name    string   `yaml:"name"`
		Proxies []string `yaml:"proxies"`
	} `yaml:"proxy-groups"`
}

func generateClashDoc(t *testing.T, nodes []*proxy.Proxy, cfg *extconfig.Config, opts Options) (*Result, clashDoc) {
	t.Helper()
	res, err := GenerateClash(context.Background(), nodes, cfg, fakeFetcher{}, opts)
	if err != nil {
		t.Fatalf("GenerateClash: %v", err)
	}
	var doc clashDoc
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("output is not Clash YAML: %v\n%s", err, res.Output)
	}
	return res, doc
}

func protocolNodes() []*proxy.Proxy {
	ss := proxy.New("ss", "SS", "ss.example.com", 8388)
	ss.Set("cipher", "aes-128-gcm")
	ss.Set("password", "pw")

	naive := proxy.New("naive", "NAIVE", "naive.example.com", 443)
	naive.Set("username", "u")
	naive.Set("password", "pw")

	tu4 := proxy.New("tuic", "TU4", "tu4.example.com", 443)
	tu4.Version = 4
	tu4.Set("password", "token")

	tu5 := proxy.New("tuic", "TU5", "tu5.example.com", 443)
	tu5.Set("uuid", "uuid-1")
	tu5.Set("password", "pw")

	snell := proxy.New("snell", "SN", "sn.example.com", 443)
	snell.Set("psk", "psk1")
	snell.Set("version", 4)

	ssh := proxy.New("ssh", "SSH", "ssh.example.com", 22)
	ssh.Set("username", "alice")
	ssh.Set("password", "pw")

	mieru := proxy.New("mieru", "MI", "mi.example.com", 443)
	mieru.Set("transport", "TCP")

	masque := proxy.New("masque", "MQ", "mq.example.com", 443)
	masque.Set("private-key", "priv")
	masque.Set("public-key", "pub")

	tt := proxy.New("trusttunnel", "TT", "tt.example.com", 443)
	tt.Set("username", "alice")
	tt.Set("password", "pw")

	awg := proxy.New("wireguard", "AWG", "wg.example.com", 51820)
	awg.Set("private-key", "priv")
	awg.Set("public-key", "pub")
	awg.Set("amnezia-wg-option", map[string]any{"jc": 5, "h1": 123456})

	return []*proxy.Proxy{ss, naive, tu4, tu5, snell, ssh, mieru, masque, tt, awg}
}

func TestGenerateClash_SkipsNaiveAndTUICv4(t *testing.T) {
	cfg := &extconfig.Config{ProxyGroups: []extconfig.ProxyGroup{
		{Name: "Auto", Type: "url-test", Selectors: []string{".*"}},
	}}
	res, doc := generateClashDoc(t, protocolNodes(), cfg, Options{})

	gotNames := make(map[string]bool, len(doc.Proxies))
	for _, p := range doc.Proxies {
		gotNames[p["name"].(string)] = true
	}
	if gotNames["NAIVE"] || gotNames["TU4"] {
		t.Errorf("skipped nodes still emitted: %v", gotNames)
	}
	for _, want := range []string{"SS", "TU5", "SN", "SSH", "MI", "MQ", "TT", "AWG"} {
		if !gotNames[want] {
			t.Errorf("node %q missing from output", want)
		}
	}
	if len(doc.Proxies) != 8 {
		t.Errorf("emitted %d proxies, want 8", len(doc.Proxies))
	}

	if len(res.SkippedNodes) != 2 {
		t.Fatalf("SkippedNodes = %v, want 2", res.SkippedNodes)
	}
	if !skipHas(res.SkippedNodes, "NAIVE", "naive") {
		t.Errorf("missing naive skip entry: %v", res.SkippedNodes)
	}
	if !skipHas(res.SkippedNodes, "TU4", "tuic") {
		t.Errorf("missing TUIC v4 skip entry: %v", res.SkippedNodes)
	}

	if len(doc.Groups) != 1 {
		t.Fatalf("groups = %+v", doc.Groups)
	}
	for _, m := range doc.Groups[0].Proxies {
		if m == "NAIVE" || m == "TU4" {
			t.Errorf("group references skipped node %q: %v", m, doc.Groups[0].Proxies)
		}
	}
	if len(doc.Groups[0].Proxies) != 8 {
		t.Errorf("group members = %v, want the 8 emitted nodes", doc.Groups[0].Proxies)
	}
}

func TestGenerateClash_PassesNewTypesUnchanged(t *testing.T) {
	cfg := &extconfig.Config{ProxyGroups: []extconfig.ProxyGroup{
		{Name: "Auto", Type: "select", Selectors: []string{".*"}},
	}}
	_, doc := generateClashDoc(t, protocolNodes(), cfg, Options{})

	byName := make(map[string]map[string]any, len(doc.Proxies))
	for _, p := range doc.Proxies {
		byName[p["name"].(string)] = p
	}
	if got := byName["SN"]["psk"]; got != "psk1" {
		t.Errorf("snell psk = %v", got)
	}
	if got := byName["SSH"]["username"]; got != "alice" {
		t.Errorf("ssh username = %v", got)
	}
	if got := byName["MI"]["transport"]; got != "TCP" {
		t.Errorf("mieru transport = %v", got)
	}
	if got := byName["MQ"]["private-key"]; got != "priv" {
		t.Errorf("masque private-key = %v", got)
	}
	if got := byName["TT"]["username"]; got != "alice" {
		t.Errorf("trusttunnel username = %v", got)
	}
	awgOpts, ok := byName["AWG"]["amnezia-wg-option"].(map[string]any)
	if !ok || awgOpts["jc"] != 5 {
		t.Errorf("AWG option lost: %v", byName["AWG"]["amnezia-wg-option"])
	}
}

// A literal selector can name a skipped node directly. The group must not keep
// a reference to a proxy line that is not in the document.
func TestGenerateClash_LiteralSelectorDropsSkippedNode(t *testing.T) {
	cfg := &extconfig.Config{ProxyGroups: []extconfig.ProxyGroup{
		{Name: "Picked", Type: "select", Selectors: []string{"[]NAIVE", "[]SS"}},
		{Name: "GroupRef", Type: "select", Selectors: []string{"[]Picked"}},
	}}
	res, doc := generateClashDoc(t, protocolNodes(), cfg, Options{})

	var picked, groupRef []string
	for _, g := range doc.Groups {
		switch g.Name {
		case "Picked":
			picked = g.Proxies
		case "GroupRef":
			groupRef = g.Proxies
		}
	}
	if len(picked) != 1 || picked[0] != "SS" {
		t.Errorf("Picked = %v, want [SS]", picked)
	}
	if len(groupRef) != 1 || groupRef[0] != "Picked" {
		t.Errorf("GroupRef = %v, want [Picked]", groupRef)
	}
	if len(res.EmptyGroups) != 0 {
		t.Errorf("EmptyGroups = %v", res.EmptyGroups)
	}
}

func TestGenerateClash_LiteralSelectorAllSkippedFallsBackToDirect(t *testing.T) {
	cfg := &extconfig.Config{ProxyGroups: []extconfig.ProxyGroup{
		{Name: "OnlyNaive", Type: "select", Selectors: []string{"[]NAIVE"}},
	}}
	res, doc := generateClashDoc(t, protocolNodes(), cfg, Options{})
	if len(doc.Groups) != 1 {
		t.Fatalf("groups = %+v", doc.Groups)
	}
	if got := doc.Groups[0].Proxies; len(got) != 1 || got[0] != "DIRECT" {
		t.Errorf("members = %v, want [DIRECT]", got)
	}
	if !clashContains(res.EmptyGroups, "OnlyNaive") {
		t.Errorf("EmptyGroups = %v, want OnlyNaive", res.EmptyGroups)
	}
}

func TestGenerateClash_ListOnlySkipsUnsupported(t *testing.T) {
	_, doc := generateClashDoc(t, protocolNodes(), &extconfig.Config{}, Options{ListOnly: true})
	for _, p := range doc.Proxies {
		if p["name"] == "NAIVE" || p["name"] == "TU4" {
			t.Errorf("list output carries skipped node %v", p["name"])
		}
	}
}

func skipHas(skipped []string, name, typ string) bool {
	for _, s := range skipped {
		if strings.HasPrefix(s, name+" ("+typ+": ") && strings.HasSuffix(s, ")") {
			return true
		}
	}
	return false
}

func clashContains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
