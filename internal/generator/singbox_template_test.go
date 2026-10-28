package generator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/parser"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

const miniTemplate = `{
  "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen_port": 2080}],
  "outbounds": [
    {"type": "selector", "tag": "手动", "outbounds": [
      {{ "" | NotesName }}
    ]},
    {"type": "urltest", "tag": "香港", "outbounds": [
      {{ "香港|HK" | NotesName }}
    ]},
    {"type": "urltest", "tag": "日本", "outbounds": [
      {{ "日本|JP" | NotesName }}
    ]},
    {{ Nodes }},
    {"type": "direct", "tag": "➜ Direct"}
  ],
  "route": {"final": "手动"}
}`

// subFromLinks builds a base64 subscription body from share links.
func subFromLinks(links ...string) []byte {
	return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
}

// parseLinks parses share links into nodes via the regular subscription parser.
func parseLinks(links ...string) ([]*proxy.Proxy, []string, error) {
	return parser.Parse(subFromLinks(links...))
}

func TestGenerateSingboxTemplate(t *testing.T) {
	nodes, _, err := parseLinks(
		"ss://"+b64("aes-256-gcm:pass")+"@1.2.3.4:8388#HK01",
		"ss://"+b64("aes-256-gcm:pass")+"@5.6.7.8:8388#JP01",
		// Provider placeholder node pointing at loopback: must be dropped.
		"ss://"+b64("aes-256-gcm:pass")+"@127.0.0.1:8388#官网",
	)
	if err != nil {
		t.Fatal(err)
	}

	res, err := GenerateSingboxTemplate(context.Background(), nodes, &extconfig.Config{EnableRuleGenerator: true}, []byte(miniTemplate), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ContentType != ctJSON {
		t.Errorf("content type = %q", res.ContentType)
	}
	if strings.Contains(string(res.Output), "{{") {
		t.Errorf("placeholder left unrendered:\n%s", res.Output)
	}

	var doc struct {
		Outbounds []struct {
			Tag       string   `json:"tag"`
			Type      string   `json:"type"`
			Outbounds []string `json:"outbounds"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	groups := map[string][]string{}
	kinds := map[string]string{}
	for _, ob := range doc.Outbounds {
		groups[ob.Tag] = ob.Outbounds
		kinds[ob.Tag] = ob.Type
	}
	if len(groups["手动"]) != 2 {
		t.Errorf("手动 members = %v, want the 2 real nodes", groups["手动"])
	}
	if len(groups["香港"]) != 1 || groups["香港"][0] != "HK01" {
		t.Errorf("香港 members = %v, want [HK01]", groups["香港"])
	}
	if len(groups["日本"]) != 1 || groups["日本"][0] != "JP01" {
		t.Errorf("日本 members = %v, want [JP01]", groups["日本"])
	}
	if kinds["HK01"] == "" || kinds["JP01"] == "" {
		t.Errorf("node outbounds missing: %v", kinds)
	}
	if res.NodeCount != 2 {
		t.Errorf("NodeCount = %d, want 2", res.NodeCount)
	}
	if len(res.SkippedNodes) != 1 || !strings.Contains(res.SkippedNodes[0], "local placeholder") {
		t.Errorf("SkippedNodes = %v, want the loopback placeholder", res.SkippedNodes)
	}
}

func TestGenerateSingboxTemplate_EmptyNotesFallsBackToDirect(t *testing.T) {
	nodes, _, err := parseLinks("ss://" + b64("aes-256-gcm:pass") + "@1.2.3.4:8388#HK01")
	if err != nil {
		t.Fatal(err)
	}
	res, err := GenerateSingboxTemplate(context.Background(), nodes, &extconfig.Config{EnableRuleGenerator: true}, []byte(miniTemplate), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Outbounds []struct {
			Tag       string   `json:"tag"`
			Outbounds []string `json:"outbounds"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, ob := range doc.Outbounds {
		if ob.Tag == "日本" {
			if len(ob.Outbounds) != 1 || ob.Outbounds[0] != "➜ Direct" {
				t.Errorf("empty NotesName = %v, want the ➜ Direct fallback", ob.Outbounds)
			}
			return
		}
	}
	t.Fatal("日本 group missing")
}

func TestGenerateSingboxTemplate_BuiltinMomo(t *testing.T) {
	tmpl, ok := BuiltinTemplate("momo")
	if !ok {
		t.Fatal("builtin momo template missing")
	}
	nodes, _, err := parseLinks(
		"ss://"+b64("aes-256-gcm:pass")+"@1.2.3.4:8388#香港 01",
		"ss://"+b64("aes-256-gcm:pass")+"@5.6.7.8:8388#日本 01",
	)
	if err != nil {
		t.Fatal(err)
	}
	res, err := GenerateSingboxTemplate(context.Background(), nodes, &extconfig.Config{EnableRuleGenerator: true}, tmpl, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
		Outbounds []struct {
			Tag       string   `json:"tag"`
			Outbounds []string `json:"outbounds"`
		} `json:"outbounds"`
		Route struct {
			Final string `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	tags := map[string]bool{}
	for _, ib := range doc.Inbounds {
		tags[ib.Tag] = true
	}
	for _, want := range []string{"dns-in", "tun-in"} {
		if !tags[want] {
			t.Errorf("inbound %q missing (momo self-check would fail)", want)
		}
	}
	members := map[string][]string{}
	for _, ob := range doc.Outbounds {
		members[ob.Tag] = ob.Outbounds
	}
	if len(members["🚀 手动切换"]) != 2 {
		t.Errorf("手动切换 members = %v", members["🚀 手动切换"])
	}
	if len(members["🇭🇰 香港节点"]) != 1 || members["🇭🇰 香港节点"][0] != "香港 01" {
		t.Errorf("香港节点 members = %v", members["🇭🇰 香港节点"])
	}
	if doc.Route.Final == "" {
		t.Error("route.final missing")
	}
}
