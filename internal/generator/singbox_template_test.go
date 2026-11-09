package generator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/parser"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// repoTemplateDir points templateDir at the repository's templates/ directory
// (tests run inside the package directory). The caller must restore it.
func repoTemplateDir(t *testing.T) {
	t.Helper()
	old := templateDir
	templateDir = filepath.Join("..", "..", "templates")
	t.Cleanup(func() { templateDir = old })
}

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
	repoTemplateDir(t)
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

func TestGenerateSingboxTemplate_DollarInUserDataIsLiteral(t *testing.T) {
	// "$" in passwords/node names must survive rendering: ReplaceAllString
	// would expand "$0" to the matched placeholder and "$1" to "".
	nodes, _, err := parseLinks(
		"ss://"+b64("aes-256-gcm:pass$0x1")+"@1.2.3.4:8388#[US] $0.05/GB",
		"ss://"+b64("aes-256-gcm:pass$1word")+"@5.6.7.8:8388#JP$2",
	)
	if err != nil {
		t.Fatal(err)
	}
	res, err := GenerateSingboxTemplate(context.Background(), nodes, &extconfig.Config{EnableRuleGenerator: true}, []byte(miniTemplate), Options{})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)
	for _, want := range []string{"pass$0x1", "[US] $0.05/GB", "pass$1word", "JP$2"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing literal %q ($-expansion corrupted it):\n%s", want, out)
		}
	}
	if strings.Contains(out, "{{ Nodes }}") {
		t.Errorf("placeholder expanded into user data:\n%s", out)
	}
}

func TestBuiltinTemplate_ReadsFromDisk(t *testing.T) {
	old := templateDir
	templateDir = t.TempDir()
	t.Cleanup(func() { templateDir = old })

	// Unknown names are rejected without touching the disk.
	if b, ok := BuiltinTemplate("../momo"); ok {
		t.Errorf(`BuiltinTemplate("../momo") = (%d bytes, true), want not found`, len(b))
	}
	// A known name whose file is missing is a miss, not an error.
	if b, ok := BuiltinTemplate("momo"); ok {
		t.Errorf("BuiltinTemplate(momo) with no file on disk = (%d bytes, true), want not found", len(b))
	}
	// Writing templates/momo.json into templateDir makes the lookup succeed.
	if err := os.WriteFile(filepath.Join(templateDir, "momo.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, ok := BuiltinTemplate(" MOMO ") // names are case-insensitive, trimmed
	if !ok || string(b) != "{}" {
		t.Errorf("BuiltinTemplate(momo) = (%q, %v), want ({}, true)", b, ok)
	}
}

func TestGenerateSingboxTemplate_NoValidNodesFailsClosed(t *testing.T) {
	// All nodes filtered/dropped/unsupported: must return a clear business
	// error, not a leading-comma JSON syntax error from an empty injection.
	nodes, _, err := parseLinks("ss://" + b64("aes-256-gcm:pass") + "@127.0.0.1:8388#官网占位")
	if err != nil {
		t.Fatal(err)
	}
	_, err = GenerateSingboxTemplate(context.Background(), nodes, &extconfig.Config{EnableRuleGenerator: true}, []byte(miniTemplate), Options{})
	if err == nil {
		t.Fatal("expected error for zero renderable outbounds")
	}
	if !strings.Contains(err.Error(), "no valid nodes") {
		t.Errorf("error = %v, want a clear no-nodes message", err)
	}
}

func TestGenerateSingboxTemplate_MissingPlaceholderFailsClosed(t *testing.T) {
	// A template without {{ Nodes }} would silently drop every node; reject it.
	nodes, _, err := parseLinks("ss://" + b64("aes-256-gcm:pass") + "@1.2.3.4:8388#HK01")
	if err != nil {
		t.Fatal(err)
	}
	bad := `{"outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}`
	_, err = GenerateSingboxTemplate(context.Background(), nodes, &extconfig.Config{EnableRuleGenerator: true}, []byte(bad), Options{})
	if err == nil {
		t.Fatal("expected error for template without {{ Nodes }}")
	}
	if !strings.Contains(err.Error(), "placeholder") {
		t.Errorf("error = %v, want a missing-placeholder message", err)
	}
}
