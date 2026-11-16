package generator

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
	"gopkg.in/yaml.v3"
)

func attrNodes() []*proxy.Proxy {
	hk := proxy.New("ss", "HK 01", "1.1.1.1", 443)
	us := proxy.New("vmess", "US 01", "2.2.2.2", 8388)
	sg := proxy.New("trojan", "SG 01", "sg.example.com", 9000)
	return []*proxy.Proxy{hk, us, sg}
}

func groupMembers(t *testing.T, res *Result) map[string][]string {
	t.Helper()
	var doc struct {
		Groups []struct {
			Name    string   `yaml:"name"`
			Proxies []string `yaml:"proxies"`
		} `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal(res.Output, &doc); err != nil {
		t.Fatal(err)
	}
	out := make(map[string][]string, len(doc.Groups))
	for _, g := range doc.Groups {
		out[g.Name] = g.Proxies
	}
	return out
}

func runAttr(t *testing.T, selectors []string) map[string][]string {
	t.Helper()
	cfg := &extconfig.Config{ProxyGroups: []extconfig.ProxyGroup{{
		Name: "G", Type: "select", Selectors: selectors,
	}}}
	res, err := GenerateClash(context.Background(), attrNodes(), cfg, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatalf("GenerateClash: %v", err)
	}
	return groupMembers(t, res)
}

func TestAttributeSelectorType(t *testing.T) {
	cases := []struct {
		selector string
		want     []string
	}{
		{`!!TYPE=VMESS`, []string{"US 01"}},
		{`!!TYPE=(?i)vmess`, []string{"US 01"}},
		{`!!TYPE=SS|TROJAN`, []string{"HK 01", "SG 01"}},
		{`!!TYPE=S`, []string{"DIRECT"}}, // full match: SS does not equal S
		{`!!TYPE=SS!!HK`, []string{"HK 01"}},
	}
	for _, c := range cases {
		got := runAttr(t, []string{c.selector})["G"]
		if len(got) != len(c.want) {
			t.Errorf("%s = %v, want %v", c.selector, got, c.want)
			continue
		}
		for i := range c.want {
			if got[i] != c.want[i] {
				t.Errorf("%s = %v, want %v", c.selector, got, c.want)
			}
		}
	}
}

func TestAttributeSelectorPort(t *testing.T) {
	cases := []struct {
		selector string
		want     []string
	}{
		{`!!PORT=443`, []string{"HK 01"}},
		{`!!PORT=8000-9000`, []string{"US 01", "SG 01"}},
		{`!!PORT=8000+`, []string{"US 01", "SG 01"}},
		{`!!PORT=1000-`, []string{"HK 01"}},
		{`!!PORT=!443`, []string{"US 01", "SG 01"}},
		{`!!PORT=443,9000`, []string{"HK 01", "SG 01"}},
	}
	for _, c := range cases {
		got := runAttr(t, []string{c.selector})["G"]
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s = %v, want %v", c.selector, got, c.want)
		}
	}
}

func TestAttributeSelectorServer(t *testing.T) {
	got := runAttr(t, []string{`!!SERVER=sg\.example\.com`})["G"]
	if len(got) != 1 || got[0] != "SG 01" {
		t.Errorf("server selector = %v, want [SG 01]", got)
	}
}

func TestAttributeSelectorGroup(t *testing.T) {
	nodes := attrNodes()
	nodes[0].Group = "Primary"
	nodes[1].Group = "Backup"
	cfg := &extconfig.Config{ProxyGroups: []extconfig.ProxyGroup{{
		Name: "G", Type: "select", Selectors: []string{`!!GROUP=Primary`},
	}}}
	res, err := GenerateClash(context.Background(), nodes, cfg, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := groupMembers(t, res)["G"]
	if len(got) != 1 || got[0] != "HK 01" {
		t.Errorf("group selector = %v, want [HK 01]", got)
	}
}

func TestAttributeSelectorGroupIDAndInsert(t *testing.T) {
	nodes := attrNodes()
	nodes[0].GroupID = 0
	nodes[1].GroupID = 1
	nodes[2].GroupID = -1
	cases := []struct {
		selector string
		want     string
	}{
		{`!!GROUPID=1`, "US 01"},
		{`!!INSERT=1`, "SG 01"},
	}
	for _, c := range cases {
		cfg := &extconfig.Config{ProxyGroups: []extconfig.ProxyGroup{{
			Name: "G", Type: "select", Selectors: []string{c.selector},
		}}}
		res, err := GenerateClash(context.Background(), nodes, cfg, fakeFetcher{}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		got := groupMembers(t, res)["G"]
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%s = %v, want [%s]", c.selector, got, c.want)
		}
	}
}

func TestAttributeSelectorErrors(t *testing.T) {
	for _, sel := range []string{`!!TYPE=`, `!!NOPE=ss`, `!!PORT=abc`, `!!PROVIDER=p1`} {
		cfg := &extconfig.Config{ProxyGroups: []extconfig.ProxyGroup{{
			Name: "G", Type: "select", Selectors: []string{sel},
		}}}
		_, err := GenerateClash(context.Background(), attrNodes(), cfg, fakeFetcher{}, Options{})
		if !errors.Is(err, ErrConfigInvalid) {
			t.Errorf("%s: err = %v, want ErrConfigInvalid", sel, err)
		}
	}
}

func TestMatchRange(t *testing.T) {
	cases := []struct {
		spec   string
		target int
		want   bool
	}{
		{"443", 443, true},
		{"443", 444, false},
		{"1000-2000", 1500, true},
		{"1000-2000", 2001, false},
		{"1000-", 500, true},
		{"1000-", 1001, false},
		{"1000+", 1001, true},
		{"1000+", 999, false},
		{"!443", 444, true},
		{"!443", 443, false},
		{"!1000-2000", 1500, false},
		{"!1000-2000", 900, true},
		{"443,!443", 443, false},
	}
	for _, c := range cases {
		tokens, err := parseRange(c.spec)
		if err != nil {
			t.Errorf("parseRange(%q): %v", c.spec, err)
			continue
		}
		if got := matchRange(tokens, c.target); got != c.want {
			t.Errorf("matchRange(%q, %d) = %v, want %v", c.spec, c.target, got, c.want)
		}
	}
}
