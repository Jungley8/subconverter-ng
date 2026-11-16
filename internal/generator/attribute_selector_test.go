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

func runAttrWith(t *testing.T, nodes []*proxy.Proxy, selectors []string) map[string][]string {
	t.Helper()
	cfg := &extconfig.Config{ProxyGroups: []extconfig.ProxyGroup{{
		Name: "G", Type: "select", Selectors: selectors,
	}}}
	res, err := GenerateClash(context.Background(), nodes, cfg, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatalf("GenerateClash: %v", err)
	}
	return groupMembers(t, res)
}

func runAttr(t *testing.T, selectors []string) map[string][]string {
	t.Helper()
	return runAttrWith(t, attrNodes(), selectors)
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

func TestAttributeSelectorTypeTLS(t *testing.T) {
	plain := proxy.New("http", "Plain HTTP", "3.3.3.3", 80)
	secure := proxy.New("http", "TLS HTTP", "4.4.4.4", 443)
	secure.SetRaw("tls", true)
	https := proxy.New("https", "HTTPS Node", "5.5.5.5", 8443)
	nodes := []*proxy.Proxy{plain, secure, https}
	cases := []struct {
		selector string
		want     []string
	}{
		{`!!TYPE=HTTP`, []string{"Plain HTTP"}},
		{`!!TYPE=HTTPS`, []string{"TLS HTTP", "HTTPS Node"}},
	}
	for _, c := range cases {
		got := runAttrWith(t, nodes, []string{c.selector})["G"]
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s = %v, want %v", c.selector, got, c.want)
		}
	}
}

func TestAttributeSelectorTail(t *testing.T) {
	cases := []struct {
		selector string
		want     []string
	}{
		{`!!TYPE=(?:SS|VMESS)!!HK`, []string{"HK 01"}},
		{`!!PORT=8000-9000!!US`, []string{"US 01"}},
		{`!!TYPE=SS!!NOPE`, []string{"DIRECT"}},
	}
	for _, c := range cases {
		got := runAttr(t, []string{c.selector})["G"]
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s = %v, want %v", c.selector, got, c.want)
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
	cases := []struct {
		selector string
		want     string
	}{
		{`!!SERVER=sg\.example\.com`, "SG 01"},
		// Upstream regFind is a substring match, not a full match.
		{`!!SERVER=example\.com`, "SG 01"},
	}
	for _, c := range cases {
		got := runAttr(t, []string{c.selector})["G"]
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%s = %v, want [%s]", c.selector, got, c.want)
		}
	}
}

func TestAttributeSelectorServerIPv6(t *testing.T) {
	nodes := []*proxy.Proxy{proxy.New("ss", "V6 01", "::1", 443)}
	for _, sel := range []string{`!!SERVER=::1`, `!!SERVER=\[::1\]`} {
		got := runAttrWith(t, nodes, []string{sel})["G"]
		if len(got) != 1 || got[0] != "V6 01" {
			t.Errorf("%s = %v, want [V6 01]", sel, got)
		}
	}
}

func TestAttributeSelectorGroup(t *testing.T) {
	nodes := attrNodes()
	nodes[0].Group = "Primary"
	nodes[1].Group = "Backup"
	cases := []struct {
		selector string
		want     string
	}{
		{`!!GROUP=Primary`, "HK 01"},
		// Upstream regFind is a substring match, not a full match.
		{`!!GROUP=rimary`, "HK 01"},
	}
	for _, c := range cases {
		got := runAttrWith(t, nodes, []string{c.selector})["G"]
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%s = %v, want [%s]", c.selector, got, c.want)
		}
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
	for _, sel := range []string{
		`!!TYPE=`, `!!NOPE=ss`, `!!PORT=abc`, `!!PROVIDER=p1`,
		`!!PORT=!1000-`, `!!PORT=!1000+`, `!!PORT=+5`,
	} {
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
