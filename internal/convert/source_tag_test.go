package convert

import (
	"context"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSplitSource(t *testing.T) {
	cases := []struct {
		name      string
		raw       string
		wantGroup string
		wantLink  string
	}{
		{
			name:      "comma inside link stays in link",
			raw:       "tag:Primary,https://example.com/sub?a=1,2",
			wantGroup: "Primary",
			wantLink:  "https://example.com/sub?a=1,2",
		},
		{
			name:      "tag without comma is not a tag",
			raw:       "tag:",
			wantGroup: "",
			wantLink:  "tag:",
		},
		{
			name:      "surrounding spaces are tolerated",
			raw:       "  tag:Primary,https://example.com/sub  ",
			wantGroup: "Primary",
			wantLink:  "https://example.com/sub",
		},
		{
			name:      "plain url is unchanged",
			raw:       "https://example.com/sub",
			wantGroup: "",
			wantLink:  "https://example.com/sub",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			group, link := splitSource(tc.raw)
			if group != tc.wantGroup || link != tc.wantLink {
				t.Errorf("splitSource(%q) = (%q, %q), want (%q, %q)", tc.raw, group, link, tc.wantGroup, tc.wantLink)
			}
		})
	}
}

func TestFetchAndParseAll_SourceTags(t *testing.T) {
	linkA := "ss://" + b64("aes-256-gcm:pass") + "@1.1.1.1:8388#A"
	linkB := "ss://" + b64("aes-256-gcm:pass") + "@2.2.2.2:8388#B"
	sub := func(links ...string) []byte {
		return []byte(b64(strings.Join(links, "\n")))
	}

	t.Run("tagged source stamps every node", func(t *testing.T) {
		f := fakeFetcher{"primary.example.com": sub(linkA, linkB)}
		nodes, _, _, err := fetchAndParseAll(context.Background(), f,
			[]string{"tag:Primary,https://primary.example.com/sub"},
			func(i int) int { return i })
		if err != nil {
			t.Fatalf("fetchAndParseAll: %v", err)
		}
		if len(nodes) != 2 {
			t.Fatalf("got %d nodes, want 2", len(nodes))
		}
		for i, n := range nodes {
			if n.Group != "Primary" {
				t.Errorf("nodes[%d].Group = %q, want Primary", i, n.Group)
			}
			if n.GroupID != 0 {
				t.Errorf("nodes[%d].GroupID = %d, want 0", i, n.GroupID)
			}
		}
	})

	t.Run("untagged source keeps empty group", func(t *testing.T) {
		f := fakeFetcher{
			"tagged.example.com": sub(linkA),
			"plain.example.com":  sub(linkB),
		}
		nodes, _, _, err := fetchAndParseAll(context.Background(), f,
			[]string{"tag:Primary,https://tagged.example.com/sub", "https://plain.example.com/sub"},
			func(i int) int { return i })
		if err != nil {
			t.Fatalf("fetchAndParseAll: %v", err)
		}
		if len(nodes) != 2 {
			t.Fatalf("got %d nodes, want 2", len(nodes))
		}
		if nodes[0].Group != "Primary" || nodes[0].GroupID != 0 {
			t.Errorf("tagged node = (%q, %d), want (Primary, 0)", nodes[0].Group, nodes[0].GroupID)
		}
		if nodes[1].Group != "" || nodes[1].GroupID != 1 {
			t.Errorf("untagged node = (%q, %d), want (\"\", 1)", nodes[1].Group, nodes[1].GroupID)
		}
	})
}

func TestRun_SourceTagGroupAndIDs(t *testing.T) {
	linkA := "ss://" + b64("aes-256-gcm:pass") + "@1.1.1.1:8388#A"
	linkB := "ss://" + b64("aes-256-gcm:pass") + "@2.2.2.2:8388#B"
	linkI := "ss://" + b64("aes-256-gcm:pass") + "@3.3.3.3:8388#I"
	const ini = "[custom]\n" +
		"ruleset=G,[]FINAL\n" +
		"custom_proxy_group=ByGroup`select`!!GROUP=Primary\n" +
		"custom_proxy_group=ById`select`!!GROUPID=1\n" +
		"custom_proxy_group=ByInsert`select`!!INSERT=1\n"
	f := fakeFetcher{"config.init": []byte(ini)}
	req := Request{
		Target:     "clash",
		SubURLs:    []string{"tag:Primary," + linkA, linkB},
		InsertURLs: []string{linkI},
		ConfigURL:  "https://example.com/config.init",
	}
	out, _, err := Run(context.Background(), f, req)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var doc struct {
		Groups []struct {
			Name    string   `yaml:"name"`
			Proxies []string `yaml:"proxies"`
		} `yaml:"proxy-groups"`
	}
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	got := make(map[string][]string, len(doc.Groups))
	for _, g := range doc.Groups {
		got[g.Name] = g.Proxies
	}
	for name, want := range map[string]string{
		"ByGroup":  "A",
		"ById":     "B",
		"ByInsert": "I",
	} {
		if len(got[name]) != 1 || got[name][0] != want {
			t.Errorf("%s = %v, want [%s]", name, got[name], want)
		}
	}
}
