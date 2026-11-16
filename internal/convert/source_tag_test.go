package convert

import (
	"context"
	"testing"

	"gopkg.in/yaml.v3"
)

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
