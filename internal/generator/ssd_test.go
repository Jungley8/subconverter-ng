package generator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/parser"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

func ssdNodes() []*proxy.Proxy {
	a := proxy.New("ss", "🇭🇰 HK 01", "1.2.3.4", 8388)
	a.Set("cipher", "aes-128-gcm")
	a.Set("password", "pw1")
	b := proxy.New("ss", "🇺🇸 US 01", "2.2.3.4", 8443)
	b.Set("cipher", "chacha20-ietf-poly1305")
	b.Set("password", "pw2")
	b.Set("plugin", "obfs")
	b.Set("plugin-opts", map[string]any{"mode": "http", "host": "bing.com"})
	v := proxy.New("vmess", "🇯🇵 JP 01", "3.3.3.4", 443)
	return []*proxy.Proxy{a, b, v}
}

func TestGenerateSSD_Shape(t *testing.T) {
	res, err := GenerateSSD(context.Background(), ssdNodes(), &extconfig.Config{}, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatalf("GenerateSSD: %v", err)
	}
	out := string(res.Output)
	if !strings.HasPrefix(out, "ssd://") {
		t.Fatalf("output does not start with ssd://: %.40s", out)
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(out, "ssd://"))
	if err != nil {
		t.Fatalf("body is not base64: %v", err)
	}
	var doc struct {
		Airport    string `json:"airport"`
		Port       int    `json:"port"`
		Encryption string `json:"encryption"`
		Servers    []struct {
			Server        string `json:"server"`
			Port          int    `json:"port"`
			Encryption    string `json:"encryption"`
			Plugin        string `json:"plugin"`
			PluginOptions string `json:"plugin_options"`
			Remarks       string `json:"remarks"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("body is not SSD JSON: %v\n%s", err, body)
	}
	if doc.Airport == "" || doc.Port != 8388 || doc.Encryption != "aes-128-gcm" {
		t.Errorf("document defaults = %+v, want the first server's values", doc)
	}
	if len(doc.Servers) != 2 {
		t.Fatalf("got %d servers, want 2: %s", len(doc.Servers), body)
	}
	if doc.Servers[1].Plugin != "obfs-local" || doc.Servers[1].PluginOptions != "obfs=http;obfs-host=bing.com" {
		t.Errorf("plugin fields = %q/%q", doc.Servers[1].Plugin, doc.Servers[1].PluginOptions)
	}
	if res.NodeCount != 2 {
		t.Errorf("NodeCount = %d, want 2", res.NodeCount)
	}
	if len(res.SkippedNodes) != 1 || !strings.Contains(res.SkippedNodes[0], "vmess") {
		t.Errorf("SkippedNodes = %v, want the vmess node named", res.SkippedNodes)
	}
}

// A conversion must survive a round trip through its own output: what we emit
// as ssd:// is what the parser accepts as a subscription.
func TestGenerateSSD_RoundTrip(t *testing.T) {
	res, err := GenerateSSD(context.Background(), ssdNodes(), &extconfig.Config{}, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	nodes, skipped, err := parser.Parse(res.Output)
	if err != nil {
		t.Fatalf("parser rejected our own output: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %v", skipped)
	}
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes back, want 2", len(nodes))
	}
	for i, want := range []struct {
		name, server string
		port         int
		cipher       string
	}{{"🇭🇰 HK 01", "1.2.3.4", 8388, "aes-128-gcm"}, {"🇺🇸 US 01", "2.2.3.4", 8443, "chacha20-ietf-poly1305"}} {
		n := nodes[i]
		if n.Name != want.name || n.Server != want.server || n.Port != want.port || cs(n.Clash, "cipher") != want.cipher {
			t.Errorf("node[%d] = %+v, want %+v", i, n, want)
		}
	}
}

func TestGenerateSSD_NoShadowsocksNodes(t *testing.T) {
	onlyVMess := []*proxy.Proxy{proxy.New("vmess", "JP", "3.3.3.4", 443)}
	_, err := GenerateSSD(context.Background(), onlyVMess, &extconfig.Config{}, fakeFetcher{}, Options{})
	if !errors.Is(err, ErrTargetNodes) {
		t.Fatalf("err = %v, want ErrTargetNodes", err)
	}
}
