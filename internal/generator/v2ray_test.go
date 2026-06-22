package generator

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/parser"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// TestGenerateV2ray_RoundTrip parses share-links into nodes, re-renders them via
// the v2ray generator, then parses the result again. The two node sets must
// agree on the identifying fields — exercising both render directions.
func TestGenerateV2ray_RoundTrip(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"JP","add":"jp.example.com","port":"443","id":"uuid-1","aid":"0","scy":"auto","net":"ws","host":"jp.example.com","path":"/path","tls":"tls","sni":"jp.example.com"}`
	links := []string{
		"ss://" + b64("aes-256-gcm:pass") + "@1.2.3.4:8388#HK",
		"vmess://" + b64(vmessJSON),
		"vless://uuid-2@us.example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=ab&flow=xtls-rprx-vision&type=tcp#US",
		"trojan://pass@sg.example.com:443?sni=sg.example.com&type=ws&host=sg.example.com&path=/tj#SG",
		"hysteria2://authpass@hk2.example.com:443?sni=hk2.example.com&insecure=1&obfs=salamander&obfs-password=xyz#HK2",
		"tuic://uuid-3:tpass@tw.example.com:443?congestion_control=bbr&alpn=h3&sni=tw.example.com#TW",
	}
	sub := []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))

	nodes, _, err := parser.Parse(sub)
	if err != nil {
		t.Fatalf("parse input: %v", err)
	}
	if len(nodes) != 6 {
		t.Fatalf("parsed %d input nodes, want 6", len(nodes))
	}

	res, err := GenerateV2ray(context.Background(), nodes, &extconfig.Config{}, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ContentType != ctText {
		t.Errorf("content type = %q", res.ContentType)
	}
	if len(res.SkippedNodes) != 0 {
		t.Errorf("unexpected skipped nodes: %v", res.SkippedNodes)
	}

	nodes2, _, err := parser.Parse(res.Output)
	if err != nil {
		t.Fatalf("parse regenerated: %v", err)
	}
	if len(nodes2) != len(nodes) {
		t.Fatalf("round-trip node count = %d, want %d", len(nodes2), len(nodes))
	}
	for i := range nodes {
		a, b := nodes[i], nodes2[i]
		if a.Type != b.Type || a.Server != b.Server || a.Port != b.Port || a.Name != b.Name {
			t.Errorf("node %d mismatch:\n in: %s %s:%d %q\nout: %s %s:%d %q",
				i, a.Type, a.Server, a.Port, a.Name, b.Type, b.Server, b.Port, b.Name)
		}
	}
}

func TestGenerateV2ray_SkipsUnsupported(t *testing.T) {
	// socks5 has no share-link form here -> reported, not emitted.
	links := []string{
		"ss://" + b64("aes-256-gcm:pass") + "@1.2.3.4:8388#OK",
		"socks://" + b64("user:pass") + "@5.6.7.8:1080#SOCKS",
	}
	sub := []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
	nodes, _, err := parser.Parse(sub)
	if err != nil {
		t.Fatal(err)
	}
	res, err := GenerateV2ray(context.Background(), nodes, &extconfig.Config{}, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(res.Output))
	if err != nil {
		t.Fatalf("output not base64: %v", err)
	}
	got := strings.Split(strings.TrimSpace(string(decoded)), "\n")
	if len(got) != 1 || !strings.HasPrefix(got[0], "ss://") {
		t.Errorf("expected only the ss link, got %v", got)
	}
	if len(res.SkippedNodes) != 1 {
		t.Errorf("SkippedNodes = %v, want 1", res.SkippedNodes)
	}
}
