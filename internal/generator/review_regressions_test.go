package generator

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/parser"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

func protocolTestCfg() *extconfig.Config {
	return &extconfig.Config{}
}

func TestSurgeFamilySkipsHTTPUpgrade(t *testing.T) {
	n := proxy.New("vless", "V-HU", "v.example.com", 443)
	n.Set("uuid", "uuid-v")
	n.Set("network", "ws")
	n.Set("ws-opts", map[string]any{"path": "/up", "v2ray-http-upgrade": true})

	for _, flavor := range []surgeFlavor{flavorShadowrocket, flavorLoon} {
		res, out := renderSurgeFamily(t, flavor, []*proxy.Proxy{n}, Options{ListOnly: true})
		if strings.Contains(out, "V-HU = ") {
			t.Errorf("flavor %d downgraded httpupgrade:\n%s", flavor, out)
		}
		if len(res.SkippedNodes) != 1 || !strings.Contains(res.SkippedNodes[0], "httpupgrade") {
			t.Errorf("flavor %d SkippedNodes = %v", flavor, res.SkippedNodes)
		}
	}
}

func TestWireGuardMissingKeysSkips(t *testing.T) {
	n := proxy.New("wireguard", "WG", "wg.example.com", 51820)
	n.Set("ip", "10.0.0.2")

	clash, err := GenerateClash(context.Background(), []*proxy.Proxy{n}, protocolTestCfg(), fakeFetcher{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(clash.SkippedNodes) != 1 || !strings.Contains(clash.SkippedNodes[0], "private-key") {
		t.Errorf("clash SkippedNodes = %v", clash.SkippedNodes)
	}

	_, out := renderSurgeFamily(t, flavorSurge, []*proxy.Proxy{n}, Options{ListOnly: true})
	if strings.Contains(out, "WG = wireguard") {
		t.Errorf("surge emitted an incomplete WireGuard section:\n%s", out)
	}

	v2, err := GenerateV2ray(context.Background(), []*proxy.Proxy{n}, protocolTestCfg(), fakeFetcher{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := base64.StdEncoding.DecodeString(string(v2.Output))
	if len(body) != 0 {
		t.Errorf("v2ray must not emit an incomplete wireguard link: %s", body)
	}
}

func TestShareLinkAWGFullParameters(t *testing.T) {
	n := proxy.New("wireguard", "AWG", "awg.example.com", 51820)
	n.Set("private-key", "priv")
	n.Set("public-key", "pub")
	n.Set("ip", "10.0.0.2")
	n.Set("amnezia-wg-option", map[string]any{
		"jc": 5, "jmin": 40, "jmax": 70, "s1": 20, "s2": 30,
		"h1": 1, "h2": 2, "h3": 3, "h4": 4,
		"header-protection-key": "HPK", "content-padding-addition": "CPA",
		"rekey-after-time": 11, "rekey-timeout": 12, "reject-after-time": 13,
		"keepalive-timeout": 10, "max-handshake-attempts": 5,
		"random-trailers": true, "disable-cookies": true,
	})

	res, err := GenerateV2ray(context.Background(), []*proxy.Proxy{n}, protocolTestCfg(), fakeFetcher{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := base64.StdEncoding.DecodeString(string(res.Output))
	parsed, _, err := parser.Parse(body)
	if err != nil || len(parsed) != 1 {
		t.Fatalf("parse round-trip: %v %s", err, body)
	}
	opts, _ := parsed[0].Clash["amnezia-wg-option"].(map[string]any)
	for _, k := range []string{
		"jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4",
		"header-protection-key", "content-padding-addition",
		"rekey-after-time", "rekey-timeout", "reject-after-time",
		"keepalive-timeout", "max-handshake-attempts",
		"random-trailers", "disable-cookies",
	} {
		if _, ok := opts[k]; !ok {
			t.Errorf("AWG key %q lost in round-trip: %v", k, opts)
		}
	}
}

func TestShareLinkWireGuardKeyWithSlash(t *testing.T) {
	n := proxy.New("wireguard", "WG", "wg.example.com", 51820)
	n.Set("private-key", "priv/with/slashes+and=equals")
	n.Set("public-key", "pub")
	n.Set("ip", "10.0.0.2")

	res, err := GenerateV2ray(context.Background(), []*proxy.Proxy{n}, protocolTestCfg(), fakeFetcher{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := base64.StdEncoding.DecodeString(string(res.Output))
	parsed, skipped, err := parser.Parse(body)
	if err != nil || len(parsed) != 1 || len(skipped) != 0 {
		t.Fatalf("key escaping broke round-trip: nodes=%d skipped=%v err=%v\n%s",
			len(parsed), skipped, err, body)
	}
	if parsed[0].Clash["private-key"] != "priv/with/slashes+and=equals" {
		t.Errorf("private-key = %v", parsed[0].Clash["private-key"])
	}
}

func TestQuanXSkipsWrappersAndTransports(t *testing.T) {
	st := proxy.New("ss", "ST", "ss.example.com", 8388)
	st.Set("cipher", "aes-128-gcm")
	st.Set("password", "pw")
	st.Set("plugin", "shadow-tls")
	st.Set("plugin-opts", map[string]any{"host": "h", "password": "p", "version": 3})

	xh := proxy.New("vless", "XH", "v.example.com", 443)
	xh.Set("uuid", "u")
	xh.Set("network", "xhttp")
	xh.Set("xhttp-opts", map[string]any{"path": "/x"})

	hu := proxy.New("vless", "HU", "v.example.com", 443)
	hu.Set("uuid", "u")
	hu.Set("network", "ws")
	hu.Set("ws-opts", map[string]any{"path": "/up", "v2ray-http-upgrade": true})

	res, err := GenerateQuanX(context.Background(), []*proxy.Proxy{st, xh, hu}, protocolTestCfg(), fakeFetcher{}, Options{ListOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SkippedNodes) != 3 {
		t.Errorf("SkippedNodes = %v, want all three", res.SkippedNodes)
	}
	out := string(res.Output)
	for _, name := range []string{"ST", "XH", "HU"} {
		if strings.Contains(out, "tag="+name) {
			t.Errorf("%s emitted despite lost wrapper/transport:\n%s", name, out)
		}
	}
}

func TestSurgeTUICV4KeepsTLSOptions(t *testing.T) {
	n := proxy.New("tuic", "T4", "t4.example.com", 443)
	n.Version = 4
	n.Set("password", "tok4")
	n.Set("sni", "t4.example.com")
	n.Set("alpn", []string{"h3"})
	n.SetRaw("skip-cert-verify", true)

	_, out := renderSurgeFamily(t, flavorSurge, []*proxy.Proxy{n}, Options{ListOnly: true})
	if !strings.Contains(out, "T4 = tuic, t4.example.com, 443, token=tok4, sni=t4.example.com, alpn=h3, skip-cert-verify=true") {
		t.Errorf("TUIC v4 TLS options lost:\n%s", out)
	}
}

func TestClashSkipsXHTTPForNonVLESS(t *testing.T) {
	vm := proxy.New("vmess", "VM", "v.example.com", 443)
	vm.Set("uuid", "u")
	vm.Set("network", "xhttp")

	res, err := GenerateClash(context.Background(), []*proxy.Proxy{vm}, protocolTestCfg(), fakeFetcher{}, Options{ListOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.SkippedNodes) != 1 || !strings.Contains(res.SkippedNodes[0], "xhttp") {
		t.Errorf("clash must skip vmess xhttp: %v", res.SkippedNodes)
	}
}

func TestExcludeProtocolAWGAndTUIC4(t *testing.T) {
	awg := proxy.New("wireguard", "AWG", "awg.example.com", 51820)
	awg.Set("amnezia-wg-option", map[string]any{"jc": 5})
	plain := proxy.New("wireguard", "WG", "wg.example.com", 51820)
	t4 := proxy.New("tuic", "T4", "t4.example.com", 443)
	t4.Version = 4
	t5 := proxy.New("tuic", "T5", "t5.example.com", 443)

	kept, dropped := filterProtocols([]*proxy.Proxy{awg, plain}, ParseProtocolSet("awg"))
	if dropped != 1 || len(kept) != 1 || kept[0].Name != "WG" {
		t.Errorf("exclude awg: kept=%v dropped=%d", kept, dropped)
	}
	kept, dropped = filterProtocols([]*proxy.Proxy{t4, t5}, ParseProtocolSet("tuic4"))
	if dropped != 1 || len(kept) != 1 || kept[0].Name != "T5" {
		t.Errorf("exclude tuic4: kept=%v dropped=%d", kept, dropped)
	}
	if attrTypeName(awg) != "AWG" || attrTypeName(t4) != "TUIC4" {
		t.Errorf("attrTypeName = %q/%q", attrTypeName(awg), attrTypeName(t4))
	}
}
