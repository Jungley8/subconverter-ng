package generator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/parser"
)

func TestGenerateSingbox(t *testing.T) {
	links := []string{
		"ss://" + b64("aes-256-gcm:pass") + "@1.2.3.4:8388#HK",
		"vmess://" + b64(`{"v":"2","ps":"JP","add":"jp.example.com","port":"443","id":"uuid-1","aid":"0","scy":"auto","net":"ws","host":"jp.example.com","path":"/path","tls":"tls","sni":"jp.example.com"}`),
		"vless://uuid-2@us.example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY&sid=ab&flow=xtls-rprx-vision&type=tcp#US",
		"trojan://pass@sg.example.com:443?sni=sg.example.com#SG",
		"hysteria2://authpass@hk2.example.com:443?sni=hk2.example.com&insecure=1&obfs=salamander&obfs-password=xyz#HK2",
	}
	sub := []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n"))))
	nodes, _, err := parser.Parse(sub)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups: []extconfig.ProxyGroup{
			{Name: "Proxy", Type: "select", Selectors: []string{".*", "[]DIRECT"}},
			{Name: "Auto", Type: "url-test", Selectors: []string{".*"}, TestURL: "http://t/204", Interval: 300},
		},
		Rulesets: []extconfig.Ruleset{
			{Group: "Proxy", URL: "https://rules/PROXY.list"},
			{Group: "Proxy", Inline: "GEOIP,CN"},
			{Group: "Proxy", Inline: "FINAL"},
		},
	}
	f := fakeFetcher{"PROXY.list": []byte("DOMAIN-SUFFIX,google.com\nIP-CIDR,8.8.8.8/32,no-resolve\nGEOSITE,google\nPROCESS-NAME,ios.process\n")}

	res, err := GenerateSingbox(context.Background(), nodes, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ContentType != ctJSON {
		t.Errorf("content type = %q", res.ContentType)
	}

	// Must be valid JSON.
	var doc struct {
		HTTPClients []map[string]any `json:"http_clients"`
		DNS         struct {
			Servers []map[string]any `json:"servers"`
			Final   string           `json:"final"`
		} `json:"dns"`
		Inbounds  []map[string]any `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules              []map[string]any `json:"rules"`
			RuleSets           []map[string]any `json:"rule_set"`
			Final              string           `json:"final"`
			DefaultHTTPClient  string           `json:"default_http_client"`
			DefaultDNSResolver string           `json:"default_domain_resolver"`
		} `json:"route"`
	}
	if err := json.Unmarshal(res.Output, &doc); err != nil {
		t.Fatalf("invalid sing-box JSON: %v", err)
	}

	tags := map[string]map[string]any{}
	for _, ob := range doc.Outbounds {
		tags[ob["tag"].(string)] = ob
	}
	// Node outbounds present with correct types.
	for tag, wantType := range map[string]string{
		"HK": "shadowsocks", "JP": "vmess", "US": "vless", "SG": "trojan", "HK2": "hysteria2",
	} {
		ob, ok := tags[tag]
		if !ok {
			t.Errorf("missing outbound %q", tag)
			continue
		}
		if ob["type"] != wantType {
			t.Errorf("outbound %q type = %v, want %s", tag, ob["type"], wantType)
		}
	}
	// Group outbounds.
	if tags["Proxy"]["type"] != "selector" {
		t.Errorf("Proxy group type = %v, want selector", tags["Proxy"]["type"])
	}
	if tags["Auto"]["type"] != "urltest" {
		t.Errorf("Auto group type = %v, want urltest", tags["Auto"]["type"])
	}
	// Builtin. Rejections are route actions in current sing-box releases.
	if tags["direct"] == nil {
		t.Error("missing direct builtin")
	}
	if tags["block"] != nil {
		t.Error("legacy block outbound should not be emitted")
	}
	// VLESS reality + utls carried into tls.
	vlessTLS, _ := tags["US"]["tls"].(map[string]any)
	if vlessTLS == nil || vlessTLS["reality"] == nil || vlessTLS["utls"] == nil {
		t.Errorf("vless tls missing reality/utls: %v", tags["US"]["tls"])
	}
	// Route: FINAL -> route.final = Proxy; DNS handling and modern rule-sets
	// are present.
	if doc.Route.Final != "Proxy" {
		t.Errorf("route.final = %q, want Proxy", doc.Route.Final)
	}
	if doc.Route.DefaultHTTPClient != "rule-set-download" {
		t.Errorf("route.default_http_client = %q", doc.Route.DefaultHTTPClient)
	}
	if doc.Route.DefaultDNSResolver != "local" {
		t.Errorf("route.default_domain_resolver = %q", doc.Route.DefaultDNSResolver)
	}
	var sawSniff, sawDNSHijack bool
	for _, r := range doc.Route.Rules {
		if r["action"] == "sniff" {
			sawSniff = true
		}
		if r["protocol"] == "dns" && r["action"] == "hijack-dns" {
			sawDNSHijack = true
		}
	}
	if !sawSniff || !sawDNSHijack {
		t.Errorf("route rules missing sniff/dns hijack: %+v", doc.Route.Rules)
	}

	var sawInlineDomain, sawInlineIP, sawGeosite, sawGeoIP, sawProcess bool
	for _, rs := range doc.Route.RuleSets {
		tag, _ := rs["tag"].(string)
		switch {
		case tag == "geosite-google":
			sawGeosite = rs["type"] == "remote"
		case tag == "geoip-cn":
			sawGeoIP = rs["type"] == "remote"
		case rs["type"] == "inline":
			rules, _ := rs["rules"].([]any)
			for _, raw := range rules {
				rule, _ := raw.(map[string]any)
				if _, ok := rule["domain_suffix"]; ok {
					sawInlineDomain = true
				}
				if _, ok := rule["ip_cidr"]; ok {
					sawInlineIP = true
				}
				if _, ok := rule["process_name"]; ok {
					sawProcess = true
				}
			}
		}
	}
	if !sawInlineDomain || !sawInlineIP || !sawGeosite || !sawGeoIP {
		t.Errorf("rule-sets missing compacted or remote entries: %+v", doc.Route.RuleSets)
	}
	if sawProcess {
		t.Error("process_name must not be emitted for cross-platform sing-box profiles")
	}
	foundSkippedProcess := false
	for _, skipped := range res.SkippedRules {
		if skipped == "PROCESS-NAME,ios.process" {
			foundSkippedProcess = true
			break
		}
	}
	if !foundSkippedProcess {
		t.Errorf("PROCESS-NAME rule not reported as skipped: %v", res.SkippedRules)
	}

	// Current DNS and explicit HTTP client formats.
	if len(doc.HTTPClients) != 1 || doc.HTTPClients[0]["tag"] != "rule-set-download" {
		t.Errorf("unexpected http_clients: %+v", doc.HTTPClients)
	}
	if doc.DNS.Final != "local" {
		t.Errorf("dns.final = %q, want local", doc.DNS.Final)
	}
	if len(doc.DNS.Servers) != 1 || doc.DNS.Servers[0]["type"] != "https" {
		t.Errorf("unexpected DNS servers: %+v", doc.DNS.Servers)
	}

	// The profile includes an Apple-compatible IPv4-only TUN without removed
	// platform options.
	var tun map[string]any
	for _, inbound := range doc.Inbounds {
		if inbound["type"] == "tun" {
			tun = inbound
			break
		}
	}
	if tun == nil {
		t.Fatal("missing TUN inbound")
	}
	for _, field := range []string{"inet6_address", "strict_route", "gso", "interface_name"} {
		if _, exists := tun[field]; exists {
			t.Errorf("unsupported Apple TUN field emitted: %s", field)
		}
	}
}

func TestCompactSingboxRouteRules(t *testing.T) {
	rules := []map[string]any{
		{"outbound": "Proxy", "domain_suffix": []string{"a.example", "shared.example"}},
		{"outbound": "Proxy", "domain_suffix": []string{"shared.example", "b.example"}},
		{"outbound": "Proxy", "ip_cidr": []string{"192.0.2.0/24"}},
		{"outbound": "direct", "domain": []string{"direct.example"}},
		{"outbound": "Proxy", "domain": []string{"later.example"}},
		{"action": "reject", "domain": []string{"ads.example"}},
	}

	compacted, ruleSets := compactSingboxRouteRules(rules, nil)
	if len(compacted) != 4 {
		t.Fatalf("compacted route rules = %d, want 4", len(compacted))
	}
	if len(ruleSets) != 4 {
		t.Fatalf("rule-sets = %d, want 4", len(ruleSets))
	}

	firstTag, _ := compacted[0]["rule_set"].(string)
	if firstTag == "" || compacted[0]["outbound"] != "Proxy" {
		t.Fatalf("first compacted rule = %+v", compacted[0])
	}
	headless, _ := ruleSets[0]["rules"].([]map[string]any)
	if len(headless) != 2 {
		t.Fatalf("first rule-set headless rules = %d, want 2", len(headless))
	}
	domainValues, _ := headless[0]["domain_suffix"].([]any)
	if len(domainValues) != 3 {
		t.Errorf("deduplicated domain_suffix values = %v", domainValues)
	}
	if compacted[1]["outbound"] != "direct" {
		t.Errorf("destination boundary lost: %+v", compacted[1])
	}
	if compacted[3]["action"] != "reject" {
		t.Errorf("reject rule not preserved: %+v", compacted[3])
	}
}
