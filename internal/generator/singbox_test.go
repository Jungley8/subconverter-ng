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
	f := fakeFetcher{"PROXY.list": []byte("DOMAIN-SUFFIX,google.com\nIP-CIDR,8.8.8.8/32,no-resolve\nGEOSITE,google\n")}

	res, err := GenerateSingbox(context.Background(), nodes, cfg, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ContentType != ctJSON {
		t.Errorf("content type = %q", res.ContentType)
	}

	// Must be valid JSON.
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
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
	// Builtins.
	if tags["direct"] == nil || tags["block"] == nil {
		t.Error("missing direct/block builtins")
	}
	// VLESS reality + utls carried into tls.
	vlessTLS, _ := tags["US"]["tls"].(map[string]any)
	if vlessTLS == nil || vlessTLS["reality"] == nil || vlessTLS["utls"] == nil {
		t.Errorf("vless tls missing reality/utls: %v", tags["US"]["tls"])
	}
	// Route: FINAL -> route.final = Proxy; dns/domain_suffix/geosite rules present.
	if doc.Route.Final != "Proxy" {
		t.Errorf("route.final = %q, want Proxy", doc.Route.Final)
	}
	var sawDomainSuffix, sawDNS, sawGeosite bool
	for _, r := range doc.Route.Rules {
		if r["protocol"] == "dns" {
			sawDNS = true
		}
		if _, ok := r["domain_suffix"]; ok {
			sawDomainSuffix = true
		}
		if _, ok := r["geosite"]; ok {
			sawGeosite = true
		}
	}
	if !sawDNS || !sawDomainSuffix || !sawGeosite {
		t.Errorf("route rules missing dns/domain_suffix/geosite: %+v", doc.Route.Rules)
	}
}

// TestGenerateSingboxProtocolGate covers the TargetVersion protocol gate: with
// sing-box 1.3 declared, hysteria2 (floor 1.5) and anytls (floor 1.12) are
// dropped, while tuic (floor 1.2) and hysteria (floor 1.1) still pass. Without
// a declared version every renderable protocol (including anytls) is emitted.
func TestGenerateSingboxProtocolGate(t *testing.T) {
	gateNodes := func() []*proxy.Proxy {
		mk := func(typ, name string, fields map[string]any) *proxy.Proxy {
			p := proxy.New(typ, name, name+".example.com", 443)
			for k, v := range fields {
				p.Clash[k] = v
			}
			return p
		}
		return []*proxy.Proxy{
			mk("ss", "SS", map[string]any{"cipher": "aes-256-gcm", "password": "pass"}),
			mk("vmess", "VM", map[string]any{"uuid": "u1", "alterId": 0}),
			mk("trojan", "TJ", map[string]any{"password": "pass", "sni": "TJ.example.com"}),
			mk("tuic", "TU", map[string]any{"uuid": "u2", "password": "pass"}),
			mk("hysteria", "HY1", nil),
			mk("hysteria2", "HY2", map[string]any{"password": "auth"}),
			mk("anytls", "AT", map[string]any{"password": "pass"}),
		}
	}
	// "Proxy" references the gated hysteria2 node by name; "Auto" uses .*.
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups: []extconfig.ProxyGroup{
			{Name: "Proxy", Type: "select", Selectors: []string{"SS", "HY2"}},
			{Name: "Auto", Type: "url-test", Selectors: []string{".*"}, TestURL: "http://t/204", Interval: 300},
		},
	}

	parseTags := func(t *testing.T, res *Result) map[string]map[string]any {
		t.Helper()
		var doc struct {
			Outbounds []map[string]any `json:"outbounds"`
		}
		if err := json.Unmarshal(res.Output, &doc); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		tags := map[string]map[string]any{}
		for _, ob := range doc.Outbounds {
			tags[ob["tag"].(string)] = ob
		}
		return tags
	}
	members := func(tags map[string]map[string]any, group string) []string {
		var out []string
		for _, m := range tags[group]["outbounds"].([]any) {
			out = append(out, m.(string))
		}
		return out
	}

	// (a) sing-box 1.3: hysteria2 and anytls gated out, the rest emitted.
	res, err := GenerateSingbox(context.Background(), gateNodes(), cfg, fakeFetcher{}, Options{TargetVersion: &Version{Major: 1, Minor: 3}})
	if err != nil {
		t.Fatal(err)
	}
	skipped := strings.Join(res.SkippedNodes, "\n")
	for _, want := range []string{
		"HY2 (hysteria2: requires sing-box >= 1.5)",
		"AT (anytls: requires sing-box >= 1.12)",
	} {
		if !strings.Contains(skipped, want) {
			t.Errorf("skipped nodes missing %q: %v", want, res.SkippedNodes)
		}
	}
	// hysteria (floor 1.1) passes the 1.3 gate; it is skipped only because the
	// generator has no hysteria outbound (pre-existing behaviour).
	if !strings.Contains(skipped, "HY1 (hysteria: unsupported by sing-box generator)") {
		t.Errorf("hysteria should not be version-gated at 1.3, skipped = %v", res.SkippedNodes)
	}
	tags := parseTags(t, res)
	for _, tag := range []string{"SS", "VM", "TJ", "TU"} {
		if tags[tag] == nil {
			t.Errorf("outbound %q missing under sing-box 1.3", tag)
		}
	}
	for _, tag := range []string{"HY2", "AT"} {
		if _, ok := tags[tag]; ok {
			t.Errorf("gated outbound %q must not be emitted", tag)
		}
		if strings.Contains(string(res.Output), tag) {
			t.Errorf("gated node tag %q leaked into output JSON", tag)
		}
	}
	// (c) The selector referencing the gated node drops it from its members;
	// the .* group is built from emitted names only.
	if got := members(tags, "Proxy"); len(got) != 1 || got[0] != "SS" {
		t.Errorf("Proxy members = %v, want [SS] (HY2 gated out)", got)
	}
	if got := members(tags, "Auto"); containsStr(got, "HY2") || containsStr(got, "AT") {
		t.Errorf("Auto group must not reference gated nodes: %v", got)
	}

	// (b) No declared version: unchanged behaviour — hysteria2 and anytls
	// emitted, hysteria skipped as unsupported (no hysteria outbound exists),
	// no version-gate skips at all.
	resNil, err := GenerateSingbox(context.Background(), gateNodes(), cfg, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	tagsNil := parseTags(t, resNil)
	for _, tag := range []string{"SS", "VM", "TJ", "TU", "HY2", "AT"} {
		if tagsNil[tag] == nil {
			t.Errorf("outbound %q missing without a declared version", tag)
		}
	}
	// anytls renders as a TLS-always outbound carrying password.
	if got := tagsNil["AT"]["type"]; got != "anytls" {
		t.Errorf("outbound AT type = %v, want anytls", got)
	}
	if tagsNil["AT"]["password"] != "pass" {
		t.Errorf("outbound AT password = %v, want pass", tagsNil["AT"]["password"])
	}
	if tls, ok := tagsNil["AT"]["tls"].(map[string]any); !ok || tls["enabled"] != true {
		t.Errorf("outbound AT tls = %v, want enabled", tagsNil["AT"]["tls"])
	}
	for _, entry := range resNil.SkippedNodes {
		if strings.Contains(entry, "requires sing-box") {
			t.Errorf("unexpected version-gate skip without a declared version: %q", entry)
		}
	}
	skippedNil := strings.Join(resNil.SkippedNodes, "\n")
	if !strings.Contains(skippedNil, "HY1 (hysteria: unsupported by sing-box generator)") {
		t.Errorf("skipped nodes missing HY1: %v", resNil.SkippedNodes)
	}
	if !containsStr(members(tagsNil, "Auto"), "HY2") {
		t.Error("Auto group should reference HY2 when no version is declared")
	}
	if !containsStr(members(tagsNil, "Auto"), "AT") {
		t.Error("Auto group should reference AT when no version is declared")
	}
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// TestGenerateSingboxSchemaSwitch covers the sing-box schema migration gated on
// the declared version: >=1.11 swaps the block/dns special outbounds for rule
// actions (hijack-dns/reject), >=1.12 additionally enables the new DNS server
// format and rule_set-based geo rules (geoip:private -> ip_is_private). Without
// a declared version the legacy output is covered by the tests above.
func TestGenerateSingboxSchemaSwitch(t *testing.T) {
	nodes := func() []*proxy.Proxy {
		mk := func(typ, name string, fields map[string]any) *proxy.Proxy {
			p := proxy.New(typ, name, name+".example.com", 443)
			for k, v := range fields {
				p.Clash[k] = v
			}
			return p
		}
		return []*proxy.Proxy{
			mk("ss", "SS", map[string]any{"cipher": "aes-256-gcm", "password": "pass"}),
			mk("trojan", "TJ", map[string]any{"password": "pass", "sni": "TJ.example.com"}),
		}
	}
	cfg := &extconfig.Config{
		EnableRuleGenerator: true,
		ProxyGroups: []extconfig.ProxyGroup{
			{Name: "Proxy", Type: "select", Selectors: []string{".*", "[]REJECT", "[]DIRECT"}},
			{Name: "AdBlock", Type: "select", Selectors: []string{"[]REJECT"}},
		},
		Rulesets: []extconfig.Ruleset{
			{Group: "REJECT", Inline: "DOMAIN-SUFFIX,ads.example.com"},
			{Group: "AdBlock", Inline: "GEOSITE,ads"},
			{Group: "Proxy", Inline: "GEOIP,CN"},
			{Group: "Proxy", Inline: "GEOIP,private"},
			{Group: "Proxy", Inline: "FINAL"},
		},
	}

	type singDoc struct {
		Outbounds []map[string]any `json:"outbounds"`
		DNS       struct {
			Servers []map[string]any `json:"servers"`
			Final   string           `json:"final"`
		} `json:"dns"`
		RuleSet []map[string]any `json:"rule_set"`
		Route   struct {
			Rules []map[string]any `json:"rules"`
			Final string           `json:"final"`
		} `json:"route"`
	}
	parse := func(t *testing.T, res *Result) singDoc {
		t.Helper()
		var doc singDoc
		if err := json.Unmarshal(res.Output, &doc); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		return doc
	}
	members := func(doc singDoc, tag string) []string {
		for _, ob := range doc.Outbounds {
			if ob["tag"] == tag {
				var out []string
				for _, m := range ob["outbounds"].([]any) {
					out = append(out, m.(string))
				}
				return out
			}
		}
		return nil
	}
	noSpecialOutbounds := func(t *testing.T, doc singDoc) {
		t.Helper()
		for _, ob := range doc.Outbounds {
			if ty, _ := ob["type"].(string); ty == "block" || ty == "dns" {
				t.Errorf("outbound %v: special outbound %q must not be emitted under the action schema", ob["tag"], ty)
			}
		}
	}
	hijackDNSRule := func(t *testing.T, doc singDoc) {
		t.Helper()
		first := doc.Route.Rules[0]
		if first["protocol"] != "dns" || first["action"] != "hijack-dns" {
			t.Errorf("first route rule = %v, want protocol dns + action hijack-dns", first)
		}
		if _, ok := first["outbound"]; ok {
			t.Errorf("first route rule must not reference dns-out under the action schema: %v", first)
		}
	}

	// (a) sing-box 1.13: every schema switch on (actions + new DNS + rule_sets).
	res, err := GenerateSingbox(context.Background(), nodes(), cfg, fakeFetcher{}, Options{TargetVersion: &Version{Major: 1, Minor: 13}})
	if err != nil {
		t.Fatal(err)
	}
	doc := parse(t, res)
	noSpecialOutbounds(t, doc)
	hijackDNSRule(t, doc)
	if doc.Route.Final != "Proxy" {
		t.Errorf("route.final = %q, want Proxy", doc.Route.Final)
	}
	// The REJECT-targeted rule becomes an action rule; geo rules become
	// rule_set references; geoip:private becomes ip_is_private.
	var sawReject, sawGeosite, sawGeoipCN, sawIPPrivate bool
	for _, r := range doc.Route.Rules {
		if _, ok := r["geosite"]; ok {
			t.Errorf("inline geosite field must not appear at 1.13: %v", r)
		}
		if _, ok := r["geoip"]; ok {
			t.Errorf("inline geoip field must not appear at 1.13: %v", r)
		}
		if _, ok := r["domain_suffix"]; ok && r["action"] == "reject" && r["outbound"] == nil {
			sawReject = true
		}
		if rs, ok := r["rule_set"].([]any); ok && len(rs) == 1 {
			switch rs[0] {
			case "geosite-ads":
				sawGeosite = true
			case "geoip-cn":
				sawGeoipCN = true
			}
		}
		if r["ip_is_private"] == true {
			sawIPPrivate = true
		}
	}
	if !sawReject {
		t.Errorf("REJECT rule must become action reject at 1.13: %+v", doc.Route.Rules)
	}
	if !sawGeosite || !sawGeoipCN {
		t.Errorf("GEOSITE/GEOIP rules must become rule_set references at 1.13: %+v", doc.Route.Rules)
	}
	if !sawIPPrivate {
		t.Errorf("GEOIP,private must become ip_is_private at 1.13: %+v", doc.Route.Rules)
	}
	// Top-level rule_set definitions: geosite-ads + geoip-cn, no geoip-private.
	wantSets := map[string]string{
		"geosite-ads": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-ads.srs",
		"geoip-cn":    "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
	}
	if len(doc.RuleSet) != len(wantSets) {
		t.Errorf("top-level rule_set has %d entries, want %d: %v", len(doc.RuleSet), len(wantSets), doc.RuleSet)
	}
	for _, rs := range doc.RuleSet {
		tag, _ := rs["tag"].(string)
		wantURL, ok := wantSets[tag]
		if !ok {
			t.Errorf("unexpected top-level rule_set entry %q", tag)
			continue
		}
		if rs["type"] != "remote" || rs["format"] != "binary" || rs["url"] != wantURL {
			t.Errorf("rule_set %q = %v, want remote/binary with url %s", tag, rs, wantURL)
		}
	}
	// New DNS server format.
	if len(doc.DNS.Servers) != 2 {
		t.Errorf("dns.servers = %v, want 2 entries", doc.DNS.Servers)
	} else {
		remote, local := doc.DNS.Servers[0], doc.DNS.Servers[1]
		if remote["type"] != "tls" || remote["tag"] != "remote" || remote["server"] != "8.8.8.8" {
			t.Errorf("remote dns server = %v, want {tls, remote, 8.8.8.8}", remote)
		}
		if local["type"] != "udp" || local["tag"] != "local" || local["server"] != "223.5.5.5" || local["detour"] != "direct" {
			t.Errorf("local dns server = %v, want {udp, local, 223.5.5.5, detour direct}", local)
		}
	}
	// Selectors cannot reference the removed block outbound.
	if containsStr(members(doc, "Proxy"), "block") {
		t.Errorf("Proxy members = %v, must not contain block at 1.13", members(doc, "Proxy"))
	}

	// (b) sing-box 1.11: rule actions on, geo fields and DNS still legacy.
	res11, err := GenerateSingbox(context.Background(), nodes(), cfg, fakeFetcher{}, Options{TargetVersion: &Version{Major: 1, Minor: 11}})
	if err != nil {
		t.Fatal(err)
	}
	doc11 := parse(t, res11)
	noSpecialOutbounds(t, doc11)
	hijackDNSRule(t, doc11)
	var sawInlineGeosite, sawInlineGeoip bool
	for _, r := range doc11.Route.Rules {
		if g, ok := r["geosite"].([]any); ok && len(g) == 1 && g[0] == "ads" {
			sawInlineGeosite = true
		}
		if g, ok := r["geoip"].([]any); ok && len(g) == 1 && g[0] == "cn" {
			sawInlineGeoip = true
		}
	}
	if !sawInlineGeosite || !sawInlineGeoip {
		t.Errorf("geosite/geoip must stay inline at 1.11: %+v", doc11.Route.Rules)
	}
	if doc11.DNS.Servers[0]["address"] != "tls://8.8.8.8" {
		t.Errorf("dns must stay legacy at 1.11: %v", doc11.DNS.Servers)
	}
	if doc11.RuleSet != nil {
		t.Errorf("no top-level rule_set expected at 1.11: %v", doc11.RuleSet)
	}

	// (c) sing-box 1.12: rule_sets + new DNS on top of the 1.11 actions.
	res12, err := GenerateSingbox(context.Background(), nodes(), cfg, fakeFetcher{}, Options{TargetVersion: &Version{Major: 1, Minor: 12}})
	if err != nil {
		t.Fatal(err)
	}
	doc12 := parse(t, res12)
	noSpecialOutbounds(t, doc12)
	hijackDNSRule(t, doc12)
	if doc12.DNS.Servers[0]["type"] != "tls" || doc12.DNS.Servers[0]["server"] != "8.8.8.8" {
		t.Errorf("dns must use the new format at 1.12: %v", doc12.DNS.Servers)
	}
	if len(doc12.RuleSet) != len(wantSets) {
		t.Errorf("top-level rule_set has %d entries at 1.12, want %d: %v", len(doc12.RuleSet), len(wantSets), doc12.RuleSet)
	}
	var sawPrivate12 bool
	for _, r := range doc12.Route.Rules {
		if r["ip_is_private"] == true {
			sawPrivate12 = true
		}
	}
	if !sawPrivate12 {
		t.Errorf("GEOIP,private must become ip_is_private at 1.12: %+v", doc12.Route.Rules)
	}
}
