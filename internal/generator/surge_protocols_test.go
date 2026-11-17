package generator

import (
	"context"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/parser"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

func renderSurgeFamily(t *testing.T, flavor surgeFlavor, nodes []*proxy.Proxy, opts Options) (*Result, string) {
	t.Helper()
	res, err := generateSurgeFamily(context.Background(), flavor, nodes, &extconfig.Config{}, fakeFetcher{}, opts)
	if err != nil {
		t.Fatalf("generate surge family: %v", err)
	}
	return res, string(res.Output)
}

func renderOne(t *testing.T, flavor surgeFlavor, n *proxy.Proxy) (*Result, string) {
	t.Helper()
	return renderSurgeFamily(t, flavor, []*proxy.Proxy{n}, Options{ListOnly: true})
}

func TestSurgeProtocolLines(t *testing.T) {
	snell := proxy.New("snell", "SN", "sn.example.com", 443)
	snell.Clash["psk"] = "snpsk"
	snell.Clash["version"] = 4
	snell.Clash["reuse"] = true
	snell.Clash["udp-port"] = 8443
	snell.Clash["obfs-opts"] = map[string]any{"mode": "http", "host": "bing.com", "uri": "/"}

	snellShadowTLS := proxy.New("snell", "SN-ST", "sn.example.com", 443)
	snellShadowTLS.Clash["psk"] = "snpsk"
	snellShadowTLS.Clash["version"] = 4
	snellShadowTLS.Clash["obfs-opts"] = map[string]any{
		"mode": "shadow-tls", "host": "camouflage.example.com",
		"password": "stpass", "version": 3,
	}

	ssShadowTLS := proxy.New("ss", "SS-ST", "ss.example.com", 8388)
	ssShadowTLS.Clash["cipher"] = "aes-256-gcm"
	ssShadowTLS.Clash["password"] = "sspw"
	ssShadowTLS.Clash["plugin"] = "shadow-tls"
	ssShadowTLS.Clash["plugin-opts"] = map[string]any{
		"host": "camouflage.example.com", "password": "stpass", "version": 2,
	}

	anytls := proxy.New("anytls", "AT", "at.example.com", 443)
	anytls.Clash["password"] = "atpass"
	anytls.Clash["sni"] = "at.example.com"
	anytls.Clash["skip-cert-verify"] = true
	anytls.Clash["alpn"] = []string{"h2", "http/1.1"}

	ssh := proxy.New("ssh", "SH", "ssh.example.com", 22)
	ssh.Clash["username"] = "root"
	ssh.Clash["password"] = "sshpw"

	masque := proxy.New("masque", "MQ", "m.example.com", 443)
	masque.Clash["username"] = "u"
	masque.Clash["password"] = "mp"
	masque.Clash["port-hopping"] = "1-65535"
	masque.Clash["port-hopping-interval"] = 30
	masque.Clash["sni"] = "m.example.com"
	masque.Clash["skip-cert-verify"] = true
	masque.Clash["alpn"] = []string{"h2"}
	masque.Clash["network"] = "quic"

	trustTunnel := proxy.New("trusttunnel", "TT", "tt.example.com", 443)
	trustTunnel.Clash["username"] = "u"
	trustTunnel.Clash["password"] = "tp"
	trustTunnel.Clash["headers"] = "x-a:b"
	trustTunnel.Clash["max-streams"] = 4
	trustTunnel.Clash["h3"] = true
	trustTunnel.Clash["client-random-auth-key"] = "crk"

	tests := []struct {
		name string
		node *proxy.Proxy
		want string
	}{
		{
			name: "snell obfs",
			node: snell,
			want: "SN = snell, sn.example.com, 443, psk=snpsk, version=4, reuse=true, obfs=http, obfs-host=bing.com, obfs-uri=/, udp-port=8443",
		},
		{
			name: "snell shadow-tls",
			node: snellShadowTLS,
			want: "SN-ST = snell, sn.example.com, 443, psk=snpsk, version=4, shadow-tls-password=stpass, shadow-tls-version=3, shadow-tls-sni=camouflage.example.com",
		},
		{
			name: "ss shadow-tls",
			node: ssShadowTLS,
			want: "SS-ST = ss, ss.example.com, 8388, encrypt-method=aes-256-gcm, password=sspw, shadow-tls-password=stpass, shadow-tls-version=2, shadow-tls-sni=camouflage.example.com",
		},
		{
			name: "anytls",
			node: anytls,
			want: "AT = anytls, at.example.com, 443, password=atpass, sni=at.example.com, skip-cert-verify=true, alpn=h2,http/1.1",
		},
		{
			name: "ssh",
			node: ssh,
			want: "SH = ssh, ssh.example.com, 22, username=root, password=sshpw",
		},
		{
			name: "masque",
			node: masque,
			want: "MQ = masque, m.example.com, 443, username=u, password=mp, port-hopping=1-65535, port-hopping-interval=30, sni=m.example.com, skip-cert-verify=true, alpn=h2",
		},
		{
			name: "trust-tunnel",
			node: trustTunnel,
			want: "TT = trust-tunnel, tt.example.com, 443, username=u, password=tp, headers=x-a:b, max-streams=4, h3=true, client-random-auth-key=crk",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, out := renderOne(t, flavorSurge, tc.node)
			if !strings.Contains(out, tc.want) {
				t.Errorf("missing %q\n---\n%s", tc.want, out)
			}
		})
	}
}

// Snell is shared by Surge and Shadowrocket; Loon has no form for it.
func TestSnellFlavorCoverage(t *testing.T) {
	n := proxy.New("snell", "SN", "sn.example.com", 443)
	n.Clash["psk"] = "snpsk"
	n.Clash["version"] = 1

	_, sr := renderOne(t, flavorShadowrocket, n)
	if !strings.Contains(sr, "SN = snell, sn.example.com, 443, psk=snpsk, version=1") {
		t.Errorf("shadowrocket snell line wrong:\n%s", sr)
	}

	res, loon := renderOne(t, flavorLoon, n)
	if strings.Contains(loon, "SN = snell") {
		t.Errorf("loon must not emit snell:\n%s", loon)
	}
	if len(res.SkippedNodes) != 1 {
		t.Errorf("loon should skip snell, got %v", res.SkippedNodes)
	}
}

func TestSurgeVLESS_Transports(t *testing.T) {
	ws := proxy.New("vless", "V-WS", "v.example.com", 443)
	ws.Clash["uuid"] = "uuid-v"
	ws.Clash["tls"] = true
	ws.Clash["sni"] = "v.example.com"
	ws.Clash["network"] = "ws"
	ws.Clash["ws-opts"] = map[string]any{
		"path": "/ws", "headers": map[string]any{"Host": "v.example.com"},
	}

	httpUpgrade := proxy.New("vless", "V-HU", "v.example.com", 443)
	httpUpgrade.Clash["uuid"] = "uuid-v"
	httpUpgrade.Clash["network"] = "ws"
	httpUpgrade.Clash["ws-opts"] = map[string]any{
		"path": "/hu", "headers": map[string]any{"Host": "v.example.com"},
		"v2ray-http-upgrade": true,
	}

	xhttp := proxy.New("vless", "V-XH", "v.example.com", 443)
	xhttp.Clash["uuid"] = "uuid-v"
	xhttp.Clash["tls"] = true
	xhttp.Clash["sni"] = "v.example.com"
	xhttp.Clash["network"] = "xhttp"
	xhttp.Clash["xhttp-opts"] = map[string]any{"path": "/x", "host": "x.example.com", "mode": "auto"}

	grpc := proxy.New("vless", "V-GRPC", "v.example.com", 443)
	grpc.Clash["uuid"] = "uuid-v"
	grpc.Clash["network"] = "grpc"
	grpc.Clash["grpc-opts"] = map[string]any{"grpc-service-name": "svc"}

	raw := proxy.New("vless", "V-RAW", "v.example.com", 443)
	raw.Clash["uuid"] = "uuid-v"
	raw.Clash["tls"] = true
	raw.Clash["sni"] = "v.example.com"

	reality := proxy.New("vless", "V-REALITY", "v.example.com", 443)
	reality.Clash["uuid"] = "uuid-v"
	reality.Clash["servername"] = "www.microsoft.com"
	reality.Clash["flow"] = "xtls-rprx-vision"
	reality.Clash["reality-opts"] = map[string]any{"public-key": "PUB", "short-id": "ab"}

	tests := []struct {
		name string
		node *proxy.Proxy
		want string
	}{
		{
			name: "ws",
			node: ws,
			want: "V-WS = vless, v.example.com, 443, username=uuid-v, tls=true, sni=v.example.com, ws=true, ws-path=/ws, ws-headers=Host:v.example.com",
		},
		{
			name: "ws-http-upgrade",
			node: httpUpgrade,
			want: "V-HU = vless, v.example.com, 443, username=uuid-v, ws=true, ws-path=/hu, ws-headers=Host:v.example.com, ws-http-upgrade=true",
		},
		{
			name: "xhttp",
			node: xhttp,
			want: "V-XH = vless, v.example.com, 443, username=uuid-v, tls=true, sni=v.example.com, xhttp=true, xhttp-path=/x, xhttp-host=x.example.com, xhttp-mode=auto",
		},
		{
			name: "grpc",
			node: grpc,
			want: "V-GRPC = vless, v.example.com, 443, username=uuid-v, grpc=true, grpc-service-name=svc",
		},
		{
			name: "raw-tls",
			node: raw,
			want: "V-RAW = vless, v.example.com, 443, username=uuid-v, tls=true, sni=v.example.com",
		},
		{
			// Surge treats REALITY as its own security mode, not tls=true.
			name: "reality",
			node: reality,
			want: "V-REALITY = vless, v.example.com, 443, username=uuid-v, sni=www.microsoft.com, reality-public-key=PUB, reality-short-id=ab, flow=xtls-rprx-vision",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, out := renderOne(t, flavorSurge, tc.node)
			if !strings.Contains(out, tc.want) {
				t.Errorf("missing %q\n---\n%s", tc.want, out)
			}
		})
	}
}

func TestSurgeVMessTrojan_HTTPUpgrade(t *testing.T) {
	vm := proxy.New("vmess", "VM", "v.example.com", 443)
	vm.Clash["uuid"] = "uuid-m"
	vm.Clash["alterId"] = 0
	vm.Clash["tls"] = true
	vm.Clash["sni"] = "v.example.com"
	vm.Clash["network"] = "ws"
	vm.Clash["ws-opts"] = map[string]any{
		"path": "/u", "headers": map[string]any{"Host": "v.example.com"},
		"v2ray-http-upgrade": true,
	}

	tj := proxy.New("trojan", "TJ", "t.example.com", 443)
	tj.Clash["password"] = "tp"
	tj.Clash["sni"] = "t.example.com"
	tj.Clash["network"] = "ws"
	tj.Clash["ws-opts"] = map[string]any{
		"path": "/u", "headers": map[string]any{"Host": "t.example.com"},
		"v2ray-http-upgrade": true,
	}

	_, out := renderOne(t, flavorSurge, vm)
	wantVM := "VM = vmess, v.example.com, 443, username=uuid-m, vmess-aead=true, tls=true, sni=v.example.com, ws=true, ws-path=/u, ws-headers=Host:v.example.com, ws-http-upgrade=true"
	if !strings.Contains(out, wantVM) {
		t.Errorf("missing %q\n---\n%s", wantVM, out)
	}

	_, out = renderOne(t, flavorSurge, tj)
	wantTJ := "TJ = trojan, t.example.com, 443, password=tp, sni=t.example.com, ws=true, ws-path=/u, ws-headers=Host:t.example.com, ws-http-upgrade=true"
	if !strings.Contains(out, wantTJ) {
		t.Errorf("missing %q\n---\n%s", wantTJ, out)
	}
}

func TestSurgeTUICVersions(t *testing.T) {
	v5 := proxy.New("tuic", "T5", "t.example.com", 443)
	v5.Version = 5
	v5.Clash["uuid"] = "uuid-5"
	v5.Clash["password"] = "tpw"
	v5.Clash["sni"] = "t.example.com"
	v5.Clash["alpn"] = []string{"h3"}

	_, out := renderOne(t, flavorSurge, v5)
	want := "T5 = tuic-v5, t.example.com, 443, uuid=uuid-5, password=tpw, sni=t.example.com, alpn=h3"
	if !strings.Contains(out, want) {
		t.Errorf("surge tuic v5 missing %q\n---\n%s", want, out)
	}
	if strings.Contains(out, "token=") {
		t.Errorf("surge tuic v5 must not emit token:\n%s", out)
	}

	v4 := proxy.New("tuic", "T4", "t.example.com", 443)
	v4.Version = 4
	v4.Clash["password"] = "tok4"

	_, out = renderOne(t, flavorSurge, v4)
	if !strings.Contains(out, "T4 = tuic, t.example.com, 443, token=tok4") {
		t.Errorf("surge tuic v4 line wrong:\n%s", out)
	}
	if strings.Contains(out, "uuid=") || strings.Contains(out, "tuic-v5") {
		t.Errorf("surge tuic v4 must use token only:\n%s", out)
	}

	// Shadowrocket TUIC v5 carries the password as a bare key=value pair, the
	// UUID as `user`, the SNI as `peer`, and UDP as `udp=1`. It cannot carry v4.
	v5SR := v5
	_, out = renderOne(t, flavorShadowrocket, v5SR)
	for _, want := range []string{"T5 = tuic, t.example.com, 443, ", "user=uuid-5", "udp=1", "sni=t.example.com", "alpn=h3"} {
		if !strings.Contains(out, want) {
			t.Errorf("shadowrocket tuic v5 missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "token=") {
		t.Errorf("shadowrocket tuic v5 must not use the v4 token form:\n%s", out)
	}

	for _, flavor := range []surgeFlavor{flavorShadowrocket, flavorLoon} {
		res, out := renderOne(t, flavor, v4)
		if strings.Contains(out, "T4 = tuic") {
			t.Errorf("flavor %d must not emit TUIC v4:\n%s", flavor, out)
		}
		if len(res.SkippedNodes) != 1 || !strings.Contains(res.SkippedNodes[0], "TUIC v4") {
			t.Errorf("flavor %d should skip TUIC v4, got %v", flavor, res.SkippedNodes)
		}
	}
}

func TestSurgeWireGuardSections(t *testing.T) {
	n := proxy.New("wireguard", "WG", "wg.example.com", 51820)
	n.Clash["private-key"] = "PRIV"
	n.Clash["public-key"] = "PUB"
	n.Clash["ip"] = "10.0.0.2/32"
	n.Clash["ipv6"] = "fd00::2/128"
	n.Clash["mtu"] = 1420
	n.Clash["pre-shared-key"] = "PSK"

	cfg := &extconfig.Config{
		ProxyGroups: []extconfig.ProxyGroup{{Name: "Proxy", Type: "select", Selectors: []string{".*"}}},
	}
	res, err := generateSurgeFamily(context.Background(), flavorSurge, []*proxy.Proxy{n}, cfg, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Output)

	for _, want := range []string{
		"WG = wireguard, section-name=WG",
		"[WireGuard WG]",
		"private-key = PRIV",
		"self-ip = 10.0.0.2/32",
		"self-ip-v6 = fd00::2/128",
		"mtu = 1420",
		`peer = (public-key = PUB, allowed-ips = "0.0.0.0/0, ::/0", endpoint = wg.example.com:51820, preshared-key = PSK)`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n---\n%s", want, out)
		}
	}

	// No invented defaults: absent DNS, keepalive and MTU stay absent.
	for _, unwanted := range []string{"dns-server = 1.1.1.1", "keepalive =", "mtu = 1280"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("surge WireGuard must not invent %q:\n%s", unwanted, out)
		}
	}

	// Sections must follow [Proxy] and stay before the next section.
	proxyIdx := strings.Index(out, "[Proxy]")
	sectionIdx := strings.Index(out, "[WireGuard WG]")
	groupIdx := strings.Index(out, "[Proxy Group]")
	if proxyIdx >= sectionIdx || sectionIdx >= groupIdx {
		t.Errorf("WireGuard section order wrong: proxy=%d section=%d group=%d\n%s", proxyIdx, sectionIdx, groupIdx, out)
	}

	// Explicit DNS, keepalive and reserved fields are carried through; reserved
	// maps to Surge's client-id.
	full := proxy.New("wireguard", "WG3", "wg.example.com", 51820)
	full.Clash["private-key"] = "PRIV"
	full.Clash["public-key"] = "PUB"
	full.Clash["ip"] = "10.0.0.2/32"
	full.Clash["dns"] = []string{"1.1.1.1", "8.8.8.8"}
	full.Clash["mtu"] = 1280
	full.Clash["persistent-keepalive"] = 25
	full.Clash["reserved"] = []int{1, 2, 3}
	_, out = renderOne(t, flavorSurge, full)
	for _, want := range []string{
		"dns-server = 1.1.1.1, 8.8.8.8",
		"mtu = 1280",
		"keepalive = 25",
		"client-id = 1/2/3",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n---\n%s", want, out)
		}
	}
}

func TestSurgeWireGuardSkipsWithoutAddress(t *testing.T) {
	n := proxy.New("wireguard", "WG", "wg.example.com", 51820)
	n.Clash["private-key"] = "PRIV"
	n.Clash["public-key"] = "PUB"

	res, out := renderOne(t, flavorSurge, n)
	if strings.Contains(out, "WG = wireguard") {
		t.Errorf("must not emit WireGuard without ip/ipv6:\n%s", out)
	}
	if len(res.SkippedNodes) != 1 || !strings.Contains(res.SkippedNodes[0], "WireGuard needs ip or ipv6") {
		t.Errorf("SkippedNodes = %v", res.SkippedNodes)
	}
}

func TestSurgeSectionNameSanitizeAndDedupe(t *testing.T) {
	if got := surgeSectionName("A]B\nC "); got != "AB C" {
		t.Errorf("surgeSectionName = %q", got)
	}
	if got := surgeSectionName("   "); got != "wireguard" {
		t.Errorf("empty name fallback = %q", got)
	}

	r := newSurgeRenderer(flavorSurge)
	if got := r.uniqueSection(surgeSectionName("Dup")); got != "Dup" {
		t.Errorf("first section = %q", got)
	}
	if got := r.uniqueSection(surgeSectionName("Dup")); got != "Dup-2" {
		t.Errorf("second section = %q", got)
	}
	if got := r.uniqueSection(surgeSectionName("Dup")); got != "Dup-3" {
		t.Errorf("third section = %q", got)
	}
}

func TestSurgeFamilySkips(t *testing.T) {
	naive := proxy.New("naive", "NV", "n.example.com", 443)
	mieru := proxy.New("mieru", "MI", "m.example.com", 443)
	amnezia := proxy.New("wireguard", "AWG", "wg.example.com", 51820)
	amnezia.Clash["ip"] = "10.0.0.2/32"
	amnezia.Clash["amnezia-wg-option"] = map[string]any{"jc": 4}
	sshKeyOnly := proxy.New("ssh", "SHK", "ssh.example.com", 22)
	sshKeyOnly.Clash["username"] = "root"
	sshKeyOnly.Clash["private-key"] = "PRIV"
	vlessXHTTP := proxy.New("vless", "V-XH", "v.example.com", 443)
	vlessXHTTP.Clash["uuid"] = "uuid-v"
	vlessXHTTP.Clash["network"] = "xhttp"

	tests := []struct {
		name   string
		flavor surgeFlavor
		node   *proxy.Proxy
		reason string
	}{
		{"naive surge", flavorSurge, naive, "naive is not supported"},
		{"mieru surge", flavorSurge, mieru, "mieru is not supported"},
		{"amneziawg surge", flavorSurge, amnezia, "AWG obfuscation is not supported"},
		{"amneziawg shadowrocket", flavorShadowrocket, amnezia, "AWG obfuscation is not supported"},
		{"amneziawg loon", flavorLoon, amnezia, "unsupported by target"},
		{"ssh key only", flavorSurge, sshKeyOnly, "Keystore"},
		{"vless xhttp loon", flavorLoon, vlessXHTTP, "xhttp transport is not supported"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, out := renderOne(t, tc.flavor, tc.node)
			if len(res.SkippedNodes) != 1 {
				t.Fatalf("SkippedNodes = %v, want one entry", res.SkippedNodes)
			}
			if !strings.Contains(res.SkippedNodes[0], tc.reason) {
				t.Errorf("skip reason %q missing in %q", tc.reason, res.SkippedNodes[0])
			}
			if strings.Contains(out, tc.node.Name+" = ") {
				t.Errorf("skipped node must not be emitted:\n%s", out)
			}
		})
	}
}

func TestShadowTLSFlavorCoverage(t *testing.T) {
	ss := proxy.New("ss", "SS", "ss.example.com", 8388)
	ss.Clash["cipher"] = "aes-256-gcm"
	ss.Clash["password"] = "p"
	ss.Clash["plugin"] = "shadow-tls"
	ss.Clash["plugin-opts"] = map[string]any{
		"host": "camouflage.example.com", "password": "st", "version": 2,
	}

	_, out := renderOne(t, flavorSurge, ss)
	if !strings.Contains(out, "shadow-tls-password=st, shadow-tls-version=2, shadow-tls-sni=camouflage.example.com") {
		t.Errorf("surge ss shadow-tls params missing:\n%s", out)
	}

	for _, flavor := range []surgeFlavor{flavorShadowrocket, flavorLoon} {
		res, out := renderOne(t, flavor, ss)
		if strings.Contains(out, "SS = ") {
			t.Errorf("flavor %d must not emit shadow-tls ss:\n%s", flavor, out)
		}
		if len(res.SkippedNodes) != 1 || !strings.Contains(res.SkippedNodes[0], "shadow-tls") {
			t.Errorf("flavor %d shadow-tls skip = %v", flavor, res.SkippedNodes)
		}
	}
}

func TestSurgeOnlyProtocolsSkippedElsewhere(t *testing.T) {
	for _, typ := range []string{"anytls", "ssh", "masque", "trusttunnel"} {
		n := proxy.New(typ, "N-"+typ, "h.example.com", 443)
		n.Clash["password"] = "p"
		n.Clash["username"] = "u"

		res, out := renderOne(t, flavorShadowrocket, n)
		if strings.Contains(out, "N-"+typ+" = ") {
			t.Errorf("Shadowrocket must not emit %s:\n%s", typ, out)
		}
		if len(res.SkippedNodes) != 1 {
			t.Errorf("%s on Shadowrocket: SkippedNodes = %v", typ, res.SkippedNodes)
		}
	}
}

// TestSurgeWireGuardRoundTrip renders a WireGuard node as a Surge policy plus
// [WireGuard ...] section and parses it back. It locks the section syntax to the
// parser so the two sides cannot drift.
func TestSurgeWireGuardRoundTrip(t *testing.T) {
	n := proxy.New("wireguard", "WG-RT", "wg.example.com", 51820)
	n.Set("private-key", "priv")
	n.Set("public-key", "pub")
	n.Set("pre-shared-key", "psk")
	n.Set("ip", "10.0.0.2")
	n.Set("ipv6", "fd00::2")
	n.Set("mtu", 1280)
	n.Set("dns", []string{"1.1.1.1"})
	n.Set("allowed-ips", "0.0.0.0/0, ::/0")
	n.Set("persistent-keepalive", 25)

	_, out := renderSurgeFamily(t, flavorSurge, []*proxy.Proxy{n}, Options{ListOnly: true})
	nodes, _, err := parser.Parse([]byte(out))
	if err != nil {
		t.Fatalf("parse rendered surge: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("parsed %d nodes, want 1:\n%s", len(nodes), out)
	}
	got := nodes[0]
	for k, want := range map[string]any{
		"server": "wg.example.com", "port": 51820,
		"private-key": "priv", "public-key": "pub", "pre-shared-key": "psk",
		"ip": "10.0.0.2", "ipv6": "fd00::2", "mtu": 1280,
		"persistent-keepalive": 25,
	} {
		if got.Clash[k] != want {
			t.Errorf("round-trip %s = %v, want %v; node=%v", k, got.Clash[k], want, got.Clash)
		}
	}
	if got := joinAny(got.Clash["allowed-ips"]); got != "0.0.0.0/0,::/0" {
		t.Errorf("round-trip allowed-ips = %q, want both families", got)
	}
}

// TestSurgeWireGuardSectionNameSanitized keeps commas and brackets in a node
// name from splitting the policy line or the section header.
func TestSurgeWireGuardSectionNameSanitized(t *testing.T) {
	n := proxy.New("wireguard", "HK, [01]", "wg.example.com", 51820)
	n.Set("private-key", "priv")
	n.Set("public-key", "pub")
	n.Set("ip", "10.0.0.2")

	_, out := renderSurgeFamily(t, flavorSurge, []*proxy.Proxy{n}, Options{ListOnly: true})
	if strings.Contains(out, "section-name=HK,") {
		t.Fatalf("section name kept a comma: %s", out)
	}
	nodes, skipped, err := parser.Parse([]byte(out))
	if err != nil || len(nodes) != 1 || len(skipped) != 0 {
		t.Fatalf("round-trip failed: nodes=%d skipped=%v err=%v\n%s", len(nodes), skipped, err, out)
	}
}

func TestSurgeWireGuardIPv6EndpointBracketed(t *testing.T) {
	n := proxy.New("wireguard", "WG6", "fd00::1", 51820)
	n.Set("private-key", "priv")
	n.Set("public-key", "pub")
	n.Set("ip", "10.0.0.2")

	_, out := renderSurgeFamily(t, flavorSurge, []*proxy.Proxy{n}, Options{ListOnly: true})
	if !strings.Contains(out, "endpoint = [fd00::1]:51820") {
		t.Errorf("IPv6 endpoint must be bracketed:\n%s", out)
	}
}
