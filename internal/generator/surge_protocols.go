package generator

import (
	"strconv"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// surgeRenderer carries the per-run state of a surge-family render. Surge needs
// WireGuard out of line: a policy line in [Proxy] points at a [WireGuard ...]
// section, so the sections are collected here and written after [Proxy].
type surgeRenderer struct {
	flavor   surgeFlavor
	sections []string
	secNames map[string]bool
}

func newSurgeRenderer(flavor surgeFlavor) *surgeRenderer {
	return &surgeRenderer{flavor: flavor, secNames: map[string]bool{}}
}

// sectionsBlock renders the collected WireGuard sections. Each one is preceded
// by a blank line so the output reads as separate INI blocks.
func (r *surgeRenderer) sectionsBlock() string {
	var b strings.Builder
	for _, s := range r.sections {
		b.WriteString("\n")
		b.WriteString(s)
	}
	return b.String()
}

// surgeTransportSkip reports why a flavor cannot render the node's transport,
// or "" when it can. Surge renders raw TCP and TLS VLESS; its extra transports
// (xhttp, grpc) are VLESS-only. Shadowrocket and Loon keep ws only.
func surgeTransportSkip(flavor surgeFlavor, typ, network string) string {
	switch network {
	case "", "tcp", "ws":
		return ""
	case "xhttp":
		if flavor == flavorSurge && typ == "vless" {
			return ""
		}
		return "xhttp transport is not supported"
	case "grpc":
		if flavor == flavorSurge && typ == "vless" {
			return ""
		}
		return "gRPC transport is not supported"
	default:
		return "transport " + network + " is not supported"
	}
}

// surgeTransportParts renders vmess/vless/trojan transport params. Surge gets
// xhttp and grpc; Shadowrocket keeps ws (with the optional http-upgrade flag).
func surgeTransportParts(flavor surgeFlavor, c map[string]any) []string {
	var parts []string
	if cs(c, "network") == "ws" {
		parts = append(parts, surgeWSParts(c)...)
		if flavor == flavorSurge && isHTTPUpgrade(c) {
			parts = append(parts, "ws-http-upgrade=true")
		}
	}
	if flavor != flavorSurge {
		return parts
	}
	if isXHTTP(c) {
		x := cmap(c, "xhttp-opts")
		parts = append(parts, "xhttp=true")
		if p := cs(x, "path"); p != "" {
			parts = append(parts, "xhttp-path="+p)
		}
		if h := cs(x, "host"); h != "" {
			parts = append(parts, "xhttp-host="+h)
		}
		if m := cs(x, "mode"); m != "" {
			parts = append(parts, "xhttp-mode="+m)
		}
	}
	if cs(c, "network") == "grpc" {
		parts = append(parts, "grpc=true")
		if sn := cs(cmap(c, "grpc-opts"), "grpc-service-name"); sn != "" {
			parts = append(parts, "grpc-service-name="+sn)
		}
	}
	return parts
}

// surgeTUICTLSParts renders the TLS params shared by Surge's tuic-v5/tuic and
// Shadowrocket's legacy tuic line.
func surgeTUICTLSParts(c map[string]any) []string {
	var parts []string
	if sni := getSNI(c); sni != "" {
		parts = append(parts, "sni="+sni)
	}
	if alpn := joinAny(c["alpn"]); alpn != "" {
		parts = append(parts, "alpn="+alpn)
	}
	if cb(c, "skip-cert-verify") {
		parts = append(parts, "skip-cert-verify=true")
	}
	return parts
}

// surgeShadowTLSParams renders the shadow-tls wrapper params Surge appends to
// an ss or snell line.
func surgeShadowTLSParams(c map[string]any) []string {
	host, pass, version := shadowTLSOpts(c)
	var parts []string
	if pass != "" {
		parts = append(parts, "shadow-tls-password="+pass)
	}
	if version > 0 {
		parts = append(parts, "shadow-tls-version="+strconv.Itoa(version))
	}
	if host != "" {
		parts = append(parts, "shadow-tls-sni="+host)
	}
	return parts
}

func surgeSnellParts(c map[string]any) []string {
	version := ci(c, "version")
	if version == 0 {
		version = 1
	}
	parts := []string{
		"snell", cs(c, "server"), strconv.Itoa(ci(c, "port")),
		"psk=" + cs(c, "psk"),
		"version=" + strconv.Itoa(version),
	}
	if cb(c, "reuse") {
		parts = append(parts, "reuse=true")
	}
	obfs := cmap(c, "obfs-opts")
	switch cs(obfs, "mode") {
	case "http", "tls":
		parts = append(parts, "obfs="+cs(obfs, "mode"))
		if h := cs(obfs, "host"); h != "" {
			parts = append(parts, "obfs-host="+h)
		}
		if u := cs(obfs, "uri"); u != "" {
			parts = append(parts, "obfs-uri="+u)
		}
	case "shadow-tls":
		parts = append(parts, surgeShadowTLSParams(c)...)
	}
	if udp := ci(c, "udp-port"); udp > 0 {
		parts = append(parts, "udp-port="+strconv.Itoa(udp))
	}
	if mode := cs(c, "mode"); mode != "" {
		parts = append(parts, "mode="+mode)
	}
	return parts
}

// surgeHysteria2ObfsParts renders Hysteria2 obfuscation. Surge writes the key as
// part of the parameter name (salamander-<key>); Shadowrocket/Loon take the
// canonical obfs + obfs-<key> pair.
func surgeHysteria2ObfsParts(flavor surgeFlavor, c map[string]any) []string {
	obfs := cs(c, "obfs")
	if obfs == "" {
		return nil
	}
	key := cs(c, "obfs-password")
	if key == "" {
		return []string{"obfs=" + obfs}
	}
	if flavor == flavorSurge && (obfs == "salamander" || obfs == "gecko") {
		return []string{obfs + "-" + key}
	}
	return []string{"obfs=" + obfs, "obfs-password=" + key}
}

// surgeAnytlsParts renders anytls.
func surgeAnytlsParts(c map[string]any) []string {
	parts := []string{
		"anytls", cs(c, "server"), strconv.Itoa(ci(c, "port")),
		"password=" + cs(c, "password"),
	}
	if sni := getSNI(c); sni != "" {
		parts = append(parts, "sni="+sni)
	}
	if cb(c, "skip-cert-verify") {
		parts = append(parts, "skip-cert-verify=true")
	}
	if alpn := joinAny(c["alpn"]); alpn != "" {
		parts = append(parts, "alpn="+alpn)
	}
	return parts
}

// surgeSSHParts renders an ssh line. Surge can only authenticate with a stored
// Keystore item, so a private-key-only node has no representation.
func surgeSSHParts(c map[string]any) ([]string, string) {
	user := cs(c, "username")
	if user == "" {
		return nil, "ssh needs a username"
	}
	pass := cs(c, "password")
	if pass == "" {
		if cs(c, "private-key") != "" {
			return nil, "ssh needs a Keystore item for private-key auth"
		}
		return nil, "ssh needs a password or a Keystore item"
	}
	parts := []string{"ssh", cs(c, "server"), strconv.Itoa(ci(c, "port")), "username=" + user}
	return append(parts, "password="+pass), ""
}

func surgeMasqueParts(c map[string]any) []string {
	parts := []string{"masque", cs(c, "server"), strconv.Itoa(ci(c, "port"))}
	if u := cs(c, "username"); u != "" {
		parts = append(parts, "username="+u)
	}
	if pw := cs(c, "password"); pw != "" {
		parts = append(parts, "password="+pw)
	}
	if ph := cs(c, "port-hopping"); ph != "" {
		parts = append(parts, "port-hopping="+ph)
	}
	if phi := ci(c, "port-hopping-interval"); phi > 0 {
		parts = append(parts, "port-hopping-interval="+strconv.Itoa(phi))
	}
	if sni := getSNI(c); sni != "" {
		parts = append(parts, "sni="+sni)
	}
	if cb(c, "skip-cert-verify") {
		parts = append(parts, "skip-cert-verify=true")
	}
	if alpn := joinAny(c["alpn"]); alpn != "" {
		parts = append(parts, "alpn="+alpn)
	}
	return parts
}

func surgeTrustTunnelParts(c map[string]any) []string {
	parts := []string{
		"trust-tunnel", cs(c, "server"), strconv.Itoa(ci(c, "port")),
		"username=" + cs(c, "username"),
		"password=" + cs(c, "password"),
	}
	if h := cs(c, "headers"); h != "" {
		parts = append(parts, "headers="+h)
	}
	if ms := ci(c, "max-streams"); ms > 0 {
		parts = append(parts, "max-streams="+strconv.Itoa(ms))
	}
	if cb(c, "h3") {
		parts = append(parts, "h3=true")
	}
	if k := cs(c, "client-random-auth-key"); k != "" {
		parts = append(parts, "client-random-auth-key="+k)
	}
	return parts
}

// surgeSectionName makes a node name safe for a [WireGuard ...] header. Commas
// and equals signs would split the policy line's section-name= value.
func surgeSectionName(name string) string {
	s := strings.ReplaceAll(name, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "]", "")
	s = strings.ReplaceAll(s, "[", "")
	s = strings.ReplaceAll(s, ",", " ")
	s = strings.ReplaceAll(s, "=", " ")
	s = strings.TrimSpace(s)
	if s == "" {
		return "wireguard"
	}
	return s
}

func (r *surgeRenderer) uniqueSection(base string) string {
	name := base
	for i := 2; r.secNames[name]; i++ {
		name = base + "-" + strconv.Itoa(i)
	}
	r.secNames[name] = true
	return name
}

// surgeWireGuardPolicy renders the policy line and records its matching
// section. A node without ip or ipv6 cannot be routed and is skipped.
func (r *surgeRenderer) surgeWireGuardPolicy(n *proxy.Proxy) (string, string) {
	c := n.Clash
	if cs(c, "private-key") == "" || cs(c, "public-key") == "" {
		return "", "wireguard needs a private-key and public-key"
	}
	ip, ipv6 := cs(c, "ip"), cs(c, "ipv6")
	if ip == "" && ipv6 == "" {
		return "", "WireGuard needs ip or ipv6"
	}
	section := r.uniqueSection(surgeSectionName(n.Name))

	var b strings.Builder
	b.WriteString("[WireGuard " + section + "]\n")
	if priv := cs(c, "private-key"); priv != "" {
		b.WriteString("private-key = " + priv + "\n")
	}
	if ip != "" {
		b.WriteString("self-ip = " + ip + "\n")
	}
	if ipv6 != "" {
		b.WriteString("self-ip-v6 = " + ipv6 + "\n")
	}
	dns := joinAny(c["dns"])
	if dns == "" {
		dns = "1.1.1.1"
	}
	b.WriteString("dns-server = " + dns + "\n")
	mtu := ci(c, "mtu")
	if mtu <= 0 {
		mtu = 1280
	}
	b.WriteString("mtu = " + strconv.Itoa(mtu) + "\n")
	allowed := joinAny(c["allowed-ips"])
	if allowed == "" {
		allowed = "0.0.0.0/0, ::/0"
	}
	server := cs(c, "server")
	endpoint := server + ":" + strconv.Itoa(ci(c, "port"))
	if strings.Contains(server, ":") {
		endpoint = "[" + server + "]:" + strconv.Itoa(ci(c, "port"))
	}
	peer := []string{
		"public-key = " + cs(c, "public-key"),
		"allowed-ips = \"" + allowed + "\"",
		"endpoint = " + endpoint,
	}
	if psk := cs(c, "pre-shared-key"); psk != "" {
		peer = append(peer, "preshared-key = "+psk)
	}
	keepalive := ci(c, "persistent-keepalive")
	if keepalive <= 0 {
		keepalive = 30
	}
	peer = append(peer, "keepalive = "+strconv.Itoa(keepalive))
	b.WriteString("peer = (" + strings.Join(peer, ", ") + ")")
	r.sections = append(r.sections, b.String())

	return n.Name + " = wireguard, section-name=" + section, ""
}
