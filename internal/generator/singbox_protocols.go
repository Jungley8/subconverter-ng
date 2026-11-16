package generator

import (
	"strconv"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// singboxSkipReason reports why a node cannot become a sing-box outbound at all.
// Version floors are applied before this runs; this covers protocol support and
// the wrappers sing-box cannot express. An empty result means "renderable".
func singboxSkipReason(n *proxy.Proxy) string {
	c := n.Clash
	switch n.Type {
	case "mieru":
		return "mieru is not supported by sing-box"
	case "masque":
		return "masque is an endpoint in sing-box, not an outbound"
	case "trusttunnel":
		return "trusttunnel is not supported by sing-box"
	case "tuic":
		if n.Version == 4 {
			return "TUIC v4 is not supported by sing-box"
		}
	case "wireguard":
		if hasAmneziaWG(c) {
			return "AmneziaWG is not supported by sing-box"
		}
	case "snell":
		if isShadowTLS(c) {
			return "snell shadow-tls: unsupported by sing-box"
		}
		v := snellVersion(c)
		if v != 4 && v != 6 {
			return "requires snell version 4 or 6"
		}
		if v == 4 {
			if mode := cs(cmap(c, "obfs-opts"), "mode"); mode != "" && mode != "http" && mode != "none" {
				return "snell obfs " + mode + " is not supported by sing-box"
			}
		}
	}
	if isXHTTP(c) {
		return "xhttp transport is not supported by sing-box"
	}
	return ""
}

// singboxOutboundsForNode renders the outbound(s) for one node. A ShadowTLS-
// wrapped ss node is the only case with more than one.
func singboxOutboundsForNode(n *proxy.Proxy, usedTags map[string]bool) ([]map[string]any, bool) {
	if n.Type == "ss" && isShadowTLS(n.Clash) {
		return singboxShadowTLSChain(n, usedTags)
	}
	ob, ok := nodeSingboxOutbound(n)
	if !ok {
		return nil, false
	}
	return []map[string]any{ob}, true
}

// singboxNodeBase seeds the fields every outbound shares.
func singboxNodeBase(n *proxy.Proxy) map[string]any {
	return map[string]any{
		"tag":         n.Name,
		"server":      cs(n.Clash, "server"),
		"server_port": ci(n.Clash, "port"),
	}
}

// snellVersion reads the protocol version; the canonical model treats an absent
// version as 1.
func snellVersion(c map[string]any) int {
	if v := ci(c, "version"); v > 0 {
		return v
	}
	return 1
}

// singboxSnellOutbound renders a Snell outbound. snellVersion and the obfs mode
// were validated by singboxSkipReason: sing-box accepts only versions 4 and 6,
// and only the http obfs.
func singboxSnellOutbound(n *proxy.Proxy) (map[string]any, bool) {
	c := n.Clash
	v := snellVersion(c)
	if v != 4 && v != 6 {
		return nil, false
	}
	base := singboxNodeBase(n)
	base["type"] = "snell"
	base["psk"] = cs(c, "psk")
	base["version"] = v
	if uk := cs(c, "userkey"); uk != "" {
		base["userkey"] = uk
	}
	if cb(c, "reuse") {
		base["reuse"] = true
	}
	if v == 4 {
		opts := cmap(c, "obfs-opts")
		if cs(opts, "mode") == "http" {
			base["obfs_mode"] = "http"
			if h := cs(opts, "host"); h != "" {
				base["obfs_host"] = h
			}
		}
	} else if mode := cs(c, "mode"); mode != "" {
		base["mode"] = mode
	}
	return base, true
}

// singboxSSHOutbound renders an SSH outbound.
func singboxSSHOutbound(n *proxy.Proxy) map[string]any {
	c := n.Clash
	base := singboxNodeBase(n)
	base["type"] = "ssh"
	base["user"] = cs(c, "username")
	base["password"] = cs(c, "password")
	if pk := cs(c, "private-key"); pk != "" {
		base["private_key"] = pk
	}
	if pp := cs(c, "private-key-passphrase"); pp != "" {
		base["private_key_passphrase"] = pp
	}
	if hk := splitAny(c["host-key"]); len(hk) > 0 {
		base["host_key"] = hk
	}
	if hka := splitAny(c["host-key-algorithms"]); len(hka) > 0 {
		base["host_key_algorithms"] = hka
	}
	return base
}

// singboxNaiveOutbound renders a naive outbound. naive is always TLS; sing-box
// exposes no insecure switch for it, so skip-cert-verify is dropped rather than
// emitted as a field the client would reject.
func singboxNaiveOutbound(n *proxy.Proxy) map[string]any {
	c := n.Clash
	base := singboxNodeBase(n)
	base["type"] = "naive"
	base["username"] = cs(c, "username")
	base["password"] = cs(c, "password")
	if cb(c, "quic") {
		base["quic"] = true
	}
	tls := map[string]any{"enabled": true}
	if sni := cs(c, "sni"); sni != "" {
		tls["server_name"] = sni
	}
	if alpn := splitAny(c["alpn"]); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	base["tls"] = tls
	return base
}

// singboxShadowTLSChain renders a ShadowTLS-wrapped ss node as two outbounds:
// sing-box has no ShadowTLS plugin, so the wrapper is its own outbound and the
// shadowsocks outbound detours through it. usedTags keeps the derived tag
// unique against node names and other chains.
func singboxShadowTLSChain(n *proxy.Proxy, usedTags map[string]bool) ([]map[string]any, bool) {
	inner, ok := nodeSingboxOutbound(n)
	if !ok {
		return nil, false
	}
	host, pass, version := shadowTLSOpts(n.Clash)
	tag := uniqueTag(n.Name+"-shadowtls", usedTags)
	usedTags[tag] = true
	inner["detour"] = tag

	wrapper := singboxNodeBase(n)
	wrapper["tag"] = tag
	wrapper["type"] = "shadowtls"
	wrapper["password"] = pass
	if version > 0 {
		wrapper["version"] = version
	}
	// Only the camouflage SNI and the uTLS fingerprint apply to the wrapper; the
	// inner node's TLS fields describe a different handshake.
	wrapper["tls"] = singboxTLS(
		map[string]any{"client-fingerprint": cs(n.Clash, "client-fingerprint")}, host, true)
	return []map[string]any{inner, wrapper}, true
}

// uniqueTag returns base, or base-2/base-3/... when the tag is already taken.
func uniqueTag(base string, used map[string]bool) string {
	if !used[base] {
		return base
	}
	for i := 2; ; i++ {
		candidate := base + "-" + strconv.Itoa(i)
		if !used[candidate] {
			return candidate
		}
	}
}
