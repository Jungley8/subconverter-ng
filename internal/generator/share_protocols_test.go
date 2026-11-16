package generator

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/parser"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

func mustParseLink(t *testing.T, link string) *url.URL {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse %q: %v", link, err)
	}
	return u
}

func TestShareSnell(t *testing.T) {
	n := proxy.New("snell", "SN", "sn.example.com", 443)
	n.Set("psk", "psk1")
	n.Set("version", 4)
	n.Set("userkey", "uk1")
	n.SetRaw("reuse", true)
	n.Set("mode", "unshaped")
	n.Set("obfs-opts", map[string]any{"mode": "http", "host": "bing.com", "uri": "/"})

	link, ok := nodeShareLink(n)
	if !ok {
		t.Fatal("no share link")
	}
	u := mustParseLink(t, link)
	if u.Scheme != "snell" || u.Host != "sn.example.com:443" {
		t.Errorf("scheme/host = %q/%q", u.Scheme, u.Host)
	}
	if pw, hasPass := u.User.Password(); hasPass || u.User.Username() != "psk1" || pw != "" {
		t.Errorf("userinfo = %q, want the psk alone", u.User.String())
	}
	q := u.Query()
	want := map[string]string{
		"version": "4", "obfs": "http", "obfs-host": "bing.com",
		"obfs-uri": "/", "userkey": "uk1", "reuse": "1", "mode": "unshaped",
	}
	for k, v := range want {
		if got := q.Get(k); got != v {
			t.Errorf("query %s = %q, want %q", k, got, v)
		}
	}
	if u.Fragment != "SN" {
		t.Errorf("fragment = %q", u.Fragment)
	}
}

func TestShareSnell_AbsentVersionOmitted(t *testing.T) {
	n := proxy.New("snell", "SN", "sn.example.com", 443)
	n.Set("psk", "psk1")
	link, _ := nodeShareLink(n)
	if strings.Contains(link, "version=") {
		t.Errorf("absent version should stay absent: %s", link)
	}
}

func TestShareSSH(t *testing.T) {
	n := proxy.New("ssh", "SSH", "ssh.example.com", 22)
	n.Set("username", "alice")
	n.Set("password", "pw1")
	n.Set("private-key", "KEYDATA")
	n.Set("private-key-passphrase", "kp")
	n.Set("host-key", []string{"ssh-ed25519 AAAA", "ssh-rsa BBBB"})
	n.Set("host-key-algorithms", []string{"ssh-ed25519"})

	link, ok := nodeShareLink(n)
	if !ok {
		t.Fatal("no share link")
	}
	u := mustParseLink(t, link)
	if u.Scheme != "ssh" || u.Host != "ssh.example.com:22" {
		t.Errorf("scheme/host = %q/%q", u.Scheme, u.Host)
	}
	if got := u.User.String(); got != "alice:pw1" {
		t.Errorf("userinfo = %q, want alice:pw1", got)
	}
	q := u.Query()
	if q.Get("private-key") != "KEYDATA" || q.Get("private-key-passphrase") != "kp" {
		t.Errorf("key query = %v", q)
	}
	if got := q.Get("host-key"); got != "ssh-ed25519 AAAA,ssh-rsa BBBB" {
		t.Errorf("host-key = %q", got)
	}
	if got := q.Get("host-key-algorithms"); got != "ssh-ed25519" {
		t.Errorf("host-key-algorithms = %q", got)
	}
}

func TestShareNaive(t *testing.T) {
	n := proxy.New("naive", "NV", "nv.example.com", 443)
	n.Set("username", "u")
	n.Set("password", "pw1")
	n.Set("sni", "sni.example.com")
	n.SetRaw("skip-cert-verify", true)
	n.Set("alpn", []string{"h2", "http/1.1"})

	link, ok := nodeShareLink(n)
	if !ok {
		t.Fatal("no share link")
	}
	u := mustParseLink(t, link)
	if u.Scheme != "naive+https" {
		t.Errorf("scheme = %q, want naive+https", u.Scheme)
	}
	if got := u.User.String(); got != "u:pw1" {
		t.Errorf("userinfo = %q", got)
	}
	q := u.Query()
	if q.Get("sni") != "sni.example.com" || q.Get("insecure") != "1" || q.Get("alpn") != "h2,http/1.1" {
		t.Errorf("query = %v", q)
	}
}

func TestShareNaive_QUIC(t *testing.T) {
	n := proxy.New("naive", "NV", "nv.example.com", 443)
	n.Set("username", "u")
	n.Set("password", "pw1")
	n.Set("sni", "sni.example.com")
	n.SetRaw("quic", true)
	n.Set("alpn", []string{"h3"})

	link, _ := nodeShareLink(n)
	u := mustParseLink(t, link)
	if u.Scheme != "naive+quic" {
		t.Errorf("scheme = %q, want naive+quic", u.Scheme)
	}
	q := u.Query()
	if q.Get("sni") != "sni.example.com" {
		t.Errorf("sni = %q", q.Get("sni"))
	}
	if q.Has("insecure") || q.Has("alpn") {
		t.Errorf("quic link should not carry HTTPS-only settings: %v", q)
	}
}

func TestShareAnyTLS(t *testing.T) {
	n := proxy.New("anytls", "AT", "at.example.com", 8443)
	n.Set("password", "pw1")
	n.Set("sni", "sni.example.com")
	n.SetRaw("skip-cert-verify", true)
	n.Set("alpn", []string{"h2", "http/1.1"})

	link, ok := nodeShareLink(n)
	if !ok {
		t.Fatal("no share link")
	}
	u := mustParseLink(t, link)
	if u.Scheme != "anytls" || u.Host != "at.example.com:8443" {
		t.Errorf("scheme/host = %q/%q", u.Scheme, u.Host)
	}
	if pw, hasPass := u.User.Password(); hasPass || u.User.Username() != "pw1" || pw != "" {
		t.Errorf("userinfo = %q", u.User.String())
	}
	q := u.Query()
	if q.Get("sni") != "sni.example.com" || q.Get("insecure") != "1" || q.Get("alpn") != "h2,http/1.1" {
		t.Errorf("query = %v", q)
	}
}

func TestShareTUICv4(t *testing.T) {
	n := proxy.New("tuic", "T4", "t4.example.com", 443)
	n.Version = 4
	n.Set("password", "token1")
	n.Set("uuid", "should-be-ignored")
	n.Set("sni", "t4.example.com")

	link, ok := nodeShareLink(n)
	if !ok {
		t.Fatal("no share link")
	}
	u := mustParseLink(t, link)
	if got := u.User.String(); got != "token1" {
		t.Errorf("userinfo = %q, want the token alone", got)
	}
	if pw, hasPass := u.User.Password(); hasPass || pw != "" {
		t.Errorf("v4 userinfo must not carry a uuid: %q", u.User.String())
	}
	if u.Query().Has("uuid") {
		t.Errorf("v4 link must not carry a uuid query key: %s", link)
	}
}

func TestShareTUICv5Unchanged(t *testing.T) {
	n := proxy.New("tuic", "T5", "t5.example.com", 443)
	n.Set("uuid", "uuid-1")
	n.Set("password", "pw1")
	link, _ := nodeShareLink(n)
	u := mustParseLink(t, link)
	if got := u.User.String(); got != "uuid-1:pw1" {
		t.Errorf("userinfo = %q, want uuid:password", got)
	}
}

func TestSSPluginSpec_ShadowTLS(t *testing.T) {
	c := map[string]any{
		"plugin": "shadow-tls",
		"plugin-opts": map[string]any{
			"host":     "tls.example.com",
			"password": "tlspw",
			"version":  3,
		},
	}
	want := "shadow-tls;host=tls.example.com;password=tlspw;version=3"
	if got := ssPluginSpec(c); got != want {
		t.Fatalf("ssPluginSpec = %q, want %q", got, want)
	}

	n := proxy.New("ss", "SS", "s.example.com", 8388)
	n.Set("cipher", "aes-128-gcm")
	n.Set("password", "sspw")
	for k, v := range c {
		n.Set(k, v)
	}
	link, _ := nodeShareLink(n)
	u := mustParseLink(t, link)
	if got := u.Query().Get("plugin"); got != want {
		t.Errorf("plugin query = %q, want %q", got, want)
	}
}

func TestApplyV2RayTransportQuery_HTTPUpgrade(t *testing.T) {
	n := proxy.New("vless", "VL", "v.example.com", 443)
	n.Set("uuid", "uuid-1")
	n.Set("network", "ws")
	n.Set("ws-opts", map[string]any{
		"path":               "/up",
		"v2ray-http-upgrade": true,
		"headers":            map[string]any{"Host": "cdn.example.com"},
	})

	link, _ := nodeShareLink(n)
	q := mustParseLink(t, link).Query()
	if q.Get("type") != "httpupgrade" {
		t.Errorf("type = %q, want httpupgrade", q.Get("type"))
	}
	if q.Get("path") != "/up" || q.Get("host") != "cdn.example.com" {
		t.Errorf("transport query = %v", q)
	}
}

func TestApplyV2RayTransportQuery_PlainWS(t *testing.T) {
	n := proxy.New("vless", "VL", "v.example.com", 443)
	n.Set("uuid", "uuid-1")
	n.Set("network", "ws")
	n.Set("ws-opts", map[string]any{
		"path":    "/plain",
		"headers": map[string]any{"Host": "cdn.example.com"},
	})

	link, _ := nodeShareLink(n)
	q := mustParseLink(t, link).Query()
	if q.Get("type") != "ws" || q.Get("path") != "/plain" || q.Get("host") != "cdn.example.com" {
		t.Errorf("plain ws query = %v", q)
	}
}

func TestApplyV2RayTransportQuery_XHTTP(t *testing.T) {
	n := proxy.New("vless", "VL", "v.example.com", 443)
	n.Set("uuid", "uuid-1")
	n.Set("network", "xhttp")
	n.Set("xhttp-opts", map[string]any{
		"path":               "/x",
		"host":               "xh.example.com",
		"mode":               "stream-up",
		"uplink-http-method": "PUT",
		"no-grpc-header":     true,
	})

	link, _ := nodeShareLink(n)
	q := mustParseLink(t, link).Query()
	if q.Get("type") != "xhttp" || q.Get("path") != "/x" || q.Get("host") != "xh.example.com" || q.Get("mode") != "stream-up" {
		t.Errorf("transport query = %v", q)
	}
	raw := q.Get("extra")
	if raw == "" {
		t.Fatal("extra JSON missing")
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(raw), &extra); err != nil {
		t.Fatalf("extra is not JSON: %v (%q)", err, raw)
	}
	if _, ok := extra["path"]; ok {
		t.Errorf("extra must not repeat path: %v", extra)
	}
	if extra["uplink-http-method"] != "PUT" || extra["no-grpc-header"] != true {
		t.Errorf("extra = %v", extra)
	}
}

func TestApplyV2RayTransportQuery_XHTTP_NoExtra(t *testing.T) {
	n := proxy.New("vless", "VL", "v.example.com", 443)
	n.Set("uuid", "uuid-1")
	n.Set("network", "xhttp")
	n.Set("xhttp-opts", map[string]any{"path": "/x", "host": "xh.example.com", "mode": "auto"})

	link, _ := nodeShareLink(n)
	q := mustParseLink(t, link).Query()
	if q.Has("extra") {
		t.Errorf("extra emitted with no keys beyond path/host/mode: %v", q)
	}
}

func TestApplyVMessTransportJSON_HTTPUpgrade(t *testing.T) {
	n := proxy.New("vmess", "VM", "vm.example.com", 443)
	n.Set("uuid", "uuid-1")
	n.Set("network", "ws")
	n.Set("ws-opts", map[string]any{
		"path":               "/up",
		"v2ray-http-upgrade": true,
		"headers":            map[string]any{"Host": "cdn.example.com"},
	})

	link, ok := nodeShareLink(n)
	if !ok {
		t.Fatal("no share link")
	}
	j := decodeVMessJSON(t, link)
	if j["net"] != "httpupgrade" || j["path"] != "/up" || j["host"] != "cdn.example.com" {
		t.Errorf("vmess transport JSON = %v", j)
	}
}

func TestApplyVMessTransportJSON_XHTTP(t *testing.T) {
	n := proxy.New("vmess", "VM", "vm.example.com", 443)
	n.Set("uuid", "uuid-1")
	n.Set("network", "xhttp")
	n.Set("xhttp-opts", map[string]any{
		"path":               "/x",
		"host":               "xh.example.com",
		"mode":               "packet-up",
		"uplink-http-method": "PUT",
	})

	link, _ := nodeShareLink(n)
	j := decodeVMessJSON(t, link)
	if j["net"] != "xhttp" || j["path"] != "/x" || j["host"] != "xh.example.com" || j["mode"] != "packet-up" {
		t.Errorf("vmess transport JSON = %v", j)
	}
	raw, _ := j["extra"].(string)
	if raw == "" {
		t.Fatal("extra JSON missing")
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(raw), &extra); err != nil {
		t.Fatalf("extra is not JSON: %v (%q)", err, raw)
	}
	if extra["uplink-http-method"] != "PUT" {
		t.Errorf("extra = %v", extra)
	}
}

func TestWireGuardAmneziaWGQuery(t *testing.T) {
	n := proxy.New("wireguard", "AWG", "wg.example.com", 51820)
	n.Set("private-key", "priv")
	n.Set("public-key", "pub")
	n.Set("ip", "10.0.0.2")
	n.Set("amnezia-wg-option", map[string]any{
		"jc": 5, "jmin": 50, "jmax": 1000,
		"s1": 10, "s2": 20,
		"h1": 123456, "h4": "987654",
		"i1": "<b 0x1234>", "j1": 7,
		"itime": 42, "version": 2,
	})

	link, ok := nodeShareLink(n)
	if !ok {
		t.Fatal("no share link")
	}
	u := mustParseLink(t, link)
	if u.Scheme != "wireguard" {
		t.Errorf("scheme = %q", u.Scheme)
	}
	q := u.Query()
	want := map[string]string{
		"jc": "5", "jmin": "50", "jmax": "1000", "s1": "10", "s2": "20",
		"h1": "123456", "h4": "987654", "i1": "<b 0x1234>", "j1": "7",
		"itime": "42", "version": "2",
	}
	for k, v := range want {
		if got := q.Get(k); got != v {
			t.Errorf("query %s = %q, want %q", k, got, v)
		}
	}
	if q.Has("s3") || q.Has("h2") || q.Has("i5") {
		t.Errorf("absent AWG keys must stay absent: %v", q)
	}
}

func TestGenerateSSD_ShadowTLSPlugin(t *testing.T) {
	a := proxy.New("ss", "HK", "1.2.3.4", 8388)
	a.Set("cipher", "aes-128-gcm")
	a.Set("password", "pw1")
	a.Set("plugin", "shadow-tls")
	a.Set("plugin-opts", map[string]any{
		"host":     "tls.example.com",
		"password": "tlspw",
		"version":  3,
	})

	res, err := GenerateSSD(context.Background(), []*proxy.Proxy{a}, &extconfig.Config{}, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatalf("GenerateSSD: %v", err)
	}
	body, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(string(res.Output), "ssd://"))
	if err != nil {
		t.Fatalf("body is not base64: %v", err)
	}
	var doc struct {
		Servers []struct {
			Plugin        string `json:"plugin"`
			PluginOptions string `json:"plugin_options"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("body is not SSD JSON: %v\n%s", err, body)
	}
	if len(doc.Servers) != 1 {
		t.Fatalf("servers = %+v", doc.Servers)
	}
	srv := doc.Servers[0]
	if srv.Plugin != "shadow-tls" {
		t.Errorf("plugin = %q, want shadow-tls", srv.Plugin)
	}
	want := "host=tls.example.com;password=tlspw;version=3"
	if srv.PluginOptions != want {
		t.Errorf("plugin_options = %q, want %q", srv.PluginOptions, want)
	}
}

func decodeVMessJSON(t *testing.T, link string) map[string]any {
	t.Helper()
	body := strings.TrimPrefix(link, "vmess://")
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("vmess body is not base64: %v", err)
	}
	var j map[string]any
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatalf("vmess body is not JSON: %v\n%s", err, raw)
	}
	return j
}

// decodeShareLinks renders nodes as a v2ray link list and parses the decoded
// result back. It is the round-trip guard for newly supported link forms.
func decodeShareLinks(t *testing.T, nodes []*proxy.Proxy) []*proxy.Proxy {
	t.Helper()
	res, err := GenerateV2ray(context.Background(), nodes, &extconfig.Config{}, fakeFetcher{}, Options{})
	if err != nil {
		t.Fatalf("generate v2ray: %v", err)
	}
	body, err := base64.StdEncoding.DecodeString(string(res.Output))
	if err != nil {
		t.Fatalf("decode v2ray list: %v", err)
	}
	parsed, skipped, err := parser.Parse(body)
	if err != nil {
		t.Fatalf("parse rendered links: %v\n%s", err, body)
	}
	if len(skipped) != 0 {
		t.Fatalf("rendered links did not parse: %v\n%s", skipped, body)
	}
	return parsed
}

func TestShareLinkRoundTrip_ModernProtocols(t *testing.T) {
	snell := proxy.New("snell", "SN", "sn.example.com", 443)
	snell.Set("psk", "pskpass")
	snell.SetRaw("version", 4)
	snell.Set("obfs-opts", map[string]any{"mode": "http", "host": "bing.com", "uri": "/"})

	snellST := proxy.New("snell", "SN-ST", "sn2.example.com", 443)
	snellST.Set("psk", "pskpass2")
	snellST.SetRaw("version", 4)
	snellST.Set("obfs-opts", map[string]any{
		"mode": "shadow-tls", "host": "camouflage.example.com",
		"password": "stpass", "version": 3,
	})

	ssh := proxy.New("ssh", "SSH", "ssh.example.com", 22)
	ssh.Set("username", "root")
	ssh.Set("password", "sshpass")
	ssh.Set("private-key", "KEY")

	naive := proxy.New("naive", "NV", "naive.example.com", 443)
	naive.Set("username", "user")
	naive.Set("password", "naivepass")
	naive.Set("sni", "naive.example.com")

	anytls := proxy.New("anytls", "AT", "at.example.com", 8443)
	anytls.Set("password", "anypass")
	anytls.Set("sni", "at.example.com")

	tuic4 := proxy.New("tuic", "T4", "t4.example.com", 443)
	tuic4.Set("password", "v4token")
	tuic4.Version = 4

	parsed := decodeShareLinks(t, []*proxy.Proxy{snell, snellST, ssh, naive, anytls, tuic4})
	if len(parsed) != 6 {
		t.Fatalf("parsed %d links, want 6", len(parsed))
	}

	if got := parsed[0].Clash; got["psk"] != "pskpass" || ci(got, "version") != 4 ||
		cs(cmap(got, "obfs-opts"), "mode") != "http" {
		t.Errorf("snell round-trip wrong: %v", got)
	}
	sto := cmap(parsed[1].Clash, "obfs-opts")
	if cs(sto, "mode") != "shadow-tls" || cs(sto, "host") != "camouflage.example.com" ||
		cs(sto, "password") != "stpass" || ci(sto, "version") != 3 {
		t.Errorf("snell shadow-tls round-trip wrong: %v", parsed[1].Clash)
	}
	if parsed[2].Clash["username"] != "root" || parsed[2].Clash["private-key"] != "KEY" {
		t.Errorf("ssh round-trip wrong: %v", parsed[2].Clash)
	}
	if parsed[3].Clash["username"] != "user" || parsed[3].Clash["sni"] != "naive.example.com" {
		t.Errorf("naive round-trip wrong: %v", parsed[3].Clash)
	}
	if parsed[4].Clash["sni"] != "at.example.com" {
		t.Errorf("anytls round-trip wrong: %v", parsed[4].Clash)
	}
	if parsed[5].Version != 4 || parsed[5].Clash["password"] != "v4token" {
		t.Errorf("tuic v4 round-trip wrong: version=%d clash=%v", parsed[5].Version, parsed[5].Clash)
	}
}
