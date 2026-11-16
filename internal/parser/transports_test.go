package parser

import (
	"net/url"
	"testing"
)

func TestParseTUIC_V4AndV5(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		want    map[string]any
		version int
		wantErr bool
	}{
		{
			name:    "v4 token in userinfo",
			uri:     "tuic://tok123@h.example.com:443#T4",
			version: 4,
			want: map[string]any{
				"type":     "tuic",
				"password": "tok123",
				"uuid":     nil,
			},
		},
		{
			name:    "v4 token in query",
			uri:     "tuic://h.example.com:443?token=tok456#T4Q",
			version: 4,
			want: map[string]any{
				"type":     "tuic",
				"password": "tok456",
			},
		},
		{
			name:    "v5 uuid and password",
			uri:     "tuic://uuid-1:tpass@h.example.com:443?congestion_control=bbr#T5",
			version: 0,
			want: map[string]any{
				"type":                  "tuic",
				"uuid":                  "uuid-1",
				"password":              "tpass",
				"congestion-controller": "bbr",
			},
		},
		{
			name:    "v5 uuid in query",
			uri:     "tuic://:tpass@h.example.com:443?uuid=uuid-2#T5Q",
			version: 0,
			want: map[string]any{
				"type":     "tuic",
				"uuid":     "uuid-2",
				"password": "tpass",
			},
		},
		{name: "v5 missing password", uri: "tuic://uuid@h.example.com:443?uuid=uuid-3", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseTUIC(tc.uri)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", p)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if p.Version != tc.version {
				t.Errorf("Version = %d, want %d", p.Version, tc.version)
			}
			checkClash(t, p, tc.want)
		})
	}
}

func TestParseVLESS_Transports(t *testing.T) {
	extra := url.QueryEscape(`{"no-grpc-header":true,"uplink-http-method":"POST","path":"/ignored"}`)
	tests := []struct {
		name string
		uri  string
		want map[string]any
	}{
		{
			name: "xhttp merges extra and query wins",
			uri:  "vless://uuid@h.example.com:443?type=xhttp&path=/x&host=cdn.example.com&mode=stream-one&extra=" + extra + "#X",
			want: map[string]any{
				"network": "xhttp",
				"xhttp-opts": map[string]any{
					"path":               "/x",
					"host":               "cdn.example.com",
					"mode":               "stream-one",
					"no-grpc-header":     true,
					"uplink-http-method": "POST",
				},
			},
		},
		{
			name: "splithttp maps to xhttp",
			uri:  "vless://uuid@h.example.com:443?type=splithttp&path=/s#S",
			want: map[string]any{
				"network":    "xhttp",
				"xhttp-opts": map[string]any{"path": "/s"},
			},
		},
		{
			name: "httpupgrade maps to ws",
			uri:  "vless://uuid@h.example.com:443?type=httpupgrade&host=up.example.com&path=/up#HU",
			want: map[string]any{
				"network": "ws",
				"ws-opts": map[string]any{
					"path":               "/up",
					"headers":            map[string]any{"Host": "up.example.com"},
					"v2ray-http-upgrade": true,
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseVLESS(tc.uri)
			if err != nil {
				t.Fatal(err)
			}
			checkClash(t, p, tc.want)
		})
	}
}

func TestParseVMess_Transports(t *testing.T) {
	tests := []struct {
		name string
		json string
		want map[string]any
	}{
		{
			name: "net httpupgrade",
			json: `{"ps":"HU","add":"h.example.com","port":443,"id":"u","net":"httpupgrade","host":"up.example.com","path":"/up"}`,
			want: map[string]any{
				"network": "ws",
				"ws-opts": map[string]any{
					"path":               "/up",
					"headers":            map[string]any{"Host": "up.example.com"},
					"v2ray-http-upgrade": true,
				},
			},
		},
		{
			name: "net xhttp",
			json: `{"ps":"X","add":"h.example.com","port":443,"id":"u","net":"xhttp","host":"cdn.example.com","path":"/x"}`,
			want: map[string]any{
				"network": "xhttp",
				"xhttp-opts": map[string]any{
					"path": "/x",
					"host": "cdn.example.com",
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseVMess("vmess://" + b64(tc.json))
			if err != nil {
				t.Fatal(err)
			}
			checkClash(t, p, tc.want)
		})
	}
}

func TestParseClashYAML_TUICV4(t *testing.T) {
	doc := `
proxies:
  - name: V4
    type: tuic
    server: 1.2.3.4
    port: 443
    token: tok-v4
  - name: V5
    type: tuic
    server: 2.3.4.5
    port: 443
    uuid: uuid-5
    password: pw-5
`
	nodes, skipped, err := parseClashYAML(doc)
	if err != nil || len(skipped) != 0 || len(nodes) != 2 {
		t.Fatalf("parse failed: nodes=%v skipped=%v err=%v", nodes, skipped, err)
	}
	v4, v5 := nodes[0], nodes[1]
	if v4.Version != 4 {
		t.Errorf("V4 Version = %d, want 4", v4.Version)
	}
	if v4.Clash["password"] != "tok-v4" {
		t.Errorf("V4 password = %v, want tok-v4", v4.Clash["password"])
	}
	if _, ok := v4.Clash["token"]; ok {
		t.Error("V4 token key should be removed")
	}
	if _, ok := v4.Clash["uuid"]; ok {
		t.Error("V4 should have no uuid")
	}
	if v5.Version != 0 {
		t.Errorf("V5 Version = %d, want 0", v5.Version)
	}
}

func TestParseSS_ShadowTLSPlugin(t *testing.T) {
	plugin := url.QueryEscape("shadow-tls;host=cdn.example.com;password=stpass;version=3")
	uri := "ss://" + b64("aes-256-gcm:spw") + "@h.example.com:443?plugin=" + plugin + "#ST"
	p, err := parseSS(uri)
	if err != nil {
		t.Fatal(err)
	}
	if p.Clash["plugin"] != "shadow-tls" {
		t.Fatalf("plugin = %v, want shadow-tls", p.Clash["plugin"])
	}
	opts, _ := p.Clash["plugin-opts"].(map[string]any)
	want := map[string]any{
		"host":     "cdn.example.com",
		"password": "stpass",
		"version":  3,
	}
	for k, v := range want {
		if opts[k] != v {
			t.Errorf("plugin-opts[%q] = %#v, want %#v", k, opts[k], v)
		}
	}
}
