package parser

import (
	"net/url"
	"reflect"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// checkClash asserts the canonical map fields a parser is expected to write.
func checkClash(t *testing.T, p *proxy.Proxy, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if !reflect.DeepEqual(p.Clash[k], v) {
			t.Errorf("%s: Clash[%q] = %#v, want %#v", p.Name, k, p.Clash[k], v)
		}
	}
}

func TestParseSnell(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		want    map[string]any
		wantErr bool
	}{
		{
			name: "full link",
			uri:  "snell://secretpsk@sn.example.com:8388?version=4&obfs=http&obfs-host=bing.com&obfs-uri=/&userkey=ukey&reuse=1&udp=1&mode=unshaped&client-fingerprint=chrome#SN",
			want: map[string]any{
				"type":               "snell",
				"server":             "sn.example.com",
				"port":               8388,
				"psk":                "secretpsk",
				"version":            4,
				"userkey":            "ukey",
				"reuse":              true,
				"udp":                true,
				"mode":               "unshaped",
				"client-fingerprint": "chrome",
				"obfs-opts": map[string]any{
					"mode": "http",
					"host": "bing.com",
					"uri":  "/",
				},
			},
		},
		{
			name: "psk in query and default version",
			uri:  "snell://sn.example.com:443?psk=qpsk#Q",
			want: map[string]any{
				"type":    "snell",
				"psk":     "qpsk",
				"version": 1,
			},
		},
		{name: "missing psk", uri: "snell://h.example.com:443", wantErr: true},
		{name: "version out of range", uri: "snell://p@h.example.com:443?version=9", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseSnell(tc.uri)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", p)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			checkClash(t, p, tc.want)
		})
	}
}

func TestSnellObfsOptsShadowTLS(t *testing.T) {
	q := url.Values{}
	q.Set("obfs", "shadow-tls")
	q.Set("obfs-host", "cdn.example.com")
	q.Set("obfs-password", "wpass")
	q.Set("obfs-version", "3")
	q.Set("obfs-alpn", "h2,http/1.1")

	want := map[string]any{
		"mode":     "shadow-tls",
		"host":     "cdn.example.com",
		"password": "wpass",
		"version":  3,
		"alpn":     []string{"h2", "http/1.1"},
	}
	if got := snellObfsOpts(q); !reflect.DeepEqual(got, want) {
		t.Errorf("snellObfsOpts = %#v, want %#v", got, want)
	}
}

func TestParse_SnellViaDispatch(t *testing.T) {
	nodes, skipped, err := Parse([]byte("snell://p@h.example.com:8388?version=4#SN"))
	if err != nil || len(skipped) != 0 || len(nodes) != 1 {
		t.Fatalf("dispatch failed: nodes=%v skipped=%v err=%v", nodes, skipped, err)
	}
	if nodes[0].Type != "snell" || nodes[0].Name != "SN" {
		t.Errorf("unexpected node: %+v", nodes[0])
	}
}
