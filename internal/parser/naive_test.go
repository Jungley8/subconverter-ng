package parser

import "testing"

func TestParseNaive(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		want    map[string]any
		wantErr bool
	}{
		{
			name: "https",
			uri:  "naive+https://user:napw@n.example.com:443?sni=n.example.com&insecure=1&alpn=h2,http/1.1#N",
			want: map[string]any{
				"type":             "naive",
				"server":           "n.example.com",
				"port":             443,
				"username":         "user",
				"password":         "napw",
				"tls":              true,
				"sni":              "n.example.com",
				"skip-cert-verify": true,
				"alpn":             []string{"h2", "http/1.1"},
			},
		},
		{
			name: "quic",
			uri:  "naive+quic://user:napw@n.example.com:8443?sni=cdn.example.com#Q",
			want: map[string]any{
				"type":     "naive",
				"port":     8443,
				"username": "user",
				"quic":     true,
				"tls":      true,
				"sni":      "cdn.example.com",
			},
		},
		{name: "missing password", uri: "naive+https://user@n.example.com:443", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseNaive(tc.uri)
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

func TestParse_NaiveViaDispatch(t *testing.T) {
	for _, uri := range []string{
		"naive+https://u:p@h.example.com:443#H",
		"naive+quic://u:p@h.example.com:443#H",
	} {
		nodes, skipped, err := Parse([]byte(uri))
		if err != nil || len(skipped) != 0 || len(nodes) != 1 {
			t.Fatalf("dispatch failed for %q: nodes=%v skipped=%v err=%v", uri, nodes, skipped, err)
		}
		if nodes[0].Type != "naive" {
			t.Errorf("%q: type = %q", uri, nodes[0].Type)
		}
	}
}
