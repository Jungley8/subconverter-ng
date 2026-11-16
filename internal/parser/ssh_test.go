package parser

import "testing"

func TestParseSSH(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		want    map[string]any
		wantErr bool
	}{
		{
			name: "full link",
			uri:  "ssh://alice:alicepw@ssh.example.com:2222?private-key=PRIVATEKEYMATERIAL&private-key-passphrase=PASSPHRASE&host-key=hk1,hk2&host-key-algorithms=ed25519,rsa-sha2-256#SSH",
			want: map[string]any{
				"type":                   "ssh",
				"server":                 "ssh.example.com",
				"port":                   2222,
				"username":               "alice",
				"password":               "alicepw",
				"private-key":            "PRIVATEKEYMATERIAL",
				"private-key-passphrase": "PASSPHRASE",
				"host-key":               []string{"hk1", "hk2"},
				"host-key-algorithms":    []string{"ed25519", "rsa-sha2-256"},
			},
		},
		{
			name: "snake case attributes",
			uri:  "ssh://bob@ssh.example.com:22?private_key=KEYMATERIAL&private_key_passphrase=p#B",
			want: map[string]any{
				"type":                   "ssh",
				"username":               "bob",
				"private-key":            "KEYMATERIAL",
				"private-key-passphrase": "p",
			},
		},
		{name: "missing username", uri: "ssh://ssh.example.com:22", wantErr: true},
		{name: "missing port", uri: "ssh://bob@ssh.example.com", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseSSH(tc.uri)
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

func TestParse_SSHViaDispatch(t *testing.T) {
	nodes, skipped, err := Parse([]byte("ssh://u:p@h.example.com:22#S"))
	if err != nil || len(skipped) != 0 || len(nodes) != 1 {
		t.Fatalf("dispatch failed: nodes=%v skipped=%v err=%v", nodes, skipped, err)
	}
	if nodes[0].Type != "ssh" || nodes[0].Name != "S" {
		t.Errorf("unexpected node: %+v", nodes[0])
	}
}
