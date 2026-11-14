package parser

import (
	"encoding/base64"
	"testing"
)

func ssdURI(t *testing.T, doc string) string {
	t.Helper()
	return "ssd://" + base64.StdEncoding.EncodeToString([]byte(doc))
}

// The document-level encryption/password/port are defaults: airports
// emit them once and let every server inherit. A server that omits them must
// still produce a usable node.
func TestParseSSD_DocumentDefaults(t *testing.T) {
	uri := ssdURI(t, `{
		"airport": "Demo Airport",
		"port": 8388,
		"encryption": "aes-128-gcm",
		"password": "shared-pw",
		"servers": [
			{"server": "1.2.3.4", "remarks": "HK 01"},
			{"server": "2.2.3.4", "port": 443, "encryption": "aes-256-gcm", "password": "own-pw"}
		]
	}`)

	if !IsShareLink(uri) {
		t.Fatal("IsShareLink(ssd://) = false: the payload is inline, not fetchable")
	}
	nodes, skipped, err := Parse([]byte(uri))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("skipped = %v", skipped)
	}
	if len(nodes) != 2 {
		t.Fatalf("got %d nodes, want 2", len(nodes))
	}

	first := nodes[0]
	if first.Type != "ss" || first.Name != "HK 01" || first.Server != "1.2.3.4" || first.Port != 8388 {
		t.Errorf("node[0] = %+v", first)
	}
	if first.Clash["cipher"] != "aes-128-gcm" || first.Clash["password"] != "shared-pw" {
		t.Errorf("node[0] did not inherit the document defaults: %v", first.Clash)
	}

	// A server-level value wins over the document default.
	second := nodes[1]
	if second.Port != 443 || second.Clash["cipher"] != "aes-256-gcm" || second.Clash["password"] != "own-pw" {
		t.Errorf("node[1] did not keep its own overrides: %+v", second)
	}
	// No remarks: name comes from the airport and the position, so the node is
	// still identifiable in a client.
	if second.Name != "Demo Airport 2" {
		t.Errorf("node[1] name = %q, want %q", second.Name, "Demo Airport 2")
	}
}

func TestParseSSD_Plugin(t *testing.T) {
	uri := ssdURI(t, `{
		"airport": "Demo",
		"port": 8388,
		"encryption": "aes-128-gcm",
		"password": "pw",
		"servers": [{
			"server": "1.2.3.4",
			"remarks": "HK obfs",
			"plugin": "obfs-local",
			"plugin_options": "obfs=http;obfs-host=bing.com"
		}]
	}`)
	nodes, _, err := Parse([]byte(uri))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(nodes))
	}
	opts, _ := nodes[0].Clash["plugin-opts"].(map[string]any)
	if nodes[0].Clash["plugin"] != "obfs" {
		t.Errorf("plugin = %v, want obfs", nodes[0].Clash["plugin"])
	}
	if opts["mode"] != "http" || opts["host"] != "bing.com" {
		t.Errorf("plugin-opts = %v, want mode=http host=bing.com", opts)
	}
}

// A broken SSD body is node content the user pasted, not a URL: it must be
// reported as a skipped entry. Fetching it as a URL produces a confusing
// "unsupported scheme" error instead.
func TestParseSSD_Malformed(t *testing.T) {
	cases := []struct{ name, uri string }{
		{"not base64", "ssd://!!!not-base64!!!"},
		{"not json", ssdURI(t, "this is not json")},
		{"no servers", ssdURI(t, `{"airport":"Demo","servers":[]}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes, skipped, err := Parse([]byte(tc.uri))
			if err != nil {
				t.Fatalf("Parse returned an error instead of a skipped entry: %v", err)
			}
			if len(nodes) != 0 {
				t.Fatalf("got %d nodes, want none", len(nodes))
			}
			if len(skipped) != 1 {
				t.Fatalf("skipped = %v, want exactly one reason", skipped)
			}
		})
	}
}

// One broken server must not discard the rest.
func TestParseSSD_SkipsIncompleteServer(t *testing.T) {
	uri := ssdURI(t, `{
		"airport": "Demo",
		"encryption": "aes-128-gcm",
		"password": "pw",
		"servers": [
			{"server": "", "port": 8388, "remarks": "broken"},
			{"server": "2.2.3.4", "port": 8388, "remarks": "good"}
		]
	}`)
	nodes, skipped, err := Parse([]byte(uri))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Name != "good" {
		t.Fatalf("nodes = %+v, want only the good server", nodes)
	}
	if len(skipped) != 1 {
		t.Errorf("skipped = %v, want one entry naming the broken server", skipped)
	}
}
