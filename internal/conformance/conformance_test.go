//go:build conformance

// Package conformance renders configurations with the real generators and then
// asks the real clients whether they accept them.
//
// Unit tests assert the shape we intend to emit; this suite asserts the shape
// the client accepts. A P0 regression (sing-box 1.14 rejecting a root-level
// route.rule_set, and missing default_domain_resolver) passed every unit test
// in the repo and was only caught by feeding the output to the client binary.
//
// The suite covers exactly that class: output the client refuses to load. It
// cannot see a config the client loads but that routes nothing — mihomo accepts
// a proxy-group with no members, so the provider-mode regression where every
// group held only DIRECT passed `mihomo -t` too. Check rendered semantics in
// unit tests; check acceptance here.
//
// Every new target or schema switch earns a case here.
//
// Run it with `make conformance`, or:
//
//	CONFORMANCE_SINGBOX=$(which sing-box) CONFORMANCE_MIHOMO=$(which mihomo) \
//	  go test -tags conformance ./internal/conformance -v
//
// CONFORMANCE_SINGBOX accepts a comma-separated list so the matrix can pick the
// smallest binary that satisfies a declared target version; a single binary
// still validates every case it is new enough for.
package conformance

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Jungley8/subconverter-ng/internal/convert"
	"github.com/Jungley8/subconverter-ng/internal/generator"
)

// fixtureBase is a host that never resolves: every fixture URL is served by
// mapFetcher, so a case that reaches the network fails loudly instead of
// silently depending on the internet.
const fixtureBase = "https://fixture.invalid"

// localNode is a share link, not a subscription URL. Provider mode keeps it
// inline, so the provider-mode case exercises both halves of that output.
const localNode = "trojan://pw@1.2.3.4:443?sni=example.com#Local%20Node"

type mapFetcher map[string][]byte

func (m mapFetcher) Get(_ context.Context, url string) ([]byte, error) {
	b, ok := m[url]
	if !ok {
		return nil, fmt.Errorf("no fixture for %s", url)
	}
	return b, nil
}

func fixtures(t *testing.T) convert.Fetcher {
	t.Helper()
	files := mapFetcher{}
	for _, name := range []string{
		"nodes.yaml",
		"acl4ssr.ini",
		"acl4ssr-remote.ini",
		"singbox.ini",
		"template.json",
	} {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		files[fixtureBase+"/"+name] = b
	}
	// The remote ruleset feed expanded by expand=true and referenced by
	// rule-providers with expand=false.
	files[fixtureBase+"/rules/proxy.list"] = []byte(
		"DOMAIN-SUFFIX,google.com\nDOMAIN-KEYWORD,github\nIP-CIDR,1.1.1.0/24,no-resolve\n")
	return files
}

// --- client binaries -------------------------------------------------------

type client struct {
	path                string
	major, minor, patch int
}

func (c client) atLeast(major, minor int) bool {
	return c.major > major || (c.major == major && c.minor >= minor)
}

var versionRe = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

func probeClient(t *testing.T, path, versionFlag string) client {
	t.Helper()
	out, err := exec.Command(path, versionFlag).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v (%s)", filepath.Base(path), versionFlag, err, out)
	}
	m := versionRe.FindStringSubmatch(string(out))
	if m == nil {
		t.Fatalf("cannot parse %s version from %q", filepath.Base(path), out)
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	return client{path: path, major: major, minor: minor, patch: patch}
}

// requireTools reports whether a missing binary is a hard failure. Locally a
// missing client means "skip this part"; in CI the matrix is the point, so a
// missing binary must not pass silently.
func requireTools() bool { return os.Getenv("CONFORMANCE_REQUIRE") == "1" }

func envPaths(name string) []string {
	var out []string
	for _, p := range strings.Split(os.Getenv(name), ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// singboxClients returns every configured sing-box binary, oldest first, so a
// version-gated case is validated by the closest matching client rather than by
// the newest one (which may already reject the older schema).
func singboxClients(t *testing.T) []client {
	t.Helper()
	paths := envPaths("CONFORMANCE_SINGBOX")
	if len(paths) == 0 {
		if p, err := exec.LookPath("sing-box"); err == nil {
			paths = []string{p}
		}
	}
	if len(paths) == 0 {
		if requireTools() {
			t.Fatal("CONFORMANCE_REQUIRE=1 but no sing-box binary: set CONFORMANCE_SINGBOX")
		}
		t.Skip("no sing-box binary: set CONFORMANCE_SINGBOX=/path/to/sing-box")
	}
	clients := make([]client, 0, len(paths))
	for _, p := range paths {
		clients = append(clients, probeClient(t, p, "version"))
	}
	sort.Slice(clients, func(i, j int) bool {
		a, b := clients[i], clients[j]
		if a.major != b.major {
			return a.major < b.major
		}
		if a.minor != b.minor {
			return a.minor < b.minor
		}
		return a.patch < b.patch
	})
	return clients
}

// pickSingbox returns the oldest client that is at least as new as the declared
// target version.
func pickSingbox(clients []client, need generator.Version) *client {
	for i := range clients {
		if clients[i].atLeast(need.Major, need.Minor) {
			return &clients[i]
		}
	}
	return nil
}

func mihomoClient(t *testing.T) *client {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("CONFORMANCE_MIHOMO"))
	if path == "" {
		if p, err := exec.LookPath("mihomo"); err == nil {
			path = p
		}
	}
	if path == "" {
		if requireTools() {
			t.Fatal("CONFORMANCE_REQUIRE=1 but no mihomo binary: set CONFORMANCE_MIHOMO")
		}
		t.Skip("no mihomo binary: set CONFORMANCE_MIHOMO=/path/to/mihomo")
	}
	c := probeClient(t, path, "-v")
	return &c
}

// --- helpers ---------------------------------------------------------------

func run(t *testing.T, f convert.Fetcher, req convert.Request) []byte {
	t.Helper()
	out, diag, err := convert.Run(context.Background(), f, req)
	if err != nil {
		t.Fatalf("convert.Run: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("convert.Run returned empty output")
	}
	if diag.NodeCount == 0 {
		t.Fatal("convert.Run reported zero nodes: fixture is not exercising anything")
	}
	return out
}

// writeConfig dumps the rendered config next to a failing test for inspection.
func writeConfig(t *testing.T, name string, out []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatalf("write rendered config: %v", err)
	}
	return path
}

// --- sing-box ---------------------------------------------------------------

// TestSingboxClientAcceptsOutput covers every schema generation the sing-box
// generator can emit: no version (current release), each declared version that
// flips a schema switch, and template rendering.
func TestSingboxClientAcceptsOutput(t *testing.T) {
	clients := singboxClients(t)

	cases := []struct {
		name     string
		target   string
		template bool
		// need is the schema generation the case must be validated with; the
		// binary has to be at least this new.
		need generator.Version
		// what the case is here to catch, used in the skip message.
		covers string
	}{
		{"default", "singbox", false, generator.Version{Major: 1, Minor: 14},
			"the unversioned target must work with the current sing-box release"},
		{"declared-1.10", "singbox/1.10", false, generator.Version{Major: 1, Minor: 10},
			"pre-action rules, pre-rule_set routing"},
		{"declared-1.11", "singbox/1.11", false, generator.Version{Major: 1, Minor: 11},
			"1.11 rule actions (hijack-dns / reject)"},
		{"declared-1.12", "singbox/1.12", false, generator.Version{Major: 1, Minor: 12},
			"1.12 DNS format, route.rule_set, default_domain_resolver"},
		{"declared-1.13", "singbox/1.13", false, generator.Version{Major: 1, Minor: 13},
			"1.13 removal of block / dns-out"},
		{"template", "singbox", true, generator.Version{Major: 1, Minor: 14},
			"Liquid-Formula template output is a complete config"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin := pickSingbox(clients, tc.need)
			if bin == nil {
				t.Skipf("no sing-box >= %d.%d installed (case covers: %s)",
					tc.need.Major, tc.need.Minor, tc.covers)
			}

			req := convert.Request{
				Target:    tc.target,
				SubURLs:   []string{fixtureBase + "/nodes.yaml"},
				ConfigURL: fixtureBase + "/singbox.ini",
			}
			if tc.template {
				req.ConfigURL = ""
				req.Template = fixtureBase + "/template.json"
			}
			out := run(t, fixtures(t), req)

			path := writeConfig(t, "config.json", out)
			cmd := exec.Command(bin.path, "check", "-c", path)
			if msg, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("sing-box %d.%d.%d check failed: %v\n%s\n--- rendered config ---\n%s",
					bin.major, bin.minor, bin.patch, err, msg, out)
			}
		})
	}
}

// --- mihomo -----------------------------------------------------------------

// TestClashClientAcceptsOutput covers the three clash output shapes: inline
// rules (expand=true), rule-providers (expand=false), and proxy-provider mode
// (&provider=true), which changes the group model entirely.
func TestClashClientAcceptsOutput(t *testing.T) {
	bin := mihomoClient(t)

	cases := []struct {
		name     string
		config   string
		provider bool
		noExpand bool
	}{
		{"inline-rules", "acl4ssr.ini", false, false},
		{"rule-providers", "acl4ssr-remote.ini", false, true},
		{"proxy-providers", "acl4ssr.ini", true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			subs := []string{fixtureBase + "/nodes.yaml"}
			if tc.provider {
				// Provider mode splits urls into providers (http) and inline
				// nodes (share links); both halves must render.
				subs = append(subs, localNode)
			}
			req := convert.Request{
				Target:    "clash",
				SubURLs:   subs,
				ConfigURL: fixtureBase + "/" + tc.config,
				Provider:  tc.provider,
			}
			if tc.noExpand {
				req.Gen.UseRuleProviders = true
			}
			out := run(t, fixtures(t), req)

			path := writeConfig(t, "config.yaml", out)
			// -d keeps mihomo's cache/log out of the user's home and out of the
			// repo; -t only parses the config, it never dials a node.
			cmd := exec.Command(bin.path, "-t", "-d", t.TempDir(), "-f", path)
			if msg, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("mihomo %d.%d.%d -t failed: %v\n%s\n--- rendered config ---\n%s",
					bin.major, bin.minor, bin.patch, err, msg, out)
			}
		})
	}
}
