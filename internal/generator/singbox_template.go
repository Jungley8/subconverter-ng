package generator

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

//go:embed templates/momo.json
var templateFS embed.FS

// builtinTemplates maps a &template= value to an embedded sing-box template.
// Add an entry (and the file under templates/) to publish a new variant.
var builtinTemplates = map[string]string{
	"momo": "templates/momo.json",
}

// BuiltinTemplate returns the embedded template bytes for a &template= name.
func BuiltinTemplate(name string) ([]byte, bool) {
	path, ok := builtinTemplates[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return nil, false
	}
	b, err := templateFS.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return b, true
}

// BuiltinTemplateNames lists the &template= names, sorted for error messages.
func BuiltinTemplateNames() []string {
	names := make([]string, 0, len(builtinTemplates))
	for n := range builtinTemplates {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// nodesPlaceholder matches Liquid Formula's {{ Nodes }} injection point.
var nodesPlaceholder = regexp.MustCompile(`\{\{\s*Nodes\s*\}\}`)

// notesNamePlaceholder matches Liquid Formula's {{ "<regex>" | NotesName }}
// selector expansion.
var notesNamePlaceholder = regexp.MustCompile(`\{\{\s*"([^"]*)"\s*\|\s*NotesName\s*\}\}`)

// notesFallback is emitted when a NotesName selector matches no node. sing-box
// rejects a selector/urltest without outbounds, and Liquid Formula renders the
// same direct fallback, so the template output stays byte-compatible.
const notesFallback = `"➜ Direct"`

// GenerateSingboxTemplate injects converted nodes into a full sing-box JSON
// template, expanding the two Liquid Formula placeholders the momo template
// uses: {{ Nodes }} (node outbounds) and {{ "<regex>" | NotesName }} (quoted
// node names matching the regex). Everything else — inbounds, DNS/fake-ip,
// rule_set references and route rules — comes from the template verbatim, so
// the output is a complete config a router-side client can consume directly.
func GenerateSingboxTemplate(ctx context.Context, nodes []*proxy.Proxy, cfg *extconfig.Config, tmpl []byte, opts Options) (*Result, error) {
	res := &Result{ContentType: ctJSON}
	nodes = prepareNodes(nodes, cfg, opts, res)
	nodes = dropLocalNodes(nodes, res)
	res.NodeCount = len(nodes)
	outbounds, _, _ := nodeOutbounds(nodes, opts, res)

	// Node outbounds are rendered compactly and joined with commas; the
	// template keeps its own trailing comma after the placeholder.
	var b strings.Builder
	for i, ob := range outbounds {
		raw, err := json.Marshal(ob)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			b.WriteString(",\n    ")
		}
		b.Write(raw)
	}
	out := nodesPlaceholder.ReplaceAllString(string(tmpl), b.String())

	var notesErr error
	out = notesNamePlaceholder.ReplaceAllStringFunc(out, func(m string) string {
		if notesErr != nil {
			return m
		}
		pattern := notesNamePlaceholder.FindStringSubmatch(m)[1]
		re, err := regexp.Compile(pattern)
		if err != nil {
			notesErr = fmt.Errorf("invalid NotesName regex %q: %w", pattern, err)
			return m
		}
		members := make([]string, 0, len(nodes))
		for _, n := range nodes {
			if re.MatchString(n.Name) {
				q, err := json.Marshal(n.Name)
				if err != nil {
					notesErr = err
					return m
				}
				members = append(members, string(q))
			}
		}
		if len(members) == 0 {
			return notesFallback
		}
		return strings.Join(members, ", ")
	})
	if notesErr != nil {
		return nil, notesErr
	}

	// Fail fast here rather than shipping a config the client rejects at startup.
	var probe map[string]any
	if err := json.Unmarshal([]byte(out), &probe); err != nil {
		return nil, fmt.Errorf("rendered template is not valid JSON: %w", err)
	}
	res.Output = []byte(out)
	return res, nil
}

// dropLocalNodes removes loopback placeholder entries some providers inject
// (e.g. "官网: …" pointing at 127.0.0.1:10000). They are not real exits and
// would otherwise be picked up by the template's catch-all groups.
func dropLocalNodes(nodes []*proxy.Proxy, res *Result) []*proxy.Proxy {
	out := make([]*proxy.Proxy, 0, len(nodes))
	for _, n := range nodes {
		switch strings.ToLower(cs(n.Clash, "server")) {
		case "127.0.0.1", "localhost", "::1", "0.0.0.0":
			res.SkippedNodes = append(res.SkippedNodes, n.Name+" (local placeholder node)")
			continue
		}
		out = append(out, n)
	}
	return out
}
