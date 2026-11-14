package generator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// nodesPlaceholder matches Liquid Formula's {{ Nodes }} injection point.
var nodesPlaceholder = regexp.MustCompile(`\{\{\s*Nodes\s*\}\}`)

// notesNamePlaceholder matches Liquid Formula's {{ "<regex>" | NotesName }}
// selector expansion.
var notesNamePlaceholder = regexp.MustCompile(`\{\{\s*"([^"]*)"\s*\|\s*NotesName\s*\}\}`)

// ErrTemplateInvalid marks template problems the user can fix: no {{ Nodes }}
// placeholder, an invalid NotesName regex, or output that is not valid JSON.
// Callers answer 400 for these instead of blaming the upstream.
var ErrTemplateInvalid = errors.New("invalid template")

// notesFallback is emitted when a NotesName selector matches no node. sing-box
// rejects a selector/urltest without outbounds, and Liquid Formula renders the
// same direct fallback, so the template output stays byte-compatible.
const notesFallback = `"➜ Direct"`

// GenerateSingboxTemplate injects converted nodes into a full sing-box JSON
// template, expanding the two Liquid Formula placeholders such templates use: {{ Nodes }} (node outbounds) and {{ "<regex>" | NotesName }} (quoted
// node names matching the regex). Everything else — inbounds, DNS/fake-ip,
// rule_set references and route rules — comes from the template verbatim, so
// the output is a complete config a router-side client can consume directly.
func GenerateSingboxTemplate(ctx context.Context, nodes []*proxy.Proxy, cfg *extconfig.Config, tmpl []byte, opts Options) (*Result, error) {
	res := &Result{ContentType: ctJSON}
	nodes = prepareNodes(nodes, cfg, opts, res)
	nodes = dropLocalNodes(nodes, res)
	res.NodeCount = len(nodes)
	outbounds, _, _ := nodeOutbounds(nodes, opts, res)

	// Fail closed before rendering: an empty injection would leave the
	// template's trailing comma as a syntax error, and a template without the
	// placeholder would silently drop every converted node.
	if len(outbounds) == 0 {
		return nil, fmt.Errorf("no valid nodes for template rendering: all nodes were filtered out, dropped, or unsupported by sing-box")
	}
	if !nodesPlaceholder.Match(tmpl) {
		return nil, fmt.Errorf(`%w: no {{ Nodes }} placeholder, refusing to render a config without the converted nodes`, ErrTemplateInvalid)
	}

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
	// ReplaceAllLiteralString, NOT ReplaceAllString: the injected JSON contains
	// user data (passwords, node names) where "$" would otherwise be expanded
	// as a capture-group reference ($0 even expands to the matched placeholder
	// itself), silently corrupting credentials like "pass$1word" -> "pass".
	out := nodesPlaceholder.ReplaceAllLiteralString(string(tmpl), b.String())

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
		return nil, fmt.Errorf("%w: rendered template is not valid JSON: %w", ErrTemplateInvalid, err)
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
