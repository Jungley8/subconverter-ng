package generator

import (
	"bytes"
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"
)

// parseBase decodes a clash_rule_base document, requiring a top-level mapping.
// The base stays a yaml.Node tree so its key order, comments and scalar quotes
// survive. yaml.v3 does not record blank lines, so those are lost.
func parseBase(data []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(stripDirectives(data), &doc); err != nil {
		return nil, fmt.Errorf("%w: clash_rule_base is not valid YAML: %w", ErrConfigInvalid, err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: clash_rule_base must be a YAML mapping", ErrConfigInvalid)
	}
	root := doc.Content[0]
	if err := checkDuplicateKeys(root); err != nil {
		return nil, err
	}
	return root, nil
}

// stripDirectives drops leading YAML directive lines (%YAML, %TAG) and the
// blank lines between them. yaml.v3 refuses a %YAML 1.2 document even though
// Clash accepts it. The leading --- marker is kept, and a document without
// directives is returned untouched.
func stripDirectives(data []byte) []byte {
	seen := false
	offset := 0
	for offset < len(data) {
		var line []byte
		next := len(data)
		if end := bytes.IndexByte(data[offset:], '\n'); end >= 0 {
			line = data[offset : offset+end]
			next = offset + end + 1
		} else {
			line = data[offset:]
		}
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			if trimmed[0] == '%' {
				seen = true
			} else {
				if !seen {
					return data
				}
				return data[offset:]
			}
		}
		offset = next
	}
	if !seen {
		return data
	}
	return data[offset:]
}

// checkDuplicateKeys rejects a base that repeats a mapping key. yaml.v3 accepts
// duplicates when decoding into a Node but rejects them on the next parse, so
// the injected document would be unloadable.
func checkDuplicateKeys(n *yaml.Node) error {
	switch n.Kind {
	case yaml.MappingNode:
		seen := make(map[string]bool, len(n.Content)/2)
		mergeSeen := false
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Tag == "!!merge" || k.Value == "<<" {
				if mergeSeen {
					return fmt.Errorf("%w: clash_rule_base repeats the key %q", ErrConfigInvalid, "<<")
				}
				mergeSeen = true
			} else {
				if seen[k.Value] {
					return fmt.Errorf("%w: clash_rule_base repeats the key %q", ErrConfigInvalid, k.Value)
				}
				seen[k.Value] = true
			}
			if err := checkDuplicateKeys(v); err != nil {
				return err
			}
		}
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			if err := checkDuplicateKeys(c); err != nil {
				return err
			}
		}
	}
	return nil
}

// encodeBase renders a base document with the indentation width found in the
// base, so a 4-space base stays 4-space and the generated sections follow it.
// Widths outside 1..8 fall back to the 2-space indent Clash configs use.
func encodeBase(root *yaml.Node) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(baseIndentWidth(root))
	if err := enc.Encode(root); err != nil {
		return nil, fmt.Errorf("encode clash_rule_base: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode clash_rule_base: %w", err)
	}
	return buf.Bytes(), nil
}

// baseIndentWidth reports the indentation width the base was authored with.
// yaml.v3 records Line and Column while parsing, so a nested block node's
// column minus its key's column is the indent step. Generated nodes injected
// into the tree have zero positions; they are skipped.
func baseIndentWidth(root *yaml.Node) int {
	if width := nestedIndentWidth(root); width >= 1 && width <= 8 {
		return width
	}
	return 2
}

// nestedIndentWidth returns the indentation step of the first nested block in
// source order, or 0 when the document has none.
func nestedIndentWidth(n *yaml.Node) int {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if (v.Kind == yaml.MappingNode || v.Kind == yaml.SequenceNode) &&
				v.Line > k.Line && v.Column > k.Column {
				return v.Column - k.Column
			}
			if width := nestedIndentWidth(v); width > 0 {
				return width
			}
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if width := nestedIndentWidth(c); width > 0 {
				return width
			}
		}
	}
	return 0
}

// mappingValue returns the value node for key. A direct key wins over a merged
// one, even when its value is null; a null value counts as absent so callers
// fill it in. Aliases are followed and merge keys are searched recursively.
func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	v, _ := lookupKey(mapping, key, make(map[*yaml.Node]bool))
	return v
}

// lookupKey finds key in mapping, following merge keys recursively. The bool
// reports presence: a present but null key shadows merge sources, as YAML
// specifies, while the returned value is nil.
func lookupKey(mapping *yaml.Node, key string, visited map[*yaml.Node]bool) (*yaml.Node, bool) {
	if mapping == nil || mapping.Kind != yaml.MappingNode || visited[mapping] {
		return nil, false
	}
	visited[mapping] = true
	if v, ok := mappingEntry(mapping, key); ok {
		return nonNull(deref(v)), true
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Tag != "!!merge" {
			continue
		}
		for _, src := range mergeSources(mapping.Content[i+1]) {
			if v, ok := lookupKey(src, key, visited); ok {
				return v, true
			}
		}
	}
	return nil, false
}

// mappingEntry reports the value node for key and whether the key is present.
func mappingEntry(mapping *yaml.Node, key string) (*yaml.Node, bool) {
	if mapping == nil || mapping.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			return mapping.Content[i+1], true
		}
	}
	return nil, false
}

func nonNull(n *yaml.Node) *yaml.Node {
	if n != nil && n.Tag == "!!null" {
		return nil
	}
	return n
}

func deref(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode {
		return n.Alias
	}
	return n
}

// mergeSources returns the mapping nodes a `<<` value merges, earlier first.
func mergeSources(n *yaml.Node) []*yaml.Node {
	n = deref(n)
	if n == nil {
		return nil
	}
	if n.Kind != yaml.SequenceNode {
		return []*yaml.Node{n}
	}
	out := make([]*yaml.Node, 0, len(n.Content))
	for _, c := range n.Content {
		if m := deref(c); m != nil {
			out = append(out, m)
		}
	}
	return out
}

// setMappingValue replaces key's value in place, or appends the key when the
// base does not declare it. Comments on the key line stay attached because the
// key node itself is untouched.
func setMappingValue(mapping *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			old := mapping.Content[i+1]
			if len(val.Content) > 0 || val.Value != "" {
				val.LineComment = old.LineComment
			} else {
				// An empty replacement would flush the pending key comment onto
				// the next key.
				mapping.Content[i].LineComment = ""
			}
			// Keep the anchor so aliases elsewhere in the base stay valid.
			val.Anchor = old.Anchor
			mapping.Content[i+1] = val
			return
		}
	}
	mapping.Content = append(mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		val,
	)
}

// yamlNode encodes any generated value into a block-style yaml.Node.
func yamlNode(v any) (*yaml.Node, error) {
	n := &yaml.Node{}
	if err := n.Encode(v); err != nil {
		return nil, fmt.Errorf("encode generated section: %w", err)
	}
	return n, nil
}

// proxyKeyOrder puts the keys a reader looks for first; the rest follow in
// alphabetical order so the output is stable across runs.
var proxyKeyOrder = []string{"name", "type", "server", "port"}

// proxiesNode renders proxies as a mapping sequence with a readable key order.
// yaml.Marshal alone sorts map keys alphabetically, which puts name last.
func proxiesNode(proxies []map[string]any) (*yaml.Node, error) {
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: make([]*yaml.Node, 0, len(proxies))}
	for _, p := range proxies {
		m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		seen := make(map[string]bool, len(p))
		appendKey := func(k string) error {
			v, ok := p[k]
			if !ok {
				return nil
			}
			seen[k] = true
			vn, err := yamlNode(v)
			if err != nil {
				return err
			}
			m.Content = append(m.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, vn)
			return nil
		}
		for _, k := range proxyKeyOrder {
			if err := appendKey(k); err != nil {
				return nil, err
			}
		}
		rest := make([]string, 0, len(p))
		for k := range p {
			if !seen[k] {
				rest = append(rest, k)
			}
		}
		sort.Strings(rest)
		for _, k := range rest {
			if err := appendKey(k); err != nil {
				return nil, err
			}
		}
		seq.Content = append(seq.Content, m)
	}
	return seq, nil
}

// prependRules returns a copy of rules with extra entries in front. A base
// whose rules value is not a sequence is replaced outright: there is nothing
// to keep.
func prependRules(rules *yaml.Node, extra []string) (*yaml.Node, error) {
	if rules == nil || rules.Kind != yaml.SequenceNode {
		return yamlNode(extra)
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, e := range extra {
		n, err := yamlNode(e)
		if err != nil {
			return nil, err
		}
		seq.Content = append(seq.Content, n)
	}
	seq.Content = append(seq.Content, rules.Content...)
	return seq, nil
}
