// Package matcher compiles regexes that come from a user config or URL.
//
// Upstream subconverter compiles these with PCRE2 and documents lookahead
// selectors such as (^(?!.*(美国|日本)).*). Go's regexp (RE2) rejects lookaround,
// so Compile tries RE2 first and falls back to regexp2 for PCRE-only patterns.
// CompileClient skips RE2: patterns emitted into a mihomo config are compiled by
// mihomo with regexp2, and local matching must agree with the client.
package matcher

import (
	"fmt"
	"regexp"
	"time"

	"github.com/dlclark/regexp2"
)

// matchTimeout bounds one regexp2 match. Callers must treat a timeout as an
// error and stop: regexp2 backtracks, so a pathological pattern would otherwise
// burn CPU for every node in the subscription.
const matchTimeout = 100 * time.Millisecond

// Matcher is a compiled regex. Exactly one of re2/pcre is set.
type Matcher struct {
	pattern string
	re2     *regexp.Regexp
	pcre    *regexp2.Regexp
}

// Compile compiles pattern with RE2, falling back to regexp2 (PCRE semantics)
// when RE2 rejects constructs it cannot express, such as lookaround.
func Compile(pattern string) (*Matcher, error) {
	if re, err := regexp.Compile(pattern); err == nil {
		return &Matcher{pattern: pattern, re2: re}, nil
	}
	return compilePCRE(pattern)
}

// CompileClient compiles pattern with regexp2 only. Use it for a pattern that
// is written into a client config: mihomo compiles group filters with the same
// library, so a RE2-only construct would pass local matching and then fail in
// the client.
func CompileClient(pattern string) (*Matcher, error) {
	return compilePCRE(pattern)
}

func compilePCRE(pattern string) (*Matcher, error) {
	pcre, err := regexp2.Compile(pattern, regexp2.None)
	if err != nil {
		return nil, fmt.Errorf("not a valid pattern: %w", err)
	}
	pcre.MatchTimeout = matchTimeout
	return &Matcher{pattern: pattern, pcre: pcre}, nil
}

// Match reports whether s matches. The error reports a match that ran past the
// timeout; the caller must stop and report the pattern, not treat it as a miss.
func (m *Matcher) Match(s string) (bool, error) {
	if m.re2 != nil {
		return m.re2.MatchString(s), nil
	}
	ok, err := m.pcre.MatchString(s)
	if err != nil {
		return false, fmt.Errorf("pattern %q timed out after %s", m.pattern, matchTimeout)
	}
	return ok, nil
}

// ReplaceAll replaces every match with repl. Backreferences use $N in both
// engines.
func (m *Matcher) ReplaceAll(src, repl string) (string, error) {
	if m.re2 != nil {
		return m.re2.ReplaceAllString(src, repl), nil
	}
	out, err := m.pcre.Replace(src, repl, -1, -1)
	if err != nil {
		return "", fmt.Errorf("pattern %q timed out after %s", m.pattern, matchTimeout)
	}
	return out, nil
}

// Pattern is the source text the matcher was compiled from.
func (m *Matcher) Pattern() string { return m.pattern }
