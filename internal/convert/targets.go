package convert

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Jungley8/subconverter-ng/internal/extconfig"
	"github.com/Jungley8/subconverter-ng/internal/generator"
	"github.com/Jungley8/subconverter-ng/internal/proxy"
)

// Canonical target names. User-supplied aliases are normalised to these.
const (
	TargetClash        = "clash"
	TargetSingbox      = "singbox"
	TargetSurge        = "surge"
	TargetShadowrocket = "shadowrocket"
	TargetQuanX        = "quanx"
	TargetLoon         = "loon"
	TargetV2Ray        = "v2ray"
)

// targetAliases maps accepted spellings to a canonical target name.
var targetAliases = map[string]string{
	"clash": TargetClash, "clashmeta": TargetClash, "clash.meta": TargetClash, "clashr": TargetClash,
	"singbox": TargetSingbox, "sing-box": TargetSingbox, "sing_box": TargetSingbox,
	"surge":        TargetSurge,
	"shadowrocket": TargetShadowrocket, "shadow-rocket": TargetShadowrocket,
	"quanx": TargetQuanX, "quantumultx": TargetQuanX, "quantumult-x": TargetQuanX, "quantumult_x": TargetQuanX,
	"loon":  TargetLoon,
	"v2ray": TargetV2Ray, "mixed": TargetV2Ray, "v2rayn": TargetV2Ray, "ss": TargetV2Ray,
}

// NormalizeTarget lower-cases, trims, and maps the target through targetAliases.
// An unknown value passes through unchanged (caller validates via supportedTargets).
func NormalizeTarget(t string) string {
	key := strings.ToLower(strings.TrimSpace(t))
	if c, ok := targetAliases[key]; ok {
		return c
	}
	return key
}

// ParseTarget splits a raw target spec of the form "name[/version]" into the
// canonical target name and the parsed version, e.g. "singbox/1.3.xx" ->
// ("singbox", Version{1, 3, 0}). A spec without "/" yields a nil version.
// The name part goes through NormalizeTarget (its validity is the caller's
// concern, via supportedTargets); the version part must contain at least one
// fully-numeric "." segment or an error is returned.
func ParseTarget(raw string) (string, *generator.Version, error) {
	name, version, hasVersion := strings.Cut(strings.TrimSpace(raw), "/")
	target := NormalizeTarget(name)
	if !hasVersion {
		return target, nil, nil
	}
	ver, err := parseTargetVersion(version)
	if err != nil {
		return "", nil, err
	}
	return target, ver, nil
}

// parseTargetVersion parses "major[.minor[.patch]]" (e.g. "1.3.xx" -> 1.3.0).
// Segments are consumed left to right while they parse fully as integers; the
// first non-numeric segment stops parsing and trailing garbage is ignored.
// Fewer than one numeric segment ("abc", "") is an error.
func parseTargetVersion(s string) (*generator.Version, error) {
	s = strings.TrimSpace(s)
	var v generator.Version
	n := 0
	for _, seg := range strings.Split(s, ".") {
		num, err := strconv.Atoi(seg)
		if err != nil {
			break
		}
		switch n {
		case 0:
			v.Major = num
		case 1:
			v.Minor = num
		case 2:
			v.Patch = num
		}
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("invalid target version %q", s)
	}
	return &v, nil
}

// describeTarget renders a target for error messages: the canonical name plus
// "/major.minor[.patch]" when a version was declared (e.g. "singbox/9.9").
func describeTarget(name string, ver *generator.Version) string {
	if ver == nil {
		return name
	}
	if ver.Patch != 0 {
		return fmt.Sprintf("%s/%d.%d.%d", name, ver.Major, ver.Minor, ver.Patch)
	}
	return fmt.Sprintf("%s/%d.%d", name, ver.Major, ver.Minor)
}

// targetOrder is the stable display order for supportedList.
var targetOrder = []string{
	TargetClash, TargetSingbox, TargetSurge, TargetShadowrocket, TargetQuanX, TargetLoon, TargetV2Ray,
}

// supportedTargets is the set of canonical targets render can currently emit.
// Each generator phase adds its target here as it lands.
var supportedTargets = map[string]bool{
	TargetClash:        true,
	TargetV2Ray:        true,
	TargetSingbox:      true,
	TargetSurge:        true,
	TargetShadowrocket: true,
	TargetQuanX:        true,
	TargetLoon:         true,
}

func supportedList() string {
	var out []string
	for _, t := range targetOrder {
		if supportedTargets[t] {
			out = append(out, t)
		}
	}
	return strings.Join(out, ", ")
}

// render dispatches to the generator for the (already-normalised) target.
func render(ctx context.Context, target string, nodes []*proxy.Proxy, cfg *extconfig.Config, f Fetcher, gen generator.Options) (*generator.Result, error) {
	switch target {
	case TargetClash:
		return generator.GenerateClash(ctx, nodes, cfg, f, gen)
	case TargetV2Ray:
		return generator.GenerateV2ray(ctx, nodes, cfg, f, gen)
	case TargetSingbox:
		return generator.GenerateSingbox(ctx, nodes, cfg, f, gen)
	case TargetSurge:
		return generator.GenerateSurge(ctx, nodes, cfg, f, gen)
	case TargetShadowrocket:
		return generator.GenerateShadowrocket(ctx, nodes, cfg, f, gen)
	case TargetLoon:
		return generator.GenerateLoon(ctx, nodes, cfg, f, gen)
	case TargetQuanX:
		return generator.GenerateQuanX(ctx, nodes, cfg, f, gen)
	default:
		return nil, fmt.Errorf("unsupported target %q", target)
	}
}
