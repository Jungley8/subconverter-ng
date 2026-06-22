package convert

import (
	"context"
	"fmt"
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
