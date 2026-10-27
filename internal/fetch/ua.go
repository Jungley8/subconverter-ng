package fetch

import (
	"sort"
	"strings"
)

// uaPresetTable enumerates the supported User-Agent presets. The first name of
// each group is the primary name (used by UAPresetNames); the rest are aliases.
var uaPresetTable = []struct {
	names []string
	ua    string
}{
	{[]string{"clash.meta", "clash", "mihomo"}, "clash.meta/1.18.0 mihomo/1.18.0"},
	{[]string{"v2ray", "v2rayn"}, "v2rayN/6.45"},
	{[]string{"singbox", "sing-box"}, "sing-box/1.3.0"},
	{[]string{"surge"}, "Surge/5.9.0"},
	{[]string{"shadowrocket"}, "Shadowrocket/2.2.50"},
	{[]string{"quanx"}, "Quantumult X/1.0.30"},
	{[]string{"loon"}, "Loon/3.2.4"},
}

var (
	// uaPresetIndex maps every lowercased preset name (and alias) to its UA.
	uaPresetIndex = map[string]string{}
	// uaPresetPrimes is the sorted, deduplicated list of primary preset names.
	uaPresetPrimes []string
)

func init() {
	for _, g := range uaPresetTable {
		for _, n := range g.names {
			uaPresetIndex[n] = g.ua
		}
		uaPresetPrimes = append(uaPresetPrimes, g.names[0])
	}
	sort.Strings(uaPresetPrimes)
}

// UAPreset returns the User-Agent string for the given preset name. Matching is
// case-insensitive and ignores surrounding whitespace. The second return value
// reports whether the name matched a preset; on miss the UA is empty.
func UAPreset(name string) (string, bool) {
	ua, ok := uaPresetIndex[strings.ToLower(strings.TrimSpace(name))]
	return ua, ok
}

// UAPresetNames returns the sorted, deduplicated primary preset names, suitable
// for listing the accepted values in an error message. Callers get their own
// copy and may mutate it freely.
func UAPresetNames() []string {
	names := make([]string, len(uaPresetPrimes))
	copy(names, uaPresetPrimes)
	return names
}
