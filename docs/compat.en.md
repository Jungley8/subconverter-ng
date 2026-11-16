# Differences from the original subconverter

This repository is a Go rewrite of [tindy2013/subconverter](https://github.com/tindy2013/subconverter). It keeps the `/sub` query shape, so an old link usually works unchanged. This page lists only the differences that cost you time. This repository's code is the source of truth for what we do; check the upstream documentation for what upstream does.

## Works unchanged

- `target` names and common aliases (`clash.meta`, `clashr`, `mihomo`, `sing-box`, `quantumultx`, `surfboard`, `mixed`, and others)
- Common parameters: `url`, `config`, `include`/`exclude`, `emoji`, `add_emoji`, `remove_emoji`, `append_type`, `sort`, `dedup`, `udp`, `tfo`, `scv`, `fdn`, `list`, `expand`, `insert`, `interval`, `filename`, `template`, `flushcache`
- The external INI `[custom]` section: `enable_rule_generator`, `rename`, `custom_proxy_group`, `ruleset`

## Added here

| Parameter / feature | Purpose |
|---|---|
| `&check=true` | Return a JSON report of the conversion instead of the config (empty groups, dropped rules, unparsed lines) |
| `&provider=true` `&provider_interval=` | Clash proxy-provider mode: emit only the skeleton and let mihomo fetch nodes |
| `&ua=` `&proxy=` | Override the fetch User-Agent and upstream proxy per request |
| `&nocache=1` | Bypass the shared cache and refetch |
| `&tailscale` | Prepend Tailscale direct rules |
| `target=ssd` | Emit an SSD subscription |
| `target=singbox/1.13` | Gate protocols and schema by the target kernel version |

## Protocol and target support

This table shows how each target handles the new protocols and transports. The converter drops a node the target does not support, and logs it.

| Protocol / feature | clash (mihomo) | sing-box | Surge | Shadowrocket | Loon | v2ray link |
|---|---|---|---|---|---|---|
| Snell | Emits | v4/v6 only, minimum 1.14 | Emits | Emits | — | Emits |
| ShadowTLS | Emits (native) | ss + shadowtls chain | ss/snell parameters | — | — | ss plugin |
| SSH | Emits | Emits, minimum 1.5 | Emits | — | — | Emits |
| naive | Skips (mihomo has no naive) | Emits, minimum 1.13 | — | — | — | Emits |
| Mieru | Emits | Skips | — | — | — | — |
| MASQUE | Emits | Skips (sing-box does not treat it as a node) | Emits | — | — | — |
| TrustTunnel | Emits | Skips | Emits | — | — | — |
| XHTTP | Emits | Skips node | VLESS only | — | — | VLESS/VMess/Trojan |
| HTTPUpgrade | Emits | Emits | VLESS/VMess/Trojan | — | — | VLESS/VMess |
| AmneziaWG | Emits | Skips node | Skips node | Skips node | Skips node | Emits parameters |
| TUIC v4 | Skips (v5 only) | Skips (v5 only) | Emits `tuic` + token | — | — | Emits v4 link |
| AnyTLS share link | Emits | Emits | Emits | — | — | Emits |

Legend: "Emits" means the target produces this protocol. "Skips" means the converter drops the node and logs it. A dash means the target does not provide this protocol.

- Juicity is not supported. No target client loads it.
- Mieru works in mihomo only. MASQUE and TrustTunnel work in mihomo and Surge only.
- Only sing-box loads naive in a target config. The clash target skips naive nodes.
- Only the Surge target loads TUIC v4 with a token handshake. mihomo and sing-box support TUIC v5 only.
- Only mihomo loads AmneziaWG in a target config.
- sing-box skips XHTTP nodes.
- Surge uses XHTTP for VLESS only.
- A number in the sing-box column is the minimum sing-box version.
- sing-box 1.13 and later write WireGuard as an endpoint. Older releases use the legacy outbound.
- A MASQUE node read from Surge has no ECDSA key pair. The clash target skips it.
- Shadowrocket and Loon skip HTTPUpgrade nodes.

## Not supported

| Upstream feature | Note |
|---|---|
| `GET /getruleset` | Rule set proxy endpoint |
| `GET /render` | Template rendering endpoint |
| `GET /refreshrules`, `/upload` | Rule refresh and config upload |
| `filter_script` / `&fscript=` | JavaScript node filtering. Use the `&include=` / `&exclude=` regexes; handle complex logic at the source |
| `&preview=` | Preview mode; use `&check=true` |

A link that depends on these gets a 404 or has the parameter ignored. It never silently produces a wrong config.

## Behavior differences

**Fail loudly, never guess.** A wrong parameter is an error; there is no fallback default config:

| Situation | Response |
|---|---|
| Unknown `target`, invalid version, unusable `template`, provider mode without a subscription URL | `400` |
| The subscription parsed but holds no usable node | `422` |
| An upstream fetch failed (subscription / config / rule set) | `424` |

**Regexes in the config accept PCRE syntax.** Group selectors, `include`/`exclude`, `rename`, and `emoji` are compiled with Go RE2 first, then with a PCRE engine, which covers lookahead, lookbehind, and backreferences. Exclusion groups like `(^(?!.*(美国|日本)).*)` from the upstream docs match nodes as expected. A selector that neither engine accepts, or a match that runs past 100 ms, returns `400` and names the group and selector. In provider mode, `include`/`exclude` are written into the client `filter`, so they must also compile with the PCRE engine. Attribute selectors: `!!TYPE=` full-matches the protocol name; a TLS HTTP node is `HTTPS`, a plain one is `HTTP`. `!!PORT=` accepts `443`, `1000-2000`, `1000-`, `1000+`, `!443`, and `!1000-2000`, comma-separated, with spaces allowed. `!1000-`, `!1000+`, and `+5` return `400` because upstream reads those forms differently. `!!SERVER=` and `!!GROUP=` match a substring; `!!GROUP=` reads the `tag:<group>,` source prefix, and an untagged node has an empty group. An IPv6 address matches both `::1` and `[::1]`. `!!GROUPID=` counts from 0 for `url=`; `!!INSERT=` counts from 1 for `insert_url`. Each accepts an optional `!!<regex>` tail matched against the node name. An empty value or an unknown attribute returns `400`. `!!PROVIDER=` is not supported (provider names are generated as `sub-N`), and no `!!` selector can be expressed in a provider-mode client `filter`; both return `400`. A `tag:` source is also rejected in provider mode.

**`clash_rule_base` keeps your file layout.** Only the generated sections are replaced: `proxies`, `proxy-groups`, and `rules`; plus `proxy-providers` in provider mode and `rule-providers` with `expand=false`. Key order, quotes, and comments stay as written. Indentation follows the base's width, from 2 to 9 spaces; a base outside that range falls back to 2. A leading `%YAML 1.1` or `%YAML 1.2` directive is dropped because the YAML library rejects it, and `%TAG` directives are kept. Another version, another directive, or a directive block that no `---` terminates returns `400`. Blank lines are dropped. If the base cannot be fetched or parsed, the request fails; it does not fall back to the built-in skeleton.

**The cache is keyed by User-Agent, upstream proxy, and URL.** A request with `&ua=` neither reads nor writes the shared cache, because the UA is an unbounded key space. Set `user_agent` in the server config if you need caching.

**sing-box output follows the kernel version.** Without a declared version, the output follows the current sing-box schema; older kernels need `target=singbox/1.11` and the like. One config is not portable across sing-box major versions. That is the kernel's schema changing, not an option in this converter.

**Emoji is on by default.** Same global default as upstream (`add_emoji` and `remove_emoji` both true). Precedence is global default < external config < URL `add_emoji`/`remove_emoji` < URL `emoji`.
