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

**The cache is keyed by User-Agent, upstream proxy, and URL.** A request with `&ua=` neither reads nor writes the shared cache, because the UA is an unbounded key space. Set `user_agent` in the server config if you need caching.

**sing-box output follows the kernel version.** Without a declared version, the output follows the current sing-box schema; older kernels need `target=singbox/1.11` and the like. One config is not portable across sing-box major versions. That is the kernel's schema changing, not an option in this converter.

**Emoji is on by default.** Same global default as upstream (`add_emoji` and `remove_emoji` both true). Precedence is global default < external config < URL `add_emoji`/`remove_emoji` < URL `emoji`.
