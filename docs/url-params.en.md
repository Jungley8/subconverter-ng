# URL Parameters

Query parameters for `GET /sub`, kept as compatible as possible with [tindy2013/subconverter](https://github.com/tindy2013/subconverter) so old links can be swapped in directly.

## `target` values

`target` selects the output format. Supported values (including common aliases):

| target | Aliases | Output | Content-Type |
|---|---|---|---|
| `clash` | `clash.meta` `clashr` | Clash.Meta / mihomo YAML | `text/yaml` |
| `singbox` | `sing-box` | sing-box JSON | `application/json` |
| `surge` | | Surge `.conf` (with `[Proxy]`/`[Proxy Group]`/`[Rule]`) | `text/plain` |
| `shadowrocket` | `shadow-rocket` | Surge-style managed conf (imported via Shadowrocket's "Config" tab; use clash for home screen subscription) | `text/plain` |
| `quanx` | `quantumultx` `quantumult-x` | Quantumult X resource config | `text/plain` |
| `loon` | | Loon `.conf` | `text/plain` |
| `v2ray` | `mixed` `v2rayn` | base64 node subscription (ss/vmess/vless/trojan/hysteria2/tuic share links) | `text/plain` |

!!! note "Protocol coverage"
    Each target prioritizes the common protocols (ss/vmess/vless/trojan/hysteria2/tuic). A protocol a given
    target cannot express (e.g. Surge has no VLESS, QuanX/Surge have no hysteria2/tuic) is **skipped and listed
    in the log** rather than failing the whole config.

### Version gating (`target=name[/version]`)

`target` accepts a version suffix. Examples: `target=singbox/1.3.xx` (`xx` and other non-numeric trailing segments are ignored, same as `1.3`) or `target=singbox/1.13.11`. Only `singbox` reads the version today. The version gates protocols. Nodes the declared kernel cannot render are dropped and listed in `SkippedNodes` / the log with the reason `requires sing-box >= 1.x`. Without a version no gating applies, and behavior is unchanged. A malformed version (for example `singbox/abc`) is an error. Other targets accept the suffix and ignore it.

sing-box protocol floors (best effort, from the official release notes):

| Protocol | Minimum sing-box version |
|---|---|
| `ss` / `socks` / `vmess` / `vless` / `trojan` / `wireguard` | 1.0 |
| `hysteria` | 1.1 |
| `tuic` | 1.2 |
| `hysteria2` | 1.5 |
| `anytls` | 1.12 |

!!! note "Known limits"
    hysteria1 (v1) has no sing-box outbound. The generator skips it as unsupported for every declared version. anytls needs sing-box 1.12 or newer.

#### Schema switch

The declared version also selects the sing-box config schema (from the official deprecation notes):

| Declared version | Schema behavior |
|---|---|
| >= 1.11 | Rule actions: DNS hijack and reject rules become `action: hijack-dns` / `action: reject`. The `block` / `dns` special outbounds are not emitted (removed in 1.13; older kernels reject them) |
| >= 1.12 | `rule_set` and the new DNS format: `GEOSITE` / `GEOIP` rules become remote `.srs` rule-set references (top-level `rule_set` array). `geoip: private` becomes `ip_is_private: true`. DNS servers use the `{type, server}` form (1.14 removes the legacy form) |
| No version | Legacy output, compatible with sing-box 1.11 and older. Identical to the output of earlier releases |

!!! note
    The `direct` outbound is never deprecated and is kept for every version. `rule_set` entries omit `download_detour`, which 1.14 deprecates.

!!! note "rule_set mapping details"
    `GEOIP` supports two-letter country codes only (SagerNet/sing-geoip publishes country categories only). `GEOIP,PRIVATE/LAN` maps to the built-in `ip_is_private: true` item. Other non-country categories (for example `GEOIP,TWITTER`) are skipped and reported in diagnostics, so the config never references a rule-set that returns 404. `GEOSITE` categories map one to one to the sing-geosite repository. Renamed upstream categories are mapped automatically (`google-cn` becomes `google@cn`). Rules parse as `TYPE,VALUE[,FLAG]`: the third field is the flag (for example `no-resolve`). For `AND` / `OR` / `NOT`, the comma-filled remainder is the value. Lines with more than three fields, or an empty value, cannot render safely. They are skipped and reported in diagnostics (for example the old `GEOIP,PRIVATE,policy,no-resolve`); the parser never truncates them into a wrong rule.

## Common parameters (apply to all targets)

| Parameter | Description | Status |
|---|---|---|
| `target` | Output target (see table above), defaults to `clash` | :material-check: |
| `url` | Subscription link; separate multiple with `\|` (required). Raw node links (e.g. `vless://…`, `ss://…`) are also accepted directly, so a single node can be converted without a subscription | :material-check: |
| `config` | External INI config URL (source of groups and rules); when omitted, the server's `default_config_url` is used (no groups/rules if that is unset either) | :material-check: |
| `insert` | Whether to merge the server-side `insert_url` nodes; overrides the config default (see below) | :material-check: |
| `include` | **Node-name allowlist regex**: keep only nodes whose name matches (alias `include_remarks`). Overrides the external INI `include_remarks`; an empty value does not override. The spec is a single regex; put multiple alternatives inside it (for example `(?i)(HK\|JP)`) | :material-check: |
| `exclude` | **Node-name blocklist regex**: drop nodes whose name matches (alias `exclude_remarks`). Overrides the external INI `exclude_remarks`; an empty value does not override. Example: `(?i)(expired)\|(traffic)\|(website)` | :material-check: |
| `template` | Render a **full config** into a built-in or remote sing-box template. `momo` is the router momo template (inbounds, DNS/fake-ip, rule_set, split routing included); nodes and `NotesName` groups are injected. Pins target to `singbox` (extension parameter) | :material-check: |
| `sort` | Sort by node name | :material-check: |
| `dedup` | Remove duplicate nodes: nodes with identical connection fields (type/address/port/credentials/transport) keep only the first | :material-check: |
| `append_type` | Prefix node names with `[type]` (e.g. `[SS] HK 01`) | :material-check: |
| `tailscale` | Prepend Tailscale DIRECT rules (`100.64.0.0/10` and `fd7a:115c:a1e0::/48` with `no-resolve`) to the very beginning of the rules list | :material-check: |
| `exclude_protocol` | Exclude nodes by protocol or type (e.g. `hy2,tuic`; aliases: `exclude_protocols`, `exclude_types`, `filter_type`) | :material-check: |
| `emoji` | Shortcut: `true` = strip old emoji then add flags by rule; `false` = strip emoji and add none. Equivalent to `add_emoji=<value>` plus `remove_emoji=true` | :material-check: |
| `add_emoji` | Whether to prepend flag emoji to node names by rule (default `true`) | :material-check: |
| `remove_emoji` | Whether to first remove existing emoji in node names (default `true`) | :material-check: |
| `filename` | Set the download filename (`Content-Disposition`) | :material-check: |
| `interval` | Client subscription auto-update interval (hours, default 24, `Profile-Update-Interval` header) | :material-check: |
| `proxy` | Upstream proxy for this request; connection initiated by server, must be publicly reachable from server (extension parameter) | :material-check: |
| `ua` | Override the fetch User-Agent for this request. Applies to every remote fetch (subscription / rules / external config) (extension parameter; the Web UI has a UA preset dropdown that fills this field) | :material-check: |
| `nocache` | When `1`, bypass this request's TTL cache and force a refetch | :material-check: |
| `flushcache` | When `1`, clear the entire shared cache before handling this request (there is also a `GET /flushcache` endpoint) | :material-check: |

## Node-processing parameters (apply to some targets)

| Parameter | Description | Applicable targets |
|---|---|---|
| `udp` | Force UDP on for all nodes | clash / surge family / sing-box |
| `tfo` | TCP Fast Open | clash (not reflected in other targets yet) |
| `scv` | skip-cert-verify | clash / surge family / sing-box; reflected as `insecure` in v2ray share links |
| `fdn` | Filter out nodes Clash.Meta doesn't support (e.g. Shadowsocks with deprecated ciphers) | mainly clash |

## Clash only

| Parameter | Description | Status |
|---|---|---|
| `list` | Output the node list only (`proxies:`), without groups or rules | :material-check: |
| `expand` | `true` (default) inlines rules into the config; `false` emits `rule-providers` referencing remote rules | :material-check: |
| `provider` | proxy-provider mode: emit a `proxy-providers` skeleton; the client fetches and refreshes nodes (see below) | :material-check: |
| `provider_interval` | Provider update interval in seconds, default 86400; only read with `provider=true`. Do not confuse it with `interval` (hours, client subscription interval) | :material-check: |

### Provider mode (`&provider=true`)

Same idea as the original subconverter `clash.proxy-provider` template. The converter stops fetching and inlining nodes. It emits a Clash.Meta skeleton with `proxy-providers`. mihomo fetches the subscription and refreshes nodes at `provider_interval`. Groups and rules stay server-side.

- Each http(s) `url=` entry becomes one `sub-N` provider. Share-link entries such as `ss://` are still parsed and inlined locally.
- `&ua=` sets the provider `header.User-Agent`. `&include=` / `&exclude=` become `filter` / `exclude-filter` and keep applying to nodes the client fetches later. `&udp=` / `&scv=` become `override`.
- Groups: `[]literal` selectors in the INI `custom_proxy_group` stay as `proxies:` members. Regex selectors become a group-level `filter` plus `use:` (native mihomo behavior, so region groups keep working). With no external config, a minimal "Rocket selector / auto-select" pair is generated.
- Not applied: emoji, rename, fdn, dedup, and protocol version gating do not touch provider payloads. The client sees the provider's raw nodes.
- Combining this with `template=` or an explicit non-clash `target=` returns 400.

!!! note "Rule handling for other targets"
    surge family / quanx / sing-box always **expand rules inline** (remote rule sets are fetched and converted
    line by line into the target syntax); rule types the target format doesn't support (e.g. Surge has no
    `GEOSITE`/`IP-SUFFIX`) are dropped and logged. Exception: sing-box with a declared version >= 1.12 keeps
    `GEOIP`/`GEOSITE` as remote `rule_set` references, so the client downloads those itself. The v2ray base64
    subscription **contains no rules** — the client manages those itself.

## insert_url (node insertion)

The server can fix a set of "insert nodes" in its config and merge them into the result on every conversion
(subconverter's `insert_url`). Commonly used to pin your own relay/landing nodes ahead of the provider's nodes.

```yaml
# config.example.yaml
insert:
  urls:
    - https://example.com/my-extra-nodes
  prepend: true    # true = before the subscription nodes, false = after
  enabled: true    # whether to insert by default
```

- The `insert` URL param overrides `enabled`: `&insert=false` skips insertion this time, `&insert=true` forces it.
- Inserted nodes also go through filtering / dedup / emoji / renaming.
- A failed insert-source fetch does not break the main conversion (silently skipped).
- Environment variables: `SUBNG_INSERT_URLS` (comma-separated), `SUBNG_INSERT_PREPEND`, `SUBNG_INSERT_ENABLED`.

## Accepted for compatibility but currently no-op

| Parameter | Description |
|---|---|
| `new_name` | subconverter's old/new naming switch; this project uses the new naming by default, no switch needed |

!!! note "Rename / cache / rate limit"
    - **rename**: in the external config, write `rename=<regex>@<replacement>` (supports `\1` / `$1` backreferences and empty replacement) to batch-rename nodes. Order of operations: remove emoji → rename → add emoji.
    - **Cache**: subscriptions and rule lists are cached in memory by URL with a TTL (default 300s), to avoid hitting GitHub for rule lists on every `/sub` and getting rate-limited. The cache key includes the User-Agent, so the same URL with different UAs does not share an entry. `cache_ttl: -1s` disables it.
    - **Rate limit**: `/sub` is rate-limited per client IP (default 30/min, burst 10); over-limit returns `429 + Retry-After`; `/version` and the Web UI are exempt. See `config.example.yaml`.
    - **Subscription-Userinfo**: the traffic / expiry headers returned by the provider are passed through to the client.

!!! note "emoji behavior (aligned with subconverter)"
    Order of operations: **first `remove_emoji` strips old → then `add_emoji` applies flags by regex rule**. Rules
    come from the external config's `emoji=<regex>,<emoji>` lines; if unconfigured, the built-in default rule set
    is used (ported from subconverter, 95 rules, adapted to Go RE2).
    Priority: the `emoji` shortcut > `add_emoji`/`remove_emoji` > external config > default (all `true`).
    To **keep the original names entirely**: `add_emoji=false&remove_emoji=false`.

!!! note "Boolean parameter values"
    `true / 1 / yes / on` are truthy, `false / 0 / no / off` are falsy; anything else falls back to the default.

## Encoding reminder

`url` and `config` are full links and **must be URL-encoded** when passed as parameters. For example:

- Raw: `https://github.com/you/clash-rule/raw/main/config.init`
- Encoded: `https%3A%2F%2Fgithub.com%2Fyou%2Fclash-rule%2Fraw%2Fmain%2Fconfig.init`

Most clients handle this automatically; remember to encode when building the URL by hand.
