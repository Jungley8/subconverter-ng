# URL Parameters

Query parameters for `GET /sub`, kept as compatible as possible with [tindy2013/subconverter](https://github.com/tindy2013/subconverter) so old links can be swapped in directly.

## `target` values

`target` selects the output format. Supported values (including common aliases):

| target | Aliases | Output | Content-Type |
|---|---|---|---|
| `clash` | `clash.meta` `clashr` | Clash.Meta / mihomo YAML | `text/yaml` |
| `singbox` | `sing-box` | sing-box JSON | `application/json` |
| `surge` | | Surge `.conf` (with `[Proxy]`/`[Proxy Group]`/`[Rule]`) | `text/plain` |
| `shadowrocket` | `shadow-rocket` | Surge-style managed conf (importable by Shadowrocket) | `text/plain` |
| `quanx` | `quantumultx` `quantumult-x` | Quantumult X resource config | `text/plain` |
| `loon` | | Loon `.conf` | `text/plain` |
| `v2ray` | `mixed` `v2rayn` | base64 node subscription (ss/vmess/vless/trojan/hysteria2/tuic share links) | `text/plain` |

!!! note "Protocol coverage"
    Each target prioritizes the common protocols (ss/vmess/vless/trojan/hysteria2/tuic). A protocol a given
    target cannot express (e.g. Surge has no VLESS, QuanX/Surge have no hysteria2/tuic) is **skipped and listed
    in the log** rather than failing the whole config.

## Common parameters (apply to all targets)

| Parameter | Description | Status |
|---|---|---|
| `target` | Output target (see table above), defaults to `clash` | :material-check: |
| `url` | Subscription link; separate multiple with `\|` (required) | :material-check: |
| `config` | External INI config URL (source of groups and rules) | :material-check: |
| `insert` | Whether to merge the server-side `insert_url` nodes; overrides the config default (see below) | :material-check: |
| `sort` | Sort by node name | :material-check: |
| `dedup` | Remove duplicate nodes: nodes with identical connection fields (type/address/port/credentials/transport) keep only the first | :material-check: |
| `append_type` | Prefix node names with `[type]` (e.g. `[SS] HK 01`) | :material-check: |
| `emoji` | Shortcut: `true` = strip old emoji then add flags by rule; `false` = strip emoji and add none. Equivalent to `add_emoji=<value>` plus `remove_emoji=true` | :material-check: |
| `add_emoji` | Whether to prepend flag emoji to node names by rule (default `true`) | :material-check: |
| `remove_emoji` | Whether to first remove existing emoji in node names (default `true`) | :material-check: |
| `filename` | Set the download filename (`Content-Disposition`) | :material-check: |
| `interval` | Client subscription auto-update interval (hours, default 24, `Profile-Update-Interval` header) | :material-check: |
| `proxy` | Upstream proxy for **this request**, overriding the global config (extension param) | :material-check: |
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

!!! note "Rule handling for other targets"
    surge family / quanx / sing-box always **expand rules inline** (remote rule sets are fetched and converted
    line by line into the target syntax); rule types the target format doesn't support (e.g. Surge has no
    `GEOSITE`/`IP-SUFFIX`) are dropped and logged. The v2ray base64 subscription **contains no rules** — the
    client manages those itself.

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
    - **Cache**: subscriptions and rule lists are cached in memory by URL with a TTL (default 300s), to avoid hitting GitHub for rule lists on every `/sub` and getting rate-limited. `cache_ttl: -1s` disables it.
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
