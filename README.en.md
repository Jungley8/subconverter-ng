# subconverter-ng

> A modern subscription converter — a Go rewrite of [subconverter](https://github.com/tindy2013/subconverter), focused on supporting modern protocols.

[简体中文](README.md) | **English**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![CI](https://github.com/Jungley8/subconverter-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/Jungley8/subconverter-ng/actions/workflows/ci.yml)
[![Docker](https://github.com/Jungley8/subconverter-ng/actions/workflows/docker.yml/badge.svg)](https://github.com/Jungley8/subconverter-ng/actions/workflows/docker.yml)

📖 **Docs**: <https://sub.jungley.net>

`subconverter` is a classic, but its development has slowed and newer protocols
like Hysteria2, TUIC and VLESS Reality are not well supported. `subconverter-ng`
is a Go rewrite that **keeps the same URL interface** (drop-in replacement) while
targeting **Clash.Meta / mihomo** so new protocols work right away.

## Features

- ✅ **Compatible API**: `/sub?target=clash&url=...&config=...` — existing clients keep working unchanged
- ✅ **Protocols**: Shadowsocks, ShadowsocksR, VMess, VLESS (Reality / XTLS-Vision), Trojan, Hysteria (v1/v2), TUIC v5, AnyTLS, SOCKS5, **WireGuard**
- ✅ **Node processing**: dedup (`dedup`), filter unsupported nodes (`fdn`), append protocol type (`append_type`), regex `rename`, emoji add/remove (subconverter-compatible)
- ✅ **Cache / rate-limit**: TTL cache for rulesets & subscriptions (on by default, flushable), per-IP rate limiting
- ✅ **Subscription-Userinfo passthrough**: clients show airport traffic / expiry directly
- ✅ **rule-providers output** (`expand=false`), proxies-only output (`list`)
- ✅ **External config**: parses subconverter's INI external config (`ruleset=` / `custom_proxy_group=` / `exclude_remarks` / `enable_rule_generator` / `clash_rule_base`), ACL4SSR-compatible
- ✅ **Access layer**: upstream proxy (http/socks5), configurable User-Agent, **automatic Cloudflare challenge bypass** (FlareSolverr)
- ✅ **Two modes**: HTTP service + one-shot CLI converter, single binary
- ✅ **Multiple output targets**: `clash` (Clash.Meta / mihomo), `singbox`, `surge`, `shadowrocket`, `quanx`, `loon`, `v2ray`/`mixed`
- ✅ **insert_url node insertion**: server-configured nodes merged into every conversion (`&insert=` overrides)

> Parsing uses Clash.Meta fields as the intermediate model, then renders to each target; protocols / rules a target can't express are skipped and logged.

## Quick start

### Binary

```bash
go build -o subconverter-ng ./cmd/subconverter-ng

# Run the server (subconverter-compatible API)
./subconverter-ng serve --listen :25500

# In a browser / client:
# http://127.0.0.1:25500/sub?target=clash&url=<url-encoded-sub>&config=<url-encoded-rules>
```

> Built-in web UI: open <http://127.0.0.1:25500/> to build subscription links visually (see [docs/web.md](docs/web.md)).

### CLI one-shot conversion

```bash
./subconverter-ng convert \
  --url 'https://your-airport.com/api/v1/client/subscribe?token=xxx' \
  --config 'https://github.com/you/clash-rule/raw/main/config.init' \
  -o clash.yaml
```

### Docker

```bash
# Pull the multi-arch image built by CI
docker run -d -p 25500:25500 ghcr.io/jungley8/subconverter-ng:latest

# Or with the FlareSolverr sidecar, batteries included
docker compose up -d
# http://127.0.0.1:25500/sub?target=clash&url=...
```

## URL parameters

Full list in [docs/url-params.md](docs/url-params.md). Common ones:

| Param | Description |
|---|---|
| `target` | output target: `clash` / `singbox` / `surge` / `shadowrocket` / `quanx` / `loon` / `v2ray` |
| `url` | subscription URL(s), `\|`-separated (required) |
| `config` | external INI config URL |
| `insert` | merge the server's `insert_url` nodes (overrides config default) |
| `sort` | sort nodes by name |
| `dedup` | remove duplicate nodes |
| `fdn` | drop nodes Clash.Meta can't use (e.g. SS with a retired cipher) |
| `list` | output only the node list (no groups / rules, **clash only**) |
| `append_type` | prepend `[TYPE]` to node names |
| `expand` | `false` emits rule-providers referencing remote rules (**clash only**) |
| `emoji` `add_emoji` `remove_emoji` | emoji add/remove (subconverter-compatible) |
| `udp` `tfo` `scv` | per-node toggles (target-dependent) |
| `filename` `interval` | download filename / client update interval |
| `nocache` `flushcache` | bypass / flush cache |
| `proxy` | per-request upstream proxy (overrides global; extension) |

> Per-target applicability is documented in [docs/url-params.md](docs/url-params.md). `new_name` is accepted for compatibility but has no effect.

## Solving access problems

Many airports require an upstream proxy, or sit behind Cloudflare. See:

- **[docs/proxy.md](docs/proxy.md)** — upstream proxy & User-Agent
- **[docs/cloudflare.md](docs/cloudflare.md)** — automatic FlareSolverr bypass

## Configuration

Server config: see [`config.example.yaml`](config.example.yaml), or env vars
`SUBNG_LISTEN` / `SUBNG_PROXY` / `SUBNG_FLARESOLVERR_URL` / `SUBNG_USER_AGENT`.

## Development

```bash
make test    # run tests
make vet
make build   # output to bin/
make run     # run the server locally
```

## License

[GPL-3.0-or-later](LICENSE) © Jungley8
