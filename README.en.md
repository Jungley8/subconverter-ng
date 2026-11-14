# subconverter-ng

> A modern subscription converter — a Go rewrite of [subconverter](https://github.com/tindy2013/subconverter), focused on new protocols and modern engineering standards.

[简体中文](README.md) | **English**

[![GitHub Release](https://img.shields.io/github/v/release/Jungley8/subconverter-ng?color=blue)](https://github.com/Jungley8/subconverter-ng/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/Jungley8/subconverter-ng)](go.mod)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![CI](https://github.com/Jungley8/subconverter-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/Jungley8/subconverter-ng/actions/workflows/ci.yml)
[![Docker](https://github.com/Jungley8/subconverter-ng/actions/workflows/docker.yml/badge.svg)](https://github.com/Jungley8/subconverter-ng/actions/workflows/docker.yml)

📖 **Documentation**: <https://sub.jungley.net>

`subconverter` is a classic tool, but active development has slowed. Modern protocols such as Hysteria2, TUIC, and VLESS Reality are often missing. `subconverter-ng` is a pure Go rewrite. It **preserves the identical URL interface** as a drop-in replacement, targets **Clash.Meta (mihomo)** alongside major modern clients, and ships first-class protocol support.

## Features

- ✅ **Drop-in compatibility**: `/sub?target=clash&url=...&config=...` keeps existing client setups working.
- ✅ **Full modern protocol support**: Shadowsocks, ShadowsocksR, VMess, VLESS (Reality / XTLS-Vision), Trojan, Hysteria (v1/v2), TUIC v5, AnyTLS, SOCKS5, **WireGuard**.
- ✅ **Full subscription source parsing**: auto-detects and decodes Clash YAML, sing-box JSON, Surge conf, and Base64 share-link lists; natively compatible with Hiddify and other sing-box based subscriptions.
- ✅ **Built-in Web UI & Subscription Manager**: Bundled into the binary. Open the root URL to generate configs visually and manage subscriptions locally (expiry countdown, traffic reset day, monthly expense estimate, batch conversion, JSON backup/restore). Data stays in local storage.
- ✅ **Multiple output targets**: `clash` (Clash.Meta / mihomo), `singbox`, `surge`, `shadowrocket`, `quanx`, `loon`, `v2ray`/`mixed`.
- ✅ **Zero-trust security defense**: Network-level SSRF defense with DNS rebinding protection (`allow_private_cidrs` can allow specific internal hosts). Mandatory credential redaction in logs and responses. Strict HTTP 424/422 responses on conversion failures to prevent client config poisoning, and the error body survives reverse proxies such as Cloudflare that replace 5xx pages.
- ✅ **Concurrency resilience**: Cross-request SingleFlight deduplication prevents thundering herd loads on upstream servers and GitHub rate-limits. Memory cache with capacity bounds and eviction. Response stream limits (10MB max).
- ✅ **Production observability**: Structured `log/slog` logging. Native health endpoints (`/healthz`, `/readyz`). Graceful shutdown via `SIGTERM`/`SIGINT`. Optional access token authentication (`api_access_token`).
- ✅ **Node processing**: Dedup (`dedup`), unsupported cipher filtering (`fdn`), protocol prefixing (`append_type`), Tailscale rules (`tailscale`), regex `rename`, and emoji additions/removals.
- ✅ **Rulesets & external configs**: Parses subconverter INI external configs (`ruleset=` / `custom_proxy_group=` / `clash_rule_base`), compatible with ACL4SSR and `expand=false` rule-providers.
- ✅ **Dual operation modes**: HTTP service daemon and one-shot offline CLI converter.
- ✅ **Cross-platform router builds**: Pre-built binaries for Linux, macOS, Windows, and OpenWrt routers (MIPS, MIPSLE, ARMv7).
- ✅ **Per-request fetch UA**: `&ua=` overrides the fetch User-Agent (the Web UI has a UA preset dropdown). `target` accepts `name/version` (for example `singbox/1.3`). The version drops protocols the declared kernel cannot render and switches to the modern schema.
- ✅ **sing-box template rendering**: `&template=<http(s) URL>` points at a sing-box JSON template. Nodes and `NotesName` groups are injected, and the output is a full config.
- ✅ **Node-name filtering**: `&include=` / `&exclude=` regex filters. Provider mode maps them to the client's `filter` / `exclude-filter`.
- ✅ **Clash proxy-provider output**: `&provider=true` emits a `proxy-providers` skeleton. The client fetches and refreshes nodes by itself.

> The kernel parses through Clash.Meta fields, then renders to each target. Protocols and rules the target format does not support are skipped and logged.

## Quick Start

### Option 1: Download Pre-built Binaries (Recommended)

Download the binary for your platform directly from the [Releases page](https://github.com/Jungley8/subconverter-ng/releases):
- **Desktop & Server**: `darwin_arm64`, `darwin_amd64`, `linux_amd64`, `linux_arm64`, `windows_amd64`
- **Routers (OpenWrt, etc.)**: `linux_mips_softfloat`, `linux_mipsle_softfloat` (MT7621 chips), `linux_armv7`

```bash
# Start the server (default listen address: :25500)
./subconverter-ng serve --listen :25500

# Access from client or browser:
# http://127.0.0.1:25500/sub?target=clash&url=<encoded-sub-url>&config=<encoded-rules-url>
```

> Built-in Web UI: Open <http://127.0.0.1:25500/> in your browser for visual subscription conversion and the "My Subscriptions" management panel (see [docs/web.md](docs/web.md)).

### Option 2: Docker Container

```bash
# Pull multi-arch image (linux/amd64, linux/arm64)
docker run -d -p 25500:25500 ghcr.io/jungley8/subconverter-ng:latest

# Or run with the FlareSolverr sidecar to bypass Cloudflare challenges
docker compose up -d
```

### Option 3: CLI One-Shot Conversion (Supports Local Files & URLs)

Convert remote subscriptions or local files offline without running an HTTP daemon:

```bash
# 1. Convert remote subscription using a local rules file
./subconverter-ng convert \
  --url 'https://your-airport.com/api/v1/client/subscribe?token=xxx' \
  --config ./local-rules.ini \
  -o clash.yaml

# 2. Convert a local node file to a Sing-box config offline
./subconverter-ng convert \
  --url ./nodes.txt \
  --target singbox \
  -o config.json
```

## Service Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/sub` | GET | Core subscription conversion endpoint. Supports `api_access_token` and IP rate-limiting. |
| `/flushcache` | GET / POST | Clears subscription and ruleset cache (rate-limited). |
| `/healthz` | GET | Liveness probe endpoint. |
| `/readyz` | GET | Readiness probe endpoint. |
| `/version` | GET | Returns build version and commit hash. |
| `/` | GET | Built-in Web UI for subscription generation and management. |

## Common URL Parameters

See [docs/url-params.md](docs/url-params.md) for full documentation. Common options:

| Parameter | Description |
|---|---|
| `target` | Output target: `clash`, `singbox`, `surge`, `shadowrocket`, `quanx`, `loon`, `v2ray` |
| `url` | Subscription URL(s), separated by `\|` (required); raw node links accepted |
| `config` | External INI configuration URL or local file path |
| `insert` | Merge server-configured `insert_url` nodes |
| `sort` | Sort nodes alphabetically |
| `dedup` | Remove duplicate nodes |
| `fdn` | Filter nodes unsupported by Clash.Meta |
| `list` | Output node list only without groups or rules (**clash only**) |
| `append_type` | Prepend `[TYPE]` to node names |
| `tailscale` | Prepend Tailscale DIRECT rules (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`) |
| `exclude_protocol` | Exclude nodes by protocol or type (e.g. `hy2,tuic`; alias: `exclude_protocols`) |
| `expand` | Set to `false` to output rule-providers referencing remote rules (**clash only**) |
| `emoji` `add_emoji` `remove_emoji` | Add or remove emoji tags |
| `udp` `tfo` `scv` | Node transport feature toggles |
| `filename` `interval` | Attachment download filename and client auto-update interval |
| `nocache` `flushcache` | Bypass or flush memory cache |
| `proxy` | Custom upstream proxy for this request |

## Overcoming Network Restrictions

Certain subscriptions require proxies or sit behind Cloudflare anti-bot checks:
- **[docs/proxy.md](docs/proxy.md)** — Configure upstream proxy and custom User-Agent
- **[docs/cloudflare.md](docs/cloudflare.md)** — Automatic challenge bypass using FlareSolverr

## Server Configuration

See [`config.example.yaml`](config.example.yaml) or configure via environment variables:
- `SUBNG_LISTEN`: Service listen address (default `:25500`)
- `SUBNG_PROXY`: Global upstream proxy URL
- `SUBNG_FLARESOLVERR_URL`: FlareSolverr instance URL
- `SUBNG_USER_AGENT`: Custom request User-Agent
- `SUBNG_API_TOKEN`: API token authentication (`api_access_token`)

## Development

```bash
make test    # Run unit tests and race detection
make vet     # Run linters and static analysis
make build   # Build single binary to bin/
make run     # Run server locally
make conformance  # Validate output with real sing-box / mihomo (needs mihomo, and CONFORMANCE_SINGBOX pointing at both 1.11 and the current release)
```

## License

[GPL-3.0-or-later](LICENSE) © Jungley8
