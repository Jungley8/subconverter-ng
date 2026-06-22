# subconverter-ng

> A modern subscription converter — a **Go** rewrite of [subconverter](https://github.com/tindy2013/subconverter), focused on day-one support for new protocols.

[![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/Jungley8/subconverter-ng/blob/main/LICENSE)
[![CI](https://github.com/Jungley8/subconverter-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/Jungley8/subconverter-ng/actions/workflows/ci.yml)
[![Docker](https://github.com/Jungley8/subconverter-ng/actions/workflows/docker.yml/badge.svg)](https://github.com/Jungley8/subconverter-ng/actions/workflows/docker.yml)

## Why this project

`subconverter` is a classic, but its development has slowed in recent years, leaving newer protocols such as **Hysteria2, TUIC and VLESS Reality** only partially supported. `subconverter-ng` is a Go rewrite:

- **Drop-in compatible API** — `/sub?target=clash&url=...&config=...`, so existing clients and bookmarks keep working without changes
- **Aligned with Clash.Meta / mihomo** — new protocols available from day one
- **The fetch layer is a first-class citizen** — built-in upstream proxy, custom User-Agent, and automatic bypass of the Cloudflare 5-second challenge

## Supported protocols

| Protocol | Link prefix | Status |
|---|---|---|
| Shadowsocks | `ss://` | :material-check: |
| ShadowsocksR | `ssr://` | :material-check: |
| VMess | `vmess://` | :material-check: |
| VLESS (incl. Reality / XTLS-Vision) | `vless://` | :material-check: |
| Trojan | `trojan://` | :material-check: |
| Hysteria v1 | `hysteria://` `hy://` | :material-check: |
| Hysteria2 | `hysteria2://` `hy2://` | :material-check: |
| TUIC v5 | `tuic://` | :material-check: |
| AnyTLS | `anytls://` | :material-check: |
| SOCKS5 | `socks://` `socks5://` | :material-check: |
| WireGuard | `wireguard://` `wg://` | :material-check: |

> When the subscription itself is Clash/Clash.Meta YAML, the `proxies` it contains are extracted directly (any type, including WireGuard).

## Up and running in 30 seconds

=== "Docker (recommended)"

    ```bash
    docker run -d -p 25500:25500 ghcr.io/jungley8/subconverter-ng:latest
    # http://127.0.0.1:25500/sub?target=clash&url=<URL-encoded subscription>
    ```

=== "Binary"

    ```bash
    go install github.com/Jungley8/subconverter-ng/cmd/subconverter-ng@latest
    subconverter-ng serve --listen :25500
    ```

Continue with the [Quick Start](quickstart.md).

!!! tip "Can't reach your provider?"
    Many providers require a proxy to reach, or sit behind a Cloudflare challenge. See
    [Upstream Proxy & UA](proxy.md) and [Bypass Cloudflare](cloudflare.md).

## License

[GPL-3.0-or-later](https://github.com/Jungley8/subconverter-ng/blob/main/LICENSE) © Jungley8
