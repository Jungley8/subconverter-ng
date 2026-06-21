# subconverter-ng

> 现代化的订阅转换工具 —— 用 **Go** 重写的 [subconverter](https://github.com/tindy2013/subconverter)，专注第一时间支持新协议。

[![License](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/Jungley8/subconverter-ng/blob/main/LICENSE)
[![CI](https://github.com/Jungley8/subconverter-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/Jungley8/subconverter-ng/actions/workflows/ci.yml)
[![Docker](https://github.com/Jungley8/subconverter-ng/actions/workflows/docker.yml/badge.svg)](https://github.com/Jungley8/subconverter-ng/actions/workflows/docker.yml)

## 为什么做这个

`subconverter` 已经很经典，但近年迭代变慢，**Hysteria2、TUIC、VLESS Reality** 等新协议支持不全。`subconverter-ng` 用 Go 重写：

- **接口保持一致** —— `/sub?target=clash&url=...&config=...`，老客户端、老书签无需改动即可替换
- **对准 Clash.Meta / mihomo** —— 新协议第一时间可用
- **访问层是一等公民** —— 内置上游代理、自定义 User-Agent、自动绕过 Cloudflare 5 秒盾

## 支持的协议

| 协议 | 链接前缀 | 状态 |
|---|---|---|
| Shadowsocks | `ss://` | :material-check: |
| ShadowsocksR | `ssr://` | :material-check: |
| VMess | `vmess://` | :material-check: |
| VLESS（含 Reality / XTLS-Vision） | `vless://` | :material-check: |
| Trojan | `trojan://` | :material-check: |
| Hysteria v1 | `hysteria://` `hy://` | :material-check: |
| Hysteria2 | `hysteria2://` `hy2://` | :material-check: |
| TUIC v5 | `tuic://` | :material-check: |
| AnyTLS | `anytls://` | :material-check: |
| SOCKS5 | `socks://` `socks5://` | :material-check: |
| WireGuard | `wireguard://` `wg://` | :material-check: |

> 订阅本身就是 Clash/Clash.Meta YAML 时，会直接提取其中的 `proxies`（任意类型，包括 WireGuard）。

## 30 秒上手

=== "Docker（推荐）"

    ```bash
    docker run -d -p 25500:25500 ghcr.io/jungley8/subconverter-ng:latest
    # http://127.0.0.1:25500/sub?target=clash&url=<订阅URL编码>
    ```

=== "二进制"

    ```bash
    go install github.com/Jungley8/subconverter-ng/cmd/subconverter-ng@latest
    subconverter-ng serve --listen :25500
    ```

继续阅读 [快速开始](quickstart.md)。

!!! tip "访问不了机场？"
    很多机场需要走代理才能访问，或套了 Cloudflare 盾。看
    [上游代理与 UA](proxy.md) 和 [绕过 Cloudflare](cloudflare.md)。

## License

[GPL-3.0-or-later](https://github.com/Jungley8/subconverter-ng/blob/main/LICENSE) © Jungley8
