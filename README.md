# subconverter-ng

> 现代化的订阅转换工具 —— 用 Go 重写的 [subconverter](https://github.com/tindy2013/subconverter)，专注支持新协议。

**简体中文** | [English](README.en.md)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![CI](https://github.com/Jungley8/subconverter-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/Jungley8/subconverter-ng/actions/workflows/ci.yml)
[![Docker](https://github.com/Jungley8/subconverter-ng/actions/workflows/docker.yml/badge.svg)](https://github.com/Jungley8/subconverter-ng/actions/workflows/docker.yml)

📖 **文档站**：<https://sub.jungley.net>

`subconverter` 已经很经典，但近年迭代变慢，Hysteria2、TUIC、VLESS Reality 等新协议支持不全。`subconverter-ng` 用 Go 重写，**保持相同的 URL 接口**（可直接替换），同时把目标内核对准 **Clash.Meta / mihomo**，第一时间支持新协议。

## 特性

- ✅ **接口兼容**：`/sub?target=clash&url=...&config=...`，老客户端无需改动
- ✅ **协议**：Shadowsocks、ShadowsocksR、VMess、VLESS（含 Reality / XTLS-Vision）、Trojan、Hysteria（v1/v2）、TUIC v5、AnyTLS、SOCKS5、**WireGuard**
- ✅ **节点处理**：去重（`dedup`）、过滤不支持的节点（`fdn`）、追加协议类型（`append_type`）、`rename` 正则重命名、emoji 增删（对齐 subconverter）
- ✅ **缓存 / 限流**：规则与订阅 TTL 缓存（默认开，可清除）、按 IP 限流防滥用
- ✅ **Subscription-Userinfo 透传**：客户端直接显示机场流量 / 到期
- ✅ **rule-providers 输出**（`expand=false`）、仅节点列表输出（`list`）
- ✅ **外部配置**：解析 subconverter 的 INI 外部配置（`ruleset=` / `custom_proxy_group=` / `exclude_remarks` / `enable_rule_generator` / `clash_rule_base`），兼容 ACL4SSR 规则
- ✅ **访问层**：上游代理（http/socks5）、可配置 User-Agent、**自动绕过 Cloudflare 5 秒盾**（FlareSolverr）
- ✅ **两种形态**：HTTP 服务 + CLI 单次转换，单二进制
- ✅ **目标内核**：Clash.Meta / mihomo

> 目前输出 target 仅 `clash`。后续逐步支持更多输出格式。

## 快速开始

### 二进制

```bash
go build -o subconverter-ng ./cmd/subconverter-ng

# 起服务（兼容 subconverter 接口）
./subconverter-ng serve --listen :25500

# 浏览器/客户端访问：
# http://127.0.0.1:25500/sub?target=clash&url=<订阅URL编码>&config=<规则URL编码>
```

> 内置 Web 界面：浏览器打开 <http://127.0.0.1:25500/> 即可可视化生成订阅链接（详见 [docs/web.md](docs/web.md)）。

### CLI 单次转换

```bash
./subconverter-ng convert \
  --url 'https://your-airport.com/api/v1/client/subscribe?token=xxx' \
  --config 'https://github.com/you/clash-rule/raw/main/config.init' \
  -o clash.yaml
```

### Docker

```bash
# 直接拉取 CI 构建的多架构镜像
docker run -d -p 25500:25500 ghcr.io/jungley8/subconverter-ng:latest

# 或含 FlareSolverr sidecar，开箱即用
docker compose up -d
# http://127.0.0.1:25500/sub?target=clash&url=...
```

## URL 参数

完整列表见 [docs/url-params.md](docs/url-params.md)，常用：

| 参数 | 说明 |
|---|---|
| `target` | 输出目标（仅 `clash`） |
| `url` | 订阅链接，多个用 `\|` 分隔（必填） |
| `config` | 外部 INI 配置 URL |
| `sort` | 按节点名排序 |
| `dedup` | 去除重复节点 |
| `fdn` | 过滤 Clash.Meta 不支持的节点（如废弃加密的 SS） |
| `list` | 仅输出节点列表（无分组 / 规则） |
| `append_type` | 节点名前加 `[类型]` |
| `expand` | `false` 时输出 rule-providers 引用远程规则 |
| `emoji` `add_emoji` `remove_emoji` | emoji 增删（对齐 subconverter） |
| `udp` `tfo` `scv` | 节点开关 |
| `filename` `interval` | 下载文件名 / 客户端更新间隔 |
| `nocache` `flushcache` | 绕过 / 清空缓存 |
| `proxy` | 本次请求的上游代理（覆盖全局，扩展参数） |

> `insert`、`new_name` 为兼容性接收但当前无效果（见文档说明）。

## 解决访问问题

很多机场需要走代理才能访问，或套了 Cloudflare 盾。详见：

- **[docs/proxy.md](docs/proxy.md)** —— 配置上游代理 与 User-Agent
- **[docs/cloudflare.md](docs/cloudflare.md)** —— FlareSolverr 自动过盾

## 配置

服务端配置见 [`config.example.yaml`](config.example.yaml)，或用环境变量
`SUBNG_LISTEN` / `SUBNG_PROXY` / `SUBNG_FLARESOLVERR_URL` / `SUBNG_USER_AGENT`。

## 开发

```bash
make test    # 跑测试
make vet
make build   # 输出到 bin/
make run     # 本地起服务
```

## 路线图

- [x] 更多协议（hysteria1、anytls、ssr、socks5、**wireguard**）
- [x] 重命名规则 / emoji 增删（对齐 subconverter）
- [x] 订阅 / 规则缓存
- [x] rule-providers 输出模式
- [x] IP 限流防滥用
- [x] Subscription-Userinfo 透传
- [x] 内置 Web 界面
- [x] 节点去重（`dedup`）、过滤不支持节点（`fdn`）
- [x] 全量 URL 参数（`list` / `filename` / `interval` / `append_type` …）
- [ ] 更多输出 target（sing-box、surge、quanx…）
- [ ] `insert_url` 节点插入、节点测速排序

## License

[GPL-3.0-or-later](LICENSE) © Jungley8
