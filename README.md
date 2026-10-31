# subconverter-ng

> 现代化的订阅转换工具 —— 用 Go 重写的 [subconverter](https://github.com/tindy2013/subconverter)，专注支持新协议与现代工程化标准。

**简体中文** | [English](README.en.md)

[![GitHub Release](https://img.shields.io/github/v/release/Jungley8/subconverter-ng?color=blue)](https://github.com/Jungley8/subconverter-ng/releases)
[![Go Version](https://img.shields.io/github/go-mod/go-version/Jungley8/subconverter-ng)](go.mod)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![CI](https://github.com/Jungley8/subconverter-ng/actions/workflows/ci.yml/badge.svg)](https://github.com/Jungley8/subconverter-ng/actions/workflows/ci.yml)
[![Docker](https://github.com/Jungley8/subconverter-ng/actions/workflows/docker.yml/badge.svg)](https://github.com/Jungley8/subconverter-ng/actions/workflows/docker.yml)

📖 **文档站**：<https://sub.jungley.net>

`subconverter` 已经很经典，但近年迭代变慢，Hysteria2、TUIC、VLESS Reality 等新协议支持不全。`subconverter-ng` 用 Go 重写，**保持相同的 URL 接口**（可直接替换），对准 **Clash.Meta (mihomo)** 及各现代客户端标准，第一时间支持新协议。

## 特性

- ✅ **接口兼容**：`/sub?target=clash&url=...&config=...`，老客户端无需改动。
- ✅ **全协议支持**：Shadowsocks、ShadowsocksR、VMess、VLESS（含 Reality / XTLS-Vision）、Trojan、Hysteria（v1/v2）、TUIC v5、AnyTLS、SOCKS5、**WireGuard**。
- ✅ **多输出 target**：`clash`（Clash.Meta / mihomo）、`singbox`、`surge`、`shadowrocket`、`quanx`、`loon`、`v2ray`/`mixed`。
- ✅ **安全与纵深防御**：物理连接层防御 SSRF 与 DNS Rebinding；日志与响应中机场 Token 强制脱敏（Token Redaction）；转换失败严格返回 HTTP 502/422，杜绝返回 200 导致客户端有效配置被覆写（防订阅投毒）。
- ✅ **并发与抗压韧性**：跨请求 SingleFlight 并发折叠，避免高频请求击垮上游机场或触发 GitHub API 限流；带容量上限的内存缓存；响应体流控保护（10MB 防 OOM）。
- ✅ **生产级可观测性**：`log/slog` 结构化日志；健康探针（`/healthz`、`/readyz`）；支持 `SIGTERM`/`SIGINT` 优雅停机；可选 API Token 准入保护（`api_access_token`）。
- ✅ **节点处理**：去重（`dedup`）、过滤不支持节点（`fdn`）、追加协议类型（`append_type`）、Tailscale 直连规则（`tailscale`）、`rename` 正则重命名、emoji 增删（对齐 subconverter）。
- ✅ **规则集与外部配置**：解析 subconverter INI 外部配置（`ruleset=` / `custom_proxy_group=` / `exclude_remarks` / `clash_rule_base`），兼容 ACL4SSR 规则与 rule-providers 模式（`expand=false`）。
- ✅ **两种工作形态**：HTTP 服务守护进程 + CLI 单次离线转换，单静态二进制。
- ✅ **软路由多架构支持**：提供 Linux、macOS、Windows 以及 OpenWrt 路由器（MIPS / MIPSLE / ARMv7）预编译包。

## 快速开始

### 方式一：下载预编译二进制（推荐）

前往 [Releases 页面](https://github.com/Jungley8/subconverter-ng/releases) 下载对应平台的二进制文件：
- **桌面 / 服务器**：`darwin_arm64`、`darwin_amd64`、`linux_amd64`、`linux_arm64`、`windows_amd64`
- **软路由平台（OpenWrt 等）**：`linux_mips_softfloat`、`linux_mipsle_softfloat`（MT7621 等芯片）、`linux_armv7`

```bash
# 启动服务（默认监听 :25500）
./subconverter-ng serve --listen :25500

# 客户端或浏览器访问转换接口：
# http://127.0.0.1:25500/sub?target=clash&url=<订阅URL编码>&config=<规则URL编码>
```

> 内置 Web 界面：浏览器打开 <http://127.0.0.1:25500/> 即可可视化生成订阅链接（详见 [docs/web.md](docs/web.md)）。

### 方式二：Docker 容器

```bash
# 直接拉取 CI 构建的多架构镜像（linux/amd64, linux/arm64）
docker run -d -p 25500:25500 ghcr.io/jungley8/subconverter-ng:latest

# 或使用 docker-compose（含 FlareSolverr 自动绕过 Cloudflare 盾）
docker compose up -d
```

### 方式三：CLI 单次转换（支持本地文件与远程 URL）

支持通过本地规则文件、本地节点文件或远程 URL 进行单次离线转换：

```bash
# 1. 转换远程订阅并套用本地规则文件
./subconverter-ng convert \
  --url 'https://your-airport.com/api/v1/client/subscribe?token=xxx' \
  --config ./local-rules.ini \
  -o clash.yaml

# 2. 离线转换本地节点文件为 Sing-box 配置
./subconverter-ng convert \
  --url ./nodes.txt \
  --target singbox \
  -o config.json
```

## 服务接口列表

| 端点 | 方法 | 说明 |
|---|---|---|
| `/sub` | GET | 订阅转换主接口，支持可选 `api_access_token` 与 IP 限流 |
| `/flushcache` | GET / POST | 手动清空服务端规则与订阅缓存（受限流保护） |
| `/healthz` | GET | 存活探针（Liveness Probe） |
| `/readyz` | GET | 就绪探针（Readiness Probe） |
| `/version` | GET | 返回当前程序版本及构建 Git Commit |
| `/` | GET | 内置可视化订阅生成 Web 页面 |

## 常用 URL 参数

完整列表见 [docs/url-params.md](docs/url-params.md)，常用参数如下：

| 参数 | 说明 |
|---|---|
| `target` | 输出目标：`clash` / `singbox` / `surge` / `shadowrocket` / `quanx` / `loon` / `v2ray` |
| `url` | 订阅链接，多个用 `\|` 分隔（必填）；也可直接粘贴节点链接（`vless://` 等） |
| `config` | 外部 INI 配置 URL 或本地路径 |
| `insert` | 是否合并服务端 `insert_url` 节点（覆盖配置默认） |
| `sort` | 按节点名排序 |
| `dedup` | 去除重复节点 |
| `fdn` | 过滤 Clash.Meta 不支持的节点（如废弃加密的 SS） |
| `list` | 仅输出节点列表（无分组 / 规则，**仅 clash**） |
| `append_type` | 节点名前追加 `[类型]` 前缀 |
| `tailscale` | 注入 Tailscale 直连规则（`100.64.0.0/10`, `fd7a:115c:a1e0::/48`） |
| `exclude_protocol` | 手动排除指定协议（多个用逗号或竖线分隔，如 `hy2,tuic`；别名 `exclude_protocols`） |
| `expand` | `false` 时输出 rule-providers 引用远程规则（**仅 clash**） |
| `emoji` `add_emoji` `remove_emoji` | emoji 增删（对齐 subconverter） |
| `udp` `tfo` `scv` | 节点特性开关（部分 target 支持） |
| `filename` `interval` | 下载文件名 / 客户端自动更新间隔 |
| `nocache` `flushcache` | 绕过 / 清空缓存 |
| `proxy` | 本次请求使用的上游代理 |

## 解决访问限制

部分机场需要走代理才能访问，或设置了 Cloudflare 盾。详见：
- **[docs/proxy.md](docs/proxy.md)** —— 配置上游代理与自定义 User-Agent
- **[docs/cloudflare.md](docs/cloudflare.md)** —— FlareSolverr 自动绕过 5 秒盾

## 服务端配置

服务端配置可参考 [`config.example.yaml`](config.example.yaml)，支持配置文件或通过环境变量设置：
- `SUBNG_LISTEN`：服务监听地址（默认 `:25500`）
- `SUBNG_PROXY`：全局上游代理
- `SUBNG_FLARESOLVERR_URL`：FlareSolverr 服务地址
- `SUBNG_USER_AGENT`：自定义网络请求 User-Agent
- `SUBNG_API_TOKEN`：API 访问控制凭证（`api_access_token`）

## 开发与编译

```bash
make test    # 运行测试与竞态检测
make vet     # 静态检查与 linter
make build   # 编译单二进制到 bin/
make run     # 本地开发运行
```

## License

[GPL-3.0-or-later](LICENSE) © Jungley8
