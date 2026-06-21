# 上游代理 与 User-Agent

抓取订阅时有两类常见障碍，本工具都在 `fetch` 层处理。

## 1. 必须走代理才能访问的机场

有些机场（或其订阅域名）在你部署 subconverter-ng 的服务器所在网络无法直连，需要先走一个代理出口。

配置上游代理的三种方式（优先级从高到低）：

| 方式 | 示例 | 作用范围 | 优先级 |
|---|---|---|---|
| URL 参数 `&proxy=` | `/sub?...&proxy=socks5://127.0.0.1:1080` | 仅本次请求 | 最高 |
| 环境变量 `SUBNG_PROXY` | `socks5://127.0.0.1:1080` | 全局默认 | 高 |
| 配置文件 `fetch.proxy` | 见 `config.example.yaml` | 全局默认 | 高 |
| 标准环境变量 `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` | `http://127.0.0.1:7890` | 全局默认 | 兜底 |

支持的代理协议：`http://`、`https://`、`socks5://`（可带账号密码：`socks5://user:pass@host:port`）。

!!! note "SUBNG_PROXY vs HTTP_PROXY"
    没有显式配置代理时，本工具会回退到标准的 `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`
    环境变量（大小写均可），和其它 Go 工具行为一致。

    **区别**：`SUBNG_PROXY`（及 `--proxy` / `&proxy=`）是本工具专用的，除了抓取请求外，还会
    **转发给 FlareSolverr** 保证过盾与重放走同一出口；而标准 `HTTP_PROXY` 只作用于抓取本身。
    若你既要走代理又要过 Cloudflare 盾，用 `SUBNG_PROXY`。

> 该上游代理同时用于：抓订阅、抓 `config=` 外部配置、抓 ruleset 规则列表，以及（若启用）转发给 FlareSolverr 过盾，确保出口一致。

## 2. User-Agent 决定机场是否下发节点

绝大多数机场面板会根据 `User-Agent` 返回不同内容：

- 带 `clash` / `mihomo` / `meta` 的 UA → 返回节点（base64 列表或直接 Clash YAML）
- 浏览器 UA → 可能返回网页 / 登录页 / 空内容

本工具默认发送 `clash.meta/1.18.0 mihomo/1.18.0`。如某机场需要特定 UA，可覆盖：

```bash
# 全局
export SUBNG_USER_AGENT="clash-verge/v1.6.0"
# 或 convert 模式
subconverter-ng convert --url '<订阅>' --ua "ClashforWindows/0.20.39"
```

## 排错

- **订阅解析出 0 个节点**：先确认 UA。用 `curl -A "<你的UA>" '<订阅>' | base64 -d | head` 看机场到底返回了什么。
- **连接超时**：机场需要代理却没配，或代理本身不通。先用 `--proxy` 在 convert 模式下手测。
- **返回的是 Clash YAML 而非 base64**：本工具会自动识别并直接提取其中的 `proxies`，无需额外配置。
