# 绕过 Cloudflare 5 秒盾（FlareSolverr）

部分机场的订阅接口套了 Cloudflare 的 JS 质询（页面显示 `Just a moment...` / `Attention Required`）。普通 HTTP 请求拿不到节点，只会拿到一段质询 HTML。

`subconverter-ng` 通过开源项目 **[FlareSolverr](https://github.com/FlareSolverr/FlareSolverr)** 解决：它用无头 Chrome 过掉 JS 质询，拿到 `cf_clearance` Cookie，本工具再带着这个 Cookie + 相同 User-Agent 重放请求拿到真正的订阅内容。

> **GPL-3.0 兼容性**：FlareSolverr 以独立服务（单独进程 / 容器）运行，仅通过 HTTP API 调用，不与本项目链接为同一程序，二者协议互不影响。

## 工作流程

```
请求订阅 ──► 直连/上游代理 ──► 检测到 CF 质询?
                                    │ 否 ──► 返回内容
                                    │ 是
                                    ▼
                         FlareSolverr 过盾 ──► 取 cf_clearance + UA
                                    ▼
                  带 Cookie+UA 经同一出口重放 ──► 返回真正订阅
```

关键点：`cf_clearance` 与 **出口 IP** 和 **User-Agent** 绑定。所以本工具会把配置的上游代理一并转发给 FlareSolverr，保证过盾和重放走同一出口，否则 Cookie 失效。

## 启用方式

### Docker Compose（推荐）

`docker-compose.yml` 已内置 `flaresolverr` sidecar，直接：

```bash
docker compose up -d
```

`SUBNG_FLARESOLVERR_URL=http://flaresolverr:8191/v1` 已自动注入，开箱即用。

### 二进制 / 手动

先单独跑一个 FlareSolverr：

```bash
docker run -d --name flaresolverr -p 8191:8191 \
  ghcr.io/flaresolverr/flaresolverr:latest
```

然后让 subconverter-ng 指向它：

```bash
# serve 模式：通过环境变量或 config.yaml
export SUBNG_FLARESOLVERR_URL=http://127.0.0.1:8191/v1
subconverter-ng serve

# convert 模式：通过命令行参数
subconverter-ng convert --url '<订阅>' \
  --flaresolverr http://127.0.0.1:8191/v1
```

## 排错

- **仍然过不去**：CF 质询等级较高（Turnstile/交互式）时 FlareSolverr 也可能失败，多重试或换出口 IP。
- **过盾成功但订阅为空**：确认 `User-Agent` 是机场认可的（很多机场只对 `clash` / `mihomo` UA 下发节点），见 [proxy.md](proxy.md)。
- **FlareSolverr 占用内存高**：它常驻一个 Chrome 实例，属正常现象；空闲时可设置 `BROWSER_TIMEOUT` 缩短会话。
