# Docker 部署

## 镜像

CI 会自动构建多架构（`linux/amd64` + `linux/arm64`）镜像并推送到 GHCR：

```
ghcr.io/jungley8/subconverter-ng:latest      # main 分支最新
ghcr.io/jungley8/subconverter-ng:v0.1.0       # 对应 tag
```

## 最简运行

不需要过 Cloudflare、机场可直连时：

```bash
docker run -d --name subconverter-ng \
  -p 25500:25500 \
  --restart unless-stopped \
  ghcr.io/jungley8/subconverter-ng:latest
```

访问 `http://<host>:25500/sub?target=clash&url=...`。

## 带 FlareSolverr 的完整部署（推荐）

仓库根目录的 `docker-compose.yml` 已内置 FlareSolverr sidecar，用来绕过机场的 Cloudflare 盾：

```bash
git clone https://github.com/Jungley8/subconverter-ng.git
cd subconverter-ng

# 如需上游代理，先导出环境变量（可选）
export SUBNG_PROXY=socks5://host.docker.internal:1080

docker compose up -d
```

`compose` 会拉起两个服务：

- `subconverter-ng` —— 监听 `:25500`，已注入 `SUBNG_FLARESOLVERR_URL`
- `flaresolverr` —— 仅内网暴露，供前者调用

详见 [绕过 Cloudflare](cloudflare.md)。

## 默认外部配置（省去每次传 `config=`）

服务端可固定一套外部 INI 规则配置（`custom_proxy_group` / `ruleset` 来源，远端 URL），`/sub` 请求省略 `&config=` 时自动使用；显式传 `&config=` 时仍以请求参数为准。

```bash
export SUBNG_DEFAULT_CONFIG_URL=https://raw.githubusercontent.com/you/clash-rule/main/config.init
docker compose up -d
```

或写进配置文件（见 `config.example.yaml` 的 `default_config_url`）。

注意：默认配置抓取失败时**请求直接报错**，不会静默回落到无规则输出——请保证该 URL 可达（启动日志的 `default config:` 行可核对是否生效，token 已脱敏）。

## 环境变量

| 变量 | 说明 | 示例 |
|---|---|---|
| `SUBNG_LISTEN` | 监听地址 | `:25500` |
| `SUBNG_PROXY` | 全局上游代理 | `socks5://127.0.0.1:1080` |
| `SUBNG_FLARESOLVERR_URL` | FlareSolverr 端点 | `http://flaresolverr:8191/v1` |
| `SUBNG_USER_AGENT` | 抓订阅的 UA | `clash-verge/v1.6.0` |
| `SUBNG_DEFAULT_CONFIG_URL` | 默认外部 INI 规则配置（远端 URL） | `https://raw.githubusercontent.com/.../config.ini` |

## 私有镜像拉取

GHCR 包默认私有。要么在仓库 Packages 设置里把镜像设为 **public**，要么先登录：

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u <你的用户名> --password-stdin
docker pull ghcr.io/jungley8/subconverter-ng:latest
```

## 启动输出

`serve` 启动时会打印版本号和**当前生效的配置摘要**，便于核对环境变量 / 配置文件是否被正确加载。敏感信息（代理密码、订阅 token）会自动脱敏，可安全用于日志：

```text
subconverter-ng v0.5.0
  listen:         :25500
  user-agent:     (built-in default)
  upstream proxy: socks5://user:***@127.0.0.1:1080
  flaresolverr:   http://flaresolverr:8191/v1
  fetch timeout:  30s
  fetch cache:    300s (default)
  rate limit:     30/min, burst 10
  insert urls:    1 (enabled, prepend)
    - https://air.com/***
  default config: https://raw.githubusercontent.com/you/clash-rule?token=***
listening on :25500
```

- 代理凭据只保留用户名，密码显示为 `***`。
- 订阅 / 插入链接只保留 `scheme://host`，路径与查询参数中的 token 一律隐藏为 `/***`。

## 健康检查

```bash
curl http://127.0.0.1:25500/version
# subconverter-ng v0.5.0
```
