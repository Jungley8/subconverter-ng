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

## 环境变量

| 变量 | 说明 | 示例 |
|---|---|---|
| `SUBNG_LISTEN` | 监听地址 | `:25500` |
| `SUBNG_PROXY` | 全局上游代理 | `socks5://127.0.0.1:1080` |
| `SUBNG_FLARESOLVERR_URL` | FlareSolverr 端点 | `http://flaresolverr:8191/v1` |
| `SUBNG_USER_AGENT` | 抓订阅的 UA | `clash-verge/v1.6.0` |

## 私有镜像拉取

GHCR 包默认私有。要么在仓库 Packages 设置里把镜像设为 **public**，要么先登录：

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u <你的用户名> --password-stdin
docker pull ghcr.io/jungley8/subconverter-ng:latest
```

## 健康检查

```bash
curl http://127.0.0.1:25500/version
# subconverter-ng v0.4.0
```
