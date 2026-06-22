# Docker Deployment

## Images

CI automatically builds multi-arch (`linux/amd64` + `linux/arm64`) images and pushes them to GHCR:

```
ghcr.io/jungley8/subconverter-ng:latest      # latest on the main branch
ghcr.io/jungley8/subconverter-ng:v0.1.0       # the corresponding tag
```

## Minimal run

When you don't need the Cloudflare bypass and the provider is directly reachable:

```bash
docker run -d --name subconverter-ng \
  -p 25500:25500 \
  --restart unless-stopped \
  ghcr.io/jungley8/subconverter-ng:latest
```

Visit `http://<host>:25500/sub?target=clash&url=...`.

## Full deployment with FlareSolverr (recommended)

The `docker-compose.yml` at the repo root already bundles a FlareSolverr sidecar to bypass providers' Cloudflare challenges:

```bash
git clone https://github.com/Jungley8/subconverter-ng.git
cd subconverter-ng

# Export an upstream proxy first if needed (optional)
export SUBNG_PROXY=socks5://host.docker.internal:1080

docker compose up -d
```

`compose` brings up two services:

- `subconverter-ng` — listens on `:25500`, with `SUBNG_FLARESOLVERR_URL` injected
- `flaresolverr` — exposed on the internal network only, for the former to call

See [Bypass Cloudflare](cloudflare.md) for details.

## Environment variables

| Variable | Description | Example |
|---|---|---|
| `SUBNG_LISTEN` | Listen address | `:25500` |
| `SUBNG_PROXY` | Global upstream proxy | `socks5://127.0.0.1:1080` |
| `SUBNG_FLARESOLVERR_URL` | FlareSolverr endpoint | `http://flaresolverr:8191/v1` |
| `SUBNG_USER_AGENT` | UA used when fetching subscriptions | `clash-verge/v1.6.0` |

## Pulling a private image

GHCR packages are private by default. Either set the image to **public** in the repo's Packages settings, or log in first:

```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u <your-username> --password-stdin
docker pull ghcr.io/jungley8/subconverter-ng:latest
```

## Health check

```bash
curl http://127.0.0.1:25500/version
# subconverter-ng v0.4.0
```
