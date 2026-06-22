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

## Startup output

On `serve` startup the program prints the version and a **summary of the
effective config**, so you can confirm your env vars / config file were loaded
correctly. Secrets (proxy passwords, subscription tokens) are redacted, so the
output is safe to keep in logs:

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
listening on :25500
```

- Proxy credentials keep only the username; the password shows as `***`.
- Subscription / insert links keep only `scheme://host`; any token in the path or query is hidden as `/***`.

## Health check

```bash
curl http://127.0.0.1:25500/version
# subconverter-ng v0.5.0
```
