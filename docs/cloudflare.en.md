# Bypass the Cloudflare 5-second challenge (FlareSolverr)

Some providers put their subscription endpoint behind Cloudflare's JS challenge (the page shows `Just a moment...` / `Attention Required`). A plain HTTP request never gets the nodes — only the challenge HTML.

`subconverter-ng` solves this via the open-source project **[FlareSolverr](https://github.com/FlareSolverr/FlareSolverr)**: it uses headless Chrome to pass the JS challenge and obtain the `cf_clearance` cookie, then the tool replays the request with that cookie plus the same User-Agent to fetch the real subscription content.

> **GPL-3.0 compatibility**: FlareSolverr runs as a standalone service (separate process / container), called only over its HTTP API. It is not linked into the same program as this project, so the two licenses don't affect each other.

## Workflow

```
Request subscription ──► direct/upstream proxy ──► CF challenge detected?
                                                      │ no ──► return content
                                                      │ yes
                                                      ▼
                                  FlareSolverr bypass ──► get cf_clearance + UA
                                                      ▼
                     Replay with cookie+UA via same egress ──► return real subscription
```

Key point: `cf_clearance` is bound to the **egress IP** and the **User-Agent**. So the tool forwards the configured upstream proxy to FlareSolverr as well, ensuring the bypass and the replay use the same egress — otherwise the cookie is invalid.

## How to enable

### Docker Compose (recommended)

`docker-compose.yml` already includes a `flaresolverr` sidecar, so just:

```bash
docker compose up -d
```

`SUBNG_FLARESOLVERR_URL=http://flaresolverr:8191/v1` is injected automatically — works out of the box.

### Binary / manual

First run a standalone FlareSolverr:

```bash
docker run -d --name flaresolverr -p 8191:8191 \
  ghcr.io/flaresolverr/flaresolverr:latest
```

Then point subconverter-ng at it:

```bash
# serve mode: via env var or config.yaml
export SUBNG_FLARESOLVERR_URL=http://127.0.0.1:8191/v1
subconverter-ng serve

# convert mode: via command-line flag
subconverter-ng convert --url '<subscription>' \
  --flaresolverr http://127.0.0.1:8191/v1
```

## Troubleshooting

- **Still can't get through**: when the CF challenge level is high (Turnstile/interactive), FlareSolverr can fail too — retry more or switch egress IP.
- **Bypass succeeds but the subscription is empty**: confirm the `User-Agent` is one the provider accepts (many only serve nodes to a `clash` / `mihomo` UA), see [proxy.md](proxy.md).
- **FlareSolverr uses a lot of memory**: it keeps a Chrome instance resident, which is normal; set `BROWSER_TIMEOUT` to shorten idle sessions.
