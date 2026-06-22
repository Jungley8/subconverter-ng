# Upstream Proxy & User-Agent

There are two common obstacles when fetching a subscription, both handled at the `fetch` layer.

## 1. Providers that require a proxy to reach

Some providers (or their subscription domains) can't be reached directly from the network where your
subconverter-ng server runs, and need to go out through a proxy first.

Three ways to configure the upstream proxy (highest to lowest priority):

| Method | Example | Scope | Priority |
|---|---|---|---|
| URL param `&proxy=` | `/sub?...&proxy=socks5://127.0.0.1:1080` | This request only | Highest |
| Env var `SUBNG_PROXY` | `socks5://127.0.0.1:1080` | Global default | High |
| Config file `fetch.proxy` | see `config.example.yaml` | Global default | High |
| Standard env vars `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` | `http://127.0.0.1:7890` | Global default | Fallback |

Supported proxy protocols: `http://`, `https://`, `socks5://` (with optional credentials: `socks5://user:pass@host:port`).

!!! note "SUBNG_PROXY vs HTTP_PROXY"
    When no proxy is explicitly configured, the tool falls back to the standard `HTTP_PROXY` / `HTTPS_PROXY` /
    `NO_PROXY` environment variables (any case), consistent with other Go tools.

    **The difference**: `SUBNG_PROXY` (and `--proxy` / `&proxy=`) is specific to this tool — besides the fetch
    requests, it is also **forwarded to FlareSolverr** so the challenge and the replay go out through the same
    egress; whereas standard `HTTP_PROXY` only affects the fetch itself. If you need both a proxy and the
    Cloudflare bypass, use `SUBNG_PROXY`.

> This upstream proxy is used for: fetching the subscription, fetching the `config=` external config, fetching the ruleset rule lists, and (if enabled) forwarding to FlareSolverr for the bypass — ensuring a consistent egress.

## 2. The User-Agent decides whether the provider serves nodes

Most provider panels return different content based on the `User-Agent`:

- A UA containing `clash` / `mihomo` / `meta` → returns nodes (base64 list or Clash YAML directly)
- A browser UA → may return a web page / login page / empty content

The tool sends `clash.meta/1.18.0 mihomo/1.18.0` by default. If a provider needs a specific UA, override it:

```bash
# Global
export SUBNG_USER_AGENT="clash-verge/v1.6.0"
# Or convert mode
subconverter-ng convert --url '<subscription>' --ua "ClashforWindows/0.20.39"
```

## Troubleshooting

- **Subscription parses to 0 nodes**: check the UA first. Run `curl -A "<your UA>" '<subscription>' | base64 -d | head` to see what the provider actually returns.
- **Connection timeout**: the provider needs a proxy that isn't configured, or the proxy itself is down. Test with `--proxy` in convert mode first.
- **It returns Clash YAML instead of base64**: the tool auto-detects this and extracts the `proxies` directly, no extra config needed.
