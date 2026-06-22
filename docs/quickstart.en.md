# Quick Start

`subconverter-ng` is a single binary that can either run an HTTP service (compatible with the subconverter API) or perform a one-shot CLI conversion.

## Option 1: HTTP service

```bash
# Binary
subconverter-ng serve --listen :25500

# Or Docker
docker run -d -p 25500:25500 ghcr.io/jungley8/subconverter-ng:latest
```

Then access it exactly as you would subconverter (remember to URL-encode `url` / `config`):

```
http://127.0.0.1:25500/sub?target=clash&url=<URL-encoded subscription>&config=<URL-encoded rules>
```

Paste that address into the subscription field of Clash.Meta / mihomo / clash-verge.

!!! example "Full example"
    ```
    http://127.0.0.1:25500/sub?target=clash
      &url=https%3A%2F%2Fyour-airport.com%2Fapi%2Fv1%2Fclient%2Fsubscribe%3Ftoken%3Dxxx
      &config=https%3A%2F%2Fgithub.com%2Fyou%2Fclash-rule%2Fraw%2Fmain%2Fconfig.init
    ```

For all supported parameters, see [URL Parameters](url-params.md).

## Option 2: one-shot CLI conversion

Handy for generating a config file locally or inside a script:

```bash
subconverter-ng convert \
  --url 'https://your-airport.com/api/v1/client/subscribe?token=xxx' \
  --config 'https://github.com/you/clash-rule/raw/main/config.init' \
  -o clash.yaml
```

Common flags:

| Flag | Description |
|---|---|
| `--url` | Subscription link; separate multiple with `\|` (required) |
| `--config` | subconverter external INI config URL |
| `-o` | Output file (defaults to stdout) |
| `--proxy` | Upstream proxy, `http://` or `socks5://` |
| `--flaresolverr` | FlareSolverr endpoint (passes the CF challenge) |
| `--ua` | Custom User-Agent |
| `--sort` `--udp` `--tfo` `--scv` | Node-processing toggles |
| `--dedup` | Remove duplicate nodes |
| `--fdn` | Filter out nodes Clash.Meta doesn't support |
| `--list` | Output the node list only |
| `--append-type` | Prefix node names with `[type]` |
| `--expand` | `=false` emits rule-providers instead |
| `--emoji` `--add-emoji` `--remove-emoji` | Add/remove emoji |

## External config (`config`)

`subconverter-ng` parses subconverter's INI external config, is compatible with the mainstream **ACL4SSR** rules, and supports:

- `ruleset=` — remote rule lists, plus inline rules like `[]GEOIP,CN` and `[]FINAL`
- `custom_proxy_group=` — backtick-separated groups (`select` / `url-test` / regex filters / `[]` group references)
- `exclude_remarks=` / `include_remarks=` — node-name filtering
- `enable_rule_generator` / `overwrite_original_rules`
- `clash_rule_base=` — custom Clash base template

You can reuse your existing `config.init` as-is, no changes needed.

## Next steps

- Provider unreachable → [Upstream Proxy & UA](proxy.md)
- Provider behind Cloudflare → [Bypass Cloudflare](cloudflare.md)
- Production deployment → [Docker Deployment](docker.md)
