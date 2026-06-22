# Web UI

subconverter-ng ships with a lightweight visual web UI, bundled into the binary via `go:embed` — no extra service or frontend build step required.

## Opening it

Once the service is running, visit the root path in your browser:

```
http://127.0.0.1:25500/
```

(The port depends on `--listen` / `SUBNG_LISTEN`, default `25500`.)

## Using it

1. **Subscription link**: paste your provider's subscription URL into the text box, one per line; multiple lines are automatically joined with `|`.
2. **External config (optional)**: enter the URL of an INI rules config (subconverter / ACL4SSR compatible).
3. **target**: choose the output format from the dropdown — `clash` (Clash.Meta / mihomo), `singbox`, `surge`, `shadowrocket`, `quanx`, `loon`, `v2ray`/`mixed`.
4. **Options**: tick `sort nodes`, `dedup nodes`, `force UDP`, `TCP Fast Open`, `skip cert verify`, `filter incompatible nodes`, `append type to name`, `allow emoji` as needed. These map to the [URL parameters](url-params.md) `sort` / `dedup` / `udp` / `tfo` / `scv` / `fdn` / `append_type` / `emoji`.
5. **Upstream proxy (optional)**: e.g. `socks5://127.0.0.1:1080`, applied to this request only, overriding the global config.
6. Click **Generate subscription link** and the full `/sub?...` link appears below.
7. Click **Copy** and paste the link into your Clash / mihomo client's "Config URL"; or click **Open / Preview** to view the converted result directly in a new tab.

## Notes

- The generated link is based on the current host (`window.location.origin`), so it works whether deployed locally or on a server.
- The page is fully self-contained: inline CSS / JS with no external CDN dependency, well suited to restricted networks such as mainland China.
- Dark mode is supported (follows the system `prefers-color-scheme`), and the layout is mobile-responsive.
- **Form caching**: the subscription link, target and options are automatically saved to the browser's `localStorage` and restored on refresh or next visit, so you never have to re-enter them. The data stays in your local browser only and is never uploaded; switching browsers or clearing browsing data resets it.
- The link's parameters mean the same as in [URL Parameters](url-params.md).
