# Web UI

subconverter-ng ships with a lightweight visual web UI, bundled into the binary via `go:embed` — no extra service or frontend build step required.

## Opening it

Once the service is running, visit the root path in your browser:

```
http://127.0.0.1:25500/
```

(The port depends on `--listen` / `SUBNG_LISTEN`, default `25500`.)

## Using it

1. **Subscription link**: paste provider URLs one per line; multiple lines are joined with `|`.
2. **External config (optional)**: enter a subconverter-compatible INI rules URL.
3. **Generate token**: select an expiry and generate; the new token fills the Access token field and its effective expiry is displayed. Every click creates an independent token.
4. **Access token**: an existing token can also be pasted directly.
5. **target**: choose the output format; expiry replacement is primarily intended for `clash`.
6. **Options and proxy**: configure node processing as needed; managed links omit the original source, config, and proxy.
7. Click **Generate subscription link**; only then is the complete `/sub?...` link shown.
8. Click **Copy** and paste the link into the Clash / mihomo Config URL field.

To create a temporary managed subscription, enter the source URL and expiry, then click **Generate token**. Every click creates a new 64-character random token with its own current source, config, and expiry, then displays an hourly-refreshing link. After expiry, a Clash refresh receives a node-free replacement. Temporary tokens are stored in memory and disappear after a service restart.

## Notes

- The generated link is based on the current host (`window.location.origin`), so it works whether deployed locally or on a server.
- The page is fully self-contained: inline CSS / JS with no external CDN dependency, well suited to restricted networks such as mainland China.
- Dark mode is supported (follows the system `prefers-color-scheme`), and the layout is mobile-responsive.
- **Form caching**: the subscription link, target and options are automatically saved to the browser's `localStorage` and restored on refresh or next visit, so you never have to re-enter them. The data stays in your local browser only and is never uploaded; switching browsers or clearing browsing data resets it.
- **Temporary creation endpoint**: `POST /access/create` currently has no administrator authentication and is protected only by per-IP rate limiting. Any visitor can create temporary tokens on a public deployment.
- The link's parameters mean the same as in [URL Parameters](url-params.md).
