# Web UI

subconverter-ng ships with a lightweight visual web UI, bundled into the binary via `go:embed` — no extra service or frontend build step required.

## Opening it

Once the service is running, visit the root path in your browser:

```
http://127.0.0.1:25500/
```

(The port depends on `--listen` / `SUBNG_LISTEN`, default `25500`.)

## Features

The web interface offers dual modes: **Subscription Converter** and **My Subscriptions**:

### 1. Subscription Converter (⚡)

1. **Subscription link**: paste your provider's subscription URL into the text box, one per line; multiple lines are automatically joined with `|`. You can also click "Import from library" to quickly load saved subscriptions, or "Save to library" to bookmark the current link.
2. **External config (optional)**: enter the URL of an INI rules config (subconverter / ACL4SSR compatible).
3. **target**: choose the output format from the dropdown — `clash` (Clash.Meta / mihomo), `singbox`, `surge`, `shadowrocket`, `quanx`, `loon`, `v2ray`/`mixed`.
4. **Options**: tick `sort nodes`, `dedup nodes`, `force UDP`, `TCP Fast Open`, `skip cert verify`, `filter incompatible nodes`, `append type to name`, `Tailscale DIRECT`, `allow emoji` as needed. These map to the [URL parameters](url-params.md) `sort` / `dedup` / `udp` / `tfo` / `scv` / `fdn` / `append_type` / `tailscale` / `emoji`.
5. **Upstream proxy (optional)**: e.g. `socks5://127.0.0.1:1080`, applied to this request only, overriding the global config.
6. Click **Generate subscription link** and the full `/sub?...` link appears below.
7. Click **Copy** and paste the link into your Clash / mihomo client's "Config URL"; or click **Open / Preview** to view the converted result directly in a new tab.

### 2. My Subscriptions (📋 Centralized Management)

A local management panel for users managing multiple subscriptions, private nodes, or dedicated lines:

1. **Metadata Recording** (all fields optional):
   - **Name / Label**: e.g., "Primary Airport", "Backup IPLC".
   - **Subscription or node URL**: HTTP(S) subscriptions or single node share links (vless/vmess/ss).
   - **Official Website**: direct link opening in a new tab (`noopener noreferrer`) for quick renewals.
   - **Expiration Date**: automatically counts down remaining days; alerts with yellow when within 7 days, and red when expired.
   - **Traffic Reset Day**: set a fixed day of the month (1st–31st) or a custom reset rule.
   - **Cost & Billing Cycle**: record expense, currency, and cycle (monthly, quarterly, semi-annually, annually, two-year, one-time lifetime, etc.).
   - **Notes**: keep track of registered email accounts, package tiers, or promo codes.
2. **Monthly Expense Estimation**: the header dashboard aggregates costs and calculates your estimated monthly network expense.
3. **Batch Conversion**: toggle subscriptions on or off; convert multiple checked subscriptions in one click.
4. **Backup & Restore**:
   - Export and download a JSON backup file or copy it to the clipboard.
   - Import from JSON files or text with options to "Merge (dedup by URL)" or "Overwrite all", safeguarding against browser cache clears.

## Notes

- The generated link is based on the current host (`window.location.origin`), so it works whether deployed locally or on a server.
- The page is fully self-contained: inline CSS / JS with no external CDN dependency, well suited to restricted networks such as mainland China.
- Dark mode is supported (follows the system `prefers-color-scheme`), and the layout is mobile-responsive.
- **Local Storage & Privacy**: form settings and subscription library items stay in your browser's `localStorage` only; no data is ever sent to or stored on the server.
- The link's parameters mean the same as in [URL Parameters](url-params.md).
