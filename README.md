# HA Context Export

**HA Context Export** is a Home Assistant custom integration that creates a sanitized snapshot of your Home Assistant configuration for technical analysis, documentation, and AI-assisted troubleshooting.

It is **not a backup** and is not intended for restoration.

## What it exports

- Entity registry metadata
- Device metadata
- Areas
- Helper configuration where safely available
- YAML configuration files (sanitized)
- Lovelace dashboards and resources
- Installed custom integration metadata

## What it deliberately excludes

- `secrets.yaml`
- Home Assistant authentication data
- Raw `core.config_entries`
- Databases, logs, media, and backups
- Entity unique IDs
- Device MAC/network identifiers and serial numbers
- Current entity state values
- Precise GPS/location data

Sensitive-looking keys and common token formats are redacted on a best-effort basis before the export is written.

## Installation with HACS

This repository can be added to HACS as a **Custom repository** of type **Integration**.

1. Open HACS.
2. Open the menu in the top-right corner.
3. Choose **Custom repositories**.
4. Add this repository URL and select **Integration**.
5. Download **HA Context Export**.
6. Restart Home Assistant.
7. Go to **Settings → Devices & services → Add integration**.
8. Search for **HA Context Export** and add it.

## One-click dashboard download

The integration automatically loads its Lovelace card; no separate frontend repository or Lovelace resource is required.

After installing or updating the integration and restarting Home Assistant:

1. Edit a dashboard.
2. Choose **Add card**.
3. Select **HA Context Export**.
4. Press **Export erstellen & herunterladen**.

The card creates a fresh sanitized export through an authenticated Home Assistant API call and then starts a real browser download. It deliberately avoids Home Assistant markdown links and SPA routing, which can swallow ordinary download-link clicks.

If the card picker does not list the card, it can also be added manually:

```yaml
type: custom:ha-context-export-card
```

## Other usage

Home Assistant also exposes an **Export context** button entity / `ha_context_export.create` action. Those create an export and show fallback download links in a persistent Home Assistant notification.

The ZIP stays on the Home Assistant instance until it is replaced by a newer export.

## Security model

The ZIP is stored below Home Assistant's private `.storage` directory and is never placed in `/config/www`.

The dashboard card itself talks to an authenticated, administrator-only API endpoint. Once an export has been generated, HA Context Export creates a cryptographically random short-lived capability URL for the binary download. The token:

- is returned only to the authenticated frontend or embedded in a fallback notification link,
- expires after 60 minutes,
- is replaced whenever a new export is created,
- is checked with constant-time comparison before the ZIP is served.

Requests without the current valid token cannot download the export. The response is marked `no-store` and uses a `no-referrer` policy.

Automatic sanitization cannot prove that arbitrary user-authored text contains no sensitive information. Review an export before sharing it outside your own trusted workflow.

## License

MIT
