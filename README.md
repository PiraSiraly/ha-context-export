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

## Usage

After setup, Home Assistant exposes an **Export context** button. Pressing it creates a sanitized ZIP snapshot and a persistent Home Assistant notification containing a private download link.

The ZIP stays on the Home Assistant instance until it is replaced by a newer export.

## Security model

The ZIP is stored below Home Assistant's private `.storage` directory and is never placed in `/config/www`.

Direct browser navigation to authenticated Home Assistant API endpoints does not automatically carry the frontend Bearer token. To allow a download link in a Home Assistant notification to work reliably, HA Context Export therefore creates a cryptographically random capability token for each export. The token:

- is embedded only in the private download link,
- expires after 60 minutes,
- is replaced whenever a new export is created,
- is checked with constant-time comparison before the ZIP is served.

Requests without the current valid token cannot download the export. The response is also marked `no-store` and uses a `no-referrer` policy.

Automatic sanitization cannot prove that arbitrary user-authored text contains no sensitive information. Review an export before sharing it outside your own trusted workflow.

## License

MIT
