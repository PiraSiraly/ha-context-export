"""Constants for HA Context Export."""

from typing import Final

from homeassistant.const import Platform

DOMAIN: Final = "ha_context_export"
PLATFORMS: Final = [Platform.BUTTON]

SERVICE_CREATE: Final = "create"
DOWNLOAD_URL: Final = "/api/ha_context_export/download"
DOWNLOAD_TOKEN_TTL_SECONDS: Final = 60 * 60
DATA_LATEST_EXPORT: Final = "latest_export"
EXPORT_DIR_NAME: Final = "ha_context_export"

SENSITIVE_KEY_PARTS: Final = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "client_secret",
    "refresh_token",
    "access_token",
    "authorization",
    "credential",
    "webhook",
    "latitude",
    "longitude",
    "gps_accuracy",
    "address",
    "ip_address",
    "hostname",
    "host",
    "mac",
)

SAFE_STATE_ATTRIBUTE_KEYS: Final = {
    "friendly_name",
    "device_class",
    "unit_of_measurement",
    "state_class",
    "icon",
    "supported_features",
}

HELPER_DOMAINS: Final = {
    "combine",
    "counter",
    "derivative",
    "filter",
    "group",
    "history_stats",
    "input_boolean",
    "input_button",
    "input_datetime",
    "input_number",
    "input_select",
    "input_text",
    "integration",
    "min_max",
    "random",
    "schedule",
    "statistics",
    "template",
    "threshold",
    "timer",
    "tod",
    "trend",
    "utility_meter",
}

SAFE_STORAGE_EXACT: Final = {
    "lovelace",
    "lovelace_dashboards",
    "lovelace_resources",
}

EXCLUDED_YAML_FILENAMES: Final = {
    "secrets.yaml",
    "known_devices.yaml",
}

EXCLUDED_YAML_DIRS: Final = {
    ".cloud",
    ".git",
    ".storage",
    "backups",
    "custom_components",
    "deps",
    "media",
    "tts",
    "www",
}
