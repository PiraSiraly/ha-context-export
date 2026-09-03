"""Create sanitized Home Assistant context exports."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from datetime import date, datetime
from enum import Enum
from functools import partial
import json
import os
from pathlib import Path
import re
import shutil
from typing import Any
import zipfile

from homeassistant.const import __version__
from homeassistant.core import HomeAssistant
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from .const import (
    DATA_LATEST_EXPORT,
    DOMAIN,
    EXCLUDED_YAML_DIRS,
    EXCLUDED_YAML_FILENAMES,
    EXPORT_DIR_NAME,
    HELPER_DOMAINS,
    SAFE_STATE_ATTRIBUTE_KEYS,
    SAFE_STORAGE_EXACT,
    SENSITIVE_KEY_PARTS,
)

_REDACTED = "<REDACTED>"

_SECRET_LINE_RE = re.compile(
    r"""(?ix)
    ^
    (?P<indent>\s*)
    (?P<key>[^#:\n]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|
        private[_-]?key|client[_-]?secret|refresh[_-]?token|access[_-]?token|
        authorization|credential|webhook|latitude|longitude|gps[_-]?accuracy|
        address|ip[_-]?address|hostname|host|mac)[^:\n]*)
    \s*:\s*
    (?P<value>.+?)
    (?P<comment>\s+\#.*)?
    $
    """
)

_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}")
_JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)
_URL_SECRET_QUERY_RE = re.compile(
    r"""(?ix)
    ([?&](?:token|access_token|api_key|apikey|key|auth|signature|sig)=)
    ([^&#\s]+)
    """
)
_URL_USERINFO_RE = re.compile(
    r"(?i)(https?://)([^/@\s:]+):([^/@\s]+)@"
)
_TELEGRAM_TOKEN_RE = re.compile(r"\b\d{6,}:[A-Za-z0-9_-]{20,}\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")
_AGE_SECRET_RE = re.compile(r"\bAGE-SECRET-KEY-[A-Z0-9]+\b")
_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")
_DISCORD_TOKEN_RE = re.compile(
    r"\b(?:mfa\.[A-Za-z0-9_-]{20,}|"
    r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{20,})\b"
)


def _json_safe(value: Any) -> Any:
    """Convert values to JSON-safe forms without leaking arbitrary repr data."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, Enum):
        return _json_safe(value.value)

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    if isinstance(value, Path):
        return str(value)

    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}

    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_safe(item) for item in value]

    if is_dataclass(value):
        return _json_safe(asdict(value))

    return f"<{type(value).__name__}>"


def _is_sensitive_key(key: str) -> bool:
    """Return True when a key strongly suggests sensitive data."""
    normalized = key.lower().replace("-", "_").replace(" ", "_")
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def _sanitize_string(value: str) -> str:
    """Redact common inline credential formats from a useful string."""
    value = _BEARER_RE.sub("Bearer <REDACTED>", value)
    value = _JWT_RE.sub(_REDACTED, value)
    value = _URL_SECRET_QUERY_RE.sub(r"\1<REDACTED>", value)
    value = _URL_USERINFO_RE.sub(r"\1<REDACTED>:<REDACTED>@", value)
    value = _TELEGRAM_TOKEN_RE.sub(_REDACTED, value)
    value = _GITHUB_TOKEN_RE.sub(_REDACTED, value)
    value = _SLACK_TOKEN_RE.sub(_REDACTED, value)
    value = _AGE_SECRET_RE.sub(_REDACTED, value)
    value = _OPENAI_KEY_RE.sub(_REDACTED, value)
    value = _DISCORD_TOKEN_RE.sub(_REDACTED, value)
    return value


def _sanitize_obj(value: Any, key: str | None = None) -> Any:
    """Recursively sanitize a JSON-compatible object."""
    if key is not None and _is_sensitive_key(key):
        return _REDACTED

    if isinstance(value, dict):
        return {
            str(item_key): _sanitize_obj(item_value, str(item_key))
            for item_key, item_value in value.items()
        }

    if isinstance(value, (list, tuple, set, frozenset)):
        sanitized = [_sanitize_obj(item) for item in value]
        if isinstance(value, (set, frozenset)):
            return sorted(sanitized, key=str)
        return sanitized

    if isinstance(value, str):
        return _sanitize_string(value)

    return _json_safe(value)


def _sanitize_yaml_text(text: str) -> str:
    """Sanitize sensitive YAML assignments while preserving useful structure."""
    output: list[str] = []

    for line in text.splitlines():
        match = _SECRET_LINE_RE.match(line)
        if match:
            raw_value = match.group("value").strip()

            # A !secret reference contains only the reference name, not the secret.
            if raw_value.startswith("!secret"):
                output.append(line)
                continue

            comment = match.group("comment") or ""
            output.append(
                f"{match.group('indent')}{match.group('key').strip()}: "
                f"{_REDACTED}{comment}"
            )
            continue

        output.append(_sanitize_string(line))

    return "\n".join(output) + ("\n" if text.endswith("\n") else "")


def _safe_get(obj: Any, name: str, default: Any = None) -> Any:
    """Read an optional attribute across Home Assistant versions."""
    return getattr(obj, name, default)


def _collect_entity_registry(hass: HomeAssistant) -> list[dict[str, Any]]:
    """Collect entity registry metadata without entity unique IDs."""
    registry = er.async_get(hass)
    result: list[dict[str, Any]] = []

    for item in registry.entities.values():
        result.append(
            _sanitize_obj(
                {
                    "entity_id": item.entity_id,
                    "platform": _safe_get(item, "platform"),
                    "config_entry_id": _safe_get(item, "config_entry_id"),
                    "device_id": _safe_get(item, "device_id"),
                    "area_id": _safe_get(item, "area_id"),
                    "name": _safe_get(item, "name"),
                    "original_name": _safe_get(item, "original_name"),
                    "icon": _safe_get(item, "icon"),
                    "original_icon": _safe_get(item, "original_icon"),
                    "disabled_by": _safe_get(item, "disabled_by"),
                    "hidden_by": _safe_get(item, "hidden_by"),
                    "entity_category": _safe_get(item, "entity_category"),
                    "labels": _safe_get(item, "labels", set()),
                    "aliases": _safe_get(item, "aliases", set()),
                }
            )
        )

    return sorted(result, key=lambda row: row["entity_id"])


def _collect_runtime_metadata(hass: HomeAssistant) -> list[dict[str, Any]]:
    """Collect useful non-sensitive entity attributes, never current state values."""
    result: list[dict[str, Any]] = []

    for state in hass.states.async_all():
        attributes = {
            key: _json_safe(value)
            for key, value in state.attributes.items()
            if key in SAFE_STATE_ATTRIBUTE_KEYS
        }
        result.append(
            {
                "entity_id": state.entity_id,
                "attributes": _sanitize_obj(attributes),
            }
        )

    return sorted(result, key=lambda row: row["entity_id"])


def _collect_devices(hass: HomeAssistant) -> list[dict[str, Any]]:
    """Collect device metadata without identifiers, connections, or serial numbers."""
    registry = dr.async_get(hass)
    result: list[dict[str, Any]] = []

    for item in registry.devices.values():
        result.append(
            _sanitize_obj(
                {
                    "id": item.id,
                    "name": _safe_get(item, "name"),
                    "name_by_user": _safe_get(item, "name_by_user"),
                    "manufacturer": _safe_get(item, "manufacturer"),
                    "model": _safe_get(item, "model"),
                    "model_id": _safe_get(item, "model_id"),
                    "sw_version": _safe_get(item, "sw_version"),
                    "hw_version": _safe_get(item, "hw_version"),
                    "area_id": _safe_get(item, "area_id"),
                    "via_device_id": _safe_get(item, "via_device_id"),
                    "config_entries": _safe_get(item, "config_entries", set()),
                    "disabled_by": _safe_get(item, "disabled_by"),
                    "labels": _safe_get(item, "labels", set()),
                }
            )
        )

    return sorted(
        result,
        key=lambda row: (
            str(row.get("name_by_user") or row.get("name") or ""),
            str(row.get("id") or ""),
        ),
    )


def _collect_areas(hass: HomeAssistant) -> list[dict[str, Any]]:
    """Collect area registry metadata."""
    registry = ar.async_get(hass)
    result: list[dict[str, Any]] = []

    for item in registry.areas.values():
        result.append(
            _sanitize_obj(
                {
                    "id": item.id,
                    "name": item.name,
                    "icon": _safe_get(item, "icon"),
                    "aliases": _safe_get(item, "aliases", set()),
                    "labels": _safe_get(item, "labels", set()),
                    "floor_id": _safe_get(item, "floor_id"),
                }
            )
        )

    return sorted(result, key=lambda row: str(row.get("name") or ""))


def _collect_integrations(hass: HomeAssistant) -> list[dict[str, Any]]:
    """Collect configured integration metadata without config-entry credentials."""
    result: list[dict[str, Any]] = []

    for entry in hass.config_entries.async_entries():
        result.append(
            _sanitize_obj(
                {
                    "entry_id": entry.entry_id,
                    "domain": entry.domain,
                    "title": entry.title,
                    "source": entry.source,
                    "state": _safe_get(entry, "state"),
                    "disabled_by": _safe_get(entry, "disabled_by"),
                    "version": _safe_get(entry, "version"),
                    "minor_version": _safe_get(entry, "minor_version"),
                }
            )
        )

    return sorted(
        result,
        key=lambda row: (
            str(row.get("domain") or ""),
            str(row.get("title") or ""),
        ),
    )


def _collect_helpers(hass: HomeAssistant) -> dict[str, Any]:
    """Collect helper entities and sanitized helper config entries."""
    entity_registry = er.async_get(hass)
    relevant_entry_ids: set[str] = set()
    helper_entities: list[dict[str, Any]] = []

    for item in entity_registry.entities.values():
        platform = str(_safe_get(item, "platform") or "")
        entity_domain = item.entity_id.split(".", 1)[0]

        if platform not in HELPER_DOMAINS and entity_domain not in HELPER_DOMAINS:
            continue

        config_entry_id = _safe_get(item, "config_entry_id")
        if config_entry_id:
            relevant_entry_ids.add(config_entry_id)

        helper_entities.append(
            {
                "entity_id": item.entity_id,
                "platform": platform,
                "config_entry_id": config_entry_id,
                "name": _safe_get(item, "name"),
                "original_name": _safe_get(item, "original_name"),
            }
        )

    config_entries: list[dict[str, Any]] = []
    for entry in hass.config_entries.async_entries():
        if entry.entry_id not in relevant_entry_ids:
            continue

        config_entries.append(
            _sanitize_obj(
                {
                    "entry_id": entry.entry_id,
                    "domain": entry.domain,
                    "title": entry.title,
                    "data": _json_safe(dict(entry.data)),
                    "options": _json_safe(dict(entry.options)),
                    "disabled_by": _safe_get(entry, "disabled_by"),
                    "source": entry.source,
                }
            )
        )

    return {
        "entities": sorted(helper_entities, key=lambda row: row["entity_id"]),
        "config_entries": sorted(
            config_entries,
            key=lambda row: (
                str(row.get("domain") or ""),
                str(row.get("title") or ""),
            ),
        ),
    }


def _write_json(path: Path, data: Any) -> None:
    """Write formatted UTF-8 JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            _sanitize_obj(_json_safe(data)),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _copy_sanitized_yaml(source: Path, destination: Path) -> bool:
    """Copy one YAML file after best-effort sanitization."""
    if not source.is_file():
        return False

    text = source.read_text(encoding="utf-8", errors="replace")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(_sanitize_yaml_text(text), encoding="utf-8")
    return True


def _copy_user_yaml(config_dir: Path, export_dir: Path) -> list[str]:
    """Copy user YAML recursively while excluding unsafe/system directories."""
    copied: list[str] = []

    for source in sorted(config_dir.rglob("*.yaml")):
        relative = source.relative_to(config_dir)

        if source.name in EXCLUDED_YAML_FILENAMES:
            continue

        if any(part in EXCLUDED_YAML_DIRS for part in relative.parts[:-1]):
            continue

        destination = export_dir / "yaml" / relative
        if _copy_sanitized_yaml(source, destination):
            copied.append(str(relative))

    return copied


def _copy_lovelace_storage(config_dir: Path, export_dir: Path) -> list[str]:
    """Copy only sanitized Lovelace storage files."""
    storage_dir = config_dir / ".storage"
    copied: list[str] = []

    if not storage_dir.is_dir():
        return copied

    for source in storage_dir.iterdir():
        name = source.name
        allowed = name in SAFE_STORAGE_EXACT or name.startswith("lovelace.")

        if not allowed or not source.is_file():
            continue

        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeError):
            # Never fall back to copying raw .storage content.
            continue

        destination = export_dir / "dashboards" / f"{name}.json"
        _write_json(destination, raw)
        copied.append(name)

    return sorted(copied)


def _collect_custom_components(config_dir: Path) -> list[dict[str, Any]]:
    """List installed custom integrations using manifest metadata only."""
    base = config_dir / "custom_components"
    result: list[dict[str, Any]] = []

    if not base.is_dir():
        return result

    for manifest_path in base.glob("*/manifest.json"):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeError):
            continue

        result.append(
            _sanitize_obj(
                {
                    "domain": manifest_path.parent.name,
                    "name": manifest.get("name"),
                    "version": manifest.get("version"),
                    "documentation": manifest.get("documentation"),
                    "issue_tracker": manifest.get("issue_tracker"),
                }
            )
        )

    return sorted(result, key=lambda row: str(row.get("domain") or ""))


def _create_zip(source_dir: Path, zip_path: Path) -> None:
    """Create a ZIP and atomically replace the previous export."""
    temp_zip = zip_path.with_suffix(".tmp.zip")
    if temp_zip.exists():
        temp_zip.unlink()

    with zipfile.ZipFile(
        temp_zip,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
    ) as archive:
        for file_path in sorted(source_dir.rglob("*")):
            if not file_path.is_file():
                continue
            archive.write(file_path, arcname=file_path.relative_to(source_dir))

    os.replace(temp_zip, zip_path)


def _build_export_files(
    config_dir: Path,
    staging_dir: Path,
    snapshot: dict[str, Any],
) -> dict[str, Any]:
    """Write the collected data and sanitized configuration files."""
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    _write_json(staging_dir / "system" / "export_info.json", snapshot["export_info"])
    _write_json(staging_dir / "registries" / "entities.json", snapshot["entities"])
    _write_json(
        staging_dir / "registries" / "entity_runtime_metadata.json",
        snapshot["runtime_metadata"],
    )
    _write_json(staging_dir / "registries" / "devices.json", snapshot["devices"])
    _write_json(staging_dir / "registries" / "areas.json", snapshot["areas"])
    _write_json(staging_dir / "integrations" / "configured.json", snapshot["integrations"])
    _write_json(staging_dir / "helpers" / "helpers.json", snapshot["helpers"])
    _write_json(
        staging_dir / "custom_components" / "installed.json",
        snapshot["custom_components"],
    )

    yaml_copied = _copy_user_yaml(config_dir, staging_dir)
    dashboards_copied = _copy_lovelace_storage(config_dir, staging_dir)

    security_report = {
        "excluded": [
            ".storage/auth*",
            ".storage/core.config_entries raw data",
            ".storage/core.restore_state",
            ".storage/hacs* raw data",
            "secrets.yaml",
            "known_devices.yaml",
            "database files",
            "logs",
            "media",
            "backups",
            "device identifiers and network connections",
            "device serial numbers",
            "entity unique_ids",
            "current entity state values",
            "precise latitude/longitude/GPS attributes",
            "address/host/MAC-like keyed values",
        ],
        "sanitization": [
            "Sensitive JSON keys are recursively replaced with <REDACTED>.",
            "Common password/token/API-key YAML assignments are replaced with <REDACTED>.",
            "!secret references are preserved because the referenced value is not exported.",
            "Bearer/JWT-looking values and common provider token formats are redacted.",
            "Credentials embedded in HTTP(S) URL userinfo and common secret query parameters are redacted.",
        ],
        "yaml_files_copied": yaml_copied,
        "lovelace_storage_files_copied": dashboards_copied,
        "note": (
            "This is a best-effort analysis export, not a formal secret-scanning "
            "or backup product. Review the ZIP before sharing it outside your trusted workflow."
        ),
    }
    _write_json(staging_dir / "SECURITY_REPORT.json", security_report)

    readme = """\
HA Context Export

Purpose
-------
This ZIP is a sanitized Home Assistant snapshot intended for technical analysis,
documentation, troubleshooting, and AI-assisted Home Assistant work.
It is not a restorable Home Assistant backup.

Included
--------
- Entity registry metadata (without unique IDs)
- Selected non-sensitive runtime entity metadata (no current state values)
- Device metadata (without identifiers, connections, or serial numbers)
- Areas
- Configured integration metadata (without integration credentials)
- Helper-related configuration, sanitized
- User YAML files, recursively sanitized
- Lovelace dashboard/storage configuration, sanitized
- Installed custom integration manifest metadata
- Security report

Intentionally excluded
----------------------
- secrets.yaml
- authentication storage
- raw core.config_entries
- raw HACS storage
- databases, logs, media, backups
- precise GPS/location attributes
- entity unique IDs
- device MAC/network identifiers and serial numbers

Important
---------
Sanitization is deliberately conservative, but no automatic scrubber can prove
that arbitrary user-authored text contains no secret. SECURITY_REPORT.json
describes the applied rules.
"""
    (staging_dir / "README.txt").write_text(readme, encoding="utf-8")

    return {
        "yaml_files": yaml_copied,
        "dashboards": dashboards_copied,
    }


async def async_create_export(hass: HomeAssistant) -> dict[str, Any]:
    """Create the sanitized context ZIP and return metadata."""
    now = datetime.now().astimezone()
    timestamp = now.strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"ha-context-export-{timestamp}.zip"

    config_dir = Path(hass.config.config_dir)
    private_export_dir = config_dir / ".storage" / EXPORT_DIR_NAME
    staging_dir = private_export_dir / "staging"
    zip_path = private_export_dir / "latest.zip"

    entity_data = _collect_entity_registry(hass)
    runtime_metadata = _collect_runtime_metadata(hass)
    device_data = _collect_devices(hass)
    area_data = _collect_areas(hass)
    integration_data = _collect_integrations(hass)
    helper_data = _collect_helpers(hass)
    custom_components = await hass.async_add_executor_job(
        _collect_custom_components, config_dir
    )

    snapshot = {
        "export_info": {
            "generated_at": now.isoformat(),
            "home_assistant_version": __version__,
            "time_zone": hass.config.time_zone,
            "country": hass.config.country,
            "currency": hass.config.currency,
            "entity_count": len(entity_data),
            "device_count": len(device_data),
            "area_count": len(area_data),
            "integration_count": len(integration_data),
            "purpose": "Sanitized Home Assistant context snapshot",
            "format_version": 1,
        },
        "entities": entity_data,
        "runtime_metadata": runtime_metadata,
        "devices": device_data,
        "areas": area_data,
        "integrations": integration_data,
        "helpers": helper_data,
        "custom_components": custom_components,
    }

    await hass.async_add_executor_job(
        partial(private_export_dir.mkdir, parents=True, exist_ok=True)
    )

    details = await hass.async_add_executor_job(
        _build_export_files,
        config_dir,
        staging_dir,
        snapshot,
    )

    await hass.async_add_executor_job(_create_zip, staging_dir, zip_path)
    await hass.async_add_executor_job(
        partial(shutil.rmtree, staging_dir, ignore_errors=True)
    )

    hass.data.setdefault(DOMAIN, {})[DATA_LATEST_EXPORT] = {
        "path": str(zip_path),
        "filename": filename,
        "generated_at": now.isoformat(),
    }

    return {
        "path": str(zip_path),
        "filename": filename,
        "generated_at": now.isoformat(),
        **details,
    }
