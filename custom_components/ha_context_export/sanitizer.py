"""Additional sanitization hardening for HA Context Export."""

from __future__ import annotations

import json
import re
from types import ModuleType
from typing import Any

_REDACTED = "<REDACTED>"

_SENSITIVE_EXACT_KEYS = {
    "chat_id",
    "ext_pan_id",
    "network_key",
    "pan_id",
    "ssid",
    "user",
    "username",
}

_HELPER_STORAGE_NAMES = {
    "counter",
    "group",
    "input_boolean",
    "input_button",
    "input_datetime",
    "input_number",
    "input_select",
    "input_text",
    "schedule",
    "timer",
    "utility_meter",
}

_EMAIL_RE = re.compile(
    r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
)
_MAC_RE = re.compile(
    r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b"
)
_PRIVATE_IPV4_RE = re.compile(
    r"\b(?:"
    r"10[.-](?:\d{1,3}[.-]){2}\d{1,3}|"
    r"192[.-]168[.-]\d{1,3}[.-]\d{1,3}|"
    r"172[.-](?:1[6-9]|2\d|3[01])[.-]\d{1,3}[.-]\d{1,3}"
    r")\b"
)

_YAML_ASSIGNMENT_RE = re.compile(
    r"^(?P<indent>\s*)(?P<prefix>-\s+)?"
    r"(?P<key>[A-Za-z0-9_. -]+?)\s*:\s*"
    r"(?P<value>.*?)(?P<comment>\s+#.*)?$"
)

_BLOCK_SCALARS = {"|", ">", "|-", ">-", "|+", ">+"}


def _normalize_key(key: str) -> str:
    """Normalize YAML/JSON keys for exact sensitivity checks."""
    return key.lower().replace("-", "_").replace(" ", "_")


def _redact_key_recursively(value: Any, key_to_redact: str) -> Any:
    """Redact one exact key recursively in a JSON-like object."""
    if isinstance(value, dict):
        return {
            key: (
                _REDACTED
                if _normalize_key(str(key)) == key_to_redact
                else _redact_key_recursively(item, key_to_redact)
            )
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [_redact_key_recursively(item, key_to_redact) for item in value]

    return value


def install_export_sanitizers(exporter: ModuleType) -> None:
    """Install hardened sanitizers and safe helper-storage export hooks."""
    original_is_sensitive_key = exporter._is_sensitive_key
    original_sanitize_string = exporter._sanitize_string
    original_build_export_files = exporter._build_export_files

    def is_sensitive_key(key: str) -> bool:
        normalized = _normalize_key(key)
        return (
            normalized in _SENSITIVE_EXACT_KEYS
            or original_is_sensitive_key(key)
        )

    def sanitize_string(value: str) -> str:
        value = original_sanitize_string(value)
        value = _EMAIL_RE.sub(_REDACTED, value)
        value = _MAC_RE.sub(_REDACTED, value)
        return _PRIVATE_IPV4_RE.sub(_REDACTED, value)

    def sanitize_yaml_text(text: str) -> str:
        """Redact scalar and nested-block YAML secrets safely.

        A line-oriented replacement is not sufficient for YAML such as:

            network_key:
              - 1
              - 2

        When a sensitive key starts a nested mapping/list or block scalar, the
        complete indented block is discarded and replaced by one REDACTED value.
        """
        output: list[str] = []
        redact_child_indent: int | None = None

        for line in text.splitlines():
            if redact_child_indent is not None:
                if not line.strip():
                    continue

                indentation = len(line) - len(line.lstrip(" "))
                if indentation > redact_child_indent:
                    continue

                redact_child_indent = None

            match = _YAML_ASSIGNMENT_RE.match(line)
            if match and is_sensitive_key(match.group("key").strip()):
                raw_value = (match.group("value") or "").strip()

                # !secret contains a reference name only. The secret value lives
                # in secrets.yaml, which is never exported.
                if raw_value.startswith("!secret"):
                    output.append(line)
                    continue

                prefix = match.group("prefix") or ""
                comment = match.group("comment") or ""
                key = match.group("key").strip()
                output.append(
                    f"{match.group('indent')}{prefix}{key}: {_REDACTED}{comment}"
                )

                if not raw_value or raw_value in _BLOCK_SCALARS:
                    redact_child_indent = len(match.group("indent"))

                continue

            output.append(sanitize_string(line))

        return "\n".join(output) + ("\n" if text.endswith("\n") else "")

    def build_export_files(config_dir, staging_dir, snapshot):
        """Extend the regular export with sanitized UI-helper definitions."""
        details = original_build_export_files(config_dir, staging_dir, snapshot)
        storage_dir = config_dir / ".storage"
        copied: list[str] = []

        if storage_dir.is_dir():
            for name in sorted(_HELPER_STORAGE_NAMES):
                source = storage_dir / name
                if not source.is_file():
                    continue

                try:
                    raw = json.loads(source.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError, UnicodeError):
                    continue

                # input_text can contain an arbitrary configured initial value.
                # Keep its structure but never export that value.
                if name == "input_text":
                    raw = _redact_key_recursively(raw, "initial")

                exporter._write_json(
                    staging_dir / "helpers" / "storage" / f"{name}.json",
                    raw,
                )
                copied.append(name)

        report_path = staging_dir / "SECURITY_REPORT.json"
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeError):
            report = {}

        report["helper_storage_files_copied"] = copied
        report.setdefault("sanitization", []).extend(
            [
                "Sensitive nested YAML mappings/lists are replaced as a complete block.",
                "Email addresses are replaced with <REDACTED>.",
                "Chat IDs, Zigbee network identifiers/keys, SSIDs and usernames are redacted.",
                "MAC addresses and private IPv4 addresses embedded in labels/names are redacted.",
                "input_text initial values are never exported from helper storage.",
            ]
        )
        exporter._write_json(report_path, report)

        details["helper_storage"] = copied
        return details

    exporter._is_sensitive_key = is_sensitive_key
    exporter._sanitize_string = sanitize_string
    exporter._sanitize_yaml_text = sanitize_yaml_text
    exporter._build_export_files = build_export_files
