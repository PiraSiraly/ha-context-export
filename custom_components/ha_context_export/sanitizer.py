"""Additional sanitization hardening for HA Context Export."""

from __future__ import annotations

import re
from types import ModuleType

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

_EMAIL_RE = re.compile(
    r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"
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


def install_export_sanitizers(exporter: ModuleType) -> None:
    """Install hardened sanitizers into the exporter module.

    The exporter deliberately keeps its collection code independent from these
    additional privacy rules. Installing here also lets older exports remain
    readable while tightening future snapshots without touching registry logic.
    """
    original_is_sensitive_key = exporter._is_sensitive_key
    original_sanitize_string = exporter._sanitize_string

    def is_sensitive_key(key: str) -> bool:
        normalized = _normalize_key(key)
        return (
            normalized in _SENSITIVE_EXACT_KEYS
            or original_is_sensitive_key(key)
        )

    def sanitize_string(value: str) -> str:
        value = original_sanitize_string(value)
        return _EMAIL_RE.sub(_REDACTED, value)

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

    exporter._is_sensitive_key = is_sensitive_key
    exporter._sanitize_string = sanitize_string
    exporter._sanitize_yaml_text = sanitize_yaml_text
