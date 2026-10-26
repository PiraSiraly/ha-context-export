"""Regression coverage for sanitized YAML block shapes (synthetic data only)."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
import unittest


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "custom_components"
    / "ha_context_export"
    / "sanitizer.py"
)


class SanitizerYamlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        spec = importlib.util.spec_from_file_location("ha_export_sanitizer_tests", MODULE_PATH)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        exporter = ModuleType("stub_exporter")
        exporter._is_sensitive_key = lambda key: key.lower() in {"password", "token"}
        exporter._sanitize_string = lambda value: value
        exporter._build_export_files = lambda *_args, **_kwargs: {}
        module.install_export_sanitizers(exporter)
        cls.sanitize = staticmethod(exporter._sanitize_yaml_text)

    def test_indentless_chat_id_sequence_is_fully_redacted(self) -> None:
        source = (
            "data:\n"
            "  chat_id:\n"
            "  - 111111111\n"
            "  - 222222222\n"
            "  parse_mode: html\n"
        )
        result = self.sanitize(source)
        self.assertEqual(
            result,
            "data:\n  chat_id: <REDACTED>\n  parse_mode: html\n",
        )
        self.assertNotIn("111111111", result)
        self.assertNotIn("222222222", result)

    def test_nested_sensitive_list_redacts_entire_block(self) -> None:
        source = (
            "network_key:\n"
            "  - 10\n"
            "  - 20\n"
            "wifi_channel: 15\n"
        )
        self.assertEqual(
            self.sanitize(source),
            "network_key: <REDACTED>\nwifi_channel: 15\n",
        )

    def test_dash_prefixed_secret_key_stops_at_sibling_item(self) -> None:
        source = (
            "actions:\n"
            "  - chat_id:\n"
            "    - 111111111\n"
            "    - 222222222\n"
            "  - action: notify.test\n"
        )
        self.assertEqual(
            self.sanitize(source),
            "actions:\n  - chat_id: <REDACTED>\n  - action: notify.test\n",
        )

    def test_nested_map_and_same_indent_list(self) -> None:
        source = (
            "data:\n"
            "  chat_id:\n"
            "    note: hidden\n"
            "    members:\n"
            "    - 111111111\n"
            "  message: visible\n"
        )
        self.assertEqual(
            self.sanitize(source),
            "data:\n  chat_id: <REDACTED>\n  message: visible\n",
        )

    def test_secret_reference_and_other_lists_unchanged(self) -> None:
        source = (
            "chat_id: !secret telegram_chat_id\n"
            "normal_list:\n"
            "- alpha\n"
            "- beta\n"
        )
        self.assertEqual(self.sanitize(source), source)

    def test_redact_sensitive_inline_scalar(self) -> None:
        self.assertEqual(
            self.sanitize("chat_id: 111111111\nmessage: visible\n"),
            "chat_id: <REDACTED>\nmessage: visible\n",
        )


if __name__ == "__main__":
    unittest.main()
