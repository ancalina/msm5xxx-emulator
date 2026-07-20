"""Locale-selection regressions; no Tk display required."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import gui


class GuiLocaleTests(unittest.TestCase):
    def test_preferences_and_locale_selection(self) -> None:
        self.assertEqual(gui.normalize_ui_language("ko"), "ko")
        self.assertEqual(gui.normalize_ui_language("fr"), "auto")
        self.assertEqual(gui.system_ui_language("ko_KR.UTF-8"), "ko")
        self.assertEqual(gui.system_ui_language("en_US.UTF-8"), "en")
        self.assertEqual(gui.resolve_ui_language("en", "ko_KR"), "en")

    def test_environment_then_platform_locale(self) -> None:
        with mock.patch.dict("os.environ", {"LANG": "ko_KR.UTF-8"}, clear=True):
            self.assertEqual(gui.system_ui_language(), "ko")
        with mock.patch.dict("os.environ", {"LC_ALL": "C.UTF-8", "LANG": "ko_KR.UTF-8"},
                             clear=True):
            self.assertEqual(gui.system_ui_language(), "en")
        with mock.patch.dict("os.environ", {}, clear=True), \
             mock.patch.object(gui.locale, "getlocale",
                               return_value=("Korean_Korea", "949")):
            self.assertEqual(gui.system_ui_language(), "ko")

    def test_runtime_metrics_are_fixed_lines(self) -> None:
        self.assertEqual(
            gui.runtime_status_text({"instructions": 1, "pc": "0x10",
                                     "lcd_writes": 2, "frame_sequence": 3}, "en"),
            "Run 1\nPC 0x10\nLCD 2\nframe 3",
        )

    def test_preference_persists_outside_firmware_profile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "last_config.json"
            window = gui.Window.__new__(gui.Window)
            window.firmware = Path(directory) / "X430.bin"
            window.overrides = {"width": 128}
            window.ui_language_preference = "en"
            with mock.patch.object(gui, "LAST_CONFIG", path):
                gui.Window._save_config(window)
                restored = gui.Window.__new__(gui.Window)
                self.assertEqual(gui.Window._load_ui_language(restored), "en")
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(saved["profiles"][str(window.firmware.resolve())], {"width": 128})
