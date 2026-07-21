"""Locale-selection regressions; no Tk display required."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from gui import (Window, normalize_ui_language, resolve_ui_language,
                 runtime_status_text, system_ui_language)


class GuiLocaleTests(unittest.TestCase):
    def test_known_preferences_and_safe_default(self) -> None:
        self.assertEqual(normalize_ui_language("auto"), "auto")
        self.assertEqual(normalize_ui_language("ko"), "ko")
        self.assertEqual(normalize_ui_language("en"), "en")
        self.assertEqual(normalize_ui_language("fr"), "auto")

    def test_auto_uses_only_korean_system_locales(self) -> None:
        self.assertEqual(system_ui_language("ko_KR.UTF-8"), "ko")
        self.assertEqual(system_ui_language("Korean_Korea.949"), "ko")
        self.assertEqual(system_ui_language("en_US.UTF-8"), "en")
        self.assertEqual(resolve_ui_language("auto", "ko_KR"), "ko")
        self.assertEqual(resolve_ui_language("auto", "en_US"), "en")
        self.assertEqual(resolve_ui_language("en", "ko_KR"), "en")

    def test_auto_uses_posix_language_environment(self) -> None:
        with mock.patch.dict("os.environ", {"LANG": "ko_KR.UTF-8"}, clear=True):
            self.assertEqual(system_ui_language(), "ko")
        with mock.patch.dict("os.environ", {"LC_ALL": "C.UTF-8", "LANG": "ko_KR.UTF-8"},
                             clear=True):
            self.assertEqual(system_ui_language(), "en")

    def test_auto_falls_back_to_platform_locale(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True), \
             mock.patch("gui.locale.getlocale", return_value=("Korean_Korea", "949")):
            self.assertEqual(system_ui_language(), "ko")

    def test_runtime_metrics_use_one_line_per_value(self) -> None:
        self.assertEqual(
            runtime_status_text({
                "instructions": 1_234_567, "pc": "0x1000", "lcd_writes": 2,
                "frame_sequence": 3, "audio_backend": "disabled",
            }, "en"),
            "Run 1,234,567\nPC 0x1000\nLCD 2\nframe 3\nAudio unavailable",
        )

    def test_preference_is_global_not_firmware_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "last_config.json"
            window = Window.__new__(Window)
            window.firmware = Path(directory) / "X430.bin"
            window.overrides = {"width": 128}
            window.ui_language_preference = "en"
            with mock.patch("gui.LAST_CONFIG", config_path):
                Window._save_config(window)
                restored = Window.__new__(Window)
                self.assertEqual(Window._load_ui_language(restored), "en")

            saved = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["ui_language"], "en")
            self.assertEqual(saved["profiles"][str(window.firmware.resolve())],
                             {"width": 128})


if __name__ == "__main__":
    unittest.main()
