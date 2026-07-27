"""Locale-selection regressions; no Tk display required."""
from __future__ import annotations

import json
import queue
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from gui import (METRIC_TEXT, Window, display_model_name, normalize_ui_language,
                 resolve_ui_language, runtime_status_text, settings_apply_mode,
                 system_ui_language)
from msm5xxx_emulator import gui as package_gui
from msm5xxx_emulator.gui.app import main as package_main
from msm5xxx import detect
from msm5xxx_emulator.gui.controls import (ControlsMixin, detect_profile,
                                           manual_keymap,
                                           parse_manual_key_event)
from msm5xxx_emulator.gui.locale import runtime_notice_text
from msm5xxx_emulator.gui.settings import (parse_settings_values, settings_values,
                                           validate_settings_values)


class GuiLocaleTests(unittest.TestCase):
    def test_package_gui_public_exports_match_compatibility_surface(self) -> None:
        self.assertIs(package_gui.Window, Window)
        self.assertIs(package_gui.main, package_main)
        self.assertEqual(package_gui.METRIC_TEXT, METRIC_TEXT)
        self.assertIs(package_gui.settings_apply_mode, settings_apply_mode)

    def test_settings_parse_and_validation_are_gui_independent(self) -> None:
        image = bytearray(b"\xff" * 0x1000)
        for offset in range(0, 32, 4):
            struct.pack_into("<I", image, offset, 0xEA000000)
        with tempfile.TemporaryDirectory() as directory:
            firmware = Path(directory) / "settings.bin"
            firmware.write_bytes(image)
            config = detect(firmware)
            raw = settings_values(firmware, config, {})
            parsed = parse_settings_values(raw)
            effective = {name: getattr(config, name) for name in parsed}

            validate_settings_values(
                firmware, config, effective, set(), raw["flash_state"]
            )
            effective["ram_size"] = 0x08000001
            with self.assertRaisesRegex(ValueError, "RAM 크기 상한"):
                validate_settings_values(
                    firmware, config, effective, set(), raw["flash_state"]
                )

    def test_korean_metric_labels_and_pc_expansion(self) -> None:
        self.assertEqual(METRIC_TEXT["ko"]["run"][0], "실행")
        self.assertIn("Program Counter", METRIC_TEXT["ko"]["pc"][1])

    def test_apply_mode_separates_language_firmware_and_overrides(self) -> None:
        self.assertEqual(settings_apply_mode(set(), False), "language")
        self.assertEqual(settings_apply_mode(set(), True), "firmware")
        self.assertEqual(settings_apply_mode({"width"}, True), "overrides")

    def test_unverified_filename_is_not_presented_as_model_identity(self) -> None:
        self.assertEqual(display_model_name("SCH-E100", None, "ko"),
                         "SCH-E100 (미확인)")
        self.assertEqual(display_model_name("SCH-E100", None, "en"),
                         "SCH-E100 (unverified)")
        self.assertEqual(display_model_name("SCH-A650", "SCH-A650", "en"),
                         "SCH-A650")

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
             mock.patch("msm5xxx_emulator.gui.locale.locale.getlocale",
                        return_value=("Korean_Korea", "949")):
            self.assertEqual(system_ui_language(), "ko")

    def test_runtime_metrics_use_one_line_per_value(self) -> None:
        self.assertEqual(
            runtime_status_text({
                "instructions": 1_234_567, "pc": "0x1000", "lcd_writes": 2,
                "frame_sequence": 3, "audio_backend": "disabled",
            }, "en"),
            "Run 1,234,567\nPC 0x1000\nLCD 2\nframe 3\nAudio unavailable",
        )

    def test_input_errors_are_not_gui_runtime_text(self) -> None:
        latest = {
            "instructions": 12, "pc": "0x1000", "lcd_writes": 3,
            "frame_sequence": 4, "audio_play_requests": 5,
            "input_error": "fail-closed key rejected",
        }
        for language, label in (("en", "Input error"), ("ko", "입력 오류")):
            status = runtime_status_text(latest, language)
            notice = runtime_notice_text(latest, language)
            self.assertIn("12", status)
            self.assertIn("5", status)
            self.assertIn("5", notice)
            self.assertNotIn(label, status)
            self.assertNotIn(label, notice)
            self.assertNotIn("fail-closed key rejected", status)
            self.assertNotIn("fail-closed key rejected", notice)

    def test_preference_is_global_not_firmware_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "last_config.json"
            window = Window.__new__(Window)
            window.firmware = Path(directory) / "X430.bin"
            window.overrides = {"width": 128}
            window.ui_language_preference = "en"
            with mock.patch("msm5xxx_emulator.gui.controls.LAST_CONFIG", config_path):
                Window._save_config(window)
                restored = Window.__new__(Window)
                restored.firmware = window.firmware
                self.assertEqual(Window._load_ui_language(restored), "en")
                with mock.patch("msm5xxx_emulator.gui.controls.detect") as detector:
                    self.assertEqual(Window._load_config(restored), {"width": 128})
                    detector.assert_not_called()

            saved = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["ui_language"], "en")
            self.assertEqual(saved["profiles"][str(window.firmware.resolve())],
                             {"width": 128})

    def test_manual_keymap_is_validated_and_firmware_sha_scoped(self) -> None:
        firmware_sha256 = "a" * 64
        self.assertEqual(parse_manual_key_event("0x53"), 0x53)
        self.assertEqual(parse_manual_key_event("83"), 0x53)
        with self.assertRaises(ValueError):
            parse_manual_key_event("0x100")
        data = {
            "manual_keymaps": {
                firmware_sha256: {
                    "5": 0x53, "7": True, "8": 0x100, "bad": 0x51,
                },
                "b" * 64: {"5": 0x51},
            },
        }
        self.assertEqual(manual_keymap(data, firmware_sha256), {5: 0x53})

    def test_manual_keymap_save_preserves_regular_preferences(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "last_config.json"
            firmware_sha256 = "a" * 64
            config_path.write_text(json.dumps({
                "ui_language": "en",
                "profiles": {"/firmware.bin": {"width": 128}},
            }), encoding="utf-8")
            window = Window.__new__(Window)
            window.emulator = SimpleNamespace(
                config=SimpleNamespace(firmware_sha256=firmware_sha256)
            )
            with mock.patch("msm5xxx_emulator.gui.controls.LAST_CONFIG", config_path):
                Window._save_manual_key_event(window, 5, 0x53)
                self.assertEqual(Window._manual_key_event(window, 5), 0x53)
            saved = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["ui_language"], "en")
            self.assertEqual(saved["profiles"]["/firmware.bin"], {"width": 128})
            self.assertEqual(
                saved["manual_keymaps"][firmware_sha256], {"5": 0x53}
            )

    def test_manual_mapping_save_and_delete_log_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            window = Window.__new__(Window)
            window.emulator = SimpleNamespace(
                config=SimpleNamespace(firmware_sha256="a" * 64)
            )
            config_path = Path(directory) / "last_config.json"
            with (mock.patch(
                    "msm5xxx_emulator.gui.controls.LAST_CONFIG", config_path),
                  mock.patch(
                    "msm5xxx_emulator.gui.controls.LOGGER.info") as log):
                Window._save_manual_key_event(window, 5, 0x53)
                Window._save_manual_key_event(window, 5, None)
        payloads = [json.loads(call.args[1]) for call in log.call_args_list]
        self.assertEqual(payloads, [
            {
                "accepted": True, "bit": 5,
                "firmware_sha256_prefix": "a" * 12,
                "mapping_source": "manual",
                "mapping_rule": "manual-unique-event",
                "reason": "manual-mapping-saved",
                "requested_event": "0x53", "requested_source": "manual",
                "requested_value": None,
            },
            {
                "accepted": True, "bit": 5,
                "firmware_sha256_prefix": "a" * 12,
                "mapping_source": "manual",
                "mapping_rule": "manual-mapping-delete",
                "reason": "manual-mapping-deleted",
                "requested_event": None, "requested_source": "manual",
                "requested_value": None,
            },
        ])

    def test_unmapped_button_opens_editor_without_guest_command(self) -> None:
        window = Window.__new__(Window)
        window.emulator = mock.Mock()
        window.emulator.can_set_key.return_value = False
        window.commands = queue.SimpleQueue()
        with (mock.patch.object(Window, "_manual_key_event", return_value=None),
              mock.patch.object(Window, "_edit_key_mapping",
                                return_value="break") as editor):
            self.assertEqual(Window._mouse_key_press(window, "OK"), "break")
        editor.assert_called_once_with("OK")
        with self.assertRaises(queue.Empty):
            window.commands.get_nowait()

    def test_manual_button_queues_event_only_on_press(self) -> None:
        window = Window.__new__(Window)
        window.emulator = mock.Mock()
        window.emulator.can_set_key.return_value = True
        window.commands = queue.SimpleQueue()
        window.held = {}
        with mock.patch.object(Window, "_manual_key_event", return_value=0x53):
            Window._mouse_key_press(window, "OK")
            Window._mouse_key_release(window, "OK")
        self.assertEqual(window.commands.get_nowait(), (5, True, 0x53))
        self.assertEqual(window.commands.get_nowait(), (5, False))

    def test_rejected_manual_key_event_is_logged(self) -> None:
        window = Window.__new__(Window)
        window.emulator = SimpleNamespace(
            config=SimpleNamespace(firmware_sha256="a" * 64)
        )
        window.held = {}
        window.root = None
        window.ui_language = "en"
        with (mock.patch.object(Window, "_manual_key_event",
                                return_value=None),
              mock.patch.object(Window, "_key_supported", return_value=False),
              mock.patch.object(Window, "_key_text", return_value="OK"),
              mock.patch.object(Window, "_text", return_value="Input error"),
              mock.patch(
                  "msm5xxx_emulator.gui.controls.simpledialog.askstring",
                  return_value="not-a-byte",
              ),
              mock.patch(
                  "msm5xxx_emulator.gui.controls.messagebox.showerror"
              ),
              mock.patch(
                  "msm5xxx_emulator.gui.controls.LOGGER.info"
              ) as log):
            self.assertEqual(Window._edit_key_mapping(window, "OK"), "break")
        self.assertEqual(json.loads(log.call_args.args[1]), {
            "accepted": False, "bit": 5,
            "firmware_sha256_prefix": "a" * 12,
            "mapping_source": "manual",
            "mapping_rule": "manual-event-rejected",
            "reason": "invalid-value",
            "requested_event": None, "requested_source": "manual",
            "requested_value": "<invalid>",
        })

    def test_rejected_manual_key_storage_error_log_omits_path(self) -> None:
        window = Window.__new__(Window)
        window.emulator = SimpleNamespace(
            config=SimpleNamespace(firmware_sha256="a" * 64)
        )
        window.held = {}
        window.root = None
        window.ui_language = "en"
        error = OSError("write failed: /private/state.json")
        with (mock.patch.object(Window, "_manual_key_event",
                                return_value=None),
              mock.patch.object(Window, "_key_supported", return_value=True),
              mock.patch.object(Window, "_key_text", return_value="OK"),
              mock.patch.object(Window, "_text", return_value="Input error"),
              mock.patch.object(Window, "_save_manual_key_event",
                                side_effect=error),
              mock.patch(
                  "msm5xxx_emulator.gui.controls.simpledialog.askstring",
                  return_value="0x53",
              ),
              mock.patch(
                  "msm5xxx_emulator.gui.controls.messagebox.showerror"
              ) as dialog,
              mock.patch(
                  "msm5xxx_emulator.gui.controls.LOGGER.info"
              ) as log):
            self.assertEqual(Window._edit_key_mapping(window, "OK"), "break")
        self.assertEqual(json.loads(log.call_args.args[1]), {
            "accepted": False, "bit": 5,
            "firmware_sha256_prefix": "a" * 12,
            "mapping_source": "manual",
            "mapping_rule": "manual-state-io-error",
            "reason": "state-io-error",
            "requested_event": "0x53", "requested_source": "manual",
            "requested_value": "0x53",
        })
        dialog.assert_called_once_with(
            "Input error", str(error), parent=None
        )

    def test_profile_detection_reuses_baseline_without_manual_overrides(self) -> None:
        firmware = Path("firmware.bin")
        baseline = SimpleNamespace(width=128, height=160)
        overridden = SimpleNamespace(width=176, height=160)
        with mock.patch("msm5xxx_emulator.gui.controls.detect",
                        side_effect=[baseline, overridden]) as detector:
            config, overrides = detect_profile(
                firmware, {"width": 128, "height": 160, "obsolete": 1}
            )
            self.assertIs(config, baseline)
            self.assertEqual(overrides, {})
            detector.assert_called_once_with(firmware)

        with mock.patch("msm5xxx_emulator.gui.controls.detect",
                        side_effect=[baseline, overridden]) as detector:
            config, overrides = detect_profile(firmware, {"width": 176})
            self.assertIs(config, overridden)
            self.assertEqual(overrides, {"width": 176})
            self.assertEqual(detector.call_count, 2)

    def test_settings_waits_for_worker_detection_without_rescanning(self) -> None:
        class Harness(ControlsMixin):
            def _text(self, key: str) -> str:
                return key

        harness = Harness()
        harness.emulator = None
        harness._settings_requested = False
        harness.status = mock.Mock()
        with mock.patch("msm5xxx_emulator.gui.controls.detect_profile") as detector:
            harness._settings()
        detector.assert_not_called()
        self.assertTrue(harness._settings_requested)
        harness.status.set.assert_called_once_with("detecting")


if __name__ == "__main__":
    unittest.main()
