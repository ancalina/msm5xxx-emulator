"""Synthetic settings transitions for the embedded iOS session."""
import importlib.util
import json
from pathlib import Path
import sys
import struct
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SettingsApplyTests(unittest.TestCase):
    def setUp(self):
        self.shared = load("settings_shared_test", ROOT / "android/app/src/main/python/msm5xxx_android_runtime.py")
        self.real_apply_settings = self.shared._apply_settings
        self.modules = patch.dict(sys.modules, {"msm5xxx_android_runtime": self.shared})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        self.runtime = load("settings_ios_test", ROOT / "ios/python/msm5xxx_ios_runtime.py")
        self.runtime._session_spec = {"firmware": "synthetic", "settings": {},
                                      "persistent_state": True, "experimental_rex": False}
        self.runtime._display_update_lock = threading.RLock()
        self.runtime._control = SimpleNamespace(command=Mock())
        self.config = SimpleNamespace(framebuffer_address=0x1000, framebuffer_stride=8,
                                      width=4, height=4, framebuffer_format="rgb565le")
        self.decoder = SimpleNamespace(config=self.config)
        def set_format(value):
            self.assertTrue(self.runtime._display_update_lock._is_owned())
            self.config.framebuffer_format = value
        self.decoder.set_framebuffer_format = Mock(side_effect=set_format)
        self.shared._session = SimpleNamespace(config=self.config, decoder=self.decoder,
                                               process=SimpleNamespace(poll=lambda: None))
        self.shared._session_error = None
        self.shared._scanout_sent["primary"] = object()
        self.detect = patch("msm5xxx_emulator.detection.detect", return_value=object())
        self.detect.start()
        self.addCleanup(self.detect.stop)
        def apply(_firmware, _baseline, edits):
            if edits.get("width") == "invalid":
                raise ValueError("invalid width")
            return SimpleNamespace(framebuffer_address=0x1000, framebuffer_stride=8,
                                   width=4, height=4,
                                   framebuffer_format=edits.get("framebuffer_format", "rgb565le"))
        self.shared._apply_settings = Mock(side_effect=apply)

    def request(self, edits, *, persistent=True, rex=False):
        return json.dumps({"settings": edits, "persistent_state": persistent, "experimental_rex": rex})

    def test_valid_format_change_and_removal_reset_existing_machine(self):
        for edits, expected in (({"framebuffer_format": "bgr565le"}, "bgr565le"),
                                ({}, "rgb565le")):
            request = self.request(edits)
            self.assertEqual(json.loads(self.runtime.prepare_session_settings(request))["action"], "reset")
            self.assertTrue(json.loads(self.runtime.apply_reset_settings(request))["applied"])
            self.assertEqual(self.config.framebuffer_format, expected)
            self.assertEqual(self.runtime._session_spec["settings"], edits)
        self.assertEqual(self.runtime._control.command.call_args_list,
                         [unittest.mock.call("system_reset"), unittest.mock.call("system_reset")])
        self.assertEqual(self.shared._scanout_sent, {})

    def test_machine_and_backing_changes_require_new_session(self):
        for request in (self.request({"width": "5"}), self.request({}, persistent=False),
                        self.request({}, rex=True), self.request({"framebuffer_format": "none"})):
            with self.subTest(request=request):
                self.assertEqual(json.loads(self.runtime.prepare_session_settings(request))["action"], "reopen")
                with self.assertRaisesRegex(ValueError, "require a new session"):
                    self.runtime.apply_reset_settings(request)
        self.decoder.set_framebuffer_format.assert_not_called()
        self.runtime._control.command.assert_not_called()
        self.assertEqual(self.runtime._session_spec["settings"], {})

    def test_invalid_edits_do_not_interrupt_session(self):
        request = self.request({"width": "invalid"})
        with self.assertRaisesRegex(ValueError, "invalid width"):
            self.runtime.prepare_session_settings(request)
        self.runtime._control.command.assert_not_called()
        self.decoder.set_framebuffer_format.assert_not_called()

    def test_failed_reset_restores_previous_format_and_settings(self):
        self.runtime._control.command.side_effect = RuntimeError("monitor unavailable")
        with self.assertRaisesRegex(RuntimeError, "monitor unavailable"):
            self.runtime.apply_reset_settings(self.request({"framebuffer_format": "bgr565le"}))
        self.assertEqual(self.config.framebuffer_format, "rgb565le")
        self.assertEqual(self.runtime._session_spec["settings"], {})
        self.assertIn("primary", self.shared._scanout_sent)

    def test_real_parser_accepts_synthetic_framebuffer_change(self):
        self.detect.stop()
        from msm5xxx_emulator.detection import detect
        self.shared._apply_settings = self.real_apply_settings
        image = bytearray(1024 * 1024)
        for index in range(8):
            address = index * 4
            struct.pack_into("<I", image, address, 0xea000000 | ((0x100 - address - 8) // 4))
        struct.pack_into("<I", image, 0x100, 0xeafffffe)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.bin"
            path.write_bytes(image)
            baseline = detect(path)
            initial = {"framebuffer_address": hex(baseline.ram_base),
                       "framebuffer_stride": "352", "framebuffer_format": "rgb565le"}
            config = self.real_apply_settings(path, baseline, initial)
            self.runtime._session_spec["firmware"] = str(path)
            self.runtime._session_spec["settings"] = dict(initial)
            self.config = config
            self.decoder.config = config
            self.shared._session.config = config
            changed = {**initial, "framebuffer_format": "bgr565le"}
            self.assertEqual(json.loads(self.runtime.prepare_session_settings(self.request(changed)))["action"], "reset")
            self.runtime.apply_reset_settings(self.request(changed))
            self.assertEqual(config.framebuffer_format, "bgr565le")
            self.runtime._control.command.assert_called_once_with("system_reset")

    def test_bad_requests_and_dead_session_do_not_reset(self):
        for request in ("{}", self.request({}, persistent=1),
                        json.dumps({"settings": [], "persistent_state": True, "experimental_rex": False})):
            with self.subTest(request=request), self.assertRaises(ValueError):
                self.runtime.prepare_session_settings(request)
        self.shared._session.process.poll = lambda: 1
        with self.assertRaisesRegex(RuntimeError, "session is not running"):
            self.runtime.prepare_session_settings(self.request({}))
        self.runtime._control.command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
