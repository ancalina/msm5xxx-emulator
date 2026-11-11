"""Synthetic native host state; no framework, firmware, or guest execution."""
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]


class HostStatusTests(unittest.TestCase):
    def test_detection_rejection_does_not_consume_native_start(self):
        shared = SimpleNamespace(_json=json.dumps, _session=None)
        for name in ("detect_profile", "library_describe", "session_frame",
                     "session_secondary_frame", "session_fold", "session_status",
                     "can_session_key", "set_session_key"):
            setattr(shared, name, lambda *args: None)
        state = {"used": False}
        host = SimpleNamespace(has_started=lambda: state["used"])
        with patch.dict(sys.modules, {"msm5xxx_android_runtime": shared,
                                     "_msm5xxx_ios_host": host}):
            spec = importlib.util.spec_from_file_location(
                "ios_status_test", ROOT / "ios/python/msm5xxx_ios_runtime.py")
            runtime = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(runtime)
            runtime.detect_profile = lambda _: json.dumps({"accepted": False, "reject_reason": "synthetic rejection"})
            request = json.dumps({"firmware": "synthetic", "profile": {}, "qemu": "q",
                                  "state": None, "experimental_rex": False})
            with patch("msm5xxx_emulator.detection.detect", return_value=SimpleNamespace()), \
                 patch("msm5xxx_emulator.qemu.transport.Transport") as transport:
                with self.assertRaisesRegex(ValueError, "synthetic rejection"):
                    runtime.start_session(request)
                transport.assert_not_called()
            self.assertEqual(json.loads(runtime.host_status()), {"schema": 1, "used": False})
            state["used"] = True
            self.assertEqual(json.loads(runtime.host_status()), {"schema": 1, "used": True})


if __name__ == "__main__":
    unittest.main()
