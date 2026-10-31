"""Host-independent iOS protocol lifecycle tests; never starts QEMU."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class IOSRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.shared = load_module("msm5xxx_android_runtime",
                                  ROOT / "android/app/src/main/python/msm5xxx_android_runtime.py")
        self.modules = patch.dict(sys.modules, {"msm5xxx_android_runtime": self.shared})
        self.modules.start()
        self.addCleanup(self.modules.stop)
        self.runtime = load_module("msm5xxx_ios_runtime", ROOT / "ios/python/msm5xxx_ios_runtime.py")

    def test_stop_retains_resources_when_replay_still_alive(self):
        transport = self.shared._session = Mock()
        thread = self.shared._session_thread = Mock()
        thread.is_alive.return_value = True
        stop = self.shared._session_stop = Mock()
        with self.assertRaisesRegex(RuntimeError, "replay did not stop"):
            self.runtime.stop_session()
        stop.set.assert_called_once()
        transport.interrupt.assert_called_once()
        transport.close.assert_not_called()
        self.assertIs(self.shared._session, transport)

    def test_stop_closes_after_replay_finishes(self):
        transport = self.shared._session = Mock()
        thread = self.shared._session_thread = Mock()
        thread.is_alive.return_value = False
        self.shared._session_stop = Mock()
        self.shared._scanout_sent["primary"] = object()
        self.assertIn('"stopped":true', self.runtime.stop_session())
        thread.join.assert_called_once_with(3)
        transport.close.assert_called_once()
        self.assertIsNone(self.shared._session)
        self.assertEqual(self.shared._scanout_sent, {})

    def test_stop_retains_session_if_native_quit_times_out(self):
        transport = self.shared._session = Mock()
        transport.interrupt.side_effect = TimeoutError("native thread stuck")
        with self.assertRaises(TimeoutError):
            self.runtime.stop_session()
        transport.close.assert_not_called()
        self.assertIs(self.shared._session, transport)

    def test_repeated_stop_is_idempotent(self):
        self.assertIn('"stopped":true', self.runtime.stop_session())
        self.assertIn('"stopped":true', self.runtime.stop_session())
