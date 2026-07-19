"""Regression tests for platform-safe native crash logging."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import runtime_log


class NativeFaultLoggingPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        runtime_log._runtime_metadata.cache_clear()

    def tearDown(self) -> None:
        runtime_log._runtime_metadata.cache_clear()

    def test_posix_keeps_native_fault_capture_enabled(self) -> None:
        with mock.patch.object(runtime_log.sys, "platform", "linux"):
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertTrue(runtime_log._native_fault_logging_enabled())

    def test_windows_disables_recoverable_first_chance_trace_by_default(self) -> None:
        with mock.patch.object(runtime_log.sys, "platform", "win32"):
            with mock.patch.dict(os.environ, {}, clear=True):
                self.assertFalse(runtime_log._native_fault_logging_enabled())

    def test_windows_allows_explicit_native_trace_opt_in(self) -> None:
        with mock.patch.object(runtime_log.sys, "platform", "win32"):
            for value in ("1", "true", "YES", "on"):
                with self.subTest(value=value):
                    with mock.patch.dict(
                        os.environ, {"MSM5XXX_NATIVE_FAULT_LOG": value}, clear=True
                    ):
                        self.assertTrue(runtime_log._native_fault_logging_enabled())

    def test_diagnostic_includes_runtime_identity_without_local_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "private" / "firmware.bin"
            with mock.patch.dict(os.environ, {"MSM5XXX_LOG_DIR": directory}, clear=True):
                with mock.patch.object(runtime_log, "_SESSION_PATH", None):
                    with mock.patch.object(
                            runtime_log.metadata, "version",
                            side_effect=lambda name: f"{name}-version"):
                        path = runtime_log.record_diagnostic("Host Backend Fault", {
                            "firmware": {
                                "basename": private.name,
                                "bytes": 1234,
                                "sha256": "a" * 64,
                            },
                            "firmware_path": str(private),
                            "cwd": str(private.parent),
                            "argv": ["python", str(private)],
                            "nested": {"path": str(private.parent)},
                        })

            self.assertIsNotNone(path)
            assert path is not None
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(document["schema"], 1)
            self.assertEqual(document["kind"], "host-backend-fault")
            self.assertEqual(document["runtime"]["packages"], {
                "unicorn": "unicorn-version", "Pillow": "Pillow-version",
            })
            self.assertEqual(document["runtime"]["source"]["file"], "msm5xxx.py")
            self.assertEqual(set(document["runtime"]["sources"]), {
                "msm5xxx.py", "gui.py", "boot_probe.py", "runtime_log.py",
            })
            self.assertEqual(document["payload"]["firmware"]["basename"], "firmware.bin")
            self.assertNotIn("firmware_path", document["payload"])
            self.assertNotIn("cwd", document["payload"])
            self.assertNotIn("argv", document["payload"])
            self.assertNotIn(str(private.parent), path.read_text(encoding="utf-8"))

    def test_runtime_metadata_is_cached_after_first_lookup(self) -> None:
        with (mock.patch.object(runtime_log, "_source_identity",
                                return_value={"file": "msm5xxx.py", "sha256": "a"}),
              mock.patch.object(runtime_log, "_source_identities",
                                return_value={"msm5xxx.py": "a"}),
              mock.patch.object(runtime_log.metadata, "version",
                                side_effect=lambda name: f"{name}-version") as version):
            first = runtime_log._runtime_metadata()
            second = runtime_log._runtime_metadata()

        self.assertIs(first, second)
        self.assertEqual(version.call_count, 2)
        self.assertEqual(first["packages"]["unicorn"], "unicorn-version")

    def test_current_session_log_returns_installed_path(self) -> None:
        path = Path("logs/gui-session.log")
        with mock.patch.object(runtime_log, "_SESSION_PATH", path):
            self.assertEqual(runtime_log.current_session_log(), path)


if __name__ == "__main__":
    unittest.main()
