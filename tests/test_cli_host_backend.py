"""CLI host-backend diagnostic regression; no real Unicorn fault required."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest import mock

import msm5xxx
from msm5xxx import HostBackendFault


class CLIHostBackendFaultTests(unittest.TestCase):
    def test_host_error_text_drops_posix_and_windows_paths(self) -> None:
        fault = HostBackendFault(
            OSError(
                "backend failed '/private/dumps/phone dump.bin' and "
                r"C:\\private\\logs\\host-fault.bin"
            ),
            {},
        )

        text = f"{fault} {json.dumps(fault.diagnostic, sort_keys=True)}"
        self.assertIn("phone dump.bin", text)
        self.assertIn("host-fault.bin", text)
        self.assertNotIn("/private/dumps", text)
        self.assertNotIn(r"C:\\private\\logs", text)

    def test_main_records_one_safe_artifact_and_returns_nonzero(self) -> None:
        identity = {
            "basename": "SCH-X350.bin", "bytes": 0x100,
            "sha256": "a" * 64,
        }
        config = SimpleNamespace(
            model="SCH-X350", chipset="MSM5000", image_offset=0,
            load_address=0, flash_size=0x100, width=128, height=128,
            board_revision="unknown", firmware_identity=lambda: identity,
        )
        fault = HostBackendFault(
            OSError("backend failed /private/dumps/SCH-X350.bin"),
            {"checkpoint": "before emu_start"},
        )
        emulator = mock.Mock()
        emulator.run.side_effect = fault
        stdout = io.StringIO()

        with (mock.patch.object(sys, "argv", [
                    "msm5xxx.py", "SCH-X350.bin", "--steps", "1",
                ]),
              mock.patch("runtime_log.install_runtime_logging",
                         return_value=Path("logs/cli-session.log")),
              mock.patch("runtime_log.record_diagnostic",
                         return_value=Path("logs/diagnostic-host.json")) as record,
              mock.patch.object(msm5xxx, "detect", return_value=config),
              mock.patch.object(msm5xxx, "GenericMSMEmulator",
                                return_value=emulator),
              redirect_stdout(stdout)):
            self.assertEqual(msm5xxx.main(), 1)

        record.assert_called_once()
        kind, payload = record.call_args.args
        self.assertEqual(kind, "host_backend_fault")
        self.assertEqual(payload["firmware"], identity)
        self.assertEqual(payload["model"], "SCH-X350")
        self.assertEqual(payload["host_error"],
                         "OSError: backend failed SCH-X350.bin")
        self.assertNotIn("/private/dumps", json.dumps(payload, sort_keys=True))
        emulator.close.assert_called_once_with()
        self.assertEqual(stdout.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
