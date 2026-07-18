"""Corpus runner state-isolation regression."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import corpus_verify


class CorpusVerifyIsolationTests(unittest.TestCase):
    def test_each_invocation_uses_and_removes_a_fresh_state_directory(self) -> None:
        state_directories: list[Path] = []

        def run(
            command: list[str], **options: object
        ) -> subprocess.CompletedProcess[str]:
            environment = options["env"]
            assert isinstance(environment, dict)
            state_directory = Path(environment["MSM5XXX_STATE_DIR"])
            self.assertTrue(state_directory.is_dir())
            self.assertIn("/portable", environment["PYTHONPATH"])
            state_directories.append(state_directory)
            if "--detect-only" in command:
                output = json.dumps({
                    "image_kind": "firmware", "chipset": "MSM5100",
                    "rex_idle_address": 0x1000,
                })
            else:
                output = json.dumps({
                    "fault": None, "pc": "0x0", "lcd_writes": 0,
                    "frame_sequence": 0, "rex_idle_entries": 3, "rex_ticks": 2,
                })
            return subprocess.CompletedProcess(command, 0, output, "")

        with tempfile.TemporaryDirectory() as firmware_directory:
            (Path(firmware_directory) / "phone.bin").write_bytes(b"firmware")
            arguments = ["corpus_verify.py", firmware_directory, "--steps", "1",
                         "--workers", "1"]
            with mock.patch.object(corpus_verify.subprocess, "run", side_effect=run):
                with mock.patch.dict(os.environ, {"PYTHONPATH": "/portable"}):
                    for _ in range(2):
                        with mock.patch.object(corpus_verify.sys, "argv", arguments):
                            output = io.StringIO()
                            with redirect_stdout(output), redirect_stderr(io.StringIO()):
                                self.assertEqual(corpus_verify.main(), 0)
                            self.assertEqual(json.loads(output.getvalue())["rex"], {
                                "idle_signatures": 1,
                                "idle_callsites_reached": 1,
                                "tick_hle_active": 1,
                            })

        self.assertEqual(state_directories[0], state_directories[1])
        self.assertEqual(state_directories[2], state_directories[3])
        self.assertNotEqual(state_directories[0], state_directories[2])
        self.assertTrue(all(not path.exists() for path in state_directories))


if __name__ == "__main__":
    unittest.main()
