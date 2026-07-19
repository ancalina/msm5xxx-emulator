"""Update archive and prompt-state regressions without network access."""
from __future__ import annotations

import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from zipfile import ZipFile

from src.msm5xxx_emulator import update


SHA = "a" * 40


class UpdateTests(unittest.TestCase):
    def test_seen_commit_does_not_prompt_twice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "app"
            state = Path(directory) / "state"
            root.mkdir()
            def response(*_args: object, **_kwargs: object) -> io.BytesIO:
                stream = io.BytesIO(json.dumps({"sha": SHA}).encode())
                stream.headers = {}  # type: ignore[attr-defined]
                return stream

            with mock.patch.object(update, "urlopen", side_effect=response):
                found = update.check_for_update(root, state)
            self.assertEqual(found, update.UpdateInfo(SHA))
            update.remember_update(state, SHA)
            with mock.patch.object(update, "urlopen", side_effect=response):
                self.assertIsNone(update.check_for_update(root, state))

    def test_archive_extracts_to_private_revision_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            archive = Path(directory) / "update.zip"
            with ZipFile(archive, "w") as bundle:
                bundle.writestr(f"msm5xxx-emulator-{SHA}/gui.py", "# gui\n")
                bundle.writestr(f"msm5xxx-emulator-{SHA}/_compat.py", "# compat\n")
                bundle.writestr(
                    f"msm5xxx-emulator-{SHA}/src/msm5xxx_emulator/gui/app.py",
                    "# app\n",
                )

            def download(_revision: str, destination: Path) -> None:
                destination.write_bytes(archive.read_bytes())

            with mock.patch.object(update, "_download_archive", side_effect=download):
                root = update.prepare_update(update.UpdateInfo(SHA), state)
            self.assertEqual(update.local_revision(root), SHA)
            self.assertTrue((root / "gui.py").is_file())

    def test_archive_rejects_parent_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "unsafe.zip"
            with ZipFile(archive, "w") as bundle:
                bundle.writestr("../escape", "no")
            with self.assertRaises(update.UpdateError):
                update._extract_update_archive(archive, Path(directory), SHA)


if __name__ == "__main__":
    unittest.main()
