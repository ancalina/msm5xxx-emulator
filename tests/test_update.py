"""Update archive and prompt-state regressions without network access."""
from __future__ import annotations

import io
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from zipfile import ZipFile

from src.msm5xxx_emulator import update


SHA = "a" * 40


class UpdateTests(unittest.TestCase):
    @staticmethod
    def _write_manifest(root: Path, files: tuple[str, ...]) -> None:
        payload = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                   for name in files}
        (root / update.MANIFEST_FILE).write_text(
            json.dumps({"files": payload}), encoding="utf-8"
        )

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
                files = {
                    "gui.py": b"# gui\n", "_compat.py": b"# compat\n",
                    "src/msm5xxx_emulator/gui/app.py": b"# app\n",
                }
                manifest = {name: hashlib.sha256(data).hexdigest()
                            for name, data in files.items()}
                for name, data in files.items():
                    bundle.writestr(f"msm5xxx-emulator-{SHA}/{name}", data)
                bundle.writestr(
                    f"msm5xxx-emulator-{SHA}/{update.MANIFEST_FILE}",
                    json.dumps({"files": manifest}),
                )

            def download(_revision: str, destination: Path) -> None:
                destination.write_bytes(archive.read_bytes())

            with mock.patch.object(update, "_download_archive", side_effect=download):
                root = update.prepare_update(update.UpdateInfo(SHA), state)
            self.assertEqual(update.local_revision(root), SHA)
            self.assertTrue((root / "gui.py").is_file())

    def test_apply_replaces_only_manifest_files_and_preserves_user_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target, prepared, state = base / "app", base / "new", base / "state"
            for root, content in ((target, "old"), (prepared, "new")):
                (root / "src").mkdir(parents=True)
                (root / "gui.py").write_text(content, encoding="utf-8")
                (root / "src" / "core.py").write_text(content, encoding="utf-8")
                self._write_manifest(root, ("gui.py", "src/core.py"))
            (prepared / update.REVISION_FILE).write_text(SHA + "\n", encoding="ascii")
            (target / "logs").mkdir()
            (target / "logs" / "user.log").write_text("keep", encoding="utf-8")

            update.apply_prepared_update(prepared, target, state, SHA, False)

            self.assertEqual((target / "gui.py").read_text(), "new")
            self.assertEqual((target / "logs" / "user.log").read_text(), "keep")
            self.assertEqual(update.local_revision(target), SHA)

    def test_modified_install_requires_explicit_discard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target, prepared, state = base / "app", base / "new", base / "state"
            target.mkdir()
            prepared.mkdir()
            (target / "gui.py").write_text("original", encoding="utf-8")
            (prepared / "gui.py").write_text("new", encoding="utf-8")
            self._write_manifest(target, ("gui.py",))
            self._write_manifest(prepared, ("gui.py",))
            (prepared / update.REVISION_FILE).write_text(SHA + "\n", encoding="ascii")
            (target / "gui.py").write_text("edited", encoding="utf-8")

            with self.assertRaisesRegex(update.UpdateError, "local source files changed"):
                update.apply_prepared_update(prepared, target, state, SHA, False)
            update.apply_prepared_update(prepared, target, state, SHA, True)
            self.assertEqual((target / "gui.py").read_text(), "new")

    def test_archive_rejects_parent_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "unsafe.zip"
            with ZipFile(archive, "w") as bundle:
                bundle.writestr("../escape", "no")
            with self.assertRaises(update.UpdateError):
                update._extract_update_archive(archive, Path(directory), SHA)


if __name__ == "__main__":
    unittest.main()
