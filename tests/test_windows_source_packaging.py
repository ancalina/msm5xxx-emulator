import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "windows_sources",
    Path(__file__).resolve().parents[1] / "experiments/qemu-tcg/package_windows_sources.py",
)
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)


class WindowsSourceArchiveTest(unittest.TestCase):
    def test_explicit_decoder_and_pinned_recipe(self):
        recipe = b"pkgname=example\n"
        encoded = b"pinned compressed input"
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w") as source:
            for name, data in (("PKGBUILD", recipe), (".SRCINFO", b"pkgbase = example\n")):
                member = tarfile.TarInfo("package/" + name)
                member.size = len(data)
                source.addfile(member, io.BytesIO(data))
        pin = {
            "source_archive_bytes": len(encoded),
            "source_archive_sha256": hashlib.sha256(encoded).hexdigest(),
            "source_root": "package",
            "recipe_sha256": hashlib.sha256(recipe).hexdigest(),
        }
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "source.tar.zst"
            archive.write_bytes(encoded)
            with patch.object(packager, "run", return_value=payload.getvalue()) as decode:
                packager.verify_package(archive, pin)
                decode.assert_called_once_with("zstd", "-dc", str(archive))
                with self.assertRaisesRegex(RuntimeError, "PKGBUILD SHA-256"):
                    packager.verify_package(archive, dict(pin, recipe_sha256="0" * 64))


if __name__ == "__main__":
    unittest.main()
