"""Standalone protected x16 NOR protocol boundaries and atomic mutations."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class ProtectedNorCoreTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cc"), "native C compiler unavailable")
    def test_protocol_transactions_and_reset_preserve_source(self):
        root = Path(__file__).resolve().parents[1]
        native = root / "experiments/qemu-tcg"
        fixture = root / "tests/fixtures/protected_nor_selfcheck.c"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "check"
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-Wmissing-prototypes", "-I", str(native), str(fixture),
                            str(native / "msm5xxx-protected-nor.c"), "-o", str(output)], check=True)
            subprocess.run([str(output)], check=True)
