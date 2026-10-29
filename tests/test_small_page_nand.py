"""Own timed x16 transaction contract; no guest or original NAND writes."""
import subprocess
import tempfile
import unittest
from pathlib import Path


class TestSmallPageNand(unittest.TestCase):
    def test_transaction_and_unknown_identity_contract(self):
        root = Path(__file__).resolve().parents[1]
        core = root / "experiments/qemu-tcg/msm5xxx-small-page-nand.c"
        fixture = root / "tests/fixtures/small-page-nand-core.c"
        with tempfile.TemporaryDirectory(prefix="msm5xxx-nand-test-") as tmp:
            binary = Path(tmp) / "nand-core"
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined", "-O1",
                "-I", str(core.parent), str(core), str(fixture), "-o", str(binary),
            ], check=True, capture_output=True, text=True, timeout=60)
            result = subprocess.run([str(binary)], check=True, capture_output=True,
                                    text=True, timeout=60)
            self.assertIn("PASS:", result.stdout)
            self.assertEqual(result.stderr, "")
