"""Synthetic transaction tests for the boot NAND controller core."""
import subprocess
import tempfile
import unittest
from pathlib import Path


class TestBootNandCore(unittest.TestCase):
    def test_page_spare_program_erase_and_completion_protocol(self):
        root = Path(__file__).resolve().parents[1]
        core = root / "native/qemu/msm5xxx-boot-nand.c"
        fixture = root / "tests/fixtures/boot-nand-core.c"
        with tempfile.TemporaryDirectory(prefix="msm5xxx-boot-nand-") as tmp:
            binary = Path(tmp) / "boot-nand-core"
            subprocess.run([
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                "-fsanitize=undefined", "-fno-sanitize-recover=undefined", "-O1",
                "-I", str(core.parent), str(core), str(fixture), "-o", str(binary),
            ], check=True, capture_output=True, text=True, timeout=60)
            result = subprocess.run([str(binary)], check=True, capture_output=True,
                                    text=True, timeout=60)
            self.assertIn("PASS:", result.stdout)
            self.assertEqual(result.stderr, "")
