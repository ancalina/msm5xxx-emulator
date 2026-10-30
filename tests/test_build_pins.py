"""Every source hash pinned for the QEMU staging script matches the tree."""
import hashlib
import re
import unittest
from pathlib import Path

NATIVE = Path(__file__).resolve().parents[1] / "native/qemu"


class BuildPinTests(unittest.TestCase):
    def test_staged_sources_match_pins(self) -> None:
        pins = dict(re.findall(r"^(\w+)='?([0-9a-f]{64})'?$",
                               (NATIVE / "qemu_build_inputs.env").read_text(), re.M))
        stage = (NATIVE / "stage_qemu_source.sh").read_text()
        paths = {name: (NATIVE / rel).resolve()
                 for name, rel in re.findall(r'^(\w+)="\$ROOT/([^"]+)"$', stage, re.M)}
        checks = re.findall(r'^check_sha256 "\$(\w+)" "\$(\w+)"$', stage, re.M)
        checked = [(pin, var) for pin, var in checks if var in paths]  # the archive is external
        self.assertGreater(len(checked), 10)
        for pin, var in checked:
            with self.subTest(pin=pin):
                actual = hashlib.sha256(paths[var].read_bytes()).hexdigest()
                self.assertEqual(pins[pin], actual, f"refresh {pin} in qemu_build_inputs.env")

    def test_ios_patch_pin(self) -> None:
        pins = (NATIVE / "qemu_build_inputs.env").read_text()
        actual = hashlib.sha256((NATIVE / "qemu-10.2.1-ios-host.patch").read_bytes()).hexdigest()
        self.assertIn(f"MSM5XXX_IOS_PATCH_SHA256={actual}", pins)


if __name__ == "__main__":
    unittest.main()
