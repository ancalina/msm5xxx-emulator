"""Prepared profile identity validation shared by the desktop display."""
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from types import SimpleNamespace
from msm5xxx_emulator.gui.worker import _prepared_profile_matches

class PreparedProfileTests(unittest.TestCase):
    def test_prepared_profile_requires_current_identity(self) -> None:
        config = SimpleNamespace()
        with TemporaryDirectory() as directory:
            firmware = Path(directory) / "test.bin"
            firmware.write_bytes(b"firmware")
            config.path = str(firmware)
            config.file_size = 8
            config.firmware_sha256 = hashlib.sha256(b"firmware").hexdigest()
            prepared = (config, {})

            self.assertTrue(_prepared_profile_matches(
                prepared, firmware, {}
            ))
            self.assertFalse(_prepared_profile_matches(
                prepared, firmware, {"width": 128}
            ))
            self.assertFalse(_prepared_profile_matches(
                prepared, firmware.with_name("other.bin"), {}
            ))
            firmware.write_bytes(b"changed!")
            self.assertFalse(_prepared_profile_matches(
                prepared, firmware, {}
            ))
