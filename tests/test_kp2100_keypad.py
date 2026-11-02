import os
from pathlib import Path
from types import SimpleNamespace
import unittest

from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.qemu.decoder import QemuDecoder
from msm5xxx_emulator.qemu.transport import (
    qemu_kp2100_low5_property, qemu_sd840_numeric_profile,
)


class KP2100KeypadTest(unittest.TestCase):
    def test_numeric_profile_and_negative_sources(self):
        root = Path(os.environ.get("MSM5XXX_TEST_FIRMWARE_ROOT", "/nonexistent"))
        path = root / "LG-kp2100.bin"
        if not path.exists():
            self.skipTest("private KP2100 firmware not available")
        image = path.read_bytes()
        config = detect(path)
        decoder = QemuDecoder(config)
        profile = decoder.direct_input_profile
        self.assertEqual(decoder.direct_input_detection, "accepted")
        self.assertEqual(qemu_kp2100_low5_property(image, config, profile),
                         "matrix-low5=1103684:6fb98:6fc3a:6fb86:6fc4a")
        numeric = qemu_sd840_numeric_profile(profile)
        self.assertEqual(set(decoder._direct_matrix_positions(numeric)), set(range(11, 23)))
        for offset in (0x80, 0x84, 0x90, 0x94, 0x136, 0x146, 0x148):
            changed = bytearray(image)
            changed[profile["function"] + offset] ^= 1
            self.assertIsNone(qemu_kp2100_low5_property(changed, config, profile))
        altered = dict(profile)
        altered["timer_bridge"] = {**profile["timer_bridge"], "irq_route": {}}
        self.assertIsNone(qemu_kp2100_low5_property(image, config, altered))
        wrong = SimpleNamespace(model="LG-SD810", board_status_input=None)
        self.assertIsNone(qemu_kp2100_low5_property(image, wrong, profile))
