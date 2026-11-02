import os
from pathlib import Path
import unittest

from msm5xxx_emulator.detection.input_lg_kp import find_kp_legacy_scanner
from msm5xxx_emulator.detection.arm import thumb_bl_target
from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.qemu.decoder import QemuDecoder
from msm5xxx_emulator.qemu.transport import qemu_kp_low5_property


class LGKPLegacyScannerTest(unittest.TestCase):
    def test_firmware_scanner_and_negative_mutations(self):
        root = Path(os.environ.get("MSM5XXX_TEST_FIRMWARE_ROOT", "/nonexistent"))
        for model in ("LG-KP2000", "LG-KP2006"):
            with self.subTest(model=model):
                path = root / (model + ".bin")
                if not path.exists():
                    self.skipTest("private LG firmware not available")
                image = path.read_bytes()
                scanner = find_kp_legacy_scanner(image, model)
                self.assertIsNotNone(scanner)
                self.assertEqual(scanner["descriptor_pointer"], 0x010bd680)
                self.assertEqual(scanner["single_key_column_sense"], [30, 29, 27, 23, 15])
                self.assertIsNone(find_kp_legacy_scanner(image, "LG-SD810"))
                config = detect(path)
                decoder = QemuDecoder(config)
                profile = decoder.direct_input_profile
                self.assertEqual(decoder.direct_input_detection, "accepted")
                self.assertIsNotNone(qemu_kp_low5_property(image, config, profile))
                self.assertEqual(set(decoder.direct_input_positions), set(range(11, 23)))
                altered = dict(profile)
                altered["timer_bridge"] = None
                self.assertIsNone(qemu_kp_low5_property(image, config, altered))
                altered = dict(profile)
                altered["timer_bridge"] = {**profile["timer_bridge"], "irq_route": {}}
                self.assertIsNone(qemu_kp_low5_property(image, config, altered))
                helper = thumb_bl_target(image, scanner["function"] + 0x5a)
                for offset in (0x0c, 0x26, 0x42):
                    changed = bytearray(image)
                    changed[helper + offset] ^= 1
                    self.assertIsNone(find_kp_legacy_scanner(changed, model))
                for offset in (0x50, 0x86, 0x116, 0x182, 0x19c,
                               0x1b8, 0x1cc, 0x1d0):
                    changed = bytearray(image)
                    changed[scanner["function"] + offset] ^= 1
                    self.assertIsNone(find_kp_legacy_scanner(changed, model),
                                      hex(offset))
