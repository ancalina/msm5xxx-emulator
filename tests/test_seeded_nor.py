"""Seeded NOR admission must preserve descriptor/driver/consumer agreement."""
from pathlib import Path
import struct
import unittest

from msm5xxx_emulator.detection.storage import seeded_amd_x16_nor_profile
from corpus import FIRMWARE_ROOT


class SeededNorTests(unittest.TestCase):
    def test_descriptor_class_and_rejects(self):
        def detect(image, load=0, ram_size=0x800000):
            return seeded_amd_x16_nor_profile(
                image, load, len(image), 0x1000000, ram_size)

        self.assertEqual(detect(b""), (None, None))
        corpus = FIRMWARE_ROOT
        firmware = corpus / "incoming-20260914/SCH-X700_UG25_JTAG.bin"
        if not firmware.is_file():
            self.skipTest("private firmware corpus is not available")
        image = firmware.read_bytes()
        expected = ((0x800000, 0x400000, ((8, 0x2000), (63, 0x10000)),
                     0x98, 0x9C), None)
        self.assertEqual(detect(image), expected)
        self.assertIsNone(detect(image, load=0x1000)[0])
        self.assertIsNone(detect(image, ram_size=0x1000)[0])
        self.assertIsNone(detect(image[:0xA00000])[0])
        # Geometry, callbacks, code, bank literals, state and byte-unit consumer.
        for offset in (0x384618, 0x38461C, 0x384744, 0x384748,
                       0x38474C, 0x384750, 0x384754, 0x384764,
                       0x87684, 0x87728, 0x8772C, 0x87724,
                       0x87424, 0x874EA, 0x870F8, 0x7FA6A, 0x87324,
                       0x7FAC4, 0x7FB18):
            with self.subTest(offset=hex(offset)):
                changed = bytearray(image)
                changed[offset] ^= 1
                profile, reject = detect(changed)
                self.assertIsNone(profile)
                self.assertIsNotNone(reject)
        # Descriptor location is not an admission key. Duplicate records reject.
        moved = bytearray(image)
        block = image[0x384614:0x384768]
        moved[0x400000:0x400000 + len(block)] = block
        self.assertIsNone(detect(moved)[0])
        moved[0x400000 + 0x124 + 0x10] ^= 1
        self.assertIsNone(detect(moved)[0])  # Conflicting duplicate also rejects.
        moved[0x400000:0x400000 + len(block)] = block
        moved[0x384614:0x384768] = bytes(len(block))
        self.assertEqual(detect(moved), expected)
        struct.pack_into("<I", moved, 0x400000 + 0x124 + 0x18, 0xFFFFFFFD)
        self.assertIsNone(detect(moved)[0])


if __name__ == "__main__":
    unittest.main()
