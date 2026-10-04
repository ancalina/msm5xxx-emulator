"""Revision admission requires qualified consumers and a mapped boot caller."""
import struct
import unittest

from msm5xxx_emulator.detection.boot import (
    MSM5500_REVISION_RAW_GETTER, MSM5500_REVISION_TRANSFORMER,
    detect_msm5500_revision_f025,
)


class RevisionTests(unittest.TestCase):
    def test_relocated_diagnostic_admission_and_native_fallback(self):
        raw = bytearray(b"\xff" * 0x8000)

        def bl(site, target):
            delta = target - site - 4
            struct.pack_into("<2H", raw, site,
                             0xF000 | (delta >> 12 & 0x7FF),
                             0xF800 | (delta >> 1 & 0x7FF))

        raw[0x1000:0x1012] = bytes.fromhex("0c490d4a0879002811d1012008710b48808b")
        raw[0x1012:0x1012 + len(MSM5500_REVISION_TRANSFORMER)] = MSM5500_REVISION_TRANSFORMER
        struct.pack_into("<3I", raw, 0x1034, 0x01010000, 0x01020000, 0x03000740)
        raw[0x2000:0x200A] = MSM5500_REVISION_RAW_GETTER
        struct.pack_into("<I", raw, 0x200C, 0x03000740)
        for site, field in ((0x3000, 1), (0x3010, 3)):
            bl(site, 0x2000)
            struct.pack_into("<H", raw, site + 4, 0x7038 | field << 6)
        bl(0x4000, 0x5000)
        struct.pack_into("<4H", raw, 0x4004, 0x4B0E, 0x4298, 0xDA02, 0xA03D)
        bl(0x400C, 0x6000)
        struct.pack_into("<I", raw, 0x4040, 0xF022)
        raw[0x4100:0x4114] = b"UNSUPPORTED MSM REV "
        raw[0x5000:0x500C] = bytes.fromhex("7847c04600c09fe51cff2fe1")
        struct.pack_into("<I", raw, 0x500C, 0x01000001)

        def runtime(position):
            return 0x01000000 + position - 0x1000 if 0x1000 <= position < 0x1040 else position

        def file(address):
            return 0x1000 + address - 0x01000000 if 0x01000000 <= address < 0x01000040 else address

        self.assertFalse(detect_msm5500_revision_f025(bytes(raw))[0])
        self.assertTrue(detect_msm5500_revision_f025(bytes(raw), runtime, file)[0])
        self.assertFalse(detect_msm5500_revision_f025(bytes(raw), runtime, lambda _: None)[0])
        # Copy the caller/literal and veneer together while varying whether
        # the ADR's diagnostic bytes actually exist at their runtime address.
        for diagnostic_size, accepted in ((0, False), (4, False), (20, True)):
            spans = ((0x4000, 0x01400000, 0x100 + diagnostic_size),
                     (0x5000, 0x01401000, 0x10))

            def copied_runtime(position):
                for source, target, length in spans:
                    if source <= position < source + length:
                        return target + position - source
                return runtime(position)

            def copied_file(address):
                for source, target, length in spans:
                    if target <= address < target + length:
                        return source + address - target
                return file(address)

            with self.subTest(diagnostic_size=diagnostic_size):
                self.assertEqual(detect_msm5500_revision_f025(
                    bytes(raw), copied_runtime, copied_file)[0], accepted)
        for offset in (0x500C, 0x500D, 0x5000, 0x400A, 0x1004, 0x3004, 0x4100):
            with self.subTest(offset=offset):
                broken = bytearray(raw)
                broken[offset] ^= 1
                self.assertFalse(detect_msm5500_revision_f025(bytes(broken), runtime, file)[0])
        unaligned = bytearray(raw)
        unaligned[0x4001:0x4011] = raw[0x4000:0x4010]
        unaligned[0x4000] = 0xFF
        self.assertFalse(detect_msm5500_revision_f025(
            bytes(unaligned), lambda p: 0x4000 if p == 0x4001 else runtime(p), file)[0])
        duplicate = bytes(raw) + MSM5500_REVISION_RAW_GETTER
        self.assertFalse(detect_msm5500_revision_f025(duplicate, runtime, file)[0])
        raw[0x4100:0x4115] = b" UNSUPPORTED MSM REV "
        self.assertTrue(detect_msm5500_revision_f025(bytes(raw), runtime, file)[0])
        # Preserve the existing title-case admission when an older copy's
        # runtime map is still unresolved by static overlay detection.
        raw[0x7000:0x7015] = b" Unsupported MSM REV "
        self.assertTrue(detect_msm5500_revision_f025(bytes(raw))[0])


if __name__ == "__main__":
    unittest.main()
