import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.fact_memory_map import detect_linker_memory_map


def arm_branch(pc, target, link=False):
    delta = target - (pc + 8)
    return (0xEB000000 if link else 0xEA000000) | ((delta >> 2) & 0xFFFFFF)


class LinkerMemoryMapTests(unittest.TestCase):
    def test_decoder_absence_is_an_explicit_rejection(self):
        import msm5xxx_emulator.detection.fact_memory_map as memory_map
        spec = importlib.util.spec_from_file_location(
            'memory_map_without_decoder', Path(memory_map.__file__))
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, {'capstone': None}):
            spec.loader.exec_module(module)
        image = bytearray(0x40)
        struct.pack_into('<I', image, 0, 0xEA000006)
        self.assertEqual(module.detect_linker_memory_map(image),
                         (None, 'memory-map-decoder-unavailable'))

    def test_five_word_copy_and_zero_regions(self):
        image = bytearray(0x300)
        struct.pack_into("<I", image, 0, 0xEA000006)  # reset -> 0x20
        struct.pack_into("<II", image, 0x20, 0xE59F0004, 0xEAFFFFFE)
        struct.pack_into("<I", image, 0x2C, 0x100)
        struct.pack_into("<5I", image, 0x100, 0x200, 0x14000000, 0x20,
                         0x14000020, 0x40)
        profile, reason = detect_linker_memory_map(image)
        self.assertEqual(reason, "accepted")
        self.assertEqual(profile["ram_windows"], [{"base": 0x14000000, "size": 0x60}])
        self.assertEqual([r["kind"] for r in profile["regions"]], ["rw-copy", "zero-init"])

    def test_four_word_descriptor_requires_reset_call_and_init_stores(self):
        image = bytearray(0x300)
        struct.pack_into("<I", image, 0, 0xEA000006)
        struct.pack_into("<IIII", image, 0x20, 0xE59F0004, arm_branch(0x24, 0x80, True),
                         0xE59F1004, 0xEAFFFFFE)
        struct.pack_into("<I", image, 0x2C, 0x100)
        struct.pack_into("<I", image, 0x34, 0x80)
        struct.pack_into("<4I", image, 0x100, 0x200, 0x14000000, 0x20, 0x80)
        struct.pack_into("<3I", image, 0x80, 0xE5900000, 0xE5810000, 0xE12FFF1E)
        profile, reason = detect_linker_memory_map(image)
        self.assertEqual(reason, "accepted")
        self.assertEqual(profile["regions"][0]["kind"], "rw-copy")
        self.assertEqual(profile["regions"][0]["exec"], 0x14000000)

    def test_four_word_descriptor_rejects_code_after_return(self):
        image = bytearray(0x300)
        struct.pack_into("<I", image, 0, 0xEA000006)
        struct.pack_into("<IIII", image, 0x20, 0xE59F0004, arm_branch(0x24, 0x80, True),
                         0xE59F1004, 0xEAFFFFFE)
        struct.pack_into("<I", image, 0x2C, 0x100)
        struct.pack_into("<I", image, 0x34, 0x80)
        struct.pack_into("<4I", image, 0x100, 0x200, 0x14000000, 0x20, 0x80)
        struct.pack_into("<4I", image, 0x80, 0xE12FFF1E, 0xE5900000,
                         0xE5810000, 0xE12FFF1E)
        profile, reason = detect_linker_memory_map(image)
        self.assertIsNone(profile)
        self.assertEqual(reason, "memory-map-no-reset-linked-descriptor")

    def test_bic_invalidates_stale_register_pointer(self):
        from msm5xxx_emulator.detection.fact_memory_map import _reset, _trace

        image = bytearray(0x100)
        struct.pack_into("<I", image, 0, 0xEA000006)
        struct.pack_into("<4I", image, 0x20, 0xE59F0018, 0xE3C00101,
                         0xE5901000, 0xEAFFFFFE)
        struct.pack_into("<I", image, 0x40, 0x80)
        references, _ = _trace(image, _reset(image))
        self.assertFalse(any(entry.get("dereference") == 0
                             for entries in references.values() for entry in entries))

    def test_arm_thumb_interworking_veneer_and_return_reach_table(self):
        image = bytearray(0x240)
        struct.pack_into("<I", image, 0, 0xEA000006)
        # Load a tagged Thumb target and a tagged return address through
        # the ARM reset veneer, then enter Thumb with BX.
        struct.pack_into("<6I", image, 0x20,
                         0xE59F4028,       # LDR r4, [pc, #0x28]
                         0xE3140001,       # TST r4, #1
                         0x159FE030,       # LDRNE lr, [pc, #0x30]
                         0x059FE030,       # LDREQ lr, [pc, #0x30]
                         0xE12FFF14,       # BX r4
                         0xEAFFFFFE)
        struct.pack_into("<I", image, 0x50, 0x101)
        struct.pack_into("<I", image, 0x60, 0x121)
        struct.pack_into("<I", image, 0x64, 0x121)
        struct.pack_into("<H", image, 0x100, 0x4778)  # Thumb BX pc -> ARM at 0x104
        struct.pack_into("<I", image, 0x104, 0xE12FFF1E)  # ARM BX lr -> Thumb at 0x120
        struct.pack_into("<2H", image, 0x120, 0x4800, 0xE7FE)
        struct.pack_into("<I", image, 0x124, 0x180)
        struct.pack_into("<5I", image, 0x180, 0x200, 0x14000000, 0x20,
                         0x14000020, 0x40)
        profile, reason = detect_linker_memory_map(image)
        self.assertEqual(reason, "accepted")
        self.assertEqual(profile["regions"][0]["exec"], 0x14000000)

    def test_unlinked_table_is_rejected(self):
        image = bytearray(0x300)
        struct.pack_into("<I", image, 0, 0xEA000006)
        struct.pack_into("<II", image, 0x20, 0xEAFFFFFE, 0xEAFFFFFE)
        struct.pack_into("<5I", image, 0x100, 0x200, 0x14000000, 0x20,
                         0x14000020, 0x40)
        profile, reason = detect_linker_memory_map(image)
        self.assertIsNone(profile)
        self.assertEqual(reason, "memory-map-no-reset-linked-descriptor")

    def test_out_of_bounds_copy_is_rejected(self):
        image = bytearray(0x300)
        struct.pack_into("<I", image, 0, 0xEA000006)
        struct.pack_into("<II", image, 0x20, 0xE59F0004, 0xEAFFFFFE)
        struct.pack_into("<I", image, 0x2C, 0x100)
        struct.pack_into("<5I", image, 0x100, 0x2F0, 0x14000000, 0x40,
                         0x14000040, 0x40)
        profile, reason = detect_linker_memory_map(image)
        self.assertIsNone(profile)
        self.assertEqual(reason, "memory-map-no-reset-linked-descriptor")

    def test_unsupported_vector_and_non_bytes(self):
        self.assertEqual(detect_linker_memory_map(bytes(32))[1], "memory-map-reset-vector-unsupported")
        self.assertEqual(detect_linker_memory_map(None)[1], "memory-map-image-not-bytes")


if __name__ == "__main__":
    unittest.main()
