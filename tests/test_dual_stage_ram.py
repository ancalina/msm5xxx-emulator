"""Source-shaped fixtures without original firmware file dependencies."""
from corpus import snippet
import argparse
from pathlib import Path
import tempfile
from unittest.mock import patch
import struct
import unittest
from msm5xxx_emulator.core.config import LinkerLayout
from msm5xxx_emulator.detection.memory_layout import dual_stage_ram_profile

def chunks():
    return (
    (0x130, snippet("test_dual_stage_ram", "reset_interworking")),
    (0x328, snippet("test_dual_stage_ram", "reset_vector_table")),
    (0x7e0, snippet("test_dual_stage_ram", "memory_copy_routine")),
    (0xc14, snippet("test_dual_stage_ram", "bootstrap_routine")),
    (0x28f8, bytes.fromhex("0c290000fcef87010800000004f08701280a0000")),
    (0x10100, snippet("test_dual_stage_ram", "second_stage_entry")),
    (0x5b9c8, snippet("test_dual_stage_ram", "second_stage_copy_routine")),
    (0x5bbec, snippet("test_dual_stage_ram", "second_stage_copy_table")),
)


def fixture(shift=0, load=0):
    image = bytearray(0x100000 + shift)
    for at, chunk in chunks():
        image[at + shift:at + shift + len(chunk)] = chunk
    put = lambda at, value: struct.pack_into("<I", image, at + shift, value)
    struct.pack_into("<I", image, 0, 0xea000000 | ((0x130 + shift - 8) // 4))
    # All reset interworking call/return literals move with the code.
    for gate in (0x130, 0x148, 0x160, 0x190, 0x1a8, 0x1c0):
        for pc in (gate, gate + 8, gate + 12):
            op = struct.unpack_from("<I", image, pc + shift)[0]
            pool = pc + 8 + (op & 0xfff)
            old = struct.unpack_from("<I", image, pool + shift)[0]
            put(pool, old + shift + load)
    for at in (0x87c, 0x880, 0x884, 0x888, 0x88c, 0x101a0, 0x101a4, 0x101a8,
               0x5bc30, 0x5bc34, 0x5bc38):
        put(at, struct.unpack_from("<I", image, at + shift)[0] + shift + load)
    for at in range(0x5bbf0, 0x5bc2c, 4):
        put(at, struct.unpack_from("<I", image, at + shift)[0] + shift + load)
    put(0x1017c, 0xd0000 + shift + load)
    put(0x28f8, 0x290c + shift + load)
    for at, source in ((0x10140, 0x80000), (0x10154, 0xb0000), (0x10168, 0xc0000)):
        put(at, source + shift + load)
    fields = struct.unpack_from("<5I", image, 0x28f8 + shift)
    linker = LinkerLayout(0x28f8 + shift, fields[0] - load, *fields[1:])
    return image, linker


class DualStageRamTests(unittest.TestCase):
    def test_positive_relocated(self):
        for shift, load in ((0, 0), (0x4000, 0), (0, 0x10000)):
            image, linker = fixture(shift, load)
            profile, reason = dual_stage_ram_profile(image, linker, load)
            self.assertIsNone(reason)
            self.assertEqual((profile["ram_base"], profile["ram_size"]), (0x01000000, 0x01000000))
            self.assertEqual(profile["required_end"], 0x0187fa2c)
            self.assertNotIn(0x03800000, [a for a, _ in profile["required_spans"]])

    def test_instruction_mutations(self):
        for pc in (0x1d8, 0x1dc, 0x1e0, 0x10120, 0x10130,
                   0x7fc, 0x838, 0x852, 0x5b9d8, 0x5b9e6, 0x5b9e8,
                   0x5ba0c, 0x5ba1a, 0x5ba24, 0x5ba36, 0x5ba62,
                   0x5ba78, 0x5baf6, 0x5bb0a, 0x5bb88):
            with self.subTest(pc=hex(pc)):
                image, linker = fixture()
                image[pc] ^= 1
                self.assertIsNone(dual_stage_ram_profile(image, linker)[0])

    def test_literal_table_stack_mutations(self):
        for pc in (0x394, 0x398, 0x3a0, 0x3a4, 0x87c, 0x884,
                   0x86c, 0x870, 0x101a0, 0x101a4, 0x10194,
                   0x5bbf0, 0x5bc10, 0x5bc28, 0x10144, 0x10148,
                   0x1014c, 0x10150, 0x10158):
            with self.subTest(pc=hex(pc)):
                image, linker = fixture()
                struct.pack_into("<I", image, pc, 0xffffffff)
                self.assertIsNone(dual_stage_ram_profile(image, linker)[0])

    def test_linker_conflict_and_normal_owner(self):
        image, linker = fixture()
        self.assertIsNone(dual_stage_ram_profile(image, None)[0])
        wrong = LinkerLayout(linker.table_offset, linker.data_source, linker.data_target + 4,
                             linker.data_size, linker.bss_target + 4, linker.bss_size)
        self.assertEqual(dual_stage_ram_profile(image, wrong)[1], "dual-stage-linker-conflict")
        fields = struct.unpack_from("<5I", image, 0x10140)
        normal = LinkerLayout(0x10140, *fields)
        self.assertIsNotNone(dual_stage_ram_profile(image, normal)[0])

    def test_unlinked_duplicates_do_not_own_ram(self):
        image, linker = fixture()
        for at, chunk in chunks():
            if at == 0x5b9c8:
                image[0x60000:0x60000 + len(chunk)] = chunk
        self.assertIsNotNone(dual_stage_ram_profile(image, linker)[0])
        image[0x5b9e8] ^= 1
        self.assertIsNone(dual_stage_ram_profile(image, linker)[0])

    def test_appended_ram_and_rom_overlap(self):
        image, linker = fixture()
        image.extend(bytes(0x1800000 - len(image)))
        self.assertIsNotNone(dual_stage_ram_profile(image, linker)[0])
        # Appended bytes cannot turn a ROM-overlapping RAM destination valid.
        struct.pack_into("<5I", image, 0x10140, 0x80000, 0x80000, 0x25774,
                         0xa5774, 0x175ffc8)
        self.assertEqual(dual_stage_ram_profile(image, linker)[1], "dual-stage-rom-ram-overlap")

    def test_explicit_flash_keeps_downstream_primary_bounded(self):
        from msm5xxx_emulator.detection import firmware
        image, _ = fixture()
        # A complete synthetic vector table admits the real firmware pipeline.
        for index in range(1, 8):
            pc = index * 4
            struct.pack_into("<I", image, pc, 0xea000000 | ((0x130 - pc - 8) // 4))
        image.extend(bytes(0x1800000 - len(image)))
        real_leaf = firmware.dual_stage_ram_profile
        accepted = []

        def observe_leaf(*args, **kwargs):
            result = real_leaf(*args, **kwargs)
            accepted.append(result[0])
            return result

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source-shaped.bin"
            path.write_bytes(image)
            with patch.object(firmware, "dual_stage_ram_profile", side_effect=observe_leaf), patch.object(
                    firmware, "find_ready_poll_profile", wraps=firmware.find_ready_poll_profile) as downstream:
                config = firmware.detect(path, argparse.Namespace(flash_size=0x100000, image_offset=0))
                self.assertTrue(any(profile is not None for profile in accepted))
                self.assertEqual((config.ram_base, config.ram_size), (0x01000000, 0x01000000))
                self.assertEqual(config.flash_size, 0x100000)
                self.assertTrue(downstream.call_args_list)
                self.assertLessEqual(max(len(call.args[0]) for call in downstream.call_args_list), 0x100000)
            with patch.object(firmware, "dual_stage_ram_profile", wraps=real_leaf) as leaf:
                config = firmware.detect(path, argparse.Namespace(
                    flash_size=0x100000, image_offset=0,
                    ram_base=0x01800000, ram_size=0x00800000))
                self.assertEqual((config.ram_base, config.ram_size), (0x01800000, 0x00800000))
                self.assertEqual(config.flash_size, 0x100000)
                leaf.assert_not_called()

    def test_allocation_cap(self):
        image, linker = fixture()
        # A distant, disjoint third segment retains its typed copy/zero shape.
        struct.pack_into("<I", image, 0x1016c, 0x11000000)
        struct.pack_into("<I", image, 0x10174, 0x1100008c)
        self.assertEqual(dual_stage_ram_profile(image, linker)[1],
                         "dual-stage-allocation-overflow")

    def test_truncation_and_overlap(self):
        image, linker = fixture()
        for end in (0, 0x3a7, 0x88b, 0x101af, 0x5bc2b, 0x90000):
            self.assertIsNone(dual_stage_ram_profile(image[:end], linker)[0])
        for at, value in ((0x10144, 0x1000), (0x10150, 0xfffffffc),
                          (0x10168, 0xfffffff0), (0x1016c, 0x01800000)):
            broken = bytearray(image)
            struct.pack_into("<I", broken, at, value)
            self.assertIsNone(dual_stage_ram_profile(broken, linker)[0])


if __name__ == "__main__":
    unittest.main()
