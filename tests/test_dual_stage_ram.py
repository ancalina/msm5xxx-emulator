"""Source-shaped fixtures without original firmware file dependencies."""
import argparse
from pathlib import Path
import tempfile
from unittest.mock import patch
import struct
import unittest
from msm5xxx_emulator.core.config import LinkerLayout
from msm5xxx_emulator.detection.memory_layout import dual_stage_ram_profile

CHUNKS = (
    (0x130, bytes.fromhex("24429fe5010014e320e29f1520e29f0514ff2fe17847000018429fe5010014e314e29f1514e29f0514ff2fe1784700000c429fe5010014e308e29f1508e29f0514ff2fe178470000d7f021e3a4d19fe5dbf021e3f4d19fe5d3f021e3f0d19fe5f0419fe5010014e3ece19f15ece19f0514ff2fe178470000e4419fe5010014e3e0e19f15e0e19f0514ff2fe178470000d8419fe5010014e3d4e19f15d4e19f0514ff2fe178470000000050e30300001ac63f00ea")),
    (0x328, bytes.fromhex("64f28701190700009100000094000000c5030000ad000000b00000003d070000f9000000fc0000001d01000020010000ed0100005d0b00004501000048010000410a00005d010000600100007d0a0000750100007801000064f38701d4f08701850b0000a5010000a8010000e1070000bd010000c0010000150c0000d5010000d8010000a11a00000d02000010020000")),
    (0x7e0, bytes.fromhex("80b400201f4a0121002711701770013000041d4b000c9842f7db1c4bd88bd88bd88bd88b1a48d8831a48d8831a48d88300201170177001300004134b000c9842f7db117017701548154c036824681e19144b1d68046801e001cd01c4b442fbd3117017701048114c036824681e191c1c00e080c4b442fcd3117017701170177080bc704700070003ff0f0000e0ff7f01b2b20000d0d00000ffff0000fc28000000290000f82800000429000008290000")),
    (0xc14, bytes.fromhex("80b50027fff7ccff3c4908703b480078002803d1012080bc08bc18470020384b18810022052a00db66e004e0501c0004000c021cf6e71f20314b98820620314b18802f488089c106c90e1f2901d10020e1e7")),
    (0x28f8, bytes.fromhex("0c290000fcef87010800000004f08701280a0000")),
    (0x10100, bytes.fromhex("d2f021e388d09fe5dff021e384d09fe5d1f021e30dd02de07cd09fe5d3f021e378009fe5010010e374e09f1574e09f0510ff2fe1784700006c209fe512ff2fe164496700000000017457020074570201c8ff7d00d8a069003c57800170d90000ac308101d4290000487a6a00fcce87018c00000088cf870104000000d47a6a000000800388fa0000012319430160994306c0f7467cf587017cf987012cfa8701c9b90500350101003801010015f50e00")),
    (0x5b9c8, bytes.fromhex("884900b50120087000200870874a864b1568874a1f6814687f09012211e008cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c40a700870013febd2784b1f68bb085f077f0f03e008cd08c40a700870013ff9d20a700870744b1f68744b7f091c6809e001c401c401c401c401c401c401c401c40a700870013ff3d26b4b1f68bb085f077f0f02e001c40a700870013ffad20a700870664b1f68664b7f091d68664b1c6811e008cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c40a700870013febd2584b1f68bb085f077f0f03e008cd08c40a700870013ff9d20a700870544b1f68544b7f091c6809e001c401c401c401c401c401c401c401c40a700870013ff3d24b4b1f68bb085f077f0f03e0002001c40a700870013ff9d24848474b056848481f6804687f09002011e008cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c40a700870013febd2394b1f68bb085f077f0f03e008cd08c40a700870013ff9d20a700870354b1f68354b7f091c6809e001c401c401c401c401c401c401c401c40a700870013ff3d22c4b1f68bb085f077f0f03e0002001c40a700870013ff9d228488280294b27481d68284b07681c687f090fe008cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c4013fedd20768b80847077f0f01e001cd01c4013ffbd20a70002008700a700870")),
    (0x5bbec, bytes.fromhex("00070003480101004001010044010100500101004c0101005c0101005401010058010100640101006001010070010100680101006c0101007801010074010100a0008004840101007c01010080010100")),
)


def fixture(shift=0, load=0):
    image = bytearray(0x100000 + shift)
    for at, chunk in CHUNKS:
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
        for at, chunk in CHUNKS:
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
