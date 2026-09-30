"""Closed high-RAM bootstrap acceptance and negative controls."""
import argparse
from pathlib import Path
import struct
import tempfile
import unittest
from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.memory_layout import (
    find_high_ram_readback_tests, high_ram_bootstrap_profile,
)


class HighRAMBootstrapTests(unittest.TestCase):
    def test_reset_readback_extent_and_rejections(self):
        image = bytearray(0x800)
        struct.pack_into('<I', image, 0, 0xEA00003E)  # reset 0x100
        struct.pack_into('<5I', image, 0x100,
                         0xE59F4078, 0xE3140001, 0x159FE074,
                         0x059FE074, 0xE12FFF14)
        struct.pack_into('<3I', image, 0x180, 0x300, 0x115, 0x118)
        struct.pack_into('<7I', image, 0x2E4, 0x14000000, 0x3FFFFF,
                         0x10, 0x55AA0F, 0xAA0F, 0x55, 0x030006D0)
        body = bytes.fromhex('54019fe5000090e50110a0e30020a0e348319fe5003093e5004083e0001080e5002084e5003090e5010053e14500001a8110a0e1800c51e3f7ffffda0120a0e31c319fe5003093e50020c3e50020a0e30020c3e50f10a0e30010c0e5aa10a0e30110c0e55510a0e30210c0e5f4109fe5001091e5001081e0031001e50420a0e3e0309fe5003093e50240e0e1004082e78220a0e1030052e1faffffba0020d0e50f0052e32700001a0120d0e5aa0052e32400001a0220d0e5550052e32100001a0420a0e30240e0e1005092e7040055e11c00001a8220a0e1030052e1f8ffffba032011e5010052e11600001a0030a0e30330c0e570209fe5002092e5004090e5040052e10f00001a60209fe5002092e5b040d0e1040052e10a00001a50209fe5002092e5b240d0e1040052e10500001aaa20a0e30140d0e5040052e10100001a0000a0e30ef0a0e128009fe50ef0a0e1')
        image[0x300:0x450] = body
        self.assertEqual(find_high_ram_readback_tests(bytes(image)), [0x300])
        self.assertEqual(find_high_ram_readback_tests(b'\x00\x00\x00\x14' * 128), [])
        self.assertEqual(find_high_ram_readback_tests(bytes(image[:0x440])), [])
        low_ram = image.copy()
        struct.pack_into('<I', low_ram, 0x2E4, 0x01100000)
        self.assertEqual(find_high_ram_readback_tests(bytes(low_ram)), [])
        for offset, field in ((0,0),(0x10,8),(0x40,24),(0x6C,4),
                              (0x80,4),(0xF4,12),(0x108,16),(0x11C,20)):
            instruction = struct.unpack_from('<I', image, 0x300+offset)[0]
            literal = 0x300+offset+8+(instruction & 0xFFF)
            struct.pack_into('<I', image, literal, 0x2E4+field)
        self.assertEqual(high_ram_bootstrap_profile(bytes(image)),
                         (0x14000000, 0x400000))
        reserved = image.copy()
        struct.pack_into('<I', reserved, 0x2E8, 0x3FFDFF)
        self.assertEqual(high_ram_bootstrap_profile(bytes(reserved)),
                         (0x14000000, 0x400000))
        larger = image.copy()
        struct.pack_into('<I', larger, 0x2E8, 0x7FFFFF)
        self.assertEqual(high_ram_bootstrap_profile(bytes(larger)),
                         (0x14000000, 0x800000))
        for offset, value in ((0,0),(0x180,0x304),(0x188,0x11C),
                              (0x2E4,0x01000000),(0x2E8,0x5FFFFF),
                              (0x2F0,0),(0x31C,0),(0x45C,0)):
            bad = image.copy()
            struct.pack_into('<I', bad, offset, value)
            with self.subTest(offset=offset):
                self.assertIsNone(high_ram_bootstrap_profile(bytes(bad)))
        for length in (0,3,0x100,0x310,0x450):
            self.assertIsNone(high_ram_bootstrap_profile(bytes(image[:length])))
        # A reset-called Thumb copy can corroborate an otherwise uncalled
        # readback descriptor. Only literal offsets vary within the loop shape.
        copied = larger.copy()
        struct.pack_into('<I', copied, 0x180, 0x501)
        struct.pack_into('<H', copied, 0x114, 0x4778)
        struct.pack_into('<12H', copied, 0x500,
                         0x481F, 0x6804, 0x481F, 0x6800, 0x1826, 0x481F,
                         0x6805, 0xE001, 0xCD01, 0xC401, 0x42B4, 0xD3FB)
        struct.pack_into('<3I', copied, 0x580, 0x604, 0x608, 0x600)
        struct.pack_into('<3I', copied, 0x600, 0x700, 0x147F0000, 0x100)
        self.assertEqual(high_ram_bootstrap_profile(bytes(copied)),
                         (0x14000000, 0x800000))
        alternate = copied.copy()
        struct.pack_into('<12H', alternate, 0x500,
                         0x4A1F, 0x6814, 0x4A1F, 0x6812, 0x18A6, 0x4A1F,
                         0x6815, 0xE001, 0xCD04, 0xC404, 0x42B4, 0xD3FB)
        self.assertEqual(high_ram_bootstrap_profile(bytes(alternate)),
                         (0x14000000, 0x800000))
        smaller_copy = copied.copy()
        struct.pack_into('<I', smaller_copy, 0x2E8, 0x3FFFFF)
        struct.pack_into('<I', smaller_copy, 0x604, 0x143F0000)
        self.assertEqual(high_ram_bootstrap_profile(bytes(smaller_copy)),
                         (0x14000000, 0x400000))
        for offset, value, width in (
                (0x184, 0x119, 4), (0x188, 0x11C, 4), (0x114, 0, 2),
                (0x514, 0x42B5, 2), (0x502, 0x6844, 2),
                (0x50E, 0xE000, 2), (0x510, 0xCD03, 2),
                (0x580, 0x602, 4), (0x584, 0x60C, 4),
                (0x600, 0x780, 4), (0x604, 0x14800000, 4),
                (0x604, 0x14001000, 4), (0x608, 0, 4),
                (0x608, 0x101, 4), (0x31C, 0, 4)):
            bad = copied.copy()
            struct.pack_into('<I' if width == 4 else '<H', bad, offset, value)
            with self.subTest(copy_offset=offset, value=value):
                self.assertIsNone(high_ram_bootstrap_profile(bytes(bad)))
        with tempfile.TemporaryDirectory() as directory:
            firmware = Path(directory) / 'anonymous.bin'
            firmware.write_bytes(image)
            automatic = detect(firmware)
            self.assertEqual((automatic.ram_base, automatic.ram_size),
                             (0x14000000, 0x400000))
            overridden = detect(firmware, argparse.Namespace(
                ram_base=0x01800000, ram_size=0x800000))
            self.assertEqual((overridden.ram_base, overridden.ram_size),
                             (0x01800000, 0x800000))
            rebased = detect(firmware, argparse.Namespace(load_address=0x10000000))
            self.assertFalse(any('high-RAM readback/extent profile detected' in note
                                 for note in rebased.detection_notes))
            firmware.write_bytes(copied)
            copied_config = detect(firmware)
            self.assertEqual((copied_config.ram_base, copied_config.ram_size),
                             (0x14000000, 0x800000))
