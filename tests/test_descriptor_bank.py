import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.storage import descriptor_bank
from msm5xxx_emulator.devices.storage.nor import NORFlash
from msm5xxx_emulator.devices.storage.descriptor_state import load_truncated_nor_state


def half(image, at, value):
    struct.pack_into('<H', image, at, value)


def word(image, at, value):
    struct.pack_into('<I', image, at, value)


def ldr_literal(image, at, register, pool, value):
    distance = pool - ((at + 4) & ~3)
    assert distance >= 0 and distance % 4 == 0
    half(image, at, 0x4800 | register << 8 | distance // 4)
    word(image, pool, value)


def synthetic_image():
    image = bytearray(0x200000)
    identifier, table, writer, entry = 0x1000, 0x2000, 0x3000, 0x3500
    word(image, identifier - 16, table)
    word(image, identifier - 12, 0x2400)
    word(image, identifier - 8, 0x2500)
    word(image, identifier - 4, 0)
    image[identifier:identifier + 4] = b'\x00\xb5\x00\xbd'
    word(image, table, 0x2800)
    word(image, table + 4, 7)
    for i in range(7):
        word(image, table + 8 + 4 * i, 0x10000)
    descriptor = table + 8 + 7 * 4
    for i, value in enumerate((0x12340001, 0, 0x70001, 0, 0, 0xc0000, 0x38000)):
        word(image, descriptor + 4 * i, value)
    word(image, descriptor + 0x24, writer | 1)
    fixed = {0: 0xb5f0, 0x20: 0x1901, 0x2a: 0x4291, 0x32: 0xd308,
             0x38: 0x194a, 0x3a: 0x429a, 0x3c: 0xd803, 0x42: 0x4295, 0x44: 0xd92a,
             0x24: 0x2203, 0x28: 0x04d2, 0x34: 0x231f, 0x36: 0x041b,
             0x3e: 0x2207, 0x40: 0x0412}
    for off, value in fixed.items():
        half(image, writer + off, value)
    for off, value in {2: 0xb5b0, 6: 0x6980, 8: 0x6809,
                       10: 0x0040, 12: 0x1844}.items():
        half(image, entry + off, value)
    ldr_literal(image, entry, 0, 0x3580, descriptor - 4)
    ldr_literal(image, entry + 0x18, 1, 0x3584, 0x1001011)
    ldr_literal(image, entry + 0x28, 0, 0x3588, 0x1001000)
    return image, identifier, table, writer, descriptor


class DescriptorBankTests(unittest.TestCase):
    def test_enclosing_bank_and_source_rejections(self):
        image, identifier, table, writer, descriptor = synthetic_image()
        with patch.object(descriptor_bank, 'PRIMARY_FSD_AMD_X16_ID_ROUTINE',
                          b'\x00\xb5\x00\xbd'):
            detect = lambda data: descriptor_bank.find_descriptor_bank(
                bytes(data), identifier, len(data), 0x1000000, 0x800000)
            self.assertEqual(detect(image), (0x180000, 0x80000, 0x10000, 1, 0x1234))
            for offset in (identifier, identifier - 4, table + 8, descriptor + 8,
                           descriptor + 0x14, writer + 0x2a, 0x3584):
                broken = image[:]
                broken[offset] ^= 1
                self.assertIsNone(detect(broken), hex(offset))

    def test_rejects_unbounded_or_non_power_of_two_flash(self):
        self.assertIsNone(descriptor_bank.find_descriptor_bank(b'', None, 0, 0, 0))
        self.assertIsNone(descriptor_bank.find_descriptor_bank(b'\0' * 64, 16, 63, 0, 0))

    def test_truncated_image_uses_linked_extent(self):
        image, identifier, table, writer, descriptor = synthetic_image()
        with patch.object(descriptor_bank, 'PRIMARY_FSD_AMD_X16_ID_ROUTINE',
                          b'\x00\xb5\x00\xbd'):
            truncated = bytes(image[:0x190000])
            detect = lambda data, size: descriptor_bank.find_truncated_descriptor_bank(
                data, identifier, size, 0x1000000, 0x800000)
            self.assertEqual(detect(truncated, 0x1a0000),
                             (0x200000, (0x180000, 0x80000, 0x10000, 1, 0x1234)))
            self.assertIsNone(detect(truncated, 0x200000))
            self.assertIsNone(detect(truncated, 0x180000))
            broken = bytearray(truncated)
            broken[writer + 0x2a] ^= 1
            self.assertIsNone(detect(bytes(broken), 0x1a0000))

    def test_saved_state_must_preserve_code_prefix(self):
        source = b'code' + b'bank'
        profile = (4, 4, 1, 1, 1)
        self.assertTrue(descriptor_bank.source_prefix_matches(source, b'codeDATA', profile))
        self.assertFalse(descriptor_bank.source_prefix_matches(source, b'CodeDATA', profile))
        self.assertFalse(descriptor_bank.source_prefix_matches(source, b'cod', profile))

    def test_legacy_state_keeps_writable_data_and_rejects_modified_code(self):
        source = b'codebank'
        profile = (4, 8, 1, 1, 1)
        seed = source.ljust(12, b'\xff')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            flash = NORFlash(seed, path)
            flash.data[4] = ord('Z')
            flash.save()
            loaded, imported = load_truncated_nor_state(source, 12, profile, path)
            self.assertTrue(imported)
            self.assertEqual(loaded, b'codeZank' + b'\xff' * 4)
            flash = NORFlash(seed, path)
            flash.data[0] = ord('C')
            flash.save()
            self.assertIsNone(load_truncated_nor_state(source, 12, profile, path))
