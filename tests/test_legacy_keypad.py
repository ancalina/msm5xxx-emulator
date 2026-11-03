"""Synthetic GPIO scanner and board-consumer linkage."""
import hashlib
import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection import legacy_keypad
from msm5xxx_emulator.detection.legacy_keypad import (
    _SCAN_SIZE, _BOARD_SIZE, _BOARD_ANCHOR, _BOARD_BASE, find_legacy_six_row_keypad,
)


def branch(image, site, target):
    delta = target - site - 4
    struct.pack_into('<HH', image, site, 0xf000 | ((delta >> 12) & 0x7ff),
                     0xf800 | ((delta >> 1) & 0x7ff))


def literal(image, site, register, pool, value):
    delta = pool - ((site + 4) & ~3)
    assert delta >= 0 and delta % 4 == 0 and delta < 1024
    struct.pack_into('<H', image, site, 0x4800 | (register << 8) | (delta // 4))
    struct.pack_into('<I', image, pool, value)


class LegacyKeypadTests(unittest.TestCase):
    def fixture(self):
        image = bytearray(0x1000)
        scan, board = 0x100, 0x500
        image[scan:scan + _SCAN_SIZE] = bytes((i * 17 + 31) & 255 for i in range(_SCAN_SIZE))
        image[scan + 14:scan + 30] = bytes.fromhex("0126a640f3439b069b0e194311701178")
        image[board:board + _BOARD_SIZE] = bytes((i * 13 + 47) & 255 for i in range(_BOARD_SIZE))
        image[board:board + len(_BOARD_ANCHOR)] = _BOARD_ANCHOR
        base = board - 0x5a
        image[base:base + len(_BOARD_BASE)] = _BOARD_BASE
        for off, target in ((2, 0x900), (0x2a, 0x920), (0x54, 0x900), (0x6c, 0x920), (0x10e, 0x940)):
            branch(image, scan + off, target)
        for off in (0x22, 0x28, 0x50, 0x56):
            branch(image, board + off, 0x940)
        branch(image, base + 0x14, 0x960)
        for i, (off, reg, value) in enumerate(((6, 2, 0x3000690), (0x22, 2, 0x3000660),
                                                (0x2e, 0, 0x3000690), (0x3a, 1, 0x380),
                                                (0x58, 2, 0x3000690), (0x64, 2, 0x3000660))):
            literal(image, scan + off, reg, 0x300 + i * 4, value)
        for i, (off, reg) in enumerate(((0x10, 1), (0x2c, 1), (0x3e, 1))):
            literal(image, board + off, reg, 0x700 + i * 4, 0x1001000)
        literal(image, base, 1, 0x6e0, 0x1001000)
        literal(image, base + 2, 5, 0x6e4, 0x3000660)
        image[0x368:0x380] = bytes(range(12)) + b'123456789*0#'
        for col, pos in enumerate((14, 13, 11, 7)):
            image[0x380 + pos] = col
        return image

    def test_gpio_scanner_requires_consistent_board_route(self):
        image = self.fixture()
        def digest(start, size, calls, literals):
            code = bytearray(image[start:start + size])
            for offset in calls:
                code[offset:offset + 4] = bytes(4)
            for offset in literals:
                code[offset:offset + 2] = bytes(2)
            return hashlib.sha256(code).hexdigest()
        scan_hash = digest(0x100, _SCAN_SIZE, (2, 0x2a, 0x54, 0x6c),
                           (6, 0x22, 0x2e, 0x3a, 0x58, 0x64))
        board_hash = digest(0x500, _BOARD_SIZE, (0x22, 0x28, 0x50, 0x56),
                            (0x10, 0x2c, 0x3e))
        with patch.object(legacy_keypad, '_SCAN_HASH', scan_hash), \
             patch.object(legacy_keypad, '_BOARD_HASH', board_hash):
            profile = find_legacy_six_row_keypad(image)
            self.assertEqual(profile['row_output'], 0x03000660)
            for offset in (0x100, 0x500, 0x6e4, 0x368 + 12):
                altered = bytearray(image)
                altered[offset] ^= 1
                self.assertIsNone(find_legacy_six_row_keypad(altered))

    def test_revision_requires_linked_reader_and_gpio_literal(self):
        from unittest.mock import patch
        from msm5xxx_emulator.qemu.transport import qemu_legacy_board_revision_property
        image = bytearray(0x300)
        branch(image, 0x11c, 0x180)
        image[0x180:0x194] = bytes.fromhex('08b5044800ab007b58700020187000a8008808bd')
        struct.pack_into('<I', image, 0x194, 0x03000750)
        with patch('msm5xxx_emulator.detection.sharp_intel._legacy_sharp_pcr_profile', return_value={}), \
             patch('msm5xxx_emulator.detection.dmd5000.find_dmd5000_profile', return_value={'entry': 0x100}):
            self.assertEqual(qemu_legacy_board_revision_property(image, 0x800000, {}),
                             'board-revision=300075c:60')
            self.assertIsNone(qemu_legacy_board_revision_property(image, 0x800000, None))
            for offset in (0x11c, 0x180, 0x194):
                changed = bytearray(image)
                changed[offset] ^= 1
                self.assertIsNone(qemu_legacy_board_revision_property(changed, 0x800000, {}))

    def test_loaded_source_must_still_match_keypad(self):
        from msm5xxx_emulator.qemu.transport import qemu_legacy_keypad_source_matches
        candidate = {'signature': 'synthetic'}
        with patch.object(legacy_keypad, 'find_legacy_six_row_keypad',
                          side_effect=lambda image: candidate if image == b'original' else None):
            self.assertTrue(qemu_legacy_keypad_source_matches(b'original', candidate))
            self.assertFalse(qemu_legacy_keypad_source_matches(b'changed', candidate))
            self.assertTrue(qemu_legacy_keypad_source_matches(b'changed', None))

    def test_matrix_pullups_replace_only_the_matching_release_input(self):
        from msm5xxx_emulator.core.config import BoardStatusInput
        from msm5xxx_emulator.qemu.transport import qemu_legacy_keypad_status_available
        profile = {'signature': 'synthetic'}
        self.assertTrue(qemu_legacy_keypad_status_available(profile, None))
        self.assertTrue(qemu_legacy_keypad_status_available(profile, BoardStatusInput(0x3000694, 4, 4)))
        self.assertFalse(qemu_legacy_keypad_status_available(profile, BoardStatusInput(0x3000694, 8, 8)))
        self.assertFalse(qemu_legacy_keypad_status_available(None, None))
