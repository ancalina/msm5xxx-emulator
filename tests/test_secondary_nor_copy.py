"""Synthetic source-linked checks for bulk RAM copy provenance."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.devices.storage.secondary_nor_copy import (
    find_copy_source,
)


class ThumbBuilder:
    def __init__(self, base=0x200):
        self.base = base
        self.code: list[int | tuple[str, str, int]] = []
        self.labels: dict[str, int] = {}

    def label(self, name):
        self.labels[name] = self.base + 2 * len(self.code)

    def emit(self, *halfwords):
        self.code.extend(halfwords)

    def branch(self, condition, label):
        self.code.append(('branch', condition, label))

    @staticmethod
    def ldr_literal(register, at, pool):
        pc = (at + 4) & ~3
        delta = pool - pc
        if delta < 0 or delta & 3 or delta // 4 > 255:
            raise AssertionError('literal out of range')
        return 0x4800 | register << 8 | delta // 4

    @staticmethod
    def ldr_word(destination, base, offset):
        if offset & 3 or not 0 <= offset <= 124:
            raise AssertionError('word offset out of range')
        return 0x6800 | (offset // 4) << 6 | base << 3 | destination

    @staticmethod
    def shift(register, amount, left):
        return amount << 6 | register << 3 | register | (0x0000 if left else 0x0800)

    def finish(self):
        encoded = []
        for index, item in enumerate(self.code):
            at = self.base + index * 2
            if not isinstance(item, tuple):
                encoded.append(item)
                continue
            _, condition, label = item
            displacement = self.labels[label] - (at + 4)
            if displacement & 1:
                raise AssertionError('branch out of range')
            if condition == 'al':
                if not -2048 <= displacement <= 2046:
                    raise AssertionError('branch out of range')
                encoded.append(0xE000 | ((displacement >> 1) & 0x7ff))
            else:
                if not -256 <= displacement <= 254:
                    raise AssertionError('branch out of range')
                immediate = (displacement >> 1) & 0xff
                encoded.append((0xD000 if condition == 'eq' else 0xD100) | immediate)
        return encoded


def _synthetic_image(*, copy_shift=5, target=0x1800, zero_start=0x1850):
    image = bytearray(0x3000)
    image[0x800:0x800 + 0x50] = bytes(range(0x50))
    struct.pack_into('<I', image, 0x804, 0x003dc3fc)
    # One linked 5-word row: 0x50 bytes copied, then 0x50 bytes cleared.
    struct.pack_into('<5I', image, 0x1000, 0x800, target, 0x50,
                     zero_start, 0x50)
    # Reset vector and mode-safe manual interworking wrapper.
    struct.pack_into('<I', image, 0, 0xEA00000E)  # B reset at 0x40
    reset = (0xE321F0D3, 0xE59FD034, 0xE59F4034, 0xE3140001,
             0x159FE030, 0x059FE030, 0xE12FFF14)
    struct.pack_into('<7I', image, 0x40, *reset)
    struct.pack_into('<H', image, 0x5C, 0x4778)  # Thumb BX PC trampoline
    struct.pack_into('<I', image, 0x60, 0xEAFFFFFE)  # ARM return loop
    struct.pack_into('<I', image, 0x80, 0x1FFC)  # bounded RAM stack
    struct.pack_into('<I', image, 0x84, 0x201)  # reset-linked Thumb leaf
    struct.pack_into('<I', image, 0x88, 0x5D)  # Thumb return target
    struct.pack_into('<I', image, 0x8C, 0x60)  # ARM return target

    code = ThumbBuilder()
    code.emit(0xB510)  # push {r4, lr}
    code.emit(code.ldr_literal(4, 0x202, 0x400))
    code.emit(code.ldr_word(0, 4, 0))
    code.emit(code.ldr_word(1, 4, 4))
    code.emit(code.ldr_word(2, 4, 8))
    code.emit(code.shift(2, copy_shift, False))
    code.label('copy_bulk')
    for _ in range(8):
        code.emit(0xC808, 0xC108)  # ldmia r0!,{r3}; stmia r1!,{r3}
    code.emit(0x3A01)  # subs r2,#1
    code.branch('ne', 'copy_bulk')
    # Copy the source remainder: (byte_length << 27) >> 29 words.
    code.emit(code.ldr_word(2, 4, 8))
    code.emit(code.shift(2, 27, True), code.shift(2, 29, False))
    code.label('tail_bulk')
    code.emit(0xC808, 0xC108)
    code.emit(0x3A01)
    code.branch('ne', 'tail_bulk')
    code.emit(code.ldr_word(0, 4, 12))
    code.emit(code.ldr_word(2, 4, 16))
    code.emit(code.shift(2, 5, False))
    code.emit(0x2300)  # movs r3,#0
    code.label('zero_bulk')
    for _ in range(8):
        code.emit(0xC008)  # stmia r0!,{r3}
    code.emit(0x3A01)
    code.branch('ne', 'zero_bulk')
    code.emit(code.ldr_word(2, 4, 16))
    code.emit(code.shift(2, 27, True), code.shift(2, 29, False))
    code.label('zero_tail')
    code.emit(0xC008)
    code.emit(0x3A01)
    code.branch('ne', 'zero_tail')
    code.emit(0xBD10)  # pop {r4, pc}

    words = code.finish()
    for index, value in enumerate(words):
        struct.pack_into('<H', image, code.base + index * 2, value)
    struct.pack_into('<I', image, 0x400, 0x1000)
    return bytes(image)


def _return_bridge_image(*, branch_target=0x100, stack_mode=0xD3):
    image = bytearray(_synthetic_image())
    # Route reset through a Thumb helper, its ARM return bridge, and a normal
    # ARM entry whose literal-linked transfer reaches the copy leaf.
    struct.pack_into('<I', image, 0x84, 0x301)
    struct.pack_into('<I', image, 0x40, 0xE321F000 | stack_mode)
    struct.pack_into('<H', image, 0x300, 0x4770)  # bx lr
    struct.pack_into('<III', image, 0x60, 0xE3500000, 0x1A000001,
                     0xEA000000 | (((branch_target - 0x70) >> 2) & 0xFFFFFF))
    struct.pack_into('<I', image, 0x70, 0xEAFFFFFE)
    struct.pack_into('<IIIII', image, 0x100, 0xE321F0D3, 0xE1A00000,
                     0xE59F0010, 0xE3100001, 0x159FE014)
    struct.pack_into('<II', image, 0x114, 0x059FE014, 0xE12FFF10)
    struct.pack_into('<I', image, 0x120, 0x00000201)
    struct.pack_into('<II', image, 0x12C, 0x5D, 0x60)
    return bytes(image)


class SecondaryNorCopyTests(unittest.TestCase):
    def test_linked_unrolled_copy_and_zero_rows_are_proved(self):
        image = _synthetic_image()
        profile = find_copy_source(image, 0x1000, 0x1000,
                                   (0x1804, 0x1808), 0x003dc3fc)
        self.assertIsNotNone(profile)
        self.assertEqual(profile['copy_source'], 0x804)
        self.assertEqual(profile['copy_writes'], [[0x1800, 0x50, 0x800]])
        self.assertEqual(profile['zero_writes'], [[0x1850, 0x50]])
        self.assertIn([0x1000, 0x1014], profile['evidence_spans'])

    def test_arm_tail_interwork_to_thumb_leaf_is_linked(self):
        image = _synthetic_image()
        profile = find_copy_source(image, 0x1000, 0x1000,
                                   (0x1804, 0x1808), 0x003dc3fc)
        self.assertIsNotNone(profile)
        self.assertEqual(profile['entry'], 0x201)

    def test_reset_return_bridge_reaches_normal_arm_copy_entry(self):
        image = _return_bridge_image()
        profile = find_copy_source(image, 0x1000, 0x1000,
                                   (0x1804, 0x1808), 0x003dc3fc)
        self.assertIsNotNone(profile)
        self.assertEqual(profile['reset_link']['kind'], 'reset-return-bridge')
        self.assertEqual(profile['reset_link']['normal_entry'], 0x100)
        self.assertEqual(profile['reset_link']['stack_pointer'], 0x1FFC)

    def test_reset_return_bridge_requires_branch_and_svc_stack(self):
        bad_branch = _return_bridge_image(branch_target=0x200)
        self.assertIsNone(find_copy_source(bad_branch, 0x1000, 0x1000,
                                           (0x1804, 0x1808), 0x003dc3fc))
        bad_mode = _return_bridge_image(stack_mode=0xD0)
        self.assertIsNone(find_copy_source(bad_mode, 0x1000, 0x1000,
                                           (0x1804, 0x1808), 0x003dc3fc))

    def test_wrong_counter_unit_is_rejected(self):
        image = _synthetic_image(copy_shift=4)
        self.assertIsNone(find_copy_source(image, 0x1000, 0x1000,
                                           (0x1804, 0x1808), 0x003dc3fc))

    def test_wrong_target_or_zero_overlap_is_rejected(self):
        wrong_target = _synthetic_image(target=0x1900, zero_start=0x1950)
        self.assertIsNone(find_copy_source(wrong_target, 0x1000, 0x1000,
                                           (0x1804, 0x1808), 0x003dc3fc))
        zero_overlap = _synthetic_image(zero_start=0x1804)
        self.assertIsNone(find_copy_source(zero_overlap, 0x1000, 0x1000,
                                           (0x1804, 0x1808), 0x003dc3fc))

    def test_table_must_be_loaded_by_the_copy_leaf(self):
        image = bytearray(_synthetic_image())
        struct.pack_into('<I', image, 0x400, 0x1200)
        self.assertIsNone(find_copy_source(bytes(image), 0x1000, 0x1000,
                                           (0x1804, 0x1808), 0x003dc3fc))

    def test_missing_interwork_literal_or_wrong_source_object_is_rejected(self):
        image = bytearray(_synthetic_image())
        struct.pack_into('<I', image, 0x84, 0x203)
        self.assertIsNone(find_copy_source(bytes(image), 0x1000, 0x1000,
                                           (0x1804, 0x1808), 0x003dc3fc))
        image = _synthetic_image()
        self.assertIsNone(find_copy_source(image, 0x1000, 0x1000,
                                           (0x1804, 0x1808), 0x12345678))


if __name__ == '__main__':
    unittest.main()
