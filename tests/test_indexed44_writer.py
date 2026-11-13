"""Synthetic source-query checks for indexed command 44/45 displays."""
from __future__ import annotations

import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.devices.display import indexed44_writer


class ThumbImage:
    def __init__(self, size=0x300):
        self.image = bytearray(size)
        self.literal_next = 0x280

    def half(self, address, value):
        struct.pack_into('<H', self.image, address, value)

    def literal(self, address, register, value):
        pool = self.literal_next
        self.literal_next += 4
        base = (address + 4) & ~3
        delta = pool - base
        if delta < 0 or delta % 4 or delta // 4 > 255:
            raise AssertionError('literal is outside Thumb range')
        self.half(address, 0x4800 | register << 8 | delta // 4)
        struct.pack_into('<I', self.image, pool, value)

    def bl(self, address, target):
        delta = target - address - 4
        if delta & 1 or not -(1 << 22) <= delta < (1 << 22):
            raise AssertionError('call is outside Thumb range')
        value = delta >> 1
        self.half(address, 0xF000 | ((value >> 11) & 0x7ff))
        self.half(address + 2, 0xF800 | (value & 0x7ff))

    def finish(self):
        return bytes(self.image)


def _strh(register, base, offset=0):
    if offset % 2 or not 0 <= offset <= 62:
        raise ValueError('invalid Thumb halfword offset')
    return 0x8000 | (offset // 2) << 6 | base << 3 | register


def _window_image(data_offset=16, y_origin=0x40):
    image = ThumbImage()
    command_port = 0x18000000
    # A reachable caller keeps the leaf window writer in the code facts.
    image.half(0x20, 0xB500)
    image.bl(0x22, 0x100)
    image.half(0x26, 0xBD00)

    # R0/R1 become packed X bounds; R2/R3 become Y bounds after +0x40.
    image.half(0x100, 0xB410)  # push {r4}
    image.literal(0x102, 5, command_port)
    image.half(0x104, 0x2444)  # movs r4, #0x44
    image.half(0x106, _strh(4, 5))
    image.half(0x108, 0x0209)  # lsls r1, r1, #8
    image.half(0x10a, 0x4308)  # orrs r0, r1
    image.half(0x10c, _strh(0, 5, data_offset))
    image.half(0x10e, 0x3200 | y_origin)  # adds r2, #origin
    image.half(0x110, 0x3300 | y_origin)  # adds r3, #origin
    image.half(0x112, 0x021b)  # lsls r3, r3, #8
    image.half(0x114, 0x431a)  # orrs r2, r3
    image.half(0x116, 0x2445)  # movs r4, #0x45
    image.half(0x118, _strh(4, 5))
    image.half(0x11a, _strh(2, 5, data_offset))
    image.half(0x11c, 0xBC10)  # pop {r4}
    image.half(0x11e, 0x4770)  # bx lr
    return image.finish()


def _stride_image(shift=5):
    image = ThumbImage()
    image.half(0x20, shift << 6 | 1 << 3 | 2)  # lsls r2, r1, #shift
    image.half(0x22, 0x1800 | 1 << 6 | 2 << 3 | 2)  # adds r2, r2, r1
    image.half(0x24, 2 << 6 | 2 << 3 | 2)  # lsls r2, r2, #2
    image.half(0x26, 0x4770)
    return image.finish()


def _rgb565_image(channel_shift=11, clobber_pixel=False):
    image = ThumbImage()
    image.literal(0x20, 7, 0x18000000)
    image.half(0x22, 0x2022)  # movs r0, #0x22
    image.half(0x24, _strh(0, 7))
    image.half(0x26, 0x880a)  # ldrh r2, [r1]
    image.half(0x28, 0x263f)  # movs r6, #0x3f
    image.half(0x2a, 5 << 6 | 6 << 3 | 6)  # lsls r6, r6, #5
    image.half(0x2c, 0x4016)  # ands r6, r2
    image.half(0x2e, 0x0800 | channel_shift << 6 | 2 << 3 | 3)
    image.half(0x30, 0x4333)  # orrs r3, r6
    image.half(0x32, 11 << 6 | 2 << 3 | 2)  # lsls r2, r2, #11
    image.half(0x34, 0x2200 if clobber_pixel else 0x431a)
    image.half(0x36, _strh(2, 7, 16))
    image.half(0x38, 0x4770)
    return image.finish()


def _linked_rgb565_image(data_offset=16):
    image = ThumbImage()
    image.half(0x20, 0xB500)  # push {lr}
    image.bl(0x22, 0x40)
    image.half(0x26, 0xBD00)  # pop {pc}
    image.literal(0x40, 7, 0x18000000)
    image.half(0x42, 0x2022)  # movs r0, #0x22
    image.half(0x44, _strh(0, 7))
    image.half(0x46, 0x880a)  # ldrh r2, [r1]
    image.half(0x48, 0x263f)  # movs r6, #0x3f
    image.half(0x4a, 5 << 6 | 6 << 3 | 6)  # lsls r6, r6, #5
    image.half(0x4c, 0x4016)  # ands r6, r2
    image.half(0x4e, 0x0800 | 11 << 6 | 2 << 3 | 3)
    image.half(0x50, 0x4333)  # orrs r3, r6
    image.half(0x52, 11 << 6 | 2 << 3 | 2)  # lsls r2, r2, #11
    image.half(0x54, 0x431a)  # orrs r2, r3
    image.half(0x56, _strh(2, 7, 16))
    image.bl(0x58, 0xa0)
    image.half(0x5c, 0x4770)

    image.half(0xa0, 0xB410)  # push {r4}
    image.literal(0xa2, 5, 0x18000000)
    image.half(0xa4, 0x2444)  # movs r4, #0x44
    image.half(0xa6, _strh(4, 5))
    image.half(0xa8, 0x2000)  # movs r0, #0
    image.half(0xaa, _strh(0, 5, data_offset))
    image.half(0xac, 0x2445)  # movs r4, #0x45
    image.half(0xae, _strh(4, 5))
    image.half(0xb0, 0x2001)  # movs r0, #1
    image.half(0xb2, _strh(0, 5, data_offset))
    image.half(0xb4, 0xBC10)  # pop {r4}
    image.half(0xb6, 0x4770)
    return image.finish()


class Indexed44WriterQueries(unittest.TestCase):
    def test_linked_window_writer_proves_command_data_ports_and_origin(self):
        facts = facts_for(_window_image())
        calls, windows = indexed44_writer._window_candidates(facts)
        self.assertTrue(calls)
        self.assertEqual(len(windows), 1)
        profile = next(iter(windows.values()))
        self.assertEqual(profile[1:], (0x18000000, 0x18000010, 0, 0x40))

    def test_wrong_data_offset_does_not_prove_window_pair(self):
        facts = facts_for(_window_image(data_offset=12))
        _, windows = indexed44_writer._window_candidates(facts)
        self.assertEqual(windows, {})

    def test_packed_bounds_derive_a_different_physical_origin(self):
        facts = facts_for(_window_image(y_origin=0x48))
        _, windows = indexed44_writer._window_candidates(facts)
        self.assertEqual(len(windows), 1)
        self.assertEqual(next(iter(windows.values()))[1:],
                         (0x18000000, 0x18000010, 0, 0x48))

    def test_initial_cursor_must_match_derived_physical_origin(self):
        self.assertTrue(indexed44_writer._initial_cursor_proven({0x4800}, 0, 0x48))
        self.assertFalse(indexed44_writer._initial_cursor_proven({0x4000}, 0, 0x48))

    def test_cursor_stream_accepts_continuation_but_requires_order(self):
        self.assertTrue(indexed44_writer._has_cursor_stream((0x21, 0x22, 0x22)))
        self.assertTrue(indexed44_writer._has_cursor_stream((0x22, 0x21, 0x22)))
        self.assertFalse(indexed44_writer._has_cursor_stream((0x22, 0x22)))

    def test_framebuffer_row_stride_requires_132_pixels(self):
        facts = facts_for(_stride_image())
        body = facts.function(CodeAddress(0x20), budget=32)
        self.assertTrue(indexed44_writer._has_stride132(body, facts, 132))
        self.assertFalse(indexed44_writer._has_stride132(body, facts, 131))

    def test_mutated_row_stride_is_rejected(self):
        facts = facts_for(_stride_image(shift=4))
        body = facts.function(CodeAddress(0x20), budget=32)
        self.assertFalse(indexed44_writer._has_stride132(body, facts, 132))

    def test_rgb565_swap_proves_five_six_five_fields_and_data_port(self):
        facts = facts_for(_rgb565_image())
        body = facts.function(CodeAddress(0x20), budget=64)
        self.assertTrue(indexed44_writer._rgb565_swap(
            body, facts, 0x18000000, 0x18000010))

    def test_rgb565_field_shift_mutation_is_rejected(self):
        facts = facts_for(_rgb565_image(channel_shift=10))
        body = facts.function(CodeAddress(0x20), budget=64)
        self.assertFalse(indexed44_writer._rgb565_swap(
            body, facts, 0x18000000, 0x18000010))

    def test_lcd_pixel_store_consumes_the_halfword_source(self):
        facts = facts_for(_rgb565_image())
        body = facts.function(CodeAddress(0x20), budget=64)
        self.assertTrue(indexed44_writer._pixel_store_consumes(
            body, facts, CodeAddress(0x26), 0x18000000, 0x18000010))

    def test_pixel_value_clobber_breaks_lcd_source_flow(self):
        facts = facts_for(_rgb565_image(clobber_pixel=True))
        body = facts.function(CodeAddress(0x20), budget=64)
        self.assertFalse(indexed44_writer._pixel_store_consumes(
            body, facts, CodeAddress(0x26), 0x18000000, 0x18000010))

    def test_missing_rgb565_load_site_fails_closed(self):
        facts = facts_for(_rgb565_image())
        body = facts.function(CodeAddress(0x20), budget=64)
        self.assertFalse(indexed44_writer._pixel_store_consumes(
            body, facts, False, 0x18000000, 0x18000010))

    def test_rgb565_transfer_guards_linked_window_helper(self):
        facts = facts_for(_linked_rgb565_image())
        calls = facts.call_candidates('thumb')
        pair = indexed44_writer._rgb565_transfer(
            facts, calls, 0x18000000, 0x18000010)
        self.assertIsNotNone(pair)
        converter, helper = pair
        self.assertIn(CodeAddress(0xa0), helper.instructions)
        self.assertTrue(indexed44_writer._body_ok(converter))
        self.assertTrue(indexed44_writer._body_ok(helper))

    def test_rgb565_transfer_rejects_mutated_window_data_port(self):
        facts = facts_for(_linked_rgb565_image(data_offset=12))
        pair = indexed44_writer._rgb565_transfer(
            facts, facts.call_candidates('thumb'), 0x18000000, 0x18000010)
        self.assertIsNone(pair)

    def test_unlinked_synthetic_image_is_not_a_panel_profile(self):
        self.assertIsNone(indexed44_writer.find_indexed44(bytes(0x300)))

    def test_profile_query_is_memoized_for_shared_facts(self):
        image = bytes(0x300)
        with patch.object(indexed44_writer, '_find_indexed44',
                          return_value={'profile': True}) as query:
            self.assertEqual(indexed44_writer.find_indexed44(image),
                             {'profile': True})
            self.assertEqual(indexed44_writer.find_indexed44(image),
                             {'profile': True})
        query.assert_called_once_with(image)


if __name__ == '__main__':
    unittest.main()
