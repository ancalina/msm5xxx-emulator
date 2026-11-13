"""Synthetic source fixtures for an indexed 1C halfword stream."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.display.indexed1c_writer import (
    find_indexed1c_profile,
)
from msm5xxx_emulator.detection.devices.display import source_writers
from msm5xxx_emulator.devices.display.source_plan import apply_source_plan


def _strh(register, base, offset=0):
    return 0x8000 | (offset // 2) << 6 | base << 3 | register


def _bl(site, target):
    delta = (target - (site + 4)) >> 1
    sign = (delta >> 22) & 1
    i1, i2 = (delta >> 21) & 1, (delta >> 20) & 1
    j1, j2 = (~(i1 ^ sign)) & 1, (~(i2 ^ sign)) & 1
    first = 0xf000 | sign << 10 | ((delta >> 11) & 0x3ff)
    second = 0xf800 | j1 << 13 | j2 << 11 | (delta & 0x7ff)
    return first, second


class ThumbFixture:
    def __init__(self, width=4, height=3):
        self.data = bytearray(0x800)
        self.width, self.height = width, height
        self.pc = 0x100
        self.labels = {}
        self.fixups = []
        self.window_value_offsets = {}
        self.emit(0xb500)  # push {lr}
        bl_site = self.pc
        self.emit(0xf000, 0xf800)
        self.fixups.append(('bl', bl_site, 'writer'))
        self.emit(0xbd00)  # pop {pc}
        self.label('writer')
        self.emit(0xb530)  # push {r4,r5,lr}
        self.emit(0x2507, 0x06ad)  # r5 = 7 << 26, command aperture
        self._register(0x220, 0)
        self._register(0x222, 0)
        self._register(0x224, width - 1)
        self._register(0x226, height - 1)
        self.emit(0x2028, _strh(0, 5))  # begin streamed GRAM write
        self.emit(0x2000 | height)
        self.fixups.append(('b', self.pc, 'decrement'))
        self.emit(0xe000)
        self.label('row')
        self.emit(0x8821, 0x1ca2, _strh(1, 5, 4))
        for _ in range(width - 1):
            self.emit(0x8811, 0x3202, _strh(1, 5, 4))
        self.emit(0x1c94)  # r4 = end of source row + one pad halfword
        self.label('decrement')
        self.emit(0x3801)
        self.fixups.append(('cond', self.pc, 'done'))
        self.emit(0xd300)  # blo done
        self.fixups.append(('b', self.pc, 'row'))
        self.emit(0xe000)
        self.label('done')
        self.emit(0xbd30)  # pop {r4,r5,pc}
        self.patch()

    def emit(self, *words):
        for value in words:
            struct.pack_into('<H', self.data, self.pc, value)
            self.pc += 2

    def label(self, name):
        self.labels[name] = self.pc

    def _register(self, register, value):
        # Build 0x220..0x226 from a byte immediate and a four-bit shift.
        self.emit(0x2000 | (register >> 4), 0x0100)
        if register & 0xf:
            self.emit(0x3000 | (register & 0xf))
        self.emit(_strh(0, 5), 0x2000 | value)
        self.window_value_offsets[register] = self.pc - 2
        self.emit(_strh(0, 5, 4))

    def patch(self):
        for kind, site, name in self.fixups:
            target = self.labels[name]
            if kind == 'bl':
                first, second = _bl(site, target)
                struct.pack_into('<HH', self.data, site, first, second)
            elif kind == 'b':
                delta = (target - (site + 4)) // 2
                struct.pack_into('<H', self.data, site,
                                 0xe000 | (delta & 0x7ff))
            else:
                delta = (target - (site + 4)) // 2
                struct.pack_into('<H', self.data, site,
                                 0xd300 | (delta & 0xff))

    def finish(self):
        return bytes(self.data)


class Indexed1CWriterTests(unittest.TestCase):
    def test_source_proves_window_and_counted_halfword_stream(self):
        profile = find_indexed1c_profile(ThumbFixture().finish())
        self.assertIsNotNone(profile)
        self.assertEqual(profile['protocol'], 'indexed1c-halfword-stream')
        self.assertEqual((profile['command_port'], profile['data_port']),
                         (0x1c000000, 0x1c000004))
        self.assertEqual((profile['width'], profile['height']), (4, 3))
        self.assertEqual(profile['pixel_format'], 'rgb565')
        self.assertTrue(profile['evidence'])

    def test_source_geometry_is_derived_for_other_consistent_dimensions(self):
        for width, height in ((5, 3), (4, 4)):
            with self.subTest(width=width, height=height):
                profile = find_indexed1c_profile(
                    ThumbFixture(width, height).finish())
                self.assertIsNotNone(profile)
                self.assertEqual((profile['width'], profile['height']),
                                 (width, height))

    def test_window_endpoint_must_match_the_stream_loop(self):
        fixture = ThumbFixture()
        fixture.data[fixture.window_value_offsets[0x226]] = 1
        self.assertIsNone(find_indexed1c_profile(fixture.finish()))

    def test_missing_direct_caller_and_wrong_store_width_are_rejected(self):
        fixture = bytearray(ThumbFixture().finish())
        struct.pack_into('<H', fixture, 0x102, 0x2000)  # remove the BL
        self.assertIsNone(find_indexed1c_profile(bytes(fixture)))

    def test_source_writer_plan_claims_normalized_command_and_data_ports(self):
        image = bytes(0x14000)
        profile = {
            'command_port': 0x1c000000, 'data_port': 0x1c000004,
            'width': 132, 'height': 176,
            'evidence': [{'span': (0x100, 8), 'extra_spans': ()}],
        }
        config = SimpleNamespace(image_kind='firmware', load_address=0,
            image_offset=0, entry=0, missing_overlays=[],
            ram_bootstrap_profile=None, display_geometry_source='auto-default')
        with patch.object(source_writers, 'find_indexed28', return_value=None), \
             patch.object(source_writers, 'find_indexed20', return_value=None), \
             patch.object(source_writers, 'find_indexed1c_profile', return_value=profile):
            plan = source_writers.machine_plan(image, image, config)
        self.assertEqual(dict(plan.capabilities[0].parameters)['indexed1c'], (132, 176))
        self.assertEqual(plan.capabilities[0].evidence[0].locations, (0x100,))
        self.assertEqual([(claim.start, claim.end) for claim in plan.claims],
                         [(0x02000000, 0x02000002), (0x02000004, 0x02000006)])
        decoder = SimpleNamespace()
        apply_source_plan(decoder, plan)
        self.assertEqual((decoder._lcd_b0_source_page.width,
                          decoder._lcd_b0_source_page.height), (132, 176))

        fixture = bytearray(ThumbFixture().finish())
        # Replace one halfword data store with a word store.
        for at in range(0x120, len(fixture) - 1, 2):
            if struct.unpack_from('<H', fixture, at)[0] == _strh(1, 5, 4):
                struct.pack_into('<H', fixture, at, 0x6029)
                break
        self.assertIsNone(find_indexed1c_profile(bytes(fixture)))


if __name__ == '__main__':
    unittest.main()
