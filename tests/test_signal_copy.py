"""Synthetic ABI and data-flow checks for source-linked copy helpers."""
from __future__ import annotations

import struct
import unittest

from msm5xxx_emulator.detection.devices.external_bus.signal_copy import (
    direct_copy_unit, find_copy_units,
)
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


def _u16(image, at, *values):
    struct.pack_into('<' + 'H' * len(values), image, at, *values)


def _thumb_bl(source, target):
    displacement = (target - (source + 4)) & 0x1FFFFFF
    s = (displacement >> 24) & 1
    i1 = (displacement >> 23) & 1
    i2 = (displacement >> 22) & 1
    j1 = (~(i1 ^ s)) & 1
    j2 = (~(i2 ^ s)) & 1
    return (0xF000 | (s << 10) | ((displacement >> 12) & 0x3FF),
            0xD000 | (j1 << 13) | (j2 << 11)
            | ((displacement >> 1) & 0x7FF))


def _leaf(*, unit=2, load_base=0, store_base=1, clobber=False):
    image = bytearray(0x100)
    code = [0x3201, 0xE004 if clobber else 0xE003]
    if unit == 2:
        code.append(0x8800 | (load_base << 3) | 3)
        if clobber:
            code.extend((0x2300, 0x8000 | (store_base << 3) | 3,
                         0x3002, 0x3102, 0x3A01, 0xD1F8, 0x4770))
        else:
            code.extend((0x8000 | (store_base << 3) | 3,
                         0x3002, 0x3102, 0x3A01, 0xD1F9, 0x4770))
    else:
        code.extend((0x6800 | (load_base << 3) | 3,
                     0x6000 | (store_base << 3) | 3,
                     0x3004, 0x3104, 0x3A01, 0xD1F9, 0x4770))
    _u16(image, 0x40, *code)
    return image


def _copy_image(*, unit=2, swap=True, wrong_count=False, clobber=False,
                wrong_leaf=False, scaled_count=False,
                source_offset=False, destination_offset=False,
                load_pointer=False):
    reverse = unit == 2 and (swap or wrong_leaf)
    image = _leaf(unit=unit, load_base=1 if reverse else 0,
                  store_base=0 if reverse else 1,
                  clobber=clobber)
    wrapper = [0xB510, 0x1C04]
    if swap:
        wrapper.extend((0x1C08, 0x1C21))  # R0=R1; R1=R4
    else:
        wrapper.extend((0x1C00, 0x1C09))  # preserve R0/R1; wrong for half leaf
    if wrong_count:
        wrapper.append(0x2201)  # R2 no longer comes from the outer count
    if scaled_count:
        wrapper.append(0x0052)  # LSL R2,R2,#1
    if source_offset:
        wrapper.append(0x3102)  # add two to the source pointer
    if destination_offset:
        wrapper.append(0x3002)  # add two to the destination pointer
    if load_pointer:
        wrapper.append(0x6809)  # replace source pointer with *source
    call_at = 0x20 + len(wrapper) * 2
    wrapper.extend(_thumb_bl(call_at, 0x40))
    wrapper.append(0xBD10)
    _u16(image, 0x20, *wrapper)
    return bytes(image)


class SignalCopyTests(unittest.TestCase):
    def test_direct_copy_unit_checks_source_destination_and_count(self):
        image = bytearray(_leaf(unit=2, load_base=0, store_base=1))
        facts = facts_for(bytes(image))
        function = facts.function(CodeAddress(0x40), budget=64)
        self.assertEqual(direct_copy_unit(facts, function), 2)

        swapped = bytearray(_leaf(unit=2, load_base=1, store_base=0))
        swapped_facts = facts_for(bytes(swapped))
        self.assertIsNone(direct_copy_unit(
            swapped_facts, swapped_facts.function(CodeAddress(0x40), budget=64)))

    def test_swapping_wrapper_maps_halfword_leaf_back_to_outer_roles(self):
        image = _copy_image(unit=2, swap=True)
        facts = facts_for(image)
        result = find_copy_units(facts, CodeAddress(0x20))
        self.assertEqual(set(result), {2})
        self.assertEqual([item.entry.address for item in result[2]], [0x20, 0x40])

        wrong = _copy_image(unit=2, swap=False, wrong_leaf=True)
        self.assertEqual(find_copy_units(facts_for(wrong), CodeAddress(0x20)), {})

    def test_count_and_loaded_value_must_survive_the_wrapper_and_leaf(self):
        clobbered = _copy_image(unit=2, swap=True, clobber=True)
        self.assertEqual(find_copy_units(facts_for(clobbered), CodeAddress(0x20)), {})

    def test_count_scaling_pointer_offsets_and_pointer_load_are_rejected(self):
        for kwargs in (
            {'wrong_count': True},
            {'scaled_count': True},
            {'source_offset': True},
            {'destination_offset': True},
            {'load_pointer': True},
        ):
            with self.subTest(kwargs=kwargs):
                image = _copy_image(unit=2, swap=True, **kwargs)
                self.assertEqual(find_copy_units(facts_for(image),
                                                 CodeAddress(0x20)), {})

    def test_direct_word_loop_uses_source_r0_and_destination_r1(self):
        image = bytearray(0x100)
        _u16(image, 0x40, 0x3201, 0xE003, 0x6803, 0x600B,
             0x3004, 0x3104, 0x3A01, 0xD1F9, 0x4770)
        facts = facts_for(bytes(image))
        result = find_copy_units(facts, CodeAddress(0x40))
        self.assertEqual(set(result), {4})
        self.assertEqual([item.entry.address for item in result[4]], [0x40])


if __name__ == '__main__':
    unittest.main()
