"""Synthetic source and projection checks for the secondary NOR aperture."""
from __future__ import annotations

import struct
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.storage import secondary_protected_plan


def _u16(image, at, *values):
    struct.pack_into('<' + 'H' * len(values), image, at, *values)


def _u32(image, at, *values):
    struct.pack_into('<' + 'I' * len(values), image, at, *values)


def _thumb_bl(source, target):
    displacement = (target - (source + 4)) & 0x1FFFFFF
    s = (displacement >> 24) & 1
    i1 = (displacement >> 23) & 1
    i2 = (displacement >> 22) & 1
    j1 = (~(i1 ^ s)) & 1
    j2 = (~(i2 ^ s)) & 1
    first = 0xF000 | (s << 10) | ((displacement >> 12) & 0x3FF)
    second = 0xD000 | (j1 << 13) | (j2 << 11) | ((displacement >> 1) & 0x7FF)
    return first, second


def _selector_words():
    return (0xB500, 0x481F, 0x6802, 0x491F, 0x4B1F, 0x4798, 0xBD00)


def _image(*, mask=0x3F, base=0x12000000, copy_source=0x7FF8):
    image = bytearray(0x10000)
    obj = 0x6000
    _u32(image, obj + 4, 2)
    _u32(image, obj + 8, 0x10000, 0x10000)
    _u32(image, obj + 0xA4, 0x0039001C)
    _u32(image, obj + 0xAC, 2)
    _u32(image, obj + 0xB0, 0x09080000)
    _u32(image, obj + 0xB4, 0x00C80000)
    method_entries = (0x2E0, 0x300, 0x320, 0x340, 0x360, 0x380)
    for offset, entry in zip((0xB8, 0xBC, 0xC0, 0xC4, 0xC8, 0xCC),
                             method_entries):
        _u32(image, obj + offset, entry | 1)

    for entry in (0x200, 0x260, 0x280, 0x2A0, 0x2E0, 0x300,
                  0x320, 0x340, 0x360, 0x380, 0x420, 0x440):
        _u16(image, entry, 0x2000, 0x4770)  # movs r0,#0; bx lr

    query_call = _thumb_bl(0x114, 0x400)
    _u16(image, 0x100, 0xB500, 0x4A23, 0x6812, 0x481E, 0x6B00,
         0x0040, 0x491D, 0x6889, 0x1808, 0x491D, *query_call, 0xBD00)
    _u32(image, 0x180, obj + 0x80, 0x14000020, 0x14001009, 0,
         0x14001000)
    _u16(image, 0x400, 0x4708)  # bx r1 query thunk

    constructor_call = _thumb_bl(0x208, 0x100)
    _u16(image, 0x200, 0xB500, 0x480F, 0x2100, 0x6081,
         *constructor_call, 0xBD00)
    _u32(image, 0x240, 0x14000020)

    # The getter returns the selected descriptor pointer plus four bytes;
    # its null path returns directly and its non-null path adjusts the pointer.
    _u16(image, 0x220, 0x4803, 0x6840, 0x2800, 0xD100,
         0x4770, 0x3004, 0x4770)
    _u32(image, 0x230, 0x14000020)

    # The initializer calls the getter and reads the packed identity through
    # adjacent halfwords at offsets derived from the getter's +4 adjustment.
    bl = _thumb_bl(0x260, 0x220)
    _u16(image, 0x260, *bl, 0x4605, 0x2280, 0x18AB,
         0x8C19, 0x8C59, 0x4770)

    # The shared command helper compares its address argument with the bank
    # base, then masks the high-word sector index with the source limit.
    _u16(image, 0x500, 0xB500, 0x4C0F, 0x42A0,
         (16 << 6) | (0 << 3) | 2 | 0x0800,
         0x233F if mask == 0x3F else 0x237F,
         0x401A, 0xBD00)
    _u32(image, 0x540, base)

    # Generated halfword sequence: issue a word-width probe command, combine
    # the two halfword reads, write the completion value, and return the result.
    _u16(image, 0x8000, 0x2190, 0x8001, 0x8841, 0x0409, 0x8802,
         0x4311, 0x22FF, 0x8002, 0x1C08, 0x46F7)
    _u32(image, copy_source, obj)
    return bytes(image)


def _candidate(image):
    obj = 0x6000
    intervals = {
        'command_helper': [0x500, 0x50E],
        'program': [0x300, 0x304],
        'erase': [0x320, 0x324],
        'poll': [0x340, 0x344],
    }
    return {
        'signature': 'table-summed-secondary-protected-nor-x16-v1',
        'admission': 'candidate-awaiting-reset-copy',
        'bus_width': 2,
        'address': 0x12100000,
        'size': 0x20000,
        'max_bound': 0x1900000,
        'sector_sizes': [0x10000, 0x10000],
        'selected_object': obj,
        'methods': {'read': 0x2E0, 'program': 0x300, 'erase': 0x320,
                    'poll': 0x340, 'suspend': 0x360, 'resume': 0x380},
        'protocol_intervals': intervals,
        'sector_prefix_consumer': {
            'entry': 0x420, 'global_address': 0x14000020,
            'function_interval': [0x420, 0x424],
        },
        'sector_count_caller': {
            'entry': 0x440, 'function_interval': [0x440, 0x444],
        },
        'lifecycle': {
            'selector': 0x100, 'constructor': 0x200,
            'active_object_getter': 0x220, 'count_initializer': 0x260,
            'count_getter': 0x280, 'reset_caller': 0x2A0,
        },
        'unclosed': ['reset-copy-provenance'],
    }


def _query_image(*, query_pointer=0x14001009, zero_base=True,
                 query_shift=1, mask=0x7F, clobber_base=False,
                 intervening_write=False):
    image = bytearray(0x10000)
    obj, global_address = 0x6000, 0x14000020
    _u32(image, obj + 4, 2)
    _u32(image, obj + 8, 0x10000, 0x10000)
    _u32(image, obj + 0xA4, 0x0039001C)
    _u32(image, obj + 0xAC, 2)
    _u32(image, obj + 0xB0, 0x09080000)
    _u32(image, obj + 0xB4, 0x00C80000)

    # The selector probes (descriptor.begin * 2) + global.bank_base.
    call = _thumb_bl(0x110, 0x400)
    _u16(image, 0x100, 0xB500, 0x481F, 0x6B00,
         0x0040 if query_shift == 1 else 0x0080,
         0x491E, 0x6889, 0x1808, 0x491E, *call, 0xBD00)
    _u32(image, 0x180, obj + 0x80, global_address)
    _u32(image, 0x188, query_pointer)
    _u16(image, 0x400, 0x4708)  # linked BX R1 query thunk

    # The constructor initializes global.bank_base before its selector call.
    if intervening_write:
        first_call = _thumb_bl(0x208, 0x300)
        second_call = _thumb_bl(0x20C, 0x100)
        _u16(image, 0x200, 0xB500, 0x480F,
             0x2100 if zero_base else 0x2101, 0x6081,
             *first_call, *second_call, 0xBD00)
        helper_load = 0x480B  # literal at 0x330
        _u16(image, 0x300, 0xB500, helper_load, 0x2101, 0x6081, 0xBD00)
        _u32(image, 0x330, global_address)
    elif clobber_base:
        call = _thumb_bl(0x20C, 0x100)
        _u16(image, 0x200, 0xB500, 0x480F,
             0x2100 if zero_base else 0x2101, 0x6081, 0x2101, 0x6081,
             *call, 0xBD00)
    else:
        call = _thumb_bl(0x208, 0x100)
        _u16(image, 0x200, 0xB500, 0x480F,
             0x2100 if zero_base else 0x2101, 0x6081, *call, 0xBD00)
    _u32(image, 0x240, global_address)

    # No aligned-base CMP: derive the sector index from address bits 16..,
    # then mask the index using a source immediate.
    _u16(image, 0x500, 0x2100 | mask, 0x0C02, 0x400A, 0x4770)
    _u16(image, 0x600, 0x2190, 0x8001, 0x8841, 0x0409, 0x8802,
         0x4311, 0x22FF, 0x8002, 0x1C08, 0x46F7)
    _u32(image, 0x7FF8, obj)
    return bytes(image)


def _copy_profile():
    return {
        'signature': 'linked-ram-copy-table-v1',
        'required_span': [0x14001000, 0x1400101C],
        'expected_object': 0x6000,
        'copy_source': 0x7FF8,
        'copy_writes': [[0x14001000, 0x1C, 0x7FF8]],
        'zero_writes': [],
        'evidence_spans': [[0x100, 0x10D], [0x500, 0x50E],
                           [0x7FF8, 0x8014]],
    }


def _config(**changes):
    values = dict(image_kind='firmware', load_address=0, image_offset=0,
                  entry=0, file_size=0x10000, flash_size=0x10000,
                  ram_base=0x14000000, ram_size=0x02000000,
                  missing_overlays=[], ram_bootstrap_profile=None,
                  native_nand_profile=None, nand_enabled=False, nand_image=None,
                  nand_read_address=None, nand_write_address=None,
                  nand_bad_block_address=None, secondary_flash_image=None,
                  secondary_flash_image_offset=None, secondary_flash_address=None,
                  secondary_flash_read_address=None,
                  secondary_flash_write_address=None,
                  upper_flash_image=None, upper_flash_address=None,
                  primary_flash_probe_address=None)
    values.update(changes)
    return SimpleNamespace(**values)


class SecondaryProtectedPlanTests(unittest.TestCase):
    def setUp(self):
        self.original = _image()
        self.loaded = self.original
        self.config = _config()

    def plan(self, *, image=None, loaded=None, config=None, candidate=None,
             copy=None, claimed=False):
        with patch.object(secondary_protected_plan.secondary_protected_nor,
                          'find_secondary_protected_nor',
                          return_value=_candidate(self.original) if candidate is None
                          else candidate), \
             patch.object(secondary_protected_plan.secondary_nor_copy,
                          'find_copy_source',
                          return_value=_copy_profile() if copy is None else copy):
            return secondary_protected_plan.machine_plan(
                self.original if image is None else image,
                self.loaded if loaded is None else loaded,
                self.config if config is None else config, claimed=claimed)

    def test_source_plan_claims_only_the_derived_supported_window(self):
        plan = self.plan()
        self.assertEqual(dict(plan.properties), {
            'experimental-protected-nor': '12000000:400000:10000:f4240',
            'protected-nor-bank': '12000000:39001c',
        })
        self.assertEqual((plan.claims[0].start, plan.claims[0].end),
                         (0x12000000, 0x12400000))
        binding = secondary_protected_plan.project(plan)
        self.assertEqual(binding.raw_size, 0x400000)
        self.assertEqual(binding.machine,
            ',experimental-protected-nor=12000000:400000:10000:f4240,'
            'protected-nor-bank=12000000:39001c')

    def test_normalizes_detector_trailer_to_physical_flash_prefix(self):
        image = self.original + b'nonflash trailer bytes'
        loaded = image[:len(self.original)]
        config = _config(file_size=len(image), flash_size=len(loaded))
        plan = self.plan(image=image, loaded=loaded, config=config)
        self.assertTrue(plan.capabilities)
        self.assertEqual(dict(plan.capabilities[0].parameters)['firmware_size'],
                         len(loaded))

    def test_normalized_primary_seed_size_is_physical_flash_size(self):
        flash_size = 0x800000
        image = self.original + b'\xA5' * (flash_size - len(self.original)) + b'\x00tail'
        loaded = image[:flash_size]
        config = _config(file_size=len(image), flash_size=flash_size)
        profile = {'source_offset': 0x400000, 'source_length': 0x400000,
                   'identical_source_offsets': (0x400000,),
                   'evidence_spans': ((0x200, 0x204),)}
        with patch.object(secondary_protected_plan, 'find_secondary_seed',
                          return_value=profile):
            plan = self.plan(image=image, loaded=loaded, config=config)
        binding = secondary_protected_plan.project(plan)
        self.assertEqual((binding.firmware_size, binding.source_offset),
                         (flash_size, 0x400000))

    def test_supplied_bank_source_is_projected_and_all_bytes_are_guarded(self):
        image = self.original + b'\xa5' * (0x800000 - len(self.original))
        config = _config(file_size=len(image), flash_size=len(image))
        profile = {'source_offset': 0x400000, 'source_length': 0x400000,
                   'identical_source_offsets': (0x400000,),
                   'evidence_spans': ((0x200, 0x204),)}
        with patch.object(secondary_protected_plan, 'find_secondary_seed',
                          return_value=profile):
            plan = self.plan(image=image, loaded=image, config=config)
            binding = secondary_protected_plan.project(plan)
            self.assertEqual((binding.source_offset, binding.firmware_size),
                             (0x400000, len(image)))
            changed = bytearray(image)
            changed[0x400123] ^= 1
            self.assertFalse(self.plan(image=image, loaded=bytes(changed),
                                       config=config).capabilities)
        capability = plan.capabilities[0]
        parameters = dict(capability.parameters)
        for offset in (True, -1, 0x400001, 0x800000):
            broken = replace(capability,
                parameters=tuple({**parameters, 'seed_offset': offset}.items()))
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                secondary_protected_plan.project(replace(plan,
                    capabilities=(broken,)))
        with self.assertRaises(ValueError):
            without_source = replace(capability, evidence=capability.evidence[:2])
            secondary_protected_plan.project(replace(plan,
                capabilities=(without_source,)))

    def test_source_guard_includes_identical_mirror_used_by_layout_proof(self):
        image = bytes(0x3000)
        profile = {'source_offset': 0x1000, 'source_length': 0x1000,
                   'identical_source_offsets': (0x1000, 0x2000),
                   'evidence_spans': ((0, 2),)}
        with patch.object(secondary_protected_plan, 'find_secondary_seed',
                          return_value=profile):
            offset, _ = secondary_protected_plan._seed_source(
                image, image, 0x12000000, 0x1000)
            self.assertEqual(offset, 0x1000)
            changed = bytearray(image)
            changed[0x2001] = 1
            with self.assertRaises(ValueError):
                secondary_protected_plan._seed_source(
                    image, bytes(changed), 0x12000000, 0x1000)

    def test_plan_calls_copy_proof_for_exact_cell_through_probe_extent(self):
        with patch.object(secondary_protected_plan.secondary_protected_nor,
                          'find_secondary_protected_nor',
                          return_value=_candidate(self.original)), \
             patch.object(secondary_protected_plan.secondary_nor_copy,
                          'find_copy_source', return_value=_copy_profile()) as copy:
            secondary_protected_plan.machine_plan(
                self.original, self.loaded, self.config)
        args = copy.call_args.args
        self.assertEqual(args[1:], (0x14000000, 0x02000000,
                                    (0x14001000, 0x1400101C), 0x6000))

    def test_unowned_and_ordinary_load_guards_reject_selection(self):
        mutations = (
            _config(load_address=0x1000), _config(image_offset=0x20),
            _config(entry=0x100), _config(file_size=0x8000),
            _config(flash_size=0x8000), _config(secondary_flash_address=0x12000000),
            _config(flash_size=0x20000),
            _config(upper_flash_address=0x12000000),
            _config(native_nand_profile={'profile': 1}),
            _config(nand_enabled=True),
            _config(ram_base=0xFFFFFFF0, ram_size=0x100),
        )
        for config in mutations:
            with self.subTest(config=config):
                self.assertFalse(self.plan(config=config).capabilities)
        self.assertFalse(self.plan(claimed=True).capabilities)
        self.assertFalse(self.plan(loaded=self.original[:-1]).capabilities)

    def test_loaded_source_bytes_and_probe_body_are_mandatory(self):
        for offset in (0x100, 0x500, 0x6000, 0x60A4, 0x7FF8, 0x8000):
            loaded = bytearray(self.loaded)
            loaded[offset] ^= 1
            with self.subTest(offset=offset):
                self.assertFalse(self.plan(loaded=bytes(loaded)).capabilities)
        wrong_probe = bytearray(self.original)
        wrong_probe[0x8000] ^= 1
        self.assertFalse(self.plan(image=bytes(wrong_probe)).capabilities)

    def test_source_mask_and_base_are_derived_from_command_leaf(self):
        for image in (_image(mask=0x7F), _image(base=0x11000000)):
            with patch.object(secondary_protected_plan.secondary_protected_nor,
                              'find_secondary_protected_nor',
                              return_value=_candidate(image)), \
                 patch.object(secondary_protected_plan.secondary_nor_copy,
                              'find_copy_source', return_value=_copy_profile()):
                self.assertFalse(secondary_protected_plan.machine_plan(
                    image, image, self.config).capabilities)

    def test_branchless_7f_mask_requires_the_linked_f3_base_probe(self):
        from msm5xxx_emulator.detection.facts import facts_for

        image = bytearray(0x1000)
        helper, probe, caller = 0x100, 0x180, 0x200
        _u16(image, helper, 0x217F, 0x2260, 0x8002, 0x0C02,
             0x1C13, 0x400B, 0x8003, 0x23AC, 0x8003, 0x4391,
             0x8001, 0x217B, 0x8001, 0x4770)
        _u16(image, probe, 0x2100, 0x20F3, 0x8008, 0x2109,
             0x0649, 0x8008, 0x4770)
        _u16(image, caller, 0xB500, *_thumb_bl(caller + 2, probe), 0xBD00)
        candidate = {
            'address': 0x12650000,
            'size': 0x1A0000,
            'protocol_intervals': {
                'command_helper': [helper, helper + 28],
                'identify_base': [probe, probe + 14],
                'identify_caller': [caller, caller + 8],
            },
        }
        facts = facts_for(bytes(image))
        self.assertEqual(
            secondary_protected_plan.secondary_protected_protocol.bank_window(
                candidate, facts, (0x10000,) * 26),
            (0x12000000, 0x800000, 0x10000))

        without_probe = {'address': candidate['address'],
                         'protocol_intervals': {'command_helper': [helper, helper + 28],
                                                'identify_caller': [caller, caller + 8]}}
        self.assertIsNone(
            secondary_protected_plan.secondary_protected_protocol.bank_window(
                without_probe, facts, (0x10000,) * 26))

        changed = bytearray(image)
        _u16(changed, probe + 8, 0x0641)  # address shift no longer yields 0x12000000
        self.assertIsNone(
            secondary_protected_plan.secondary_protected_protocol.bank_window(
                candidate, facts_for(bytes(changed)), (0x10000,) * 26))

        unlinked = bytearray(image)
        _u16(unlinked, caller + 2, 0x46C0, 0x46C0)
        self.assertIsNone(
            secondary_protected_plan.secondary_protected_protocol.bank_window(
                candidate, facts_for(bytes(unlinked)), (0x10000,) * 26))

    def test_selector_query_and_initialized_base_derive_the_aperture(self):
        from msm5xxx_emulator.detection.facts import facts_for

        protocol = secondary_protected_plan.secondary_protected_protocol
        image = _query_image()
        candidate = {
            'address': 0x12100000, 'size': 0x20000,
            'selected_object': 0x6000,
            'protocol_intervals': {'command_helper': [0x500, 0x508]},
            'sector_prefix_consumer': {'global_address': 0x14000020},
            'lifecycle': {'selector': 0x100, 'constructor': 0x200},
        }
        facts = facts_for(image)
        self.assertEqual(protocol.selector_query_address(
            candidate, facts, 0x14001009), 0x12100000)
        self.assertEqual(protocol.selector_query_address(
            candidate, facts, 0x14001009, with_spans=True),
            (0x12100000, ((0x400, 0x402),)))
        self.assertEqual(protocol.bank_window(
            candidate, facts, (0x10000, 0x10000), query_pointer=0x14001009),
            (0x12000000, 0x800000, 0x10000))

        mutations = (
            (_query_image(query_pointer=0x1400100D), 0x14001009),
            (_query_image(zero_base=False), 0x14001009),
            (_query_image(clobber_base=True), 0x14001009),
            (_query_image(intervening_write=True), 0x14001009),
            (_query_image(query_shift=2), 0x14001009),
            (_query_image(mask=0x5F), 0x14001009),
        )
        for changed, pointer in mutations:
            with self.subTest(pointer=pointer, image=changed != image):
                changed_facts = facts_for(changed)
                self.assertIsNone(protocol.bank_window(
                    candidate, changed_facts, (0x10000, 0x10000),
                    query_pointer=pointer))

        unlinked = bytearray(image)
        _u16(unlinked, 0x110, 0x46C0, 0x46C0)
        self.assertIsNone(protocol.bank_window(
            candidate, facts_for(bytes(unlinked)), (0x10000, 0x10000),
            query_pointer=0x14001009))

        crossed_image = bytearray(image)
        _u32(crossed_image, 0x6000 + 0xB0, 0x093F8000)
        crossed = dict(candidate, address=0x127F0000, size=0x20000)
        self.assertIsNone(protocol.bank_window(
            crossed, facts_for(bytes(crossed_image)), (0x10000, 0x10000),
            query_pointer=0x14001009))

    def test_copy_profile_cannot_admit_a_missing_or_wrong_probe_mapping(self):
        for copy in (
            {**_copy_profile(), 'required_span': [0x14001000, 0x14001018]},
            {**_copy_profile(), 'copy_writes': [[0x14001000, 0x1C, 0x7000]]},
            {**_copy_profile(), 'expected_object': 0x12345678},
        ):
            with self.subTest(copy=copy):
                self.assertFalse(self.plan(copy=copy).capabilities)

    def test_packed_identity_requires_linked_getter_adjustment_and_halfword_pair(self):
        from msm5xxx_emulator.detection.facts import facts_for

        candidate = _candidate(self.original)
        facts = facts_for(self.original)
        self.assertTrue(secondary_protected_plan.secondary_protected_protocol.packed_identity_is_read(
            candidate, facts, candidate['selected_object']))
        for offset, value in ((0x22A, 0x3008), (0x26C, 0x8C19)):
            changed = bytearray(self.original)
            _u16(changed, offset, value)
            with self.subTest(offset=offset):
                self.assertFalse(secondary_protected_plan.secondary_protected_protocol.packed_identity_is_read(
                    candidate, facts_for(bytes(changed)), candidate['selected_object']))

    def test_getter_requires_pointer_load_to_dominate_return_adjustment(self):
        from msm5xxx_emulator.detection.facts import facts_for

        candidate = _candidate(self.original)
        self.assertEqual(secondary_protected_plan.secondary_protected_protocol
                         ._getter_field_adjustment(candidate, facts_for(self.original)), 4)

        clobbered = bytearray(self.original)
        _u16(clobbered, 0x228, 0x4618)  # mov r0, r3 before the adjustment
        self.assertIsNone(secondary_protected_plan.secondary_protected_protocol
                         ._getter_field_adjustment(candidate, facts_for(bytes(clobbered))))

        split_path = bytearray(self.original)
        _u16(split_path, 0x222, 0x2800)  # compare before the pointer field read
        _u16(split_path, 0x224, 0xD001)  # branch around the read to the +4 path
        _u16(split_path, 0x226, 0x6840)  # pointer field read exists on other path
        self.assertIsNone(secondary_protected_plan.secondary_protected_protocol
                         ._getter_field_adjustment(candidate, facts_for(bytes(split_path))))

    def test_project_rejects_tampered_properties_parameters_and_claims(self):
        plan = self.plan()
        cap = plan.capabilities[0]
        mutations = (
            replace(cap, properties=(('experimental-protected-nor',
                                      '12000000:200000:10000:f4240'),
                                     ('protected-nor-bank', '12000000:39001c'))),
            replace(cap, parameters=tuple((name, value) for name, value in cap.parameters
                                          if name != 'raw_size')),
            replace(cap, claims=()),
        )
        for changed in mutations:
            forged = replace(plan, capabilities=(changed,),
                             properties=changed.properties,
                             claims=changed.claims, evidence=changed.evidence)
            with self.subTest(capability=changed):
                with self.assertRaises(ValueError):
                    secondary_protected_plan.project(forged)
        self.assertIsNone(secondary_protected_plan.project(
            secondary_protected_plan.resolve_proposals(()).plan))


if __name__ == '__main__':
    unittest.main()
