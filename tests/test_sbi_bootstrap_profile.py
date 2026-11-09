"""Focused static admission checks for the SBI bootstrap-only bridge."""
from __future__ import annotations

from corpus import snippet

import struct
import unittest
from unittest.mock import patch
from capstone import arm as a

from msm5xxx_emulator.detection.fact_context import FirmwareFacts
from msm5xxx_emulator.detection.devices.sbi.bootstrap import (
    _marker_has_base_store, find_sbi_bootstrap_profile, bootstrap_layout_at,
)
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


class SbiBootstrapProfileTest(unittest.TestCase):
    @staticmethod
    def _arm_image(*, with_intervening_call: bool = False,
                   with_unknown_access: bool = False,
                   with_event_loop: bool = False) -> tuple[bytearray, int]:
        image = bytearray(0x180)
        entry, pool = 0x20, 0x100
        struct.pack_into('<2I', image, 0, 0xEB000006, 0xE12FFF1E)
        ops = [('ldr', 4, 0x03000780)]
        for index, offset, width, value in (
                (1, 0, 1, 0x45), (2, 0, 1, 0xC5),
                (3, 4, 2, 0x085F), (4, 0x0C, 2, 0x041F),
                (5, 0x10, 1, 0), (6, 0x10, 1, 1)):
            ops.extend((('ldr', 0, value), ('store', offset, width)))
            if with_intervening_call and index == 2:
                ops.append(('call',))
            if with_unknown_access and index == 2:
                ops.append(('unknown_store',))
        if with_event_loop:
            labels = {'first_store': 2}
            ops.append(('beq', 'first_store'))
        else:
            labels = {}
        labels['poll'] = len(ops)
        ops.extend((('read',), ('tst',), ('beq', 'write'), ('branch', 'poll')))
        labels['write'] = len(ops)
        ops.extend((('ldr', 0, 0x0900), ('store', 0x0C, 2),
                    ('read',), ('return',)))
        helper = entry + 0x80
        code, pool_index = [], 0
        for index, op in enumerate(ops):
            address = entry + index * 4
            if op[0] == 'ldr':
                literal = pool + pool_index * 4
                pool_index += 1
                struct.pack_into('<I', image, literal, op[2])
                word = 0xE59F0000 | op[1] << 12 | (literal - (address + 8))
            elif op[0] == 'store':
                offset, width = op[1:]
                word = (0xE5C40000 | offset if width == 1 else
                        0xE1C400B0 | (offset & 0xF0) << 4 | (offset & 0x0F))
            elif op[0] == 'read':
                word = 0xE1D400B0
            elif op[0] == 'tst':
                word = 0xE3100001
            elif op[0] in ('beq', 'branch'):
                target = entry + labels[op[1]] * 4
                displacement = (target - (address + 8)) // 4 & 0xFFFFFF
                word = (0x0A000000 if op[0] == 'beq' else 0xEA000000) | displacement
            elif op[0] == 'call':
                word = 0xEB000000 | ((helper - (address + 8)) // 4 & 0xFFFFFF)
            elif op[0] == 'unknown_store':
                word = 0xE5C50000
            else:
                word = 0xE12FFF1E
            code.append(word)
        struct.pack_into('<' + 'I' * len(code), image, entry, *code)
        if with_intervening_call:
            struct.pack_into('<I', image, helper, 0xE12FFF1E)
        return image, entry

    @staticmethod
    def _image(layout: str, entry: int | None = None) -> tuple[bytearray, int]:
        image = bytearray(0x400)
        if entry is None:
            entry = 0x80 if layout == "preserved" else 0x20
        if layout == "reloaded":
            words = {
                0:0x2045,4:0x7008,6:0x20C5,0x0A:0x7008,0x10:0x8088,
                0x16:0x8188,0x18:0x2000,0x1C:0x7408,0x1E:0x2001,0x22:0x7408,
                0x26:0x8800,0x28:0x07C0,0x2A:0x0FC0,0x2C:0x2801,
                0x2E:0xD100,0x30:0xE7F8,0x32:0x2009,0x34:0x0200,
                0x38:0x8188,0x3C:0x8800,0x3E:0x07C0,0x40:0x0FC0,
                0x42:0x2801,0x44:0xD100,0x46:0xE7F8,
            }
            literals = ((2,1,0x03000780),(8,1,0x03000780),(0x0C,0,0x085F),
                        (0x0E,1,0x03000780),(0x12,0,0x041F),(0x14,1,0x03000780),
                        (0x1A,1,0x03000780),(0x20,1,0x03000780),(0x24,0,0x03000780),
                        (0x36,1,0x03000780),(0x3A,0,0x03000780))
        elif layout == "preserved":
            prefix = snippet("test_sbi_bootstrap_profile", "preserved_layout_prefix")
            words = {offset-0x5A:struct.unpack_from('<H',prefix,offset)[0]
                     for offset in range(0,len(prefix),2)}
            words.update({0:0x2545,4:0x700D,6:0x25C5,8:0x700D,0x0C:0x808D,
                          0x10:0x818D,0x12:0x7408,0x14:0x740A,0x16:0x880D,
                          0x18:0x07ED,0x1A:0x0FED,0x1C:0x2D01,0x1E:0xD0FA,
                          0x20:0x2509,0x22:0x022D,0x24:0x818D,0x26:0x880D,
                          0x28:0x07ED,0x2A:0x0FED,0x2C:0x2D01,0x2E:0xD0FA})
            literals = ((-0x3C,0,0x0822),(-0x3A,7,0x04800080),(-0x36,0,0x0222),
                        (-0x26,5,0x0513),(-0x1A,7,0x04800040),(-0x10,7,0x03000320),
                        (2,1,0x03000780),(0x0A,5,0x085F),(0x0E,5,0x041F))
        elif layout == "arithmetic":
            words = {
                0: 0x2045, 4: 0x7008, 6: 0x20C5, 8: 0x7008,
                0x0C: 0x303D, 0x0E: 0x8088, 0x12: 0x38F4, 0x14: 0x8188,
                0x16: 0x2000, 0x1A: 0x3110, 0x1C: 0x7008, 0x1E: 0x2001,
                0x20: 0x7008, 0x24: 0x8800, 0x26: 0x0840, 0x28: 0xD2FB,
                0x2C: 0x30DE, 0x30: 0x8188, 0x34: 0x8800, 0x36: 0x0840,
                0x38: 0xD306,
            }
            literals = (
                (2, 1, 0x03000780), (0x0A, 0, 0x0822),
                (0x10, 0, 0x0513), (0x18, 1, 0x03000780),
                (0x22, 0, 0x03000780), (0x2A, 0, 0x0822),
                (0x2E, 1, 0x03000780), (0x32, 0, 0x03000780),
            )
        else:
            words = {
                0: 0x2045, 4: 0x7008, 6: 0x20C5, 8: 0x7008,
                0x0C: 0x8088, 0x10: 0x8188, 0x12: 0x2000, 0x16: 0x7008,
                0x18: 0x2001, 0x1A: 0x7008, 0x1E: 0x8800, 0x20: 0x07C0,
                0x22: 0x0FC0, 0x24: 0x2801, 0x26: 0xD100, 0x28: 0xE7F8,
                0x2A: 0x2009, 0x2C: 0x0200, 0x30: 0x8188, 0x34: 0x8800,
                0x36: 0x07C0, 0x38: 0x0FC0, 0x3A: 0x2801, 0x3C: 0xD100,
                0x3E: 0xE7F8,
            }
            literals = (
                (2, 1, 0x03000780), (0x0A, 0, 0x085F),
                (0x0E, 0, 0x041F), (0x14, 1, 0x03000790),
                (0x1C, 0, 0x03000780), (0x2E, 1, 0x03000780),
                (0x32, 0, 0x03000780),
            )
        for offset, word in words.items():
            struct.pack_into("<H", image, entry + offset, word)
        for index, (offset, register, value) in enumerate(literals):
            literal = 0x200 + index * 4
            pc = (entry + offset + 4) & ~3
            struct.pack_into("<H", image, entry + offset,
                             0x4800 | register << 8 | (literal - pc) // 4)
            struct.pack_into("<I", image, literal, value)
        owner = entry - 0x5A if layout == 'preserved' else entry
        delta = owner - 4
        struct.pack_into('<2H', image, 0,
                         0xF000 | (delta >> 12 & 0x7FF),
                         0xF800 | (delta >> 1 & 0x7FF))
        return image, entry

    def test_admits_typed_layouts_and_rejects_hardware_trace_mutation(self) -> None:
        for layout, mutation in (("arithmetic", 0x28), ("direct", 0x30)):
            with self.subTest(layout=layout):
                image, entry = self._image(layout)
                profile = find_sbi_bootstrap_profile(image)
                self.assertIsNotNone(profile)
                assert profile is not None
                self.assertEqual(profile["entries"], [entry])
                image[entry + mutation] ^= 1
                self.assertIsNone(find_sbi_bootstrap_profile(image))

    def test_inline_marker_register_allocation_does_not_need_a_catalog_row(self):
        for register in (2, 7):
            image, entry = self._image('direct')
            image[:4] = bytes(4)
            struct.pack_into('<H', image, entry, 0x2045 | register << 8)
            struct.pack_into('<H', image, entry + 4, 0x7008 | register)
            profile = find_sbi_bootstrap_profile(bytes(image))
            self.assertIsNotNone(profile)
            self.assertEqual(profile['entries'], [entry])

    def test_inline_transaction_retains_proved_prefix_payload_registers(self):
        image, entry = self._image('direct', 0x80)
        image[:4] = bytes(4)
        struct.pack_into('<2H', image, 0x60, 0x2000, 0x2201)
        for offset, word in ((0, 0x2545), (4, 0x700D), (6, 0x25C5),
                             (8, 0x700D), (0xC, 0x808D), (0x10, 0x818D),
                             (0x12, 0x46C0), (0x16, 0x7408),
                             (0x18, 0x46C0), (0x1A, 0x740A)):
            struct.pack_into('<H', image, entry + offset, word)
        word, = struct.unpack_from('<H', image, entry + 0x14)
        pool = ((entry + 0x18) & ~3) + (word & 255) * 4
        struct.pack_into('<I', image, pool, 0x03000780)
        for offset in (0xA, 0xE):
            word, = struct.unpack_from('<H', image, entry + offset)
            struct.pack_into('<H', image, entry + offset, word & 0xF8FF | 0x500)
        profile = find_sbi_bootstrap_profile(bytes(image))
        self.assertIsNotNone(profile)
        self.assertEqual(profile['entries'], [entry])
        self.assertEqual(profile['layout'], 'thumb-sbi-bootstrap-preserved-register-v1')
        struct.pack_into('<H', image, 0x64, 0xE000)
        self.assertIsNone(find_sbi_bootstrap_profile(bytes(image)))

    def test_layout_metadata_comes_from_event_and_address_evidence(self) -> None:
        expected = {
            'arithmetic': 'thumb-sbi-bootstrap-literal-arithmetic-v1',
            'direct': 'thumb-sbi-bootstrap-direct-literal-v1',
            'reloaded': 'thumb-sbi-bootstrap-reloaded-literal-v1',
        }
        for source, layout in expected.items():
            with self.subTest(source=source):
                image, entry = self._image(source)
                profile = find_sbi_bootstrap_profile(bytes(image))
                self.assertIsNotNone(profile)
                assert profile is not None
                self.assertEqual(profile['entries'], [entry])
                self.assertEqual(profile['layout'], layout)

    def test_new_layouts_relocate_and_preserve_wire_contract(self) -> None:
        for layout in ("arithmetic", "direct", "reloaded", "preserved"):
            image, entry = self._image(layout)
            for shift in (0, 0x204):
                with self.subTest(layout=layout, shift=shift):
                    profile = find_sbi_bootstrap_profile(bytes(shift) + image)
                    self.assertIsNotNone(profile)
                    self.assertEqual(profile['entries'], [entry + shift])
                    self.assertEqual(profile['signature'], 'thumb-sbi-bootstrap-only-v1')
                    self.assertEqual(profile['admission'], 'temporary-evidence-gated')
                    self.assertEqual(profile['bootstrap'], [[0,1,0x45],[0,1,0xC5],
                                     [4,2,0x085F],[12,2,0x041F],[16,1,0],[16,1,1]])
                    self.assertEqual(profile['validation'], [[0,2,None],[12,2,0x0900],[0,2,None]])
                    self.assertNotIn('C11', profile['layout'])
                    self.assertNotIn('N200', profile['layout'])

    def test_arm_and_thumb_share_the_typed_native_transaction(self) -> None:
        image, entry = self._arm_image()
        profile = find_sbi_bootstrap_profile(image)
        self.assertIsNotNone(profile)
        assert profile is not None
        self.assertEqual(profile['entries'], [entry])
        self.assertEqual(profile['bootstrap'], [[0, 1, 0x45], [0, 1, 0xC5],
                         [4, 2, 0x085F], [12, 2, 0x041F], [16, 1, 0], [16, 1, 1]])
        self.assertEqual(profile['validation'], [[0, 2, None], [12, 2, 0x0900],
                         [0, 2, None]])
        profile['bootstrap'][0][2] = 0
        refreshed = find_sbi_bootstrap_profile(image)
        self.assertIsNotNone(refreshed)
        assert refreshed is not None
        self.assertEqual(refreshed['bootstrap'][0], [0, 1, 0x45])

    def test_opaque_call_and_unresolved_scalar_store_cannot_hide_between_events(self) -> None:
        self.assertIsNone(find_sbi_bootstrap_profile(
            self._arm_image(with_intervening_call=True)[0]))
        self.assertIsNone(find_sbi_bootstrap_profile(
            self._arm_image(with_unknown_access=True)[0]))

    def test_unresolved_stack_store_cannot_hide_between_events(self) -> None:
        image, _ = self._arm_image(with_unknown_access=True)
        unknown_store = struct.pack('<I', 0xE5C50000)  # STRB r0,[r5]
        site = image.find(unknown_store)
        self.assertGreaterEqual(site, 0)
        image[site:site + 4] = struct.pack('<I', 0xE5CD0000)  # STRB r0,[sp]
        self.assertIsNone(find_sbi_bootstrap_profile(bytes(image)))

    def test_bulk_memory_and_execution_state_changes_cannot_hide_between_events(self):
        for instruction in (0xE8A50001, 0xE8B50008, 0xE121F005):
            image, _ = self._arm_image(with_unknown_access=True)
            site = image.find(struct.pack('<I', 0xE5C50000))
            struct.pack_into('<I', image, site, instruction)
            self.assertIsNone(find_sbi_bootstrap_profile(bytes(image)))

    def test_unrelated_loop_cannot_repeat_bootstrap_events(self) -> None:
        self.assertIsNone(find_sbi_bootstrap_profile(
            self._arm_image(with_event_loop=True)[0]))

    def test_event_values_poll_direction_and_source_bounds(self) -> None:
        writer = {'arithmetic': 0x2C, 'direct': 0x2A,
                  'reloaded': 0x32, 'preserved': 0x20}
        poll = {'arithmetic': 0x28, 'direct': 0x26,
                'reloaded': 0x2E, 'preserved': 0x1E}
        last_read = {'arithmetic': 0x34, 'direct': 0x34,
                     'reloaded': 0x3C, 'preserved': 0x26}
        for layout in writer:
            image, entry = self._image(layout)
            for offset in (0, writer[layout], poll[layout]):
                with self.subTest(layout=layout, offset=offset):
                    changed = bytearray(image); changed[entry + offset] ^= 1
                    self.assertIsNone(find_sbi_bootstrap_profile(bytes(changed)))
            self.assertIsNone(find_sbi_bootstrap_profile(
                bytes(image[:entry + last_read[layout] + 1])))
            # A software instruction after the last native-observed read does
            # not alter this bounded hardware contract.
            if layout == 'reloaded':
                changed = bytearray(image); changed[entry + 0x44] ^= 1
                self.assertIsNotNone(find_sbi_bootstrap_profile(bytes(changed)))
        self.assertIsNone(find_sbi_bootstrap_profile(
            bytes(self._image('reloaded')[0]) * 2))
        first, _ = self._image('reloaded'); second, _ = self._image('preserved')
        self.assertIsNone(find_sbi_bootstrap_profile(bytes(first) + bytes(second)))

    def test_preserved_prefix_supplies_registers_and_rejects_odd_alignment(self) -> None:
        self.assertIsNone(bootstrap_layout_at(bytes(4), -2))
        image, entry = self._image('preserved', 0x80)
        self.assertIsNotNone(find_sbi_bootstrap_profile(bytes(image)))
        # The supplied straight-line producers close the local transaction
        # independently of an enclosing function's direct-call nomination.
        changed = bytearray(image); changed[:4] = bytes(4)
        self.assertIsNotNone(find_sbi_bootstrap_profile(bytes(changed)))
        self.assertIsNone(find_sbi_bootstrap_profile(bytes(image[2:])))
        self.assertIsNone(find_sbi_bootstrap_profile(b'\0' + bytes(image)))
        image, entry = self._image('reloaded', 0x20)
        self.assertIsNotNone(find_sbi_bootstrap_profile(bytes(image)))

    def test_closed_local_marker_does_not_need_a_direct_call_owner(self) -> None:
        image, entry = self._image('direct', 0x80)
        # Leave the transaction embedded after unrelated code and remove its
        # only direct-call edge. Local typed evidence is the contract here.
        struct.pack_into('<I', image, 0, 0xEAFFFFFE)
        struct.pack_into('<H', image, entry - 0x10, 0x46C0)
        profile = find_sbi_bootstrap_profile(bytes(image))
        self.assertIsNotNone(profile)
        assert profile is not None
        self.assertEqual(profile['entries'], [entry])
        self.assertEqual(profile['layout'], 'thumb-sbi-bootstrap-direct-literal-v1')
        bad_port = bytearray(image)
        struct.pack_into('<I', bad_port, 0x200, 0x03000784)
        bad_poll = bytearray(image)
        bad_poll[entry + 0x26] ^= 1
        for changed in (bad_port, bad_poll, image[:entry + 0x34]):
            self.assertIsNone(find_sbi_bootstrap_profile(bytes(changed)))

    def test_thumb_marker_register_is_taken_from_the_instruction(self) -> None:
        image = bytearray(0x20)
        struct.pack_into('<HHH', image, 0, 0x2145, 0x4A03, 0x7011)
        struct.pack_into('<I', image, 0x10, 0x03000780)
        facts = facts_for(bytes(image))
        self.assertTrue(_marker_has_base_store(
            facts, CodeAddress(0, 'thumb'), a.ARM_REG_R1))

    def test_non_mmio_markers_are_rejected_before_function_analysis(self) -> None:
        image, entry = self._image('direct', 0x80)
        image.extend(bytes(0x4000 - len(image)))
        struct.pack_into('<I', image, 0, 0xEAFFFFFE)
        decoys = (0x600, 0x900, 0xC00, 0xF00)
        call_sites = (0x400, 0x404, 0x408, 0x40C)
        for target, site in zip(decoys, call_sites):
            struct.pack_into('<HH', image, target, 0x2045, 0x46C0)
            displacement = (target - (site + 4)) & 0x1FFFFFF
            sign = (displacement >> 24) & 1
            i1, i2 = (displacement >> 23) & 1, (displacement >> 22) & 1
            j1, j2 = (~(i1 ^ sign)) & 1, (~(i2 ^ sign)) & 1
            first = 0xF000 | (sign << 10) | ((displacement >> 12) & 0x3FF)
            second = (0xD000 | (j1 << 13) | (j2 << 11)
                      | ((displacement >> 1) & 0x7FF))
            struct.pack_into('<HH', image, site, first, second)
        overwritten_marker = 0x3000
        literal_pool = 0x3800
        ldr_pc = ((overwritten_marker + 2 + 4) & ~3)
        ldr_imm = (literal_pool - ldr_pc) // 4
        struct.pack_into('<HH', image, overwritten_marker,
                         0x2045, 0x4800 | ldr_imm)
        struct.pack_into('<I', image, literal_pool, 0x03000780)
        struct.pack_into('<H', image, overwritten_marker + 4, 0x7000)
        original = FirmwareFacts.function
        analysed = []

        def counted(facts, address, *args, **kwargs):
            if address.isa == 'thumb':
                analysed.append(address.address)
            return original(facts, address, *args, **kwargs)

        with patch.object(FirmwareFacts, 'function', counted):
            profile = find_sbi_bootstrap_profile(bytes(image))
        self.assertIsNotNone(profile)
        self.assertIn(entry, analysed)
        self.assertTrue(set(decoys + (overwritten_marker,)).isdisjoint(analysed))

    def test_arm_local_marker_reports_transaction_after_owner_prefix(self) -> None:
        original, _ = self._arm_image()
        moved = bytearray(0x280)
        struct.pack_into('<I', moved, 0, 0xEAFFFFFE)
        # Retain later transaction instructions and their literal pool at
        # equal relative offsets, adding the marker and its immediate base
        # producer before the first event.
        transaction = bytearray(original)
        struct.pack_into('<I', transaction, 0, 0xEAFFFFFE)
        struct.pack_into('<I', transaction, 0x20, 0xE3A01045)  # MOV r1,#0x45
        struct.pack_into('<I', transaction, 0x24, 0xE3A00403)  # MOV r0,#0x03000000
        struct.pack_into('<I', transaction, 0x28, 0xE5C01780)  # STRB r1,[r0,#0x780]
        struct.pack_into('<I', transaction, 0x2C, 0xE59F40D0)  # LDR r4,[PC,#0xd0]
        transaction[0x30:0x104] = original[0x2C:0x100]
        transaction[0x104:0x184] = original[0x100:0x180]
        # Move the complete transaction and its pool after an unrelated owner
        # prefix. No call or reset edge targets the transaction marker.
        moved[0x60:0x1C4] = transaction[0x20:0x184]
        profile = find_sbi_bootstrap_profile(bytes(moved))
        self.assertIsNotNone(profile)
        assert profile is not None
        self.assertEqual(profile['entries'], [0x60])
        self.assertEqual(profile['layout'], 'arm-sbi-bootstrap-immediate-v1')

    def test_thumb_local_marker_accepts_literal_plus_immediate_base(self) -> None:
        image, entry = self._image('direct', 0x80)
        struct.pack_into('<I', image, 0, 0xEAFFFFFE)
        original = bytes(image[entry + 4:0x100])
        image[entry + 6:0x102] = original
        struct.pack_into('<H', image, entry + 4, 0x3920)  # SUBS r1,#0x20
        struct.pack_into('<I', image, 0x200, 0x030007A0)
        for index in range(0, len(original), 2):
            old_site = entry + 4 + index
            instruction = struct.unpack_from('<H', original, index)[0]
            if instruction & 0xF800 != 0x4800:
                continue
            pool = ((old_site + 4) & ~3) + (instruction & 0xFF) * 4
            new_site = old_site + 2
            new_pc = ((new_site + 4) & ~3)
            immediate = (pool - new_pc) // 4
            struct.pack_into('<H', image, new_site,
                             (instruction & 0xFF00) | immediate)
        profile = find_sbi_bootstrap_profile(bytes(image))
        self.assertIsNotNone(profile)
        assert profile is not None
        self.assertEqual(profile['entries'], [entry])
