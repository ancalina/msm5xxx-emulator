"""Offline MA5 GPIO/parent IRQ static-candidate fixtures."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import unittest

from msm5xxx_emulator.detection import ma5_gpio_irq as _detector
from msm5xxx_emulator.detection.audio import find_ma5_readback_candidate
from test_audio_transport import _ma5_readback_image, _ma5_literal_readback_image, _thumb_bl

_FIXTURES = Path(__file__).resolve().parent / 'fixtures'


def _fixture(witness: int, relocation: int = 0) -> tuple[bytes, dict]:
    spans = json.loads((_FIXTURES / 'ma5_irq_instruction_fixtures.json').read_text())
    data = json.loads((_FIXTURES / 'ma5_irq_scatter_fixtures.json').read_text())[witness]
    base = _ma5_literal_readback_image() if witness == 0 else _ma5_readback_image()
    selected = {role: next((row for row in rows if row['witness'] == witness), None)
                for role, rows in spans.items()}
    selected = {role: row for role, row in selected.items() if row is not None}
    entries, remap = {}, {}
    at = 0x3000 + relocation
    for role, row in selected.items():
        at = (at + 3) & ~3
        at += row['start'] & 3
        entries[role] = at
        remap[row['start']] = at
        at += 0x400
    remap.update({original: target for original, target in data['audio_entries'].values()})
    stub_at = 0xC000 + relocation
    stubs = {}

    def pointer(value: int) -> int:
        nonlocal stub_at
        plain = value & ~1
        if plain in remap:
            return remap[plain] | (value & 1)
        if value > 0xFFFF and value < 0x01000000:
            if plain not in stubs:
                stubs[plain] = stub_at
                stub_at += 0x20
            return stubs[plain] | (value & 1)
        return value

    image = bytearray(b'\xff' * (0x50000 + relocation))
    image[:len(base)] = base
    for role, row in selected.items():
        entry = entries[role]
        code = bytearray.fromhex(row['code'])
        pool = (entry + len(code) + 3) & ~3
        for offset, target in row['calls']:
            target = remap.get(target, pointer(target))
            code[offset:offset + 4] = _thumb_bl(entry + offset, target)
        for offset, value in row['literals']:
            mapped = pointer(value)
            struct.pack_into('<I', image, pool, mapped)
            literal_base = (entry + offset + 4) & ~3
            assert 0 <= pool - literal_base <= 1020 and not (pool - literal_base) & 3
            code[offset] = (pool - literal_base) // 4
            pool += 4
        image[entry:entry + len(code)] = code
    for address in stubs.values():
        image[address:address + 2] = b'\x70\x47'
    # The source dispatcher invokes this existing ABI veneer with R0 target.
    thunk = selected['gpio_dispatch']['calls'][0][1]
    thunk_entry = stubs[thunk]
    thunk_leaf = 0xE000 + relocation if witness == 0 else thunk_entry
    if witness == 0:
        image[thunk_entry:thunk_entry + 12] = bytes.fromhex('7847c04600c09fe51cff2fe1')
        struct.pack_into('<I', image, thunk_entry + 12, thunk_leaf | 1)
    image[thunk_leaf:thunk_leaf + 2] = b'\x00\x47'
    target, size, source = data['ram_base'], data['data_size'], 0x10000 + relocation
    image[source:source + size] = b'\0' * size
    struct.pack_into('<5I', image, 0x80, source, target, size, target + size,
                     0x02000000 - target - size)
    gpio_table = dict(selected['gpio_init']['literals'])[0x56]
    parent_variant = selected['parent_register']
    table_offset = 0x2C if len(bytes.fromhex(parent_variant['code'])) == 128 else 0x26
    parent_table = dict(parent_variant['literals'])[table_offset]
    descriptor = parent_table + 29 * 28
    gpio_rom = source + gpio_table - target
    desc_rom = source + descriptor - target
    image[gpio_rom:gpio_rom + 72] = bytes.fromhex(data['gpio_table_hex'])
    words = list(struct.unpack('<7I', bytes.fromhex(data['descriptor_hex'])))
    words[5] = pointer(words[5])
    struct.pack_into('<7I', image, desc_rom, *words)
    struct.pack_into('<I', image, source + data['context_holder'] - target, data['initial_context'])
    boot = 0x2000 + relocation
    image[boot:boot + 4] = _thumb_bl(boot, entries['parent_init'])
    image[boot + 4:boot + 8] = _thumb_bl(boot + 4, entries['gpio_init'])
    return bytes(image), {'entries': entries, 'gpio_rom': gpio_rom, 'descriptor_rom': desc_rom,
                          'boot': boot, 'stub_start': 0xC000 + relocation,
                          'thunk': thunk_entry, 'thunk_leaf': thunk_leaf}


class MA5GPIOIRQProposalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = _detector

    def test_two_independent_call_graphs_relocate_and_keep_banks_separate(self):
        for witness in (0, 1):
            for relocation in (0, 0x1000, 0x3000):
                with self.subTest(witness=witness, relocation=relocation):
                    image, fixture = _fixture(witness, relocation)
                    audio = find_ma5_readback_candidate(image)
                    result = self.module.find_ma5_gpio_irq_candidate(image, audio)
                    self.assertEqual(result['status'], 'candidate', result)
                    self.assertFalse(result['runtime_admitted'])
                    chain = result['gpio']['indirect_call_chain']
                    self.assertEqual(chain['leaf'], fixture['thunk_leaf'])
                    self.assertEqual(chain['profile'], 'thumb-arm-literal-bx-r0-v1'
                                     if witness == 0 else 'thumb-bx-r0-v1')
                    self.assertIn([fixture['thunk_leaf'], 2], result['nor_dependencies'])
                    if witness == 0:
                        self.assertIn([fixture['thunk'], 16], result['nor_dependencies'])
                    self.assertEqual(result['gpio']['pin'], 5 if witness == 0 else 2)
                    self.assertEqual(result['gpio']['mask'], 0x20 if witness == 0 else 4)
                    self.assertEqual(result['parent']['status_ack'], 0x03000C84)
                    self.assertEqual(result['gpio']['rows'][0]['pending_ack'], 0x03000C88)
                    self.assertEqual(result['parent']['mask'], 0x2000)
                    self.assertEqual(result['chip']['isr'], fixture['entries']['chip_isr'])
                    self.assertIn([fixture['boot'], 8], result['nor_dependencies'])
                    self.assertIn('auxiliary-paths-unverified', result['admission_note'])
                    self.assertEqual(result['installation']['deferred_callback'] is not None,
                                     witness == 0)

    def test_mutated_roles_literals_rows_parent_and_cross_image_reject(self):
        for witness in (0, 1):
            image, fixture = _fixture(witness)
            for offset in (fixture['entries']['gpio_dispatch'] + 8,
                           fixture['entries']['parent_register'] + 6,
                           fixture['entries']['chip_isr'] + 0x22,
                           fixture['entries']['parent_init'] + 0x4A,
                           fixture['gpio_rom'], fixture['descriptor_rom'] + 8,
                           fixture['descriptor_rom'] + 20, fixture['boot']):
                with self.subTest(witness=witness, mutation=hex(offset)):
                    changed = bytearray(image)
                    changed[offset] ^= 1
                    audio = find_ma5_readback_candidate(bytes(changed))
                    result = self.module.find_ma5_gpio_irq_candidate(bytes(changed), audio)
                    self.assertEqual(result['status'], 'rejected')
            other, _ = _fixture(1 - witness)
            self.assertEqual(self.module.find_ma5_gpio_irq_candidate(
                image, find_ma5_readback_candidate(other))['reject_reason'],
                'audio-same-image-unmatched')

    def test_literal_role_and_bank1_pin_mutations(self):
        image, fixture = _fixture(1)
        changed = bytearray(image)
        entry = fixture['entries']['install_sense']
        changed[entry + 4] = changed[entry + 0x10] = 22
        result = self.module.find_ma5_gpio_irq_candidate(
            bytes(changed), find_ma5_readback_candidate(bytes(changed)))
        self.assertEqual((result['gpio']['bank'], result['gpio']['mask']), (1, 0x40))
        changed = bytearray(image)
        load = fixture['entries']['soc_dispatch'] + 0x12
        word = struct.unpack_from('<H', changed, load)[0]
        pool = ((load + 4) & ~3) + (word & 255) * 4
        struct.pack_into('<I', changed, pool, 0x03000720)
        result = self.module.find_ma5_gpio_irq_candidate(
            bytes(changed), find_ma5_readback_candidate(bytes(changed)))
        self.assertEqual(result['status'], 'rejected')

    def test_coherently_relocated_unaligned_callback_table_rejects(self):
        image, _ = _fixture(0)
        baseline = self.module.find_ma5_gpio_irq_candidate(
            image, find_ma5_readback_candidate(image))
        pointer = baseline['gpio']['callbacks_ram']
        changed = bytearray(image)
        count = 0
        for offset in range(0, len(changed) - 3, 4):
            if struct.unpack_from('<I', changed, offset)[0] == pointer:
                struct.pack_into('<I', changed, offset, pointer + 2)
                count += 1
        self.assertGreater(count, 1)
        result = self.module.find_ma5_gpio_irq_candidate(
            bytes(changed), find_ma5_readback_candidate(bytes(changed)))
        self.assertEqual(result['reject_reason'], 'route-table-unaligned')

    def test_interworking_veneer_roles_and_bounds_reject(self):
        image, fixture = _fixture(0)
        for offset in (fixture['thunk'] + 4, fixture['thunk'] + 12, fixture['thunk_leaf']):
            changed = bytearray(image)
            changed[offset] ^= 1
            result = self.module.find_ma5_gpio_irq_candidate(
                bytes(changed), find_ma5_readback_candidate(bytes(changed)))
            self.assertEqual(result['status'], 'rejected', (offset, result))
        changed = bytearray(image)
        struct.pack_into('<I', changed, fixture['thunk'] + 12, len(image) + 1)
        result = self.module.find_ma5_gpio_irq_candidate(
            bytes(changed), find_ma5_readback_candidate(bytes(changed)))
        self.assertEqual(result['status'], 'rejected')

    def test_copy_only_descriptor_has_no_invented_bss_extent(self):
        image = bytearray(b'\0' * 0x1000)
        struct.pack_into('<5I', image, 0x80, 0x500, 0x01800000, 0x140, 0x01800140, 0)
        layouts = self.module._layouts(bytes(image))
        row = self.module._mapping(layouts, 0x01800100, 4, data=True)
        self.assertEqual(row, (0x80, 0x500, 0x01800000, 0x140, 0x01800140))
        with self.assertRaises(self.module._Reject):
            self.module._mapping(layouts, 0x01800140, 1)

    def test_late_boot_scatter_record_keeps_unique_mapping(self):
        image, _ = _fixture(1)
        changed = bytearray(image)
        changed[0x20040:0x20054] = changed[0x80:0x94]
        changed[0x80:0x94] = b'\0' * 20
        result = self.module.find_ma5_gpio_irq_candidate(
            bytes(changed), find_ma5_readback_candidate(bytes(changed)))
        self.assertEqual(result['status'], 'candidate', result)
        self.assertIn([0x20040, 20], result['nor_dependencies'])
        changed[0x20060:0x20074] = changed[0x20040:0x20054]
        result = self.module.find_ma5_gpio_irq_candidate(
            bytes(changed), find_ma5_readback_candidate(bytes(changed)))
        self.assertEqual(result['status'], 'rejected')

    def test_duplicate_registration_and_scatter_are_ambiguous(self):
        image, fixture = _fixture(0)
        for mutation in ('caller', 'scatter'):
            changed = bytearray(image)
            if mutation == 'caller':
                entry = fixture['entries']
                changed[0x2400:0x2404] = _thumb_bl(0x2400, entry['parent_init'])
                changed[0x2404:0x2408] = _thumb_bl(0x2404, entry['gpio_init'])
            else:
                changed[0xA0:0xB4] = changed[0x80:0x94]
            result = self.module.find_ma5_gpio_irq_candidate(
                bytes(changed), find_ma5_readback_candidate(bytes(changed)))
            self.assertEqual(result['status'], 'rejected')
