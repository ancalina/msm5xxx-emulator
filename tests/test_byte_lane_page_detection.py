"""Portable complete compiler/source graph; no original firmware dependency."""
from pathlib import Path
import hashlib
import struct
import unittest

from msm5xxx_emulator.detection.byte_lane_page import _SPEC, _GLYPH_REFS, find_byte_lane_page_profile


def fixture(shift=0, ram_shift=0):
    image = bytearray(0x20000 + shift)
    roles = {name: 0x1000 + i * 0x1000 + shift for i, name in enumerate(_SPEC)}
    object_, mask, init_thunk, partial_thunk = (v + shift for v in (0x18000, 0x16000, 0x19100, 0x19102))
    context, global_, cache = (v + ram_shift for v in (0x01020000, 0x01001000, 0x01030000))
    error, diagnostic = 0x19000 + shift, 0x19004 + shift
    put = lambda at, value: struct.pack_into('<I', image, at, value)
    def bl(at, target):
        delta = target - at - 4
        struct.pack_into('<HH', image, at, 0xf000 | ((delta >> 12) & 2047), 0xf800 | ((delta >> 1) & 2047))
    def literal(at, register, pool, value):
        distance = pool - ((at + 4) & ~3)
        assert 0 <= distance <= 1020 and not distance & 3
        struct.pack_into('<H', image, at, 0x4800 | register << 8 | distance // 4)
        put(pool, value)
    for role, (pattern, calls, literals) in _SPEC.items():
        at = roles[role]
        image[at:at + len(pattern)] = pattern
        pool = at + ((len(pattern) + 15) & ~3)
        for offset, register in literals:
            if role == 'init': value = cache
            elif role == 'lookup': value = object_
            elif role in ('setup', 'wrapper'): value = global_ if offset == 2 else 0x18100 + shift
            elif role == 'plane': value = context
            elif role == 'glyph':
                kind = next(kind for off, _, kind in _GLYPH_REFS if off == offset)
                value = {'context': context, 'mask': mask, 'plane2': 0x79c}[kind]
            else: raise AssertionError(role)
            literal(at + offset, register, pool, value)
            pool += 4
        links = {'setup': {8: roles['lookup'], 20: init_thunk, 26: error, 34: diagnostic},
                 'init_callback': {2: roles['init']}, 'outer': {2: roles['setup']},
                 'wrapper': {12: error, 22: diagnostic, 42: partial_thunk},
                 'plane': {14: roles['wrapper']}}
        for off in calls: bl(at + off, links[role][off])
    for offset, role in enumerate(('init_callback', 'noop', 'on', 'contrast', 'partial', 'off'), 1):
        put(object_ + 4 * offset, roles[role] | 1)
    put(object_, 0x18100 + shift)
    for bit in range(32): put(mask + 4 * bit, 1 << bit)
    image[init_thunk:init_thunk + 2] = bytes.fromhex('0047')
    image[partial_thunk:partial_thunk + 2] = bytes.fromhex('2047')
    image[error:error + 2] = image[diagnostic:diagnostic + 2] = bytes.fromhex('7047')
    return image, roles, {'object': object_, 'mask': mask, 'global': global_, 'context': context}


def change_literal(image, pc, value):
    op = struct.unpack_from('<H', image, pc)[0]
    pool = ((pc + 4) & ~3) + (op & 255) * 4
    struct.pack_into('<I', image, pool, value)


class ByteLanePageDetectionTests(unittest.TestCase):
    def test_complete_links_and_relocation(self):
        for shift, ram_shift in ((0, 0), (0x400, 0x10000), (0x2000, 0x100000)):
            image, roles, values = fixture(shift, ram_shift)
            before = bytes(image)
            profile, reason = find_byte_lane_page_profile(image)
            self.assertIsNotNone(profile, reason)
            self.assertEqual((profile['width'], profile['height'], profile['column_capacity']), (120, 80, 128))
            self.assertEqual((profile['command_port'], profile['data_port'], profile['access_width']), (0x02000000, 0x02000002, 1))
            self.assertEqual(profile['init_commands'], [0xe2,0xab,0x67,0xae,0xa0,0xc8,0x24,0x81,0x18,0x2f,0x4c,5,0xaf,0xae,0x56,0x24,0xaf])
            self.assertEqual(profile['main_pages'], list(range(10)))
            self.assertEqual((profile['init_row_bytes'], profile['required_pages'], profile['bits_per_pixel']), (128, 10, 1))
            self.assertEqual(profile['buffer_address'], values['context'] + 0x1c)
            self.assertEqual((profile['software_width'], profile['software_height'], profile['software_column_stride']), (120, 128, 16))
            self.assertIsNone(profile['icon_page']); self.assertIsNone(profile['init_data_argument'])
            self.assertIsNone(profile['optical_polarity']); self.assertIsNone(profile['controller_part'])
            self.assertEqual(profile['object'], values['object'])
            self.assertEqual(profile['producer_entry'], roles['partial'])
            self.assertEqual(bytes(image), before)

    def test_typed_bus_geometry_stride_and_call_mutations(self):
        mutations = (('init', 8), ('init', 0x6c), ('init', 0x76), ('init', 0x80),
                     ('partial', 0xe), ('partial', 0x1e), ('partial', 0x22),
                     ('partial', 0x20), ('partial', 0x4a), ('partial', 0x58), ('partial', 0x60),
                     ('wrapper', 0x26), ('wrapper', 42), ('setup', 8), ('setup', 20),
                     ('init_callback', 2), ('outer', 2), ('plane', 10), ('plane', 14),
                     ('glyph', 0x84), ('glyph', 0xca), ('glyph', 0xd0))
        for role, off in mutations:
            with self.subTest(role=role, offset=hex(off)):
                image, roles, _ = fixture(); image[roles[role] + off] ^= 1
                self.assertIsNone(find_byte_lane_page_profile(image)[0])

    def test_explicit_width_port_stride_and_bounds_mutations(self):
        changes = (('init', 8, 0x8010),             # STRH instead of STRB
                   ('init', 6, 0x0612),             # 1<<24 rather than port1<<25
                   ('init', 0x76, 0x287e),          # 127 rather than128 bytes
                   ('init', 0x80, 0x2909),          # nine rather thanten pages
                   ('partial', 0x38, 0x0636),       # wrong command-port shift
                   ('partial', 0x60, 0x7075),       # data+1 rather than+2
                   ('partial', 0x58, 0x0145),       # column stride32 rather than16
                   ('partial', 0x10, 0x2108),       # lastpage8 rather than9
                   ('partial', 0x1e, 0x2f76),       # lastcolumn118 rather than119
                   ('glyph', 0x84, 0x0160),         # softwarecolumnstride32
                   ('glyph', 0xca, 0x2c76),         # softwarexmax118
                   ('glyph', 0xd0, 0x297e))         # softwareymax126
        for role, off, word in changes:
            with self.subTest(role=role, offset=hex(off)):
                image, roles, _ = fixture()
                self.assertNotEqual(struct.unpack_from('<H', image, roles[role] + off)[0], word)
                struct.pack_into('<H', image, roles[role] + off, word)
                self.assertIsNone(find_byte_lane_page_profile(image)[0])

    def test_object_literal_plane_and_mask_ownership(self):
        for mode in range(8):
            image, roles, values = fixture()
            if mode == 0: change_literal(image, roles['lookup'], values['object'] + 4)
            if mode == 1: struct.pack_into('<I', image, values['object'] + 20, roles['init'] | 1)
            if mode == 2: change_literal(image, roles['wrapper'] + 2, values['global'] + 4)
            if mode == 3: change_literal(image, roles['plane'] + 2, values['context'] + 0x780)
            if mode == 4: struct.pack_into('<I', image, values['mask'] + 4, 4)
            if mode == 5: change_literal(image, roles['init'] + 0x5e, values['global'])
            if mode == 6: change_literal(image, roles['setup'] + 2, 0)
            if mode == 7: change_literal(image, roles['glyph'] + 4, 0xfffffffc)
            self.assertIsNone(find_byte_lane_page_profile(image)[0], mode)

    def test_duplicate_complete_and_partial_decoy(self):
        first, _, _ = fixture()
        second, _, _ = fixture(0x20000, 0x100000)
        second[:len(first)] = first
        self.assertEqual(find_byte_lane_page_profile(second)[1], 'byte-lane-page-group-ambiguous')
        image, roles, _ = fixture()
        image[0x1a000:0x1a000 + len(_SPEC['partial'][0])] = _SPEC['partial'][0]
        self.assertIsNotNone(find_byte_lane_page_profile(image)[0])

    def test_partial_truncation_and_type(self):
        image, roles, values = fixture()
        for end in (0, roles['partial'] + 0x73, values['mask'] + 127, values['object'] + 27, 0x19103):
            self.assertIsNone(find_byte_lane_page_profile(image[:end])[0])
        self.assertIsNone(find_byte_lane_page_profile(b'\0' * 0x20000)[0])
        self.assertIsNone(find_byte_lane_page_profile(None)[0])


def paired_fixture(shift=0, variant_index=0):
    from msm5xxx_emulator.detection.byte_lane_page import _PAIRED_SPECS, _PAIRED_VARIANTS, _PAIRED_LINKS
    variant, links = _PAIRED_VARIANTS[variant_index], _PAIRED_LINKS[variant_index]
    image = bytearray(0x60000 + shift)
    entries = {role: 0x1000 + i * 0x1000 + shift for i, role in enumerate(variant)}
    entries['rectcaller'] = entries['fullcaller'] + 20
    entries['initbridge'] = 0x4a000 + shift
    values = {'context': 0x01020000, 'buffer': 0x01040000,
              'font': 0x40000 + shift, 'widths': 0x41000 + shift,
              'glyphs': 0x42000 + shift, 'table': 0x45000 + shift,
              'asset': 0x46000 + shift, 'root': 0x49000 + shift}
    def put(at, value): struct.pack_into('<I', image, at, value)
    def branch(at, target, opcode):
        delta = target - at - 8
        assert not delta & 3
        put(at, opcode & 0xff000000 | (delta // 4 & 0xffffff))
    for role, key in variant.items():
        if role == 'monitor': continue
        at = entries[role]
        pattern, calls, literals = _PAIRED_SPECS[key]
        image[at:at + len(pattern)] = pattern
        for off in calls:
            child = links[role][off]
            target = 0x48000 + shift if child == 'diagnostic' else entries[child]
            branch(at + off, target, struct.unpack_from('<I', pattern, off)[0])
        for i, off in enumerate(literals):
            op = struct.unpack_from('<I', pattern, off)[0]
            pool = at + 0x800 + i * 4 if op & 0x800000 else at - 0x400 + i * 4
            delta = abs(pool - (at + off + 8))
            assert delta <= 4095
            put(at + off, op | delta)
            value = values['table'] if role == 'lookup' else values['context'] if role in (
                'full', 'rect', 'fullcaller', 'rectcaller', 'clear') else 0x01080000
            put(pool, value)
    for role in ('fullcaller', 'rectcaller'):
        end = entries[role] + len(_PAIRED_SPECS[variant[role]][0])
        branch(end, 0x48010 + shift, 0xea000000)
    at = entries['initbridge']
    image[at:at + 8] = bytes.fromhex('00c09fe51cff2fe1')
    put(at + 8, at + 0x101)
    image[at + 0x100:at + 0x108] = bytes.fromhex('0121490608707047')
    monitor = entries['monitor']
    pattern, calls, literals = _PAIRED_SPECS[variant['monitor']]
    image[monitor:monitor + len(pattern)] = pattern
    for i, (off, reg) in enumerate(literals):
        pool = monitor + 0x200 + i * 4
        distance = pool - ((monitor + off + 4) & ~3)
        struct.pack_into('<H', image, monitor + off, 0x4800 | reg << 8 | distance // 4)
        put(pool, values['font'] if off == 0xa else values['buffer'])
    for i, (off, role) in enumerate(zip(calls, ('clear', 'fill', 'glyph', 'page', 'column', 'data'))):
        veneer = 0x4b000 + shift + i * 0x10
        image[veneer:veneer + 8] = bytes.fromhex('7847c04604f01fe5')
        put(veneer + 8, entries[role])
        delta = veneer - monitor - off - 4
        struct.pack_into('<HH', image, monitor + off,
                         0xf000 | (delta >> 12 & 2047), 0xf800 | (delta >> 1 & 2047))
    struct.pack_into('<6I', image, values['font'], 11, 11, values['widths'], values['glyphs'], 0, 256)
    image[values['widths']:values['widths'] + 256] = bytes([11]) * 256
    put(values['table'], values['asset'])
    branch(values['root'], entries['init'], 0xeb000000)
    branch(values['root'] + 4, entries['asset'], 0xeb000000)
    return image, entries, values


class DescendingPairedPageTests(unittest.TestCase):
    def test_complete_variants_relocation_and_logical_limits(self):
        for variant in (0, 1):
            for shift in (0, 0x60000):
                image, entries, values = paired_fixture(shift, variant)
                before = bytes(image)
                profile, reason = find_byte_lane_page_profile(image)
                self.assertIsNotNone(profile, reason)
                self.assertEqual(profile['class_name'], 'descending-paired-byte-page128-v1')
                self.assertEqual((profile['width'], profile['height'], profile['bits_per_pixel']), (128, 128, 2))
                self.assertEqual(profile['main_pages'], list(range(15, -1, -1)))
                self.assertEqual((profile['page_step'], profile['logical_y_reverse']), (-1, True))
                self.assertEqual(profile['logical_plane_weights'], [2, 1])
                self.assertEqual(profile['selected_asset'], values['asset'])
                self.assertEqual(profile['helpers']['pixel'], entries['pixel'])
                self.assertEqual(profile['init_commands'][0:2], [0xe2, 0xae])
                self.assertEqual(profile['init_commands'][-1], 0xaf)
                for key in ('physical_geometry', 'optical_polarity', 'optical_orientation', 'controller_part'):
                    self.assertIsNone(profile[key])
                for role in ('pixel', 'left', 'right', 'glyph', 'glyph_return', 'monitor'):
                    self.assertTrue(any(a <= entries[role] < b for a, b in profile['source_intervals']))
                self.assertEqual(bytes(image), before)

    def test_typed_bus_page_geometry_and_callee_mutations(self):
        # Each byte belongs to a real typed body, not a configurable pool field.
        cases = (('command', 4), ('data', 4), ('column', 0xc),
                 ('page', 0x4c), ('page', 0xc), ('full', 0x58),
                 ('rect', 0x1c), ('rect', 0x40), ('asset', 0x3c),
                 ('init', 4), ('pixel', 0x168), ('left', 0x14),
                 ('right', 0x10), ('glyph_return', 0), ('glyph', 0x168),
                 ('monitor', 0x52), ('monitor', 0x4e), ('monitor', 0xb2))
        for role, off in cases:
            with self.subTest(role=role, offset=off):
                image, entries, _ = paired_fixture()
                image[entries[role] + off] ^= 1
                self.assertIsNone(find_byte_lane_page_profile(image)[0])
        for off, value in ((4, 0xe1c100b0), (4, 0xe5c10004)):
            image, entries, _ = paired_fixture()
            struct.pack_into('<I', image, entries['data'] + off, value)
            self.assertIsNone(find_byte_lane_page_profile(image)[0])

    def test_selected_font_asset_context_and_stack_ownership(self):
        for mode in range(8):
            with self.subTest(mode=mode):
                image, entries, values = paired_fixture()
                if mode == 0: struct.pack_into('<I', image, values['font'] + 12, len(image) - 10)
                if mode == 1: struct.pack_into('<I', image, values['font'] + 4, 65)
                if mode == 2: struct.pack_into('<I', image, values['font'] + 20, 255)
                if mode == 3: image[values['widths']] = 12
                if mode == 4: struct.pack_into('<I', image, values['table'], entries['pixel'])
                if mode == 5:
                    pc = entries['rect'] + 0x50
                    op = struct.unpack_from('<I', image, pc)[0]
                    pool = pc + 8 + ((op & 4095) if op & 0x800000 else -(op & 4095))
                    struct.pack_into('<I', image, pool, values['context'] + 4)
                if mode == 6: image[values['root'] + 4] ^= 1
                if mode == 7: image[entries['monitor'] + 0x60] ^= 1
                self.assertIsNone(find_byte_lane_page_profile(image)[0])

    def test_veneer_and_source_boundary_mutations(self):
        for mode in range(5):
            image, entries, values = paired_fixture(variant_index=1)
            if mode == 0: image[entries['initbridge'] + 0x102] ^= 1
            if mode == 1: image[0x4b000 + 2 * 0x10 + 4] ^= 1
            if mode == 2: image[entries['glyph'] + 0x170] ^= 1
            if mode == 3: struct.pack_into('<I', image, values['table'], len(image) - 4095)
            if mode == 4: image = image[:values['asset'] + 4095]
            self.assertIsNone(find_byte_lane_page_profile(image)[0], mode)

    def test_duplicate_mixed_group_and_incomplete_decoy(self):
        first, _, _ = paired_fixture()
        second, _, _ = paired_fixture(0x60000, 1)
        second[:len(first)] = first
        self.assertEqual(find_byte_lane_page_profile(second)[1], 'byte-lane-page-group-ambiguous')
        old, _, _ = fixture()
        new, _, _ = paired_fixture(0x30000)
        new[:len(old)] = old
        self.assertEqual(find_byte_lane_page_profile(new)[1], 'byte-lane-page-group-ambiguous')
        image, entries, _ = paired_fixture()
        # A complete callee fragment is not an additional complete owned graph.
        from msm5xxx_emulator.detection.byte_lane_page import _PAIRED_SPECS
        image[0x50000:0x5000c] = _PAIRED_SPECS['data'][0]
        self.assertIsNotNone(find_byte_lane_page_profile(image)[0])


if __name__ == '__main__':
    unittest.main()
