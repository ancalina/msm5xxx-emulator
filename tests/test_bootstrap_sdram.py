"""Synthetic reset/copy/external-bus class tests; no firmware file dependency."""
from corpus import snippet
import struct
import unittest

from msm5xxx_emulator.detection.bootstrap_sdram import reset_copy_ram_profile

_FIRST = bytes.fromhex(
    '00409fe5010014e300e09f1500e09f0514ff2fe17847000000409fe5010014e300e09f1500e09f0514ff2fe178470000'
    '00409fe5010014e300e09f1500e09f0514ff2fe17847000000409fe5010014e300e09f1500e09f0514ff2fe178470000'
    'd7f021e300d09fe5dbf021e300d09fe5d3f021e300d09fe500409fe5010014e300e09f1500e09f0514ff2fe178470000'
    '00409fe5010014e300e09f1500e09f0514ff2fe17847000000409fe5010014e300e09f1500e09f0514ff2fe178470000'
    '000050e30000001a000000ea'
)

_SECOND = bytes.fromhex(
    '00409fe5010014e300e09f1500e09f0514ff2fe17847000000409fe5010014e300e09f1500e09f0514ff2fe178470000'
    '00409fe5010014e300e09f1500e09f0514ff2fe178470000d7f021e300d09fe5dbf021e300d09fe5d3f021e300d09fe5'
    '00409fe5010014e300e09f1500e09f0514ff2fe178470000'
)

_COPIER = bytes.fromhex(
    '004980b40120087000230b700048004f02683f68d619004a15680468012043e02a6822606a686260aa68a260ea68e260'
    '2a6922616a696261aa69a261ea69e2612a6a22626a6a6262aa6aa262ea6ae2622a6b22636a6b6263aa6ba263ea6be263'
    '2a6c22646a6c6264aa6ca264ea6ce2642a6d22656a6d6265aa6da265ea6de2652a6e22666a6e6266aa6ea266ea6ee266'
    '2a6f22676a6f6267aa6fa267ea6fe26708700b7080358034b442b9d30a1c0870191c1370004b004c1f6824683e193c1c'
    '22e021606160a160e16021616161a161e16121626162a162e16221636163a163e16321646164a164e16421656165a165'
    'e16521666166a166e16621676167a167e167107011708034b442dad310701170004b004c1f6824683e19004f3d681c68'
    '43e02b6823606b686360ab68a360eb68e3602b6923616b696361ab69a361eb69e3612b6a23626b6a6362ab6aa362eb6a'
    'e3622b6b23636b6b6363ab6ba363eb6be3632b6c23646b6c6364ab6ca364eb6ce3642b6d23656b6d6365ab6da365eb6d'
    'e3652b6e23666b6e6366ab6ea366eb6ee3662b6f23676b6f6367ab6fa367eb6fe3671070117080358034b442b9d31070'
    '1170004b004c1f6824683e193c1c22e021606160a160e16021616161a161e16121626162a162e16221636163a163e163'
    '21646164a164e16421656165a165e16521666166a166e16621676167a167e167107011708034b442dad310701170004b'
    '004c1f6824683e19004f3d681c6805e02b6823601070117004350434b442f7d310701170004b004c1f6824683e19004f'
    '3d681c6843e02b6823606b686360ab68a360eb68e3602b6923616b696361ab69a361eb69e3612b6a23626b6a6362ab6a'
    'a362eb6ae3622b6b23636b6b6363ab6ba363eb6be3632b6c23646b6c6364ab6ca364eb6ce3642b6d23656b6d6365ab6d'
    'a365eb6de3652b6e23666b6e6366ab6ea366eb6ee3662b6f23676b6f6367ab6fa367eb6fe3671070117080358034b442'
    'b9d310701170004b004c1f6824683e193c1c22e021606160a160e16021616161a161e16121626162a162e16221636163'
    'a163e16321646164a164e16421656165a165e16521666166a166e16621676167a167e167107011708034b442dad31070'
    '117080bc7047'
)

_READ = bytes.fromhex(
    'f04f2de90360a0e10040a0e101a012e20000a0030100a01301b016e2ff8000e20100a0130000a003a270a0e1000058e3'
    'ff0000e283df4de20200000a000050e3020086020000000a010086e2a050a0e1ff00a0e3210400e000028de5ff0001e2'
    '04028de5ff0007e208028de5811d00eb0090a0e1b71d00eb7407a0e3400f57e35010a0230010a0330010c0e508029de5'
    '7217a0e30000c1e504029de50000c1e500029de50000c1e5000059e3741d000bab1d00eb011004e27007a0e3000051e3'
    '00005a0300005b033500001a0f10d5e32700000a0010a0e325c2a0e1220000eab020d0e18130a0e1b32084e1b030d0e1'
    '812084e0b230c2e1b030d0e1b430c2e1b030d0e1b630c2e1b030d0e1b830c2e1b030d0e1ba30c2e1b030d0e1bc30c2e1'
    'b030d0e1be30c2e1b030d0e1b031c2e1b030d0e1b231c2e1b030d0e1b431c2e1b030d0e1b631c2e1b030d0e1b831c2e1'
    'b030d0e1ba31c2e1b030d0e1bc31c2e1b030d0e1be31c2e1101081e20c0251e1daffff3a0f0015e32512a0110112a011'
    '0400001a140000eab020d0e18130a0e1b32084e1011081e2050051e1f9ffff3a0d0000ea0010a0e3030000eab020d0e1'
    '8130a0e1b3208de1011081e2050051e1f9ffff3a000058e301108d120620a0e10d10a0010400a0e1641d00eb83df8de2'
    'f04fbde80100a0e31eff2fe1'
)


_FIRST_OFFSETS = (0, 8, 12, 24, 32, 36, 48, 56, 60, 72, 80, 84, 100, 108, 116, 120, 128, 132, 144, 152, 156, 168, 176, 180)
_SECOND_OFFSETS = (0, 8, 12, 24, 32, 36, 48, 56, 60, 76, 84, 92, 96, 104, 108)
_COPY_ROWS = ((0xc, 0xe, 0x16, 0xb4, 0xb6),
              (0x110, 0x112, 0x11a, 0x1b2, 0x1b4),
              (0x20e, 0x210, 0x218, None, None),
              (0x234, 0x236, 0x23e, 0x2d6, 0x2d8))


def _word(image, offset, value):
    struct.pack_into('<I', image, offset, value)


def _branch(image, pc, target, opcode=0xea, raw=None):
    delta = target - pc - 8
    assert delta % 4 == 0 and -(1 << 25) <= delta < (1 << 25)
    _word(image, pc if raw is None else raw, opcode << 24 | ((delta // 4) & 0xffffff))


def _stage(image, entry, template, offsets, calls, last):
    code = bytearray(template)
    pool = (entry + len(code) + 3) & ~3
    locations = {}
    for offset in offsets:
        value = 0x017f0000
        for call in calls:
            if offset == call:
                value = last if call == calls[-1] else 0x7801
            elif offset == call + 8:
                value = (entry + call + 20) | 1
            elif offset == call + 12:
                value = entry + call + 24
        instruction = struct.unpack_from('<I', code, offset)[0]
        distance = pool - entry - offset - 8
        assert 0 <= distance < 4096
        struct.pack_into('<I', code, offset, instruction | distance)
        _word(image, pool, value)
        locations[offset] = pool
        pool += 4
    image[entry:entry + len(code)] = code
    return locations


def _copier(image, entry, tables):
    code = bytearray(_COPIER)
    values = {0: 0x03000700}
    for table, (destination, length, source, zero, zero_size) in zip(tables, _COPY_ROWS):
        values.update({destination: table + 4, length: table + 8, source: table})
        if zero is not None:
            values.update({zero: table + 12, zero_size: table + 16})
    pool = (entry + len(code) + 3) & ~3
    locations = {}
    for offset, value in sorted(values.items()):
        distance = pool - ((entry + offset + 4) & ~3)
        assert distance % 4 == 0 and 0 <= distance <= 1020
        code[offset] = distance // 4
        _word(image, pool, value)
        locations[offset] = pool
        pool += 4
    image[entry:entry + len(code)] = code
    return locations


def _mov_operand(value):
    for rotate in range(16):
        for immediate in range(256):
            count = rotate * 2
            decoded = ((immediate >> count) | (immediate << (32 - count))) & 0xffffffff if count else immediate
            if decoded == value:
                return rotate << 8 | immediate
    raise AssertionError(hex(value))


def _fixture(shift=0, iram_source=0x13000, read_offset=0x100, data_port=0x1c00000):
    image = bytearray(0x20000)
    first, vector, second, copier = (value + shift for value in (0x1000, 0x4000, 0x4100, 0x5000))
    tables = [value + shift for value in (0x6000, 0x6020, 0x6040, 0x6060)]
    structs = [(0x10000, 0x1700000, 0x80, 0x1700080, 0x100),
               (0x11000, 0x1000000, 0x1000, 0x1001000, 0x2000),
               (iram_source, 0x3800000, 0x1000),
               (0x18000, 0x1e00000, 0x100, 0x1e00100, 0x1fb000)]
    for table, fields in zip(tables, structs):
        struct.pack_into('<' + 'I' * len(fields), image, table, *fields)
    first_pool = _stage(image, first, _FIRST, _FIRST_OFFSETS,
                        (0, 0x18, 0x30, 0x48, 0x78, 0x90, 0xa8), 0x7801)
    second_pool = _stage(image, second, _SECOND, _SECOND_OFFSETS, (0, 0x18, 0x30, 0x60), copier | 1)
    copy_pool = _copier(image, copier, tables)
    _branch(image, 0, first)
    _branch(image, first + 0xc4, first + 0x300, 0x1a)
    _branch(image, first + 0xc8, vector)
    _branch(image, vector, second)
    image[0x7800:0x7802] = bytes.fromhex('7047')
    body = bytearray(_READ)
    entry = 0x3800000 + read_offset
    reset, ready, disable, enable = (value + shift for value in (0x7000, 0x7020, 0x7040, 0x7060))
    for index, (off, helper) in enumerate(((0x6c, disable), (0x74, reset), (0xac, enable), (0xb0, ready))):
        target = 0x3800400 + index * 12
        _branch(body, entry + off, target, 0xeb if off != 0xac else 0x0b, raw=off)
        struct.pack_into('<III', image, iram_source + 0x400 + index * 12, 0xe59fc000, 0xe12fff1c, helper | 1)
    _branch(body, entry + 0x1d8, 0x3800500, 0xeb, raw=0x1d8)
    for offset, port in ((0x78, data_port + 0x100000), (0x90, data_port + 0x80000), (0xb8, data_port)):
        instruction = struct.unpack_from('<I', body, offset)[0]
        struct.pack_into('<I', body, offset, instruction & ~4095 | _mov_operand(port))
    image[iram_source + read_offset:iram_source + read_offset + len(body)] = body
    image[reset:reset + 10] = bytes([0xff, 0x20, (data_port + 0x100000) >> 20]) + bytes.fromhex('21090508707047')
    image[ready:ready + 14] = bytes.fromhex('034840690188090afcd370470000')
    _word(image, ready + 16, 0x1000100)
    struct.pack_into('<8I', image, 0x11100, 0x3000720, 0x3000720, 0x300072c, 0, 0x3000724, 0x3000724, 0x3000730, 0x4000400)
    image[disable:disable + 24] = snippet("test_bootstrap_sdram", "interrupt_disable")
    image[enable:enable + 24] = snippet("test_bootstrap_sdram", "interrupt_enable")
    return image, dict(first=first, vector=vector, second=second, copier=copier,
                       tables=tables, first_pool=first_pool, second_pool=second_pool,
                       copy_pool=copy_pool, read_raw=iram_source + read_offset,
                       iram_source=iram_source, reset=reset, ready=ready, disable=disable, enable=enable)


def synthetic_image():
    return bytes(_fixture()[0])


class BootstrapSDRAMTests(unittest.TestCase):
    def setUp(self):
        self.image, self.layout = _fixture()

    def test_exact_profile_and_bootstrap_binding(self):
        self.assertEqual(reset_copy_ram_profile(bytes(self.image)), {
            'profile': 'reset-copy-external-bus-gap-v1', 'experimental': True,
            'ram_base': 0x1000000, 'ram_size': 0xffc000,
            'reserved_base': 0x1c00000, 'reserved_size': 0x200000,
            'bootstrap_linker': dict(table_offset=0x6000, data_source=0x10000,
                                     data_target=0x1700000, data_size=0x80,
                                     bss_target=0x1700080, bss_size=0x100),
        })

    def test_code_descriptor_copy_source_and_read_relocation(self):
        image, layout = _fixture(shift=0x800, iram_source=0x14000, read_offset=0x600)
        profile = reset_copy_ram_profile(bytes(image))
        self.assertIsNotNone(profile)
        self.assertEqual(profile['bootstrap_linker']['table_offset'], layout['tables'][0])
        self.assertEqual((profile['ram_size'], profile['reserved_size']), (0xffc000, 0x200000))

    def test_external_bus_aperture_relocation(self):
        image, _ = _fixture(data_port=0x1a00000)
        profile = reset_copy_ram_profile(bytes(image))
        self.assertEqual((profile['reserved_base'], profile['reserved_size']), (0x1a00000, 0x400000))

    def test_minimum_extent_rounding_and_nonrounded_linker_size(self):
        high = self.layout['tables'][3]
        _word(self.image, high + 16, 0x1fae00)
        self.assertEqual(reset_copy_ram_profile(bytes(self.image))['ram_size'], 0xffb000)
        table = self.layout['tables'][0]
        _word(self.image, table + 8, 52)
        _word(self.image, table + 12, 0x1700034)
        profile = reset_copy_ram_profile(bytes(self.image))
        self.assertEqual((profile['bootstrap_linker']['data_size'], profile['bootstrap_linker']['bss_target']), (52, 0x1700034))

    def test_both_reset_stack_literals_reject_gap_and_ram_edges(self):
        for pools, offsets in ((self.layout['first_pool'], (100, 108, 116)),
                               (self.layout['second_pool'], (76, 84, 92))):
            for offset in offsets:
                for stack in (0xfffffc, 0x1000000, 0x1c00000, 0x1c01000,
                              0x1e00000, 0x1ffc000, 0x1ffc004):
                    image = self.image.copy()
                    _word(image, pools[offset], stack)
                    with self.subTest(pool=pools[offset], stack=stack):
                        self.assertIsNone(reset_copy_ram_profile(bytes(image)))

    def test_both_reset_stack_literals_allow_backed_boundary_words(self):
        for pools, offsets in ((self.layout['first_pool'], (100, 108, 116)),
                               (self.layout['second_pool'], (76, 84, 92))):
            for offset in offsets:
                for stack in (0x1000004, 0x1bffffc, 0x1e00004, 0x1ffbffc):
                    image = self.image.copy()
                    _word(image, pools[offset], stack)
                    with self.subTest(pool=pools[offset], stack=stack):
                        self.assertIsNotNone(reset_copy_ram_profile(bytes(image)))

    def test_root_control_flow_return_and_copier_mutations(self):
        layout = self.layout
        for offset in (0, layout['first'] + 4, layout['first'] + 0xc7,
                       layout['second'] + 4, layout['copier'] + 0x42,
                       layout['first_pool'][8], layout['second_pool'][0x6c]):
            image = self.image.copy()
            image[offset] ^= 0x80
            with self.subTest(offset=offset):
                self.assertIsNone(reset_copy_ram_profile(bytes(image)))

    def test_descriptor_bounds_alignment_and_unrolled_source_overrun(self):
        for table in self.layout['tables']:
            fields = 3 if table == self.layout['tables'][2] else 5
            for field in range(fields):
                for value in (0xffffffff, 1):
                    image = self.image.copy()
                    _word(image, table + 4 * field, value)
                    with self.subTest(table=table, field=field, value=value):
                        self.assertIsNone(reset_copy_ram_profile(bytes(image)))
        image = self.image.copy()
        high = self.layout['tables'][3]
        # Nominal0x104 bytes fit; the actual128-byte-quantized source read does not.
        struct.pack_into('<5I', image, high, len(image) - 0x104, 0x1e00000, 0x104, 0x1e00104, 0x1fb000)
        self.assertIsNone(reset_copy_ram_profile(bytes(image)))

    def test_conflicting_reachable_copy_leaf(self):
        layout = self.layout
        _word(self.image, layout['second_pool'][0], layout['copier'] | 1)
        self.assertIsNotNone(reset_copy_ram_profile(bytes(self.image)))
        tables = list(layout['tables'])
        tables[3] = 0x6080
        self.image[0x6080:0x6094] = self.image[layout['tables'][3]:layout['tables'][3] + 20]
        _word(self.image, 0x6090, 0x1fc000)
        _copier(self.image, 0x8000, tables)
        _word(self.image, layout['second_pool'][0], 0x8001)
        self.assertIsNone(reset_copy_ram_profile(bytes(self.image)))

    def test_nand_body_veneers_ready_irq_and_command_consistency(self):
        layout = self.layout
        for offset in (layout['read_raw'] + 0x88, layout['read_raw'] + 0xe0,
                       layout['read_raw'] + 0x1d8 + 3, layout['iram_source'] + 0x400,
                       layout['reset'], layout['reset'] + 2, layout['ready'] + 7,
                       layout['disable'] + 8, layout['enable'] + 8, 0x11114):
            image = self.image.copy()
            image[offset] ^= 1
            with self.subTest(offset=offset):
                self.assertIsNone(reset_copy_ram_profile(bytes(image)))
        image = self.image.copy()
        image[layout['iram_source'] + 0x800:layout['iram_source'] + 0x810] = _READ[:16]
        self.assertIsNone(reset_copy_ram_profile(bytes(image)))

    def test_consumed_helper_mapping_ambiguity_including_partial_alias(self):
        table = self.layout['tables'][0]
        for target, count in ((0x1000100, 0x80), (0x1000110, 8)):
            image = self.image.copy()
            struct.pack_into('<5I', image, table, 0x10000, target, count, target + count, 0x100)
            with self.subTest(target=target):
                self.assertIsNone(reset_copy_ram_profile(bytes(image)))

    def test_bus_gap_alignment_port_width_and_consumed_span_conflicts(self):
        high = self.layout['tables'][3]
        for target in (0x1e00004, 0x1d00000):
            image = self.image.copy()
            _word(image, high + 4, target)
            _word(image, high + 12, target + 0x100)
            with self.subTest(target=target):
                self.assertIsNone(reset_copy_ram_profile(bytes(image)))
        image, _ = _fixture(data_port=0x1600000)
        self.assertIsNone(reset_copy_ram_profile(bytes(image)))

    def test_unreachable_data_cannot_override_root(self):
        _copier(self.image, 0x8000, [0x6000, 0x6020, 0x6040, 0x6060])
        self.assertIsNotNone(reset_copy_ram_profile(bytes(self.image)))
        _branch(self.image, 0, 0x9000)
        self.assertIsNone(reset_copy_ram_profile(bytes(self.image)))

    def test_invalid_input_truncation_and_alternate_images(self):
        for image in (None, '', b'', bytes(3), bytes(100), b'\xff' * len(self.image)):
            self.assertIsNone(reset_copy_ram_profile(image))
        for size in (0x1000, 0x4100, 0x5100, 0x6048, 0x180ff):
            self.assertIsNone(reset_copy_ram_profile(bytes(self.image[:size])))


if __name__ == '__main__':
    unittest.main()
