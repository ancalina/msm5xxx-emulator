"""Finite synthetic linked NAND class plus a read-only original-NOR witness."""
import hashlib
import os
import struct
import unittest
from pathlib import Path

from msm5xxx_emulator.detection.small_page_nand import small_page_nand_profile
from test_bootstrap_sdram import _fixture as reset_fixture, _word, _branch


_PROGRAM = bytes.fromhex(
    'ffb5151c041c1f1c500884b003d333493348f4f7c5fefe07f60f08d0002d01d1012f04d02e482d490230f4f7b9fe'
    '6d08781c05994608080a0006000e01900806000e02902806000e0390baf259fe021cfff7d2fe1d200005ff2301339d42'
    '01d2002100e05021017080210170051c39210398c90408700298087001980870002a01d1baf249fee007c00f07229205'
    '002807d103e04100615a11800130b042f9d30ce0002008e021180e7800ab1e704e785e70198811800230b842f4d31020'
    '2870fff79ffefff780fe022804d0012008b0f0bc08bc18470220f9e7')
_ERASE = bytes.fromhex(
    '90b5010a0c06240e07063f0ebaf2f4fe021cfff76dff60201d21090508703920c00407700470d0200870002a01d1baf2'
    'effefff762fffff743ff012802d190bc08bc18470220fae7')
_STATUS = bytes.fromhex('0020072189051d22120580b4702717700b78c02b08d0c12b03d0044b01309842f5d3022080bc70470120fbe7')
_MOVE = bytes.fromhex(
    '013040e0020053e162feff2a030010e3030011030d00000a020080e0021081e0012052e20130712501c0718501306025'
    '01c06085022052e2f9ffff2a1eff2fe178470000013050e003005221a6feff9a10402de9021081e0020080e0030010e3'
    '013071150120421201306015faffff1a102052e2185031291850202910205222fbffff2a822eb0e11800312918002029'
    '04301145043000451040bde81eff2fe1')
_FORWARD = bytes.fromhex(
    '030052e33e00009a03c010e20800000a0130d1e402005ce30c2082e001c0d1940130c0e40130d134042042e201c0c094'
    '0130c034033011e21e00000a042052e22f00003a03c031e7020053e30800000a0f00008a2c34a0e104c0b1e5042052e2'
    '0c3c83e1043080e4f9ffff2a011081e2230000ea2c38a0e104c0b1e5042052e20c3883e1043080e4f9ffff2a021081e2'
    '1b0000ea2c3ca0e104c0b1e5042052e20c3483e1043080e4f9ffff2a031081e2130000ea7847000010402de9202052e2'
    '0500003a1850b1281850a0281850b1281850a02820205222f9ffff2a02ceb0e11850b1281850a0281800b1481800a048'
    '02cfb0e104309124043080241040bde81eff2f01822fb0e10120d1440130d12401c0d1240120c0440130c02401c0c024'
    '1eff2fe1')
_TRANSFER = bytes.fromhex(
    'f0b5151c00274200ffb083b02b488192825a520100924e00805b4401201cfff739fd012810d10098c11921231b010022'
    '2348baf29ffee11921231b0100222048fff7a4fd012805d000207fb003b0f0bc08bc18470137202fe5d30020ff2101aa'
    '1154013001235b029842f8d3154800ab01277f02d8803b1c0022291c01a8fff785fd3b1c0022291c01a8baf273feff22'
    'f93203a90c48baf28bfc00ab19890848403881635989c163084805600348815b819a8152002181530120c6e7')


def _thumb_bl(image, pc, target):
    delta = target - pc - 4
    assert delta % 2 == 0 and -0x400000 <= delta < 0x400000
    struct.pack_into('<HH', image, pc, 0xf000 | ((delta >> 12) & 0x7ff),
                     0xf800 | ((delta >> 1) & 0x7ff))


def _place(image, entry, code, calls, literals, ports=()):
    body = bytearray(code)
    pool = (entry + len(body) + 3) & ~3
    locations = {}
    for offset, value in literals.items():
        insn = struct.unpack_from('<H', body, offset)[0]
        distance = pool - ((entry + offset + 4) & ~3)
        assert 0 <= distance <= 1020 and distance % 4 == 0
        struct.pack_into('<H', body, offset, insn & 0xff00 | distance // 4)
        _word(image, pool, value)
        locations[offset] = pool
        pool += 4
    for offset, value in ports:
        body[offset] = value
    image[entry:entry + len(body)] = body
    for offset, target in calls.items():
        _thumb_bl(image, entry + offset, target)
    return locations


def _nand_fixture(shift=0, iram_source=0x13000, read_offset=0x100, data_port=0x1c00000):
    image, reset = reset_fixture(shift, iram_source, read_offset, data_port)
    address = {name: value + shift for name, value in (
        ('move', 0x8000), ('forward_veneer', 0x8200), ('program', 0x9000),
        ('erase', 0x9200), ('status', 0x9400), ('transfer', 0x9600),
        ('read_wrapper', 0x9800), ('diagnostic', 0x9900), ('copy', 0x9a00))}
    read_entry = 0x3800000 + read_offset
    forward = 0x3800a00
    _word(image, iram_source + 0x500, 0xe51ff004)
    _word(image, iram_source + 0x504, address['move'])
    image[address['move']:address['move'] + len(_MOVE)] = _MOVE
    _branch(image, address['move'] + 8, address['forward_veneer'], 0x2a)
    struct.pack_into('<II', image, address['forward_veneer'], 0xe51ff004, forward)
    image[iram_source + 0xa00:iram_source + 0xa00 + len(_FORWARD)] = _FORWARD
    image[address['read_wrapper']:address['read_wrapper'] + 8] = bytes.fromhex('7847c04604f01fe5')
    _word(image, address['read_wrapper'] + 8, read_entry)
    image[address['diagnostic']:address['diagnostic'] + 2] = bytes.fromhex('7047')
    image[address['copy']:address['copy'] + 2] = bytes.fromhex('7047')
    command, ale = data_port + 0x100000, data_port + 0x80000
    pools = {}
    pools['program'] = _place(image, address['program'], _PROGRAM,
        {0x12: address['diagnostic'], 0x2a: address['diagnostic'],
         0x4a: reset['disable'], 0x50: reset['reset'], 0x82: reset['enable'],
         0xc0: reset['ready'], 0xc4: address['status']},
        {0xe: 0x12000, 0x10: 855, 0x24: 855, 0x26: 0x12000},
        ((0x54, command >> 20), (0x6e, ale >> 19), (0x8a, data_port >> 22)))
    pools['erase'] = _place(image, address['erase'], _ERASE,
        {0xc: reset['disable'], 0x12: reset['reset'], 0x2e: reset['enable'],
         0x32: reset['ready'], 0x36: address['status']}, {},
        ((0x18, command >> 20), (0x1e, ale >> 19)))
    pools['status'] = _place(image, address['status'], _STATUS, {}, {0x1a: 20000},
        ((2, data_port >> 22), (6, command >> 20)))
    pools['transfer'] = _place(image, address['transfer'], _TRANSFER,
        {0x1e: address['erase'], 0x32: address['read_wrapper'], 0x40: address['program'],
         0x7e: address['program'], 0x8a: address['read_wrapper'], 0x96: address['copy']},
        {0xc: 0x1001000, 0x30: 0x1002040, 0x3e: 0x1002040, 0x6c: 0xfff8,
         0x94: 0x1002300, 0x9e: 0x1002040, 0xa8: 0x1002400, 0xac: 0x1001000})
    return image, dict(address, pools=pools, reset=reset)


class SmallPageNandDetectionTests(unittest.TestCase):
    def setUp(self):
        self.image, self.layout = _nand_fixture()

    def test_complete_synthetic_profile(self):
        self.assertEqual(small_page_nand_profile(bytes(self.image)), {
            'profile': 'reset-copy-x16-main-oob-v1', 'experimental': True,
            'data_address': 0x1c00000, 'address_address': 0x1c80000,
            'command_address': 0x1d00000, 'ready_address': 0x3000724, 'ready_mask': 0x80,
            'page_size': 512, 'spare_size': 16, 'pages_per_block': 32,
            'pages': 65536, 'idle_reset_ns': 200})

    def test_relocation_of_producers_callees_read_and_ports(self):
        image, _ = _nand_fixture(0x800, 0x14000, 0x600, 0x1800000)
        profile = small_page_nand_profile(bytes(image))
        self.assertIsNotNone(profile)
        self.assertEqual((profile['data_address'], profile['command_address']), (0x1800000, 0x1900000))

    def test_reset_read_and_every_producer_opcode_mutations(self):
        layout = self.layout
        offsets = [0, layout['reset']['read_raw'] + 0x88,
                   layout['reset']['disable'] + 8, layout['reset']['ready'] + 7]
        offsets += [layout[name] + offset for name, offset in (
            ('program', 0x68), ('program', 0xbc), ('program', 0x98),
            ('erase', 0x16), ('erase', 0x26), ('status', 0x12), ('status', 0x16),
            ('transfer', 0x2a), ('transfer', 0x56), ('transfer', 0x72))]
        for offset in offsets:
            image = self.image.copy()
            image[offset] ^= 1
            with self.subTest(offset=offset):
                self.assertIsNone(small_page_nand_profile(bytes(image)))

    def test_read_only_port_encoding_cannot_relax_linked_thumb_producers(self):
        image, _ = _nand_fixture(data_port=0x1a00000)
        self.assertIsNone(small_page_nand_profile(bytes(image)))

    def test_wrong_link_ownership_and_diagnostic_mismatch(self):
        layout = self.layout
        for name, offset, target in (
                ('program', 0x4a, layout['reset']['enable']),
                ('program', 0x2a, layout['copy']), ('erase', 0x36, layout['diagnostic']),
                ('transfer', 0x1e, layout['program']), ('transfer', 0x32, layout['copy']),
                ('transfer', 0x7e, layout['erase'])):
            image = self.image.copy()
            _thumb_bl(image, layout[name] + offset, target)
            with self.subTest(name=name, offset=offset):
                self.assertIsNone(small_page_nand_profile(bytes(image)))

    def test_copy_chain_full_body_width_branch_and_veneer_mutations(self):
        layout = self.layout
        for offset in (layout['move'] + 0x18, layout['move'] + 0x70,
                       layout['forward_veneer'], layout['reset']['iram_source'] + 0xa00 + 0x68,
                       layout['read_wrapper'] + 4, layout['read_wrapper'] + 8):
            image = self.image.copy()
            image[offset] ^= 1
            with self.subTest(offset=offset):
                self.assertIsNone(small_page_nand_profile(bytes(image)))
        image = self.image.copy()
        _branch(image, layout['move'] + 8, layout['copy'], 0x2a)
        self.assertIsNone(small_page_nand_profile(bytes(image)))

    def test_truncated_partial_owner_and_ambiguous_heads(self):
        layout = self.layout
        for size in (0, 4, layout['program'] + 50, 0x13a80, 0x180ff):
            with self.subTest(size=size):
                self.assertIsNone(small_page_nand_profile(bytes(self.image[:size])))
        for name, code in (('program', _PROGRAM), ('erase', _ERASE), ('transfer', _TRANSFER)):
            image = self.image.copy()
            image[0x1b000:0x1b00c] = code[:12]
            with self.subTest(name=name):
                self.assertIsNone(small_page_nand_profile(bytes(image)))
        image = self.image.copy()
        _word(image, layout['reset']['iram_source'] + 0x504, 0x3800ff0)
        self.assertIsNone(small_page_nand_profile(bytes(image)))

    def test_poll_and_transfer_literal_bounds(self):
        layout = self.layout
        for value in (0, 0x100001):
            image = self.image.copy()
            _word(image, layout['pools']['status'][0x1a], value)
            self.assertIsNone(small_page_nand_profile(bytes(image)))
        for field, value in ((0x94, 0x1d00000), (0xa8, 0x1ffffff), (0x30, 0x1d00000),
                             (0xc, 0x1ffbffc), (0x6c, 0xffff)):
            image = self.image.copy()
            _word(image, layout['pools']['transfer'][field], value)
            with self.subTest(field=field):
                self.assertIsNone(small_page_nand_profile(bytes(image)))

    def test_invalid_inputs_and_no_match(self):
        for value in (None, '', bytearray(self.image), b'', bytes(len(self.image))):
            self.assertIsNone(small_page_nand_profile(value))

    def test_original_nor_readonly_witness(self):
        root = Path(__file__).resolve().parents[1]
        corpus = Path(os.environ.get('MSM5XXX_TEST_FIRMWARE_ROOT', root / 'firmwares')) / 'incoming-20261020-audio-agent'
        path = corpus / 'SCH-X850_NOR_00000000_len_01000000(1).bin'
        if not path.is_file():
            self.skipTest('optional original NOR witness unavailable')
        image = path.read_bytes()
        before = hashlib.sha256(image).digest()
        profile = small_page_nand_profile(image)
        self.assertIsNotNone(profile)
        self.assertEqual((profile['data_address'], profile['ready_address']), (0x1c00000, 0x3000724))
        self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)


if __name__ == '__main__':
    unittest.main()
