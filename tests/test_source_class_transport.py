"""Source-class serialization and preserving writable native images."""
from copy import deepcopy
from pathlib import Path
import os
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from msm5xxx_emulator.qemu.transport import (prepare_protected_nor_state, qemu_loaded_source_matches,
                            qemu_row734_property, qemu_protected_nor_properties,
                            qemu_amd_bank_profile, qemu_loaded_uart_console_property,
                            qemu_uart_console_property, PERSISTENT_STATE_FILES)
from msm5xxx_emulator.qemu.transport import qemu_dmd5100_property


class DMDProgramBindingTests(unittest.TestCase):
    def setUp(self):
        from test_dmd5100 import _relocated_fixture
        self.image = bytes(_relocated_fixture())
        self.config = config(len(self.image))
        self.config.image_offset = 0
        self.config.dmd_download_address = 0x100

    def bind(self, loaded=None, **kwargs):
        return qemu_dmd5100_property(
            self.image, self.image if loaded is None else loaded, self.config, **kwargs)

    def test_pristine_binding_and_known_mutable_tail(self):
        expected = ("dmd5100-program=100:4000:1800:a00", None)
        self.assertEqual(self.bind(), expected)
        changed = bytearray(self.image)
        changed[0x5800] ^= 1
        self.assertIsNone(self.bind(bytes(changed))[0])
        self.assertEqual(self.bind(bytes(changed), immutable_limit=0x5000), expected)

    def test_loaded_helper_body_and_payload_mutations_retain_fallback(self):
        # Mutation after the guarded entry still changes active callee code.
        for offset in (0x1002, 0x100, 0x4000, 0x1800, 0x800):
            with self.subTest(offset=offset):
                changed = bytearray(self.image)
                changed[offset] ^= 1
                wire, reason = self.bind(bytes(changed))
                self.assertIsNone(wire)
                self.assertEqual(reason, "dmd5100-loaded-immutable-source-changed")

    def test_layout_and_completion_ownership_reject(self):
        self.assertIsNone(self.bind(layout_claimed=True)[0])
        self.assertIsNone(self.bind(immutable_limit=0x3000)[0])
        self.assertIsNone(self.bind(self.image[:-1])[0])
        for field, value in (("load_address", 4), ("image_offset", 4),
                             ("entry", 4), ("ram_base", -1),
                             ("ram_size", 1), ("flash_size", True),
                             ("dmd_download_address", 0x102),
                             ("ram_bootstrap_profile", {}),
                             ("missing_overlays", [1]), ("ram_image_size", 4)):
            with self.subTest(field=field):
                current = deepcopy(self.config)
                setattr(current, field, value)
                self.assertIsNone(qemu_dmd5100_property(self.image, self.image, current)[0])

    def test_unrelated_source_keeps_existing_bridge_path(self):
        self.assertEqual(qemu_dmd5100_property(bytes(len(self.image)), self.image,
                                             self.config), (None, None))

    def test_foreign_byte_halfword_and_eeprom_owners_keep_existing_bridge(self):
        for address in (0x03000050, 0x0300004F, 0x030007EA):
            self.config.board_status_input = SimpleNamespace(address=address, mask=1, default=1)
            self.assertEqual(self.bind(), (None, "dmd5100-input-owner-conflict"))
        self.config.board_status_input = SimpleNamespace(address=0x03000670, mask=1, default=1)
        self.assertIsNotNone(self.bind()[0])
        self.assertIsNone(self.bind(input_profile={"register": 0x030007E7, "register_width": 2})[0])
        self.assertIsNone(self.bind(eeprom_window=(0x03000040, 32))[0])
        self.assertIsNotNone(self.bind(input_profile={"register": 0x0300072C, "register_width": 2},
                                      eeprom_window=(0x03000660, 32))[0])
        self.config.uart_console = {"base": 0x0300004C, "pulse_address": 0x03000624}
        self.assertIsNone(self.bind()[0])
        self.config.uart_console["base"] = 0x03000F0C
        self.assertIsNotNone(self.bind()[0])


def config(size):
    return SimpleNamespace(image_kind='firmware', load_address=0, entry=0,
                           flash_size=size, ram_base=0x1000000, ram_size=0x800000,
                           key_register=None, board_status_input=None)


def row_fixture():
    import struct
    image=bytearray(0x1000)
    for pc in (0x12,0x22,0x32,0x42):
        struct.pack_into('<HH',image,pc-2,0x6b70,0x8800)
    struct.pack_into('<HH',image,0x50,0x4807,0x8980)
    struct.pack_into('<I',image,0x70,0x3000720)
    p=dict(grammar='descriptor-row734-low5-6x5-v1',family='descriptor-row734-byte-ring32-v1',
           admission='temporary-evidence-gated',rows=6,columns=5,no_key=31,
           row_mask=0x9f,row_output=0x3000728,row_select=0x3000734,sense_address=0x300072c,
           auxiliary_status=dict(address=0x3000720,width=2,mask=4,level=4),
           senses=[30,29,27,23,15],descriptor_pointer=0x1001000,
           presence_sites=[0x12,0x32],row_sense_sites=[0x22,0x42],boot_sense_site=0x52,
           row_tables=[0x1001100,0x1001120],code_intervals=[[0x10,0x14]],
           literal_intervals=[[0x70,0x74]],data_intervals=[[0x80,0x84]],
           boot_guard_intervals=[[0x50,0x54]])
    return bytes(image),p


def nor_fixture():
    p=dict(signature='arm-thumb-copy-selected-protected-nor-x16-v1',
           admission='temporary-evidence-gated',bus_width=2,initial_base=0,
           address=0x1000,size=0x2000,sector_sizes=[0x1000,0x1000],
           selected_object=0x400,object_global=0x1001000,selection_cell=0x1001004,
           state_global=0x1001010,discarded_probe=dict(address=0x1001100,source=0x800,size=20),
           runtime_guards=dict(active_object=0x1001000,expected_object=0x400,
               selection_cell=0x1001004,expected_selection=0x400,base_address=0x1001010,
               expected_base=0,mode_address=0x1001014,operation_address=0x1001018),
           code_intervals=[[0,4]],literal_intervals=[],data_intervals=[[0x400,0x4d0]])
    return bytes(0x4000),p


def probe_console_fixture():
    profile = dict(signature='thumb-byte-uart-finite-ff-dd-console-v1',
                   admission='temporary-evidence-gated',
                   policy='provisional-synchronous-null-console',
                   register_width=2, csr_value=0xff, csr_sequence=[0xff, 0xdd],
                   base=0x3000f0c, status_address=0x3000f14,
                   fifo_address=0x3000f18, control_address=0x3000f1c,
                   isr_address=0x3000f20, pulse_address=0x3000700,
                   primary_entry=0x100, init_entry=0x200, tx_entry=0x300,
                   code_intervals=[[0x100, 0x104]],
                   literal_intervals=[[0x400, 0x404]],
                   data_intervals=[[0x500, 0x504]],
                   boot_guard_intervals=[[0, 4]],
                   ram_intervals=[[0x1000000, 0x1800000]], iram_intervals=[])
    return bytes(0x1000), profile


class SourceClassTransportTests(unittest.TestCase):
    def test_three_round_console_requires_its_own_source_contract_and_iram(self):
        image, old = probe_console_fixture()
        profile = dict(old, signature='thumb-byte-uart-finite-ff-cc-99-console-v1',
                       csr_sequence=[0xff, 0xcc, 0x99],
                       iram_intervals=[[0x3800000, 0x3800100]])
        expected = ('uart-console-probe=3000f0c:ff:cc:99', None)
        self.assertEqual(qemu_uart_console_property(profile, len(image)), expected)
        for values in ([0xff, 0xdd], [0xff, 0x99, 0xcc], [0xff, 0xcc], []):
            self.assertEqual(qemu_uart_console_property(dict(profile, csr_sequence=values), len(image)),
                             (None, 'unsupported-probe-register-wire'))
        target = 'msm5xxx_emulator.detection.uart_console.find_uart_console_profile'
        with patch(target, return_value=(profile, 'accepted')):
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, image, config(len(image))),
                             expected)
            self.assertEqual(qemu_loaded_uart_console_property(dict(profile, iram_intervals=[]),
                             image, image, config(len(image))),
                             (None, 'console-loaded-iram_intervals-unverified'))

    def test_reset_reentry_wire_binds_exact_consumers_and_loaded_code(self):
        image, profile = probe_console_fixture()
        profile.update(console_root=0x80, code_intervals=[
            [0x80, 0x90], [0x100, 0x130], [0x200, 0x230]])
        descriptor = dict(write_pcs=[0x104, 0x106], status_read_pc=0x10a,
                          root_lr=0x87, config_lr=0x21b, address=0x3000f1c,
                          width=1, value=0x20, status_address=0x3000f14, status_mask=8)
        profile['reset_reentry'] = descriptor
        expected = ('uart-console-probe=3000f0c:ff:dd,'
                    'uart-console-rearm=104:106:10a:87:21b', None)
        self.assertEqual(qemu_uart_console_property(profile, len(image)), expected)
        target = 'msm5xxx_emulator.detection.uart_console.find_uart_console_profile'
        with patch(target, return_value=(profile, 'accepted')):
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, image, config(len(image))),
                             expected)
            for address in (0x82, 0x104, 0x106, 0x10a, 0x216):
                changed = bytearray(image); changed[address] = 1
                self.assertEqual(qemu_loaded_uart_console_property(profile, image, bytes(changed),
                                 config(len(image))), (None, 'console-loaded-source-mismatch'))
            changed = deepcopy(profile)
            changed['console_root'] += 2
            changed['reset_reentry']['root_lr'] += 2
            self.assertEqual(qemu_loaded_uart_console_property(changed, image, image, config(len(image))),
                             (None, 'console-loaded-owner-mismatch'))
        for field, value in (('write_pcs', [0x104, 0x108]), ('root_lr', 0x86),
                             ('status_mask', 4), ('width', True), ('address', 0x3000f18)):
            changed = deepcopy(profile); changed['reset_reentry'][field] = value
            self.assertEqual(qemu_uart_console_property(changed, len(image)),
                             (None, 'inconsistent-reset-reentry-sites'), field)
        for intervals in (None, [], [[0x100, 0x130]], [[0x80, 0x90], [0x100, 0x130], [0x200, 0x218]]):
            self.assertEqual(qemu_uart_console_property(dict(profile, code_intervals=intervals), len(image)),
                             (None, 'reset-reentry-code-owner-unclosed'))
        changed = dict(profile, signature='thumb-byte-uart-finite-ff-cc-99-console-v1',
                       csr_sequence=[0xff, 0xcc, 0x99])
        self.assertEqual(qemu_uart_console_property(changed, len(image)),
                         (None, 'unsupported-reset-reentry-contract'))

    def test_finite_console_wire_does_not_admit_other_probe_dialects(self):
        image, profile = probe_console_fixture()
        self.assertEqual(qemu_uart_console_property(profile, len(image)),
                         ('uart-console-probe=3000f0c:ff:dd', None))
        for fields in ({'csr_sequence': [0xff, 0xcc, 0x99]},
                       {'csr_sequence': [0xdd, 0xff]},
                       {'csr_sequence': []}, {'csr_value': 0xdd},
                       {'register_width': 1}, {'signature': []}):
            changed = dict(profile, **fields)
            self.assertIsNone(qemu_uart_console_property(changed, len(image))[0], fields)
        changed = deepcopy(profile)
        changed['base'] += 0x100
        for name in ('status_address', 'fifo_address', 'control_address', 'isr_address'):
            changed[name] += 0x100
        self.assertEqual(qemu_uart_console_property(changed, len(image)),
                         (None, 'unsupported-probe-register-wire'))

    def test_finite_console_loaded_guards_allow_only_proven_no_iram_layout(self):
        image, profile = probe_console_fixture()
        c = config(len(image))
        target = 'msm5xxx_emulator.detection.uart_console.find_uart_console_profile'
        with patch(target, return_value=(profile, 'accepted')):
            expected = ('uart-console-probe=3000f0c:ff:dd', None)
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, image, c), expected)
            for address in (0, 0x100, 0x400, 0x500):
                changed = bytearray(image); changed[address] ^= 1
                self.assertEqual(qemu_loaded_uart_console_property(profile, image, bytes(changed), c),
                                 (None, 'console-loaded-source-mismatch'))
            unowned = bytearray(image); unowned[0x900] = 1
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, bytes(unowned), c), expected)
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, image, c, ram_claimed=True),
                             (None, 'console-loaded-memory-owner-unclosed'))
            undersized = deepcopy(c); undersized.ram_size -= 1
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, image, undersized),
                             (None, 'console-loaded-ram_intervals-unverified'))
            reserved = deepcopy(c); reserved.ram_bootstrap_profile = {'owned': True}
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, image, reserved),
                             (None, 'console-loaded-reserved-owner-unclosed'))
            missing = dict(profile, iram_intervals=None)
            self.assertEqual(qemu_loaded_uart_console_property(missing, image, image, c),
                             (None, 'console-loaded-iram_intervals-unverified'))
            fixed = dict(profile, signature='thumb-byte-uart-word-flag-fixed-ff-mixed-v1')
            self.assertEqual(qemu_loaded_uart_console_property(fixed, image, image, c),
                             (None, 'console-loaded-iram_intervals-unverified'))
            for role in ('code_intervals', 'literal_intervals', 'data_intervals', 'boot_guard_intervals'):
                self.assertEqual(qemu_loaded_uart_console_property(dict(profile, **{role: []}), image, image, c),
                                 (None, 'console-boot-guards-unclosed'))
        with patch(target, return_value=(None, 'rejected')):
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, image, c),
                             (None, 'console-loaded-owner-mismatch'))

    def test_row_source_roles_and_conflicting_owners(self):
        image,p=row_fixture();c=config(len(image))
        expected='matrix-row734=1001000:12:22:32:42:52:1001100:1001120'
        self.assertEqual(qemu_row734_property(image,c,p),(expected,None))
        self.assertIsNone(qemu_row734_property(image,c,p,input_claimed=True)[0])
        self.assertEqual(qemu_row734_property(image,c,p,eeprom_window=(0x3000660,32)),(expected,None))
        self.assertIsNone(qemu_row734_property(image,c,p,eeprom_window=(0x3000730,32))[0])
        for field,value in [('image_kind','framebuffer'),('load_address',False),('entry',4),('board_status_input',object())]:
            changed=deepcopy(c);setattr(changed,field,value)
            self.assertIsNone(qemu_row734_property(image,changed,p)[0],field)
        for field,value in [('descriptor_pointer',0x1800000),('row_tables',[0x1001101,0x1001120]),
                            ('presence_sites',[0x12]),('row_sense_sites',[0x12,0x42]),
                            ('senses',[30,29,27,23,31]),('boot_guard_intervals',[])]:
            changed=deepcopy(p);changed[field]=value
            self.assertIsNone(qemu_row734_property(image,c,changed)[0],field)
        for pc in (0x10,0x12,0x50,0x52,0x70):
            changed=bytearray(image);changed[pc]^=1
            self.assertIsNone(qemu_row734_property(bytes(changed),c,p)[0],hex(pc))

    def test_loaded_guards_include_boot_and_data_but_not_writable_array(self):
        image,p=row_fixture()
        self.assertTrue(qemu_loaded_source_matches(p,image,image))
        changed=bytearray(image);changed[0x900]=9
        self.assertTrue(qemu_loaded_source_matches(p,image,bytes(changed)))
        for pc in (0x10,0x50,0x70,0x80):
            changed=bytearray(image);changed[pc]^=1
            self.assertFalse(qemu_loaded_source_matches(p,image,bytes(changed)),hex(pc))
        bad=deepcopy(p);bad['data_intervals']=[[0x800,0x2000]]
        self.assertFalse(qemu_loaded_source_matches(bad,image,image))

    def test_fixed_ff_console_requires_loaded_boot_guards_and_mapped_state(self):
        image = bytes(0x2000)
        c = config(len(image))
        profile = dict(signature='thumb-byte-uart-word-flag-fixed-ff-mixed-v1',
                       admission='temporary-evidence-gated',
                       policy='provisional-synchronous-null-console',
                       register_width=2, csr_value=0xff, base=0x03000f0c,
                       status_address=0x03000f14, fifo_address=0x03000f18,
                       control_address=0x03000f1c, isr_address=0x03000f20,
                       pulse_address=0x03000700, primary_entry=0x100,
                       init_entry=0x200, tx_entry=0x300,
                       code_intervals=[[0x100, 0x110]],
                       literal_intervals=[[0x50, 0x54]],
                       data_intervals=[[0x500, 0x510]],
                       boot_guard_intervals=[[0x20, 0x24]],
                       ram_intervals=[[0x01000000, 0x01002000]],
                       iram_intervals=[[0x03800000, 0x03800040]])
        target = 'msm5xxx_emulator.detection.uart_console.find_uart_console_profile'
        with patch(target, return_value=(profile, 'accepted')):
            expected = ('uart-console=3000f0c:2:ff', None)
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, image, c), expected)
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, image, c, ram_claimed=True),
                             (None, 'console-loaded-memory-owner-unclosed'))
            for at in (0x20, 0x50, 0x100, 0x500):
                changed = bytearray(image); changed[at] = 1
                self.assertEqual(qemu_loaded_uart_console_property(profile, image, bytes(changed), c),
                                 (None, 'console-loaded-source-mismatch'))
            changed = bytearray(image); changed[0x1000] = 1
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, bytes(changed), c), expected)
            undersized = deepcopy(c); undersized.ram_size = 0x1000
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, image, undersized),
                             (None, 'console-loaded-ram_intervals-unverified'))
            reserved = deepcopy(c)
            reserved.ram_bootstrap_profile = dict(reserved_base=0x01001000, reserved_size=0x1000)
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, image, reserved),
                             (None, 'console-loaded-reserved-owner-unclosed'))
            bad = dict(profile, iram_intervals=[[0x037ffff0, 0x03800040]])
            self.assertEqual(qemu_loaded_uart_console_property(bad, image, image, c),
                             (None, 'console-loaded-iram_intervals-unverified'))
            bad = dict(profile, boot_guard_intervals=[])
            self.assertEqual(qemu_loaded_uart_console_property(bad, image, image, c),
                             (None, 'console-boot-guards-unclosed'))
        with patch(target, return_value=(None, 'ambiguous')):
            self.assertEqual(qemu_loaded_uart_console_property(profile, image, image, c),
                             (None, 'console-loaded-owner-mismatch'))

    def test_amd_bank_admission_preserves_loaded_guards_and_native_owners(self):
        image = bytes(0x8000)
        c = config(len(image))
        profile = dict(signature='thumb-copy-selected-amd-x16-bank-v1',
                       admission='temporary-evidence-gated', base=0x4000,
                       size=0x3000, sector_size=0x1000, backing_size=0x4000,
                       id0=0x98, id1=0x95, guard_intervals=[[0x20, 0x40], [0x50, 0x58]])
        module = SimpleNamespace(find_amd_bank_profile=lambda *_: (profile, 'accepted'))
        with patch.dict(sys.modules, {'msm5xxx_emulator.detection.amd_bank': module}):
            self.assertEqual(qemu_amd_bank_profile(image, image, c), (profile, None))
            nv = bytearray(image); nv[0x4000] = 0x55
            self.assertEqual(qemu_amd_bank_profile(image, bytes(nv), c), (profile, None))
            self.assertEqual(qemu_amd_bank_profile(image, image, c, nor_claimed=True),
                             (None, 'amd-bank-owner-conflict'))
            for address in (0x20, 0x3f, 0x50, 0x57):
                changed = bytearray(image); changed[address] = 1
                self.assertEqual(qemu_amd_bank_profile(image, bytes(changed), c),
                                 (None, 'amd-bank-loaded-source-mismatch'))
            self.assertEqual(qemu_amd_bank_profile(image[:-1], image, c),
                             (None, 'amd-bank-source-layout-unverified'))
            for key, value in (('base', 0), ('size', 0), ('sector_size', 0x3000),
                               ('backing_size', 0x3000), ('id0', 0x10000)):
                bad = dict(profile, **{key: value})
                module.find_amd_bank_profile = lambda *_, p=bad: (p, 'accepted')
                self.assertEqual(qemu_amd_bank_profile(image, image, c),
                                 (None, 'amd-bank-geometry-unclosed'), key)
            bad = dict(profile, guard_intervals=[[0x4000, 0x4002]])
            module.find_amd_bank_profile = lambda *_: (bad, 'accepted')
            self.assertEqual(qemu_amd_bank_profile(image, image, c),
                             (None, 'amd-bank-source-overlaps-array'))

    def test_nor_geometry_runtime_contract_and_provided_extent(self):
        image,p=nor_fixture();c=config(len(image))
        expected=('experimental-protected-nor=1000:2000:1000:f4240,'
                  'protected-nor-source=1001000:400:1001004:1001010:1001100:800')
        self.assertEqual(qemu_protected_nor_properties(image,c,p),(expected,None))
        self.assertIsNone(qemu_protected_nor_properties(image,c,p,nor_claimed=True)[0])
        self.assertIsNone(qemu_protected_nor_properties(image[:0x1800],c,p)[0])
        for field,value in [('sector_sizes',[0x800,0x1800]),('selected_object',0x1000),
                            ('selection_cell',0x1800000),('runtime_guards',{}),('initial_base',4)]:
            changed=deepcopy(p);changed[field]=value
            self.assertIsNone(qemu_protected_nor_properties(image,c,changed)[0],field)
        changed=deepcopy(p);changed['discarded_probe']['source']=0x1000
        self.assertIsNone(qemu_protected_nor_properties(image,c,changed)[0])

    def test_seed_preservation_aliases_and_reset_inventory(self):
        self.assertIn('protected-nor.raw',PERSISTENT_STATE_FILES)
        seed=bytes(range(256))*2
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);original=base/'firmware.bin';original.write_bytes(seed)
            state=base/'protected-nor.raw'
            self.assertEqual(prepare_protected_nor_state(state,seed,(original,)),state)
            self.assertEqual(state.read_bytes(),seed)
            changed=b'\x00'*len(seed);state.write_bytes(changed)
            prepare_protected_nor_state(state,seed,(original,));self.assertEqual(state.read_bytes(),changed)
            state.write_bytes(b'bad')
            with self.assertRaises(ValueError):prepare_protected_nor_state(state,seed,(original,))
            self.assertEqual(state.read_bytes(),b'bad')
            with self.assertRaises(ValueError):prepare_protected_nor_state(original,seed,(original,))
            alias=base/'alias.raw';os.link(original,alias)
            with self.assertRaises(ValueError):prepare_protected_nor_state(alias,seed,(original,))
            symlink=base/'link.raw';symlink.symlink_to(original)
            with self.assertRaises(ValueError):prepare_protected_nor_state(symlink,seed,(original,))
            self.assertEqual(original.read_bytes(),seed)
            with self.assertRaises(ValueError):prepare_protected_nor_state(base/'empty.raw',b'',(original,))
            self.assertFalse((base/'empty.raw').exists())

    def test_actual_profiles_loaded_guards_and_numeric_route(self):
        import hashlib
        from msm5xxx_emulator.detection.input_row734 import find_row734_input_profile
        from msm5xxx_emulator.detection.protected_nor import find_protected_nor_profile
        from msm5xxx_emulator.devices.input import InputMixin
        from msm5xxx_emulator.qemu.transport import Transport, matrix_input_command, HOST_INPUT
        root=Path(os.environ.get('MSM5XXX_TEST_FIRMWARE_ROOT', Path(__file__).resolve().parents[1] / 'firmwares')) / 'incoming-20260719-r1/MSM5100'
        controls=(('SCP-4900_1.059SP_JTAG.bin','6ff77b7f6a2933c227a1097043ffa162d4b693fd9e9d2890a40f2375b600111e'),
                  ('SCP-7200_2.046SP_JTAG.bin','72486e9a0b3bac598adee2913405ad287a65880bc896816f69453131fe949714'))
        for name,sha in controls:
            with self.subTest(name=name):
                path=root/name
                if not path.exists():
                    self.skipTest('private supplied-image controls unavailable')
                before=path.stat();image=path.read_bytes()
                self.assertEqual(hashlib.sha256(image).hexdigest(),sha)
                cfg=config(len(image));cfg.ram_size=0x1000000
                row,reason=find_row734_input_profile(image,cfg.ram_base,cfg.ram_size,0)
                self.assertIsNotNone(row,reason)
                nor,reason=find_protected_nor_profile(image,cfg.ram_base,cfg.ram_size,0)
                self.assertIsNotNone(nor,reason)
                wire,reason=qemu_row734_property(image,cfg,row)
                self.assertIsNone(reason);self.assertEqual(len(wire.split('=')[1].split(':')),8)
                props,reason=qemu_protected_nor_properties(image,cfg,nor)
                self.assertIsNone(reason);self.assertIn(',protected-nor-source=',props)
                self.assertNotIn('cache=unsafe',props)
                nv=bytearray(image);nv[nor['address']+0x7600]^=1
                for profile in (row,nor):
                    self.assertTrue(qemu_loaded_source_matches(profile,image,bytes(nv)))
                    self.assertTrue(qemu_loaded_source_matches(profile,image,image))
                    for field in ('code_intervals','literal_intervals','data_intervals','boot_guard_intervals'):
                        for start,end in profile.get(field,()):
                            if start==end:continue
                            bad=bytearray(image);bad[start]^=1
                            self.assertFalse(qemu_loaded_source_matches(profile,image,bytes(bad)),field)
                            break
                positions=InputMixin._direct_matrix_positions(row)
                self.assertEqual(set(positions),set(range(11,23)))
                decoder=SimpleNamespace(direct_input_positions=positions)
                transport=SimpleNamespace(matrix_input_profile=row,decoder=decoder)
                for bit,position in positions.items():
                    self.assertEqual(Transport._matrix_input_position(transport,bit,None),position)
                    self.assertEqual(Transport._matrix_input_position(transport,bit,position[0]),position)
                    self.assertIsNone(Transport._matrix_input_position(transport,bit,0xd2))
                self.assertIsNone(Transport._matrix_input_position(transport,0,0x31))
                position=positions[11]
                self.assertEqual(position,(0x31,1,2))
                self.assertEqual(matrix_input_command(row,position,True),bytes((HOST_INPUT,1,1,0x1b)))
                self.assertEqual(matrix_input_command(row,position,False),bytes((HOST_INPUT,0,0,0)))
                self.assertEqual((before.st_size,before.st_mtime_ns),(path.stat().st_size,path.stat().st_mtime_ns))
