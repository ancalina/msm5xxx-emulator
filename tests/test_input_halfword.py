"""Mapped-row synthetic cases and pinned loop-class mutation/relocation cases."""
import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection import input_halfword
from msm5xxx_emulator.detection.input_halfword import (
    find_indirect_matrix_scanners, find_loop_row_scanners, interrupt_helper, resolve_indirect_matrix_input,
)
from msm5xxx_emulator.detection.arm import thumb_bl_target
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[2]



class MappedRowTests(unittest.TestCase):
    @staticmethod
    def bl(image, pc, target):
        delta = target - pc - 4
        struct.pack_into('<HH', image, pc, 0xf000 | ((delta >> 12) & 0x7ff),
                         0xf800 | ((delta >> 1) & 0x7ff))

    @staticmethod
    def literal(image, pc, register, slot, value):
        delta = slot - ((pc + 4) & ~3)
        assert delta % 4 == 0 and 0 <= delta <= 1020
        struct.pack_into('<H', image, pc, 0x4800 | (register << 8) | (delta // 4))
        struct.pack_into('<I', image, slot, value)

    @staticmethod
    def branch(image, pc, target, conditional=None):
        delta = (target - pc - 4) // 2
        struct.pack_into('<H', image, pc,
                         (0xe000 | (delta & 0x7ff)) if conditional is None
                         else 0xd000 | (conditional << 8) | (delta & 255))

    def image(self):
        image = bytearray(bytes.fromhex('c046') * 0x1200)
        # Separate source/destination/length slots read by a literal-driven loop.
        code = bytes.fromhex('38480068384909684018061c37480068051c34480068041c'
                             'b4420dd204e0281d051c201d041cf7e7286820600120')
        image[0x100:0x100 + len(code)] = code
        for offset, register, slot, value in ((0,0,0x1e0,0x2104),
                (4,1,0x1e4,0x2108),(12,0,0x1e8,0x2100),(18,0,0x1ec,0x2104)):
            self.literal(image,0x100 + offset,register,slot,value)
        struct.pack_into('<5I',image,0x2100,0x2200,0x1001000,0x100,0x1001100,0x100)
        for offset,value in ((0,0x3000720),(0x10,0x3000724),
                             (0x20,0x3000728),(0x34,0x300072c)):
            struct.pack_into('<I',image,0x2220 + offset,value)
        for entry,opcode in ((0x1800,'80'),(0x1818,'c0')):
            image[entry:entry + 24] = bytes.fromhex(
                '7847000000000fe1c010' + opcode + 'e301f021e1c00000e21eff2fe1')
        image[0x300:0x322] = bytes.fromhex(
            '00b5b7f1d3fa0749074b8a8b1a408a838a8b09690a80002801d1b7f1d3fa08bc1847')
        self.bl(image,0x302,0x1800)
        self.bl(image,0x31a,0x1818)
        self.literal(image,0x306,1,0x3d0,0x1001020)
        self.literal(image,0x308,3,0x3d4,0xffffc4fc)
        for offset,code in {
            0:'b0b5071c',0x0c:'602f00d054e0',
            0x52:'687829781d308007800f884200d12ce0',
            0x68:'6878240c2a78411c8907890f914207d040198770687801308007800f687004e0',
            0x92:'002c01d1',0x9c:'ff2f01d0078002e0ff2101310180',
            0xbc:'b0bc08bc1847',
        }.items():
            image[0x600 + offset:0x600 + offset + len(code)//2] = bytes.fromhex(code)
        self.literal(image,0x642,5,0x720,0x1001200)
        self.bl(image,0x662,0x1800)
        self.bl(image,0x696,0x1818)
        self.literal(image,0x9a0,6,0xd00,0x1001020)
        image[0x9a2:0x9aa] = bytes.fromhex('706b008810231840')
        self.bl(image,0x9fe,0x300)
        image[0xa02:0xa0e] = bytes.fromhex('706b00880007000f0f2800d1')
        image[0xa20:0xa2e] = bytes.fromhex('072d00d300e002a35b5d5b009f44')
        self.branch(image,0xa24,0xb08)
        image[0xa30:0xa37] = bytes.fromhex('04132333414f5d')
        arms = [0xa38,0xa56,0xa76,0xa96,0xab2,0xace,0xaea]
        for row,(arm,bit) in enumerate(zip(arms,(0,1,8,9,11,12,13))):
            self.bl(image,arm,0x1800)
            image[arm + 4:arm + 6] = bytes.fromhex('b18b')
            self.literal(image,arm + 6,3,0xc00,0xffffc4fc)
            self.literal(image,arm + 8,2,0xc04 + 4*row,0x3b03 ^ (1 << bit))
            image[arm + 10:arm + 24] = bytes.fromhex('19401143b183b18b326911800028')
            self.branch(image,arm + 24,0xb08,conditional=1)
            self.branch(image,arm + 26,0xb04)
        self.bl(image,0xb04,0x1818)
        tail = bytes.fromhex('706b00880007000f0f2808d070491039085cc300181a1c394018475d'
                             '05e001352d062d0e072d00da76e7')
        image[0xb08:0xb08 + len(tail)] = tail
        self.literal(image,0xb14,1,0xc40,0x1c2c)
        image[0x1c00:0x1c1c] = bytes.fromhex('000000675455642a37343150655b30383532528a6323393633006653')
        image[0x1c1c:0x1c2c] = bytes([0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,0])
        self.bl(image,0xb32,0x300)
        image[0xb88:0xb8a] = bytes.fromhex('381c')
        self.bl(image,0xb8a,0x600)
        image[0xb8e:0xb90] = bytes.fromhex('f0bd')
        return image

    def test_closed_mapped_rows_and_rejections(self):
        image = self.image()
        candidate,status,_ = resolve_indirect_matrix_input(bytes(image))
        self.assertEqual(status,'static-candidate')
        self.assertEqual(candidate['grammar'],'indirect-halfword-mapped-row-v1')
        self.assertEqual((candidate['rows'],candidate['columns'],candidate['no_key']),(7,4,15))
        self.assertEqual(candidate['row_select_mask'],0x3b03)
        self.assertEqual(candidate['row_select_bits'],[0,1,8,9,11,12,13])
        self.assertEqual((candidate['presence_site'],candidate['sense_site']),(0xa04,0xb0a))
        self.assertEqual(candidate['descriptor_copy']['descriptor_rom'],0x2220)
        self.assertEqual(candidate['producer']['wrap_mask'],3)
        self.assertEqual(candidate['producer']['slots'],4)
        self.assertEqual({cell['token'] for cell in candidate['token_cells']},set('123456789*0#'))
        self.assertFalse(candidate['runtime_admitted'])
        self.assertEqual(find_indirect_matrix_scanners(bytes(image)),[])
        self.assertIsNone(interrupt_helper(bytes(image),0x1800,False))
        for site in (0x128,0x2220,0x308,0x3d4,0xa20,0xa30,0xa44,0xb08,
                     0xb18,0xb20,0xb2c,0xb88,0xb8a,0x670,0x680,0x1810):
            with self.subTest(site=hex(site)):
                changed = image.copy()
                changed[site] ^= 1
                self.assertIsNone(resolve_indirect_matrix_input(bytes(changed))[0])
        changed = image.copy()
        changed[0x1c0a] = ord('2')  # Duplicate2, absent1.
        self.assertIsNone(resolve_indirect_matrix_input(bytes(changed))[0])
        changed = image.copy()
        struct.pack_into('<I',changed,0xc08,0x3b02)  # Duplicate selected row0.
        self.assertIsNone(resolve_indirect_matrix_input(bytes(changed))[0])
        for register in (5,7):
            changed = image.copy()
            struct.pack_into('<H',changed,0x644,0x2000 | (register << 8))
            self.assertIsNone(resolve_indirect_matrix_input(bytes(changed))[0])
        changed = image.copy()
        self.branch(changed,0xa52,0x620)  # Outside the closed selector region.
        self.assertIsNone(resolve_indirect_matrix_input(bytes(changed))[0])
        changed = image.copy()
        changed[0xa51] ^= 1  # Invert zero/nonzero unlock selection.
        self.assertIsNone(resolve_indirect_matrix_input(bytes(changed))[0])
        for site,word in ((0xb02,0x4770),(0xb02,0xe400),(0xaf6,0x4770)):
            with self.subTest(last_arm=hex(site),word=hex(word)):
                changed = image.copy()
                struct.pack_into('<H',changed,site,word)
                self.assertIsNone(resolve_indirect_matrix_input(bytes(changed))[0])
        with patch('msm5xxx_emulator.detection.input_halfword.find_indirect_matrix_scanners',
                   return_value=[{'grammar':'indirect-halfword-six-row-v1'}]):
            self.assertEqual(resolve_indirect_matrix_input(bytes(image))[1],'ambiguous-scanners')
        self.assertEqual(resolve_indirect_matrix_input(bytes(image),4)[1],'unsupported-load-address')


class LoopRowTests(unittest.TestCase):
    def image(self):
        p = ROOT / 'firmwares' / 'KTFT_X3500_verX3p56.73.0_riffdump_clean.bin'
        image = p.read_bytes()
        self.assertEqual(hashlib.sha256(image).hexdigest(), '7406845487ce4b47c23d134c201a5b26b781c8aa45469bed3f1f1e8b09fcf7b2')
        return image

    def test_exact_loop_and_relative_shape(self):
        image = self.image()
        profile,status,_ = resolve_indirect_matrix_input(image)
        self.assertEqual(status,'static-candidate')
        self.assertEqual(profile['grammar'],'indirect-halfword-loop-six-row-v1')
        self.assertEqual((profile['contact_site'],profile['presence_site'],profile['sense_site']),
                         (0x44066a,0x44067a,0x44071e))
        self.assertEqual((profile['rows'],profile['columns'],profile['no_key']),(6,4,31))
        self.assertEqual(profile['single_key_column_sense'],[30,29,27,23])
        self.assertEqual({c['token'] for c in profile['token_cells']},set('123456789*0#O'))
        self.assertEqual(next(c for c in profile['token_cells'] if c['token']=='5'),
                         {'token':'5','event':0x35,'row':2,'column':2})
        self.assertFalse(profile['runtime_admitted'])
        self.assertEqual(profile['descriptor_copy']['source'],0x19390)
        changed = bytearray(image)
        old,new = 0x440650,0x500000
        changed[new:new+0x198] = image[old:old+0x198]
        for delta in (0x10,0x24,0x4e,0x76,0x7a,0x94,0xac,0xb0,0xc8,0xe8,0xfa,0x11e,0x140,0x156,0x15c,0x16c):
            MappedRowTests.bl(changed,new+delta,thumb_bl_target(image,old+delta))
        changed[old:old+0x170] = bytes(0x170)
        relocated,status,_ = resolve_indirect_matrix_input(bytes(changed))
        self.assertEqual(status,'static-candidate')
        self.assertEqual(relocated['contact_site'],new+0x1a)
        self.assertEqual(relocated['descriptor'],profile['descriptor'])
        changed[old:old+0x170] = image[old:old+0x170]
        self.assertEqual(resolve_indirect_matrix_input(bytes(changed))[1],'ambiguous-scanners')

    def test_loop_rejects_broken_edges_tables_and_aliases(self):
        image = self.image()
        for pc in (0x44066a,0x44067a,0x44071e,0x4406b8,0x4406bc,0x44070e,
                   0x440746,0x44076c,0x44078e,0x4405d4,0x44059a,0x6a89b6,
                   0x6a8274,0x553fca,0xb0c,0x193b0,0x6c922b):
            with self.subTest(pc=hex(pc)):
                changed = bytearray(image);changed[pc] ^= 1
                self.assertEqual(find_loop_row_scanners(bytes(changed)),[])
        for pc in (0x440674,0x44074a,0x440790,0x4405be,0x4405e6,0x440576):
            with self.subTest(call=hex(pc)):
                changed=bytearray(image);MappedRowTests.bl(changed,pc,0)
                self.assertEqual(find_loop_row_scanners(bytes(changed)),[])
        changed=bytearray(image);changed[0x6c9204+14]=ord('2')
        self.assertEqual(find_loop_row_scanners(bytes(changed)),[])
        # Required literal missing, descriptor shadow alias and accessed RAM extent.
        for pc,value in ((0x4407cc,0),(0x4407d0,0x10005bc),(0x4407c4,0x1fffffe),
                         (0x4407c4,0x1001afd),(0x4407c8,0x1021faa)):
            changed=bytearray(image);struct.pack_into('<I',changed,pc,value)
            self.assertEqual(find_loop_row_scanners(bytes(changed)),[])
        self.assertIsNone(resolve_indirect_matrix_input(image,4)[0])

    def test_different_structural_peer_rejected(self):
        p = ROOT / 'firmwares' / 'incoming-20260814' / 'KTF-E2000_-_2.bin'
        image = p.read_bytes()
        self.assertEqual(hashlib.sha256(image).hexdigest(),
                         '2500e169ad9ff6b32139f289e4586e434b052e4e141117418821c762d4acab61')
        self.assertEqual(find_loop_row_scanners(image),[])
        self.assertEqual(resolve_indirect_matrix_input(image)[1],'not-found')


class FunctionalConfirmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = (ROOT / 'firmwares/KTFT_X3500_verX3p56.73.0_riffdump_clean.bin').read_bytes()
        assert hashlib.sha256(cls.original).hexdigest() == '7406845487ce4b47c23d134c201a5b26b781c8aa45469bed3f1f1e8b09fcf7b2'

    def resolve(self, image):
        profile,status,_ = resolve_indirect_matrix_input(bytes(image))
        self.assertEqual(status,'static-candidate')
        numbers = [c for c in profile['token_cells'] if c['token'] in '123456789*0#']
        self.assertEqual({c['token'] for c in numbers},set('123456789*0#'))
        self.assertEqual(next(c for c in numbers if c['token']=='5'),
                         {'token':'5','event':0x35,'row':2,'column':2})
        return profile

    def accepted(self, image):
        profile = self.resolve(image)
        self.assertEqual(profile['ok_mapping_status'],'accepted-provisional')
        mapping = profile['provisional_mappings'][5]
        self.assertEqual(mapping['event'],0x53)  # Hex53, never NUM5 hex35.
        self.assertEqual(mapping['rule'],'same-image-loop-functional-confirm-v1')
        self.assertEqual(mapping['semantic_status'],'temporary-evidence-gated-provisional')
        self.assertTrue(mapping['functional_only'])
        self.assertFalse(mapping['physical_keycap_proven'])
        self.assertEqual(next(c for c in profile['token_cells'] if c['token']=='O'),
                         {'token':'O','event':0x53,'row':1,'column':0})
        self.assertEqual(profile['event_codes'][5],0x83)
        self.assertNotIn('M',{c['token'] for c in profile['token_cells']})
        self.assertFalse(profile['runtime_admitted'])
        return profile

    def rejected(self, image):
        profile = self.resolve(image)
        self.assertEqual(profile['ok_mapping_status'],'rejected')
        self.assertTrue(profile['ok_mapping_reject_reasons'])
        self.assertNotIn('provisional_mappings',profile)
        self.assertNotIn('O',{c['token'] for c in profile['token_cells']})

    @staticmethod
    def literal_slot(image,pc):
        opcode = struct.unpack_from('<H',image,pc)[0]
        return ((pc+4)&~3)+4*(opcode&255)

    def test_actual_and_import_order_fallback(self):
        from msm5xxx_emulator.detection import input_halfword_status
        with patch.object(input_halfword_status,'resolve_indirect_board_status',
                          side_effect=AssertionError('public resolver must not recurse')):
            self.accepted(self.original)
        with patch.object(input_halfword_status,'_loop_status',return_value=(None,'not-found',[])):
            self.rejected(self.original)

    def test_relocated_consumers_and_registry_copy(self):
        image = bytearray(self.original)
        # Bodies and their literal pools move; BLs retain original external targets.
        for name,old,new,size in (('selection_wrapper',0x545dcc,0x600000,0x70),
                                   ('typed',0x557f68,0x610000,0x274)):
            image[new:new+size] = self.original[old:old+size]
            for offset in input_halfword._LOOP_CONFIRM_SHAPES[name][4]:
                MappedRowTests.bl(image,new+offset,thumb_bl_target(self.original,old+offset))
            image[old:old+size] = bytes(size)
        struct.pack_into('<I',image,0x8f74a4,0x600001)
        for pc in (0x5500f0,0x550150):
            MappedRowTests.bl(image,pc,0x610000)
        # The typed descriptors' ROM source also moves independently of RAM.
        old,new,size = 0x8ea0c8,0xa00000,0x18148
        image[new:new+size] = image[old:old+size]
        image[old:old+size] = bytes(size)
        struct.pack_into('<I',image,0x3d000c,new)
        profile = self.accepted(image)
        mapping = profile['provisional_mappings'][5]
        self.assertEqual(mapping['typed_dispatch'],0x610000)
        self.assertEqual(mapping['registry_copy']['source'],new)
        self.assertEqual(mapping['registered_callbacks'][0]['callback'],0x600001)

    def test_broken_and_retargeted_edges_keep_numbers(self):
        for name,shape in input_halfword._LOOP_CONFIRM_SHAPES.items():
            if not shape[4]:
                continue
            # Evidence addresses for mutation only, never candidate admission.
            entries = {'selection':0x545d00,'selection_wrapper':0x545dcc,
                'save_wrapper':0x549114,'save':0x5491d4,'commit':0x5495a4,
                'record':0x554df8,'registrar':0x551090,'lookup':0x54fd78,
                'allocator':0x550e74,'action_drain':0x5500b6,
                'typed':0x557f68,'dispatch':0x558a08}
            pc = entries[name]+shape[4][0]
            with self.subTest(deleted=name):
                image=bytearray(self.original);image[pc:pc+4]=bytes(4)
                self.rejected(image)
        for pc,target in ((0x545e16,0x5491d4),(0x5492ae,0x554df8),
                          (0x5510ae,0x550e74),(0x558134,0x6a89b6),
                          (0x550150,0x545d00),(0x558ad8,0x54febc)):
            with self.subTest(retarget=hex(pc)):
                image=bytearray(self.original);MappedRowTests.bl(image,pc,target)
                self.rejected(image)
        image=bytearray(self.original);image[0x440bba:0x440bbe]=bytes(4)
        self.rejected(image)  # Reused status proof must retain BL-offset guards.

    def test_namespace_registry_and_named_result_negatives(self):
        mutations = [(0x6c9204,0x53,1), (0x3d0014,0x100,4),
                     (0x8f74a4,0x549115,4), (0x8f7498,0,2),
                     (0x7b632c,0x100d6e4,4)]
        for pc,value,width in mutations:
            with self.subTest(address=hex(pc)):
                image=bytearray(self.original)
                struct.pack_into({1:'<B',2:'<H',4:'<I'}[width],image,pc,value)
                self.rejected(image)
        image=bytearray(self.original)
        slot=self.literal_slot(image,0x550ee0)
        struct.pack_into('<I',image,slot,0x100d928)  # Publisher/dispatcher mismatch.
        self.rejected(image)
        image=bytearray(self.original)
        text=struct.unpack_from('<I',image,0x7b6698+4*0x11d)[0]
        image[text]^=1
        self.rejected(image)
        image=bytearray(self.original)
        old,new=0x545dcc,0x600000
        image[new:new+0x70]=image[old:old+0x70]
        for d in input_halfword._LOOP_CONFIRM_SHAPES['selection_wrapper'][4]:
            MappedRowTests.bl(image,new+d,thumb_bl_target(self.original,old+d))
        self.rejected(image)  # Ambiguous exact wrapper is conservative fallback.


class MappedScanGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = (ROOT / 'firmwares/SPH-X7700.bin').read_bytes()
        assert hashlib.sha256(cls.original).hexdigest() == '8e2c5b84c210052d414f61559c60d8cdb423851579a105dcbd8478439eb8eb07'

    def resolve(self, image):
        profile,status,_ = resolve_indirect_matrix_input(bytes(image))
        self.assertEqual(status,'static-candidate')
        self.assertEqual(profile['grammar'],'indirect-halfword-mapped-row-v1')
        expected = set('123456789*0#')
        if profile['menu_mapping_status'] == 'accepted-provisional':
            expected.add('M')
            self.assertEqual(next(c for c in profile['token_cells'] if c['token']=='M'),
                             {'token':'M','event':0x5b,'row':6,'column':1})
        if profile.get('ok_mapping_status') == 'accepted-provisional':
            self.assertEqual(profile['menu_mapping_status'], 'accepted-provisional')
            mapping = profile['provisional_mappings'][5]
            self.assertEqual(mapping['rule'], 'same-image-mapped-functional-confirm-v1')
            self.assertTrue(mapping['functional_only'])
            self.assertFalse(mapping['physical_keycap_proven'])
            expected.add('O')
            self.assertEqual([c for c in profile['token_cells'] if c['token'] == 'O'],
                             [{'token':'O','event':0x53,'row':6,'column':3}])
        self.assertEqual({c['token'] for c in profile['token_cells']}, expected)
        self.assertEqual(next(c for c in profile['token_cells'] if c['token']=='5'),
                         {'token':'5','event':0x35,'row':2,'column':2})
        return profile

    def reject_gates(self, image):
        profile = self.resolve(image)
        self.assertEqual(profile['scan_gate_status'],'rejected')
        self.assertTrue(profile['scan_gate_reject_reasons'])
        self.assertNotIn('scan_gates',profile)

    def test_actual_optional_gate_metadata_and_missing_proof(self):
        profile = self.resolve(self.original)
        self.assertEqual(profile['scan_gate_status'],'accepted-provisional')
        self.assertEqual(profile['scan_gate_reject_reasons'],[])
        gates = profile['scan_gates']
        self.assertEqual(gates['grammar'],'mapped-halfword-contact-status-gates-v1')
        self.assertEqual((gates['contact_site'],gates['status_site']),(0xa09ea,0xa07ba))
        self.assertEqual((gates['descriptor'],gates['scanner_state'],gates['queue_sink']),
                         (profile['descriptor'],0x100221c,int(profile['queue_sink'],16)))
        self.assertEqual((gates['contact_mask'],gates['status_mask']),(16,2))
        self.assertEqual((gates['contact_pointer_offset'],gates['configuration_pointer_offset'],
                          gates['status_pointer_offset']),(52,8,36))
        self.assertEqual((gates['contact_width'],gates['status_width']),(2,2))
        self.assertEqual(gates['promotion'],'temporary-evidence-gated')
        self.assertFalse(gates['runtime_admitted'])
        self.assertIsNone(gates['physical_role'])
        self.assertIsNone(gates['default_level'])
        self.assertEqual((gates['status_state_offset'],gates['status_set_bit_state'],
                          gates['status_clear_bit_state']),(8,0,1))
        self.assertEqual(gates['ram_spans'][:2],[[profile['descriptor'],0x38],[0x100221c,0x20]])
        self.assertEqual(len(gates['ram_spans']),13)
        self.assertTrue(all(type(span) is list and len(span)==2
                            and all(type(v) is int for v in span)
                            for span in gates['ram_spans']))
        wrong_relation = dict(profile, presence_site=profile['presence_site']+2)
        gate, reasons = input_halfword._mapped_scan_gates(
            self.original,wrong_relation,0xa09e6,0xa0990)
        self.assertIsNone(gate)
        self.assertEqual(reasons,['scan-gate-contact-presence-relation'])
        numeric,status,_ = resolve_indirect_matrix_input(bytes(MappedRowTests().image()))
        self.assertEqual(status,'static-candidate')
        self.assertEqual(numeric['scan_gate_status'],'rejected')
        self.assertNotIn('scan_gates',numeric)
        self.assertEqual(len(numeric['token_cells']),12)

    def test_relocated_linked_bodies_and_ambiguity(self):
        image = bytearray(self.original)
        # Include all relative literal pools; preserve BL's signed 4MiB reach.
        old,end,new = 0xa07b4,0xa0d90,0x300000
        image[new:new+end-old] = self.original[old:end]
        for pc in range(old,end-3,2):
            target = thumb_bl_target(self.original,pc)
            if target is not None:
                if old <= target < end:
                    target += new-old
                self.assertTrue(-(1<<22) <= target-(new+pc-old)-4 < (1<<22))
                MappedRowTests.bl(image,new+pc-old,target)
        image[old:end] = bytes(end-old)
        profile = self.resolve(image)
        self.assertEqual(profile['scan_gate_status'],'accepted-provisional')
        gates = profile['scan_gates']
        self.assertEqual(gates['contact_site'],new+0xa09ea-old)
        self.assertEqual(gates['status_site'],new+6)
        self.assertEqual(gates['filter_site'],new+0xa0cec-old)
        self.assertEqual(gates['queue_sink'],0xa06d8)
        image[old:end] = self.original[old:end]
        self.assertEqual(resolve_indirect_matrix_input(bytes(image))[1],'ambiguous-scanners')

    def test_gate_mutations_preserve_numeric_cells(self):
        # +24 was not required by the original numeric descriptor class.
        for pc,value in ((0x6ac13c,0x300072c),(0x6ac120,0x3000728)):
            with self.subTest(descriptor=hex(pc)):
                image=bytearray(self.original);struct.pack_into('<I',image,pc,value)
                self.reject_gates(image)
        for pc in (0xa07bc,0xa07cc,0xa07e8,0xa09f2,0xa0cf0):
            with self.subTest(opcode=hex(pc)):
                image=bytearray(self.original);image[pc]^=1
                self.reject_gates(image)
        # The digest alone masks a deleted BL; the offset tuple must reject it.
        for pc in (0xa07e0,0xa09c6,0xa0d16):
            with self.subTest(deleted_call=hex(pc)):
                image=bytearray(self.original);image[pc:pc+4]=bytes(4)
                self.reject_gates(image)
        for pc,target in ((0xa09d2,0xa08a0),(0xa083c,0xa08a0),(0xa07e0,-2)):
            with self.subTest(retargeted_call=hex(pc)):
                image=bytearray(self.original);MappedRowTests.bl(image,pc,target)
                self.reject_gates(image)
        # Rewrite the shared G literals together: equality cannot bless an alias.
        for value in (0x1000628,0x10c7f00,0x1fffff0,0x100221e,0):
            with self.subTest(state=value):
                image=bytearray(self.original)
                for pc in (0xa07c6,0xa09f4,0xa0a16,0xa0a30,0xa0a44,0xa0bae,0xa0bc2):
                    slot = FunctionalConfirmTests.literal_slot(image,pc)
                    struct.pack_into('<I',image,slot,value)
                self.reject_gates(image)
        for pc,value in ((0xa09f0,0x100221c),(0xa07c4,0x1000628),
                         (0xa07fe,0x2000000),(0xa0baa,0)):
            with self.subTest(control=hex(pc)):
                image=bytearray(self.original)
                slot=FunctionalConfirmTests.literal_slot(image,pc)
                struct.pack_into('<I',image,slot,value)
                self.reject_gates(image)





class MappedPhysicalMenuTests(unittest.TestCase):
    # Sparse synthetic ROM: only exact class spans, literal slots and bounded queue CFG.
    # No complete firmware fixture or whole-image hash admission.
    FIXTURE = (
        'c-rjU37B1FeK`JeW+sz6A(?C}lVk{Y5|#;DCPXkSVn|T#O&|h_QW2Q2=mcD5CJ0%i2CX_FE-'
        'Y$ipjNb0sjWY8tEd!XT^iTkLr^h5dlHvWYwg8a?<|?j|2=1J&?@~u|L6Dom$v`U=Xo;s-'
        'gDpco_GDe?>WQ6L=gZ0000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '000000000008{Y)4b;5O|v%*tcsJU*n7c1TfA)h)a^63ZJOQNdqMQ(>9H0900000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000000000000000000000000000000000000000000N}r?J3f2Fg;U#$J&j#W-'
        '&?tAXY<b1m8;@3dtKi%u&ODUDE?j7jPj>z9~~+7#9eWF)Y-'
        'J>Kc>5;=Z;m4m16hGD4I9*wmTj!Jlu9c6kUF7Yy8Q7U8aHIzlh<_PSoCf@P*~1xH4YZ7TxjpM^8NeoYE_wf6j$3Zab&+{o1ET&nk'
        'B>D_wh5d203a@fBO5&ciFwV6-*roK@LbyJ_O|i+XyOY>Jwr*4tK1tu%BtCRfz{Vq{sl(A~4Cv$v~#eeDm%qt3?4L~&-'
        '<@@nVk@fVd&pP4RckAE+=ltQ!!CD^{adc<f?&yt?oR{e8Qyl8&<`zgD-'
        '!xfiItz^+9+P<sfyz0YaQL(ePyJzyq^6IZfR&2_y+TGI;@_8zmS&G8v_gAJ}^gwvMD=C!Y;y~}M)#j0R?hkEn@vQirZIkiobFW(('
        '{d{U`+<Qe7ulUuB__|j`@v)1d*hm2Y000000000000000000000000000000{=d~URM-@Co|iNYmBQ-_lF#LTpXtox>ZQ-GbT2)<'
        'vUTb5N^x`4Ikhq+|65ay$tOxHLyFGIgZbZenl?1BCF*Riq~X)N<S+8Gk4Tyaw}rH`llNDz8p%@KT>Zj<sI#TgH1wHbsW&d(Tz$)d'
        'sMuFsJ^b+gPi~5fqqPTyKevDSP$A?MC0C?ZFO8DR(~0o&vUF?sd1?Bl@be|<d-'
        'D7btGsM!W971?apg5jrzBH4vhxRqCr*f;KYb`F7W$7Gj6yzBlOyxj#^i|nHLk=RQ5tnjE1p$--^jK+r$Xh;`D;_<oKTh-&-'
        '~@VI6bF&?(og!tTm3RY|6i#n{+RYD$xnAUK1B*^_BV#9~$WYeC>53mn@BwONtF?_tJ*S8%lp%T|Yc`Xdu*kdgbb+(<&273zcj0^W'
        ')Hx4awY4wt<av26yh*R%qOPbtrvQ?CozIoGi!0(&kX3rckqnN^4e&-'
        'oj96YgV#}a3l&f+&VIKFxvdvNBT#eA4(8auO2_?$=3W`X?*sR4;@qJY<jfu&la>Tc;ypqA3Q&*ZX9oI`ds6;nqJnlzv;*+=S^ABw'
        '0!B0D$|~vnV)m{Sl7}gE6bMdshqa-'
        '>Es9dpSSdTmD88*uAH%SZ&KNxwfp+L(NhDVmQnJD`_6xI#nP`;&RqJH%2oN<H;rAr^gGD|p<Gicg^p88Z+PaIv8eb!Up5}5R3>{g'
        'PJUgzVYF!|4z&t(u9ha^;>K#<XyeeD8;=OR*H_&h-'
        'j}X@Fz<<MM8%y^<<ooLUwz?lcI4*jy<^$9_}JdxjGt@9KC<_OH2ZsD56+LG?!s|#dTA6rcytuK_X{V)E3b{BKl(xxx3tIcgI}5(K'
        'RG3e=B=On`(gJ#bVA&Gd>k)%RTNJ@F^+%G9nw{!=;Xti;`O19NAK;)Yxd%?F!Cx_@2{5Pj=2B2P|lIsWfO77hc=#7eg1e<opJCTA'
        '@z6DW1qY=ynZJA!|?NerEdv8A4%W3bYGH&n$NBjLm###(}qf+PScXO`ufqRvpJb4&g(k4`s%SQ#gnVoj!g^wUFv^&<DaJk;p~s5x'
        '98V?>w$@-'
        'UrHV=XD!%LnH&vMD&H+<Bm6t1(b~r0Z<R~=ca!5{N+rwX*5b}+w08aQCpTTcWJW$Kr`2a;bMobUG&UqzO{xdKSl%`8iqJO`Cp16*'
        'p^)pYZKJiJ;m?-~A?>kwk9O40JUV$_^`?nzet#;T7e^$m`HY&KoK#&Mj?YMD4DJl+T9UuauP`MkbbKs~gx1kGjD!!BCl>D-'
        'h?ftpijphS`|=b~<?^&Ef4w-'
        '3A9z{qw$b>3H$3ymXmrO1!g)uIMni@9yE<1sx?%g;_A@HiEsBe0SEo#zmBz*U`p?@Rg`Ziwj#T36*F${y_j-FiGP<Q0Ri}?n3nQ)'
        '6KT^AA;-vj?G0gem(;JTuXQln!8;cw73;p+s15fX0?u?(9)A@rZZp%xwJBd0*YS$l}v;TqZtJ|kkuIo6v`l*RHJ-a$GF;VO-'
        '$6dR&Z7Mx*ThDE8%+r6da%0wJ{e_Ja#o^jX2Ybrlnj8P^r-x?34WS<QjASz*i*F;f6$h_dG`%CM$A=DHU5`0gT#b|U#r8CNcX-'
        '}gvy;p79thE@Si0%#>RS$8k*Ci7ZeLc%3r8<0Hl?q~kL^t^4&!I_Xm-u*^}c#r=&L_H7<Ilqxgd|z@2~gOU7@dD7mmNX-dDFLEAu'
        '?wp6u8ghdDW8e03@6h<hhz?1JQs{M&`eZ=!r0#_{{AHy@mg=Z}VVZ~m=#e$PlD{p6;`bk5+8j-6Xu=4W+&Wc*NWS<Tv#td>V4v-'
        '8n9yV6;&*9rM+OLBZUix0==r6_kahL(C@<mynr-'
        '6L83qRNYYI$6WfP>NGRDSn;I%xn0|dJTUOYItBg>ik)~hCfXTdCvQi`Fr2AtTldFnD1E}$YMYiFAl|lY~HVYUTYo?CMKe2@ikHWP'
        'shb^{}oaEsx>FZ?IHawi{p4x`1kL5j?H<`H75U-fBIBjuWW4RF)z&Vr-!qCJ-'
        'd4U_&?`;Ij!=uyrhju)~8+lOTswr>Tgfu>h9re{{DEfC6XW2SBp!F^U^2t_Z@l5ofz_bB&0kt*>h+;DHhVHgDbODF3kRITe3NDNo'
        'cDVjGU4_ny0B%e!l-(_0=-VqY(1=lPsDh-^h<XRr%@u?D!F3oc&#ScKUZ&T<Pu(c`O)-i`Bla{)yt;uHo7v2fkb`Y&yI%-'
        'g9{9oyq<@Ixp4yyxvFE`*UvPp>np9m|5Q+G*)H~?%Xu%o>?0|ovoU^h2AxJpFT1?*_&7W<Tt(f;_<9EKlFROdBlI{%@5amb9vgcC'
        '5vj)@*PWava3F?{{28)?CCEIWq(g{qF4xX<*)N=eWN}zz80=DJLLG~<Q@5y{-'
        '%DV&xb3eVR!P``jtMJ4CGh(c!*+eFTMVmznsXTSo2S^IyZz_cxl(Se{x$n+x29t@Ie2_j|)BVibD7Ml8M@TMnC_Pt@+u<)MM{ti#'
        '3OMe&<9MdpCwrzH4JczM7nRAkE`IZ+=FSJoe*7)$77ax2tkl@qv9;=A|5|WOez_zE}SzxxPBj^~&GMwXvS-EAulxlDuu-qUxC;*A'
        'G-)Q@nNGq1L)8Z>?MQU7V*X{$9Rk<@sLlTlxNAY;sLMzaGIi@4r0cJU!(6;mXU37w=nEFYib8Pwo_(D~AoP%-'
        '5T2oZL})?p~Xpmt&&X(6w~m<asUm>}pPW^1a(cvD|f1HJNzsv&Y7=v!@KsE>B)@a$aU>qe{!Z?9=I$d3kwXkhJ9G`$RIQT*yb@NQ'
        'irdzKP<CyMDR%&^$jB7qUG;76-n4RTPhf_s<J^hiw0l#eggp9EuxROv&~cr+2o-'
        'kG(mHpU$r}H7Vr#w4dfzj4DU(pPb>N$=>|PuaoPF5ACh*rz?}u<5PQ|yN0*tHQb$_w<o!__$R+}-'
        'uwTP^Io5y_x1d`k0f8o&;LTwGWeD9${Pn(HC9flzTiMpy>H^m^~K)36UD_{ult?cU-'
        'O^j{=z)>Pvp73C;6*9_Z=bkzshrO2)*{At_$|Qy7;1yYg5;%y@$?QoS%1peFUx8oAvJUy_0*J#>xk?6`;R4o!rkfRPN2z)c)I-'
        '9+uplUtww}^}eyGomuJsVXQgC+Plixe!C&LJ?xvJ6Hcn`9$VNsJ$ZK?i3*iV!yfyRrA^6>$?GMB-'
        'b<Fw$Y*y$SZ_|MK0G!h<ngxh8?xPY`<=D-ju!LP`<BTln`|u?`nH785{LI8I`&<%bat2-'
        '?;4+6owI#Ke|ez)<~+tXRd(H)os&iQ2lLupn6C#>rIb#_pYxN~<@v4*acK8wR^K;Pmxgt0MWwsG623C8Wmn~@y!<DJd$L0B<O=)x'
        'XTE;msx^hhcfM<A^__3K^Idapn7u8#T6Vm5b3@pHz5bcc9(ehhrsqiU*)YT2SpDXBar0!v>a7lpd~#E?WM<{}cZlcz)(-'
        'I>N4765B&$l%K-@XM5-o~4vc2Wpw5uN9FI)PnaJTZyN>{z~E6VYrLVIHxFPi8$Wmzd2scjiMv>Q4t#L>Cq*>33g@=2w?-'
        '<F**t#WF8HT})qT-'
        'J+6mm9)L)LH7e?Sb1)D800{al9*ES1$>vCP!yn*;SmKzI5qfm11c!r|ZML)~mxE)V1Lb>bh`ul$A8=pQFl6XAazU)zVYLh&(RDk&'
        'llrOS5^J&GEl$nH^WI3-kBdD4);ST+Z$nt_-o@`tKCtcZNMf77w!hLT7Unzv-DJ`TilB_u2j++bbN}H%zv{^OL372)?N?JvslpG+'
        'Dp&lyEP2Qn>$HQkk_hezJM#aeGdvulC31acFwDkLs+fXdkY%<m>LDa#w%0-'
        'Y(oTBi#Qk2;a`jza1UUzMWtHcIM=2oE}xbi~UUtHY8c<9}WL??Z%0z?QvzI);j!u?MXmZ&#VoycFF3U#k=<Z7ysV!YeqJ;cpd`)0'
        '00000000000000000000000000000008{|N%gZ|fAFxs=qSFW_Uqx1i=yI4xpSjd`LC{_`n3aEf&V@CUm3;QXT-'
        '6V0002^uWnCyVsW9TW%=N$IEku*W6@LZPG8!Yy<d3n#3xVh{D0z_*XQ}~I(YVzSLg3mj!k>=Wt~y-'
        ';(eEepR4y>ksob8sCW3EWBB4(o|6Co|AQSrn3ki>QD;jfD$Zy>eyGsbQN3n-q8N8|cAuE;DMeeSbRM5{-7{-'
        '*L+7H(57t~9(k@J%H@I`h%EFA@-'
        '&xySeCye5x3m;1eNl0|_O=7xC^a4Tl@(v>ot{R;uKvbw{Htq@Dt_gxO7HSwp?g<3E*5&fUXF^TzI}TqbBT916z|PbpK{Nv{^G{w>'
        'NN*WAI!=WRVsTwm+GVcGp}1a+5UayU3m|Db*$;Qo>JBWr|tdU%kipmb8%PSD@uoTd}YO#duQ&|#{c)*`hwQ@ckemg`A8IJzo%WlV'
        '7B`Y0D%9(PJhYprsnK7Asx&5<KzB&)?s+liyy2$TzI(cg5Ml_=$uyjPyhe`000000000000000000000002~%edpSvtKf^H2cDb*'
        '01d8Xy3GcqFCwbtd5RF#oMBmw)Jh_*fg=EsS<ZZ%~9+0&R;z-r5qJcURLNHULO}%^xu*H-?-'
        '1;5XCFcYmIL_*Z+$f00000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000008*!@0rj3*@MNu9NZoqdwuN#<HP0QQlV|p9ox3Xoh``;wd*'
        'GSz1-4MSa#d0hQ}8TMa6-Q|5~0=T-ngl)^TTHOL)KNuK1F+;+;|Fzg+Z-'
        'mo!&?QHnQ3OHQan9dYlm>0`BD9*jC0E05J)HW78USBAIF?VMNHSBkb~M~g!PTjI{ym8UmlpVCqkUZ*Ahn7=kwp3GkxlEn}Fy0&BF'
        'iTu-)%AWi+uI#S;c(}5zrMNBbYFim{i7Snraq_zA&xXHQ`er%W+_mhOP^MXxV+ONpO;55K-cYTL>?}_#j+YOvDs;z5L-'
        'nlT#x(op3*|!hSIeJY^VPM5P4~1dyesZ3BzdWlg@e(S?0QkL(EG{KgXO<j6ZKrucJ!UyolVK7);1L@%OCG=O1Fe^9z7HnclCaJUD'
        'vtQqvv(C-?4LZ)H$Ov(eY=ccv;*%QCoJPp?cI<{Jd!=k3P{JT5?z4UtU-'
        'Y*EqTIv2r22c2=rAaaXl_T4!sr>Y0y?|M{B2;yd3pwEE7s-'
        'TAILH_YA^N|7I*nJ(;{6W$Gtf8aS&42?&{_mzvih2CoSAFX*`>5jG0rq6GE?C6!t?`@lS-VM)NaQB^S=e>8wh4b&;zV^X$?r;0Ub'
        '#3qMUj8R-'
        'E6*5M6(yfZ|EPRRY1^4A+m6a>Ft4(qdihw?c|_$cdCSjE+6H%q7MYP8HMFbmsG)(rf2_3~m^T=0&RT2hny6z&b@afNJZ)1YUKDpk'
        '#n$Ri#up6k4E-=A=?v+PsXU#%fA-'
        't&kKdfei=zB}Wqd=m7_Jv3uT5W_=Mp8aNwdC)D%Yknic!OL<yWOg4{i(jytr~ro?=y{JA8U!(w%>5O|Gtwq~36JYI5P^cuHQGxAL'
        'OO#rfxjmH9*2=lRKo>eHi9=V6sg^Y5ot*45KD6gO0VIM$j*#fjRE(GAt_jb>*zhNIsdTbORBerGfr7jZF48$*gMqlc$ied17u*M~'
        'YhlIMAPp4ZfTgf}H;l+P-?x%Tm~C-*N6#~<3bBERC1m7i^mi*b8&VpDSB=Ik{Jv**Ok3+`=ceqw7&>-'
        '^Q>b1`a;TH{5n)s^Fub&ryV)5Z1n`CNKjo>P>3D$T~}!u)tCIXZtmKW~Tgl4;@7iZqIbFP;^rmqyXC*R{soh2!GOFP#-'
        '1yFQAa=#JuJ7e(=_)|?nGc~um@;nddnpN@;;i;s??mDfhmJHHUcPle;1%~9MQ(hYuYRy=E06z_ji6o0sIT6ELmIBsc=<L2Yz_}*W'
        'h7+*RgioP^Gj<dG>d0xJSm4D7lG{4^VM~1dPF>j|I*W3Qbzt#2&#-'
        '`<M|DBPn%?}?tKeYMWdYgBoPt;THsmF!y)#E}`oEy@OjAW4`8x@Cz@%zh>ES^+K`53KVyRnk>+6PDGh1C0=O+7V~=!x*Dweqz*^|'
        'ZX_rq-iCW3n^9%C{?DDrfEdrP3qiFNJt;Y1@%^J+kKEwU@RXan~2ube(l++u?Wp%c4u;m1kekHuvto4#$h(-R!%PaBR-'
        'q6N@itn;Rm~tUE(Zs^^Z(8XDM|jqX>4l6+t!n>FR?#DT0gUs@mcFG)X|Uw3Wtk^J?7<j+ep@5o1fa({m0+)(Z}hjY(LW)800bl$>'
        '|C8t07nJ^Q|)sG#Rs2w{xCB(CPN)wB>-Ttv~<%VSD&?}3j-'
        'ig{#;hV;!r*`i|*7_5*nWGJ%WhQEejkbpIn&mZfC|*(O&EAE!Om5HnX-Z{#>4e(s1MkRNp<Mmhf#I#qVQ#-I|29s3P<v`@L-'
        'p>_*6OVXvKq8hURyseOFy%E^61QJ&v0M)4W(_%R<^a?u`_&kMy01T(XsQ^V-'
        '`i7bCZp0+qO>cocq*dyEjyN*Uav1OphFVeL31%=zV=T4*48eoS$w8>1K6KeX^$<cTMYU+xUv?o12R1q4Tb(pVytA*PWj?zu2~MW_'
        'rcisAJy7wQJknl(qOPOP8;S-aM;!-'
        'c2tLC4EJ?aLeQ@JGydNeVn~4e?6k|lDsC(l}p0siQ1co*XC^yV#dG)p?xmOSGK9iMD2mGrgZYVFy4A6bBjaEUN>@1Y3G)vY@}A#9'
        '{lY!=J3j~^=nN=*y)usL$0T-'
        'n9@1*hhfC8omh0rX)`)55AFA=;om;*s66@|UOD`C&R%lp?8oEc?B6>31;ef7mCH&Y%|(^=@UHOYrVt}K>aim3XerL9?j3$%n$6*C'
        'o@aCV<}kN!3IBc-V#FCC24wR(izC&xD4G>wLl!goLcG}a<+=I%f9E4n{I(D;!c2-'
        'E3+aCq;>(Fo&x(H*;>klHZe+0{iyJE!#c^jip2eY4!t2IxPH3AwaaZA%4b>xuvmR*A=f}LHV`yM=*7Ajpe<`hcX4hy(wj1f&P;Cj'
        'R3SrJ%KbFPVxnULFzUkYwS53slrD;#~S7BtIl1%2Yq%xVuqGWQ;Elhf<Kc2|efFG7t=JDw0yhZ0E2Wy|6$X1fcRcl)EXx=)_NulG'
        'r;o5%~t{sPKN5zou#-'
        '8e~i7bkjtH+LI=XMP3+EEDoJ3H(;W(^evLg~V5X<%w+)8mIqH)Eo``o6K~jz>y=Q*LRC29K{jIQDQDExY=^bxixv$l0aMhj%vYX&'
        ';KaN`37^*{7&-Y1%%tuvqGQtX3M$`uUTgObsFL2lElRI{8Gt_MS6xZrW4(^mw-0n%w)eB_GR6e|Qq2NXM7EKUzL-'
        '{Y1y(%i_0uxZD!<Y9ZRTN1@M;85x>f8IyVG2lIFHDqVT2R5xdH^4|Q|%n(PSJQfV)*J~QtQ6G2N+Bdy=%|xj4)@<&Dw!R@w<515#'
        '%7yjsDa9MkDXxBI+Q>W0rS${rmuwEZ#L!#c2(ODPBU`5|DJBbtTDC+>+Cv=4%GDOWEr-vCCpVXOp4rkfuxe)I4W-'
        'FAbnE20nsjZ>`aG__W9*jF$_-'
        'JvsdQsVTj;)}zQepWPk&}5+jT^hx1@823R|+sdTTnowIRH2PA9J!Rc=aOlV3HeydiDQcOP?yvN;k}UXxxwxz1Lu3Hy%8cURUU^B<'
        '&>JD;fXvh?Mp3(MO!>^!sFlkKA}OfM~6zBbx0xT<A$!=jg$7gTQ?URR12mCDhE1=S5BJ+-|DvUoDtN3)aj@@vdU&dvMi+-'
        'Ljf%)C^KLLarKXXR<y^In;k_sWsU8Tqj}$?5gI&kH7Z&6T9~y^*Qe868X4#J$<xYDV?c;ZsW6LMtsTb%a(bbswzlKNwfPGu}S5E8'
        'pYJs4gE{u&!%M+||`TIYauA$7;`n`Sto_NuKWwN$-'
        '|yJ}ldEZ0O5lhodD;$wz8`I~;XP)V7XvZTU>+<xfn@qF#S#%bayxXGERP594B@_PUYN(~}Qtitm5uggicEv7>E%6lHPY`tKC-'
        '81YAsMftwt2M<T_KlZlf`;Rxx2>XX{d^p66Ph1(rp9=qqQwmWQFOGUah&Rjk#!rXz7vCDiv%+^-'
        'T=__C%ka<2y}bilrgz3qM8#77{?d6{dN-'
        'A-e>L&ra;g7ErIlN<I1=tXx(52+8Ol06ZA||mlzO0lYWn25tcGzC7kk5ZUHwz5Bf}@u_6|S3_In-W_#180?|f{{_scWx`exf<cYX'
        '8dmeU?>+r4($U4yHd9-np3tZW@mezmvb-p6<BUA!Qkb<gFi=M0>)_?4@-wavQc(t&Ml-'
        '&k|UwTI<naDL^mFuvl@gI_C0gW2ew{ll-8<KriaySrL@53BzAz|K&j*4|QYNZ+3weYiZm`qANO^|Pnd&wl9Hvp-XAc=qfc9Qb7Y>'
        '}mD0KOW8=82*d${c8qpoV_6%p$qm#$A7ro6|ZdjaCz35=e4!mna_meW9grkSGKL*6mNRVrUec2R%bQ&gVkRN@8_@1>au!sw0V2mf'
        '`+!$g|_#VcU`;v#(`CHD(_zNm1E{?xbp0~S2aHRmR0ei1FH%@%;v>g)9X%*9^aN;w<OwqYZ{$;WHNm)yI*SzF>(7q^OC8RhA@xAX'
        'd9RkMqqPj`LNeb<KmmMm8ti-G(I)1G@Lp=Y02w*c(OShAGmCD`A|)-IdF5mrY-'
        'fF_J^9z9ljvsu{fP^>T!FrGaEW<mAEs@Wnjy<wsZ`&?8wR=S}hzYY+bvxW2js|QpnP5{Z=@#y?$g**tJ}dU-jtpq*E8{`Q1GJ_4o'
        '4l>F?$7RPwp~@fjzb8tr+}{?+Bu+SU#C-WX=d-K*Bb@$GG;^3=O7X`8k=I&ocPTF5DD>8#aXy1M!9+e1EwTE6+-'
        'd)ubmea_mc_sm-UXxmFS&B^;@%DwlrEnmCm+QPl}gb2C&m@Ciz^s1&u-'
        '@mHi(d<a`52F(oC)b_Y@x#Ks*PXQR(c3qFYjbv1$Gr=7+_UP)WZIUsTP8nW5k9vj-'
        '`cW$OV;Zh_ujMP&Q;CHjC<m)i~EXU=d^2MLmGEAcHaL)TY2EdIU%MWSw6AY+}?F&)17lmE4#K`nT`IwG>f&%lf(1K+fbQXiaWl1('
        '?oGz*M{oH$7bbG<e18ga5R2n)6lw&FG#Z(@ZK++kjI1vLrlo#bT;3g4ttFo&uxu=9$xPVdyFi0Wc!aSMobi+Su?L|R`>L@TEEl$*'
        'JpG5m->C`Kh-1Z&+^xn`sXRhzBO^j9rO0D+17Sm|4&1FyzR2xwGST5R+S&ucW+PCSG2v8tA6GC`5AlGbe*=XE$)juI(mB-Hn&HeZ'
        '{0KFo{O`4jHkX+{z0jwt+4sD&c>%^+!GZq?h7klSD|lrt^Z(_<98<4qvY#(jwe-'
        '4JpQ<JVBXiuU19$lhZS&M_PnGoI<+a;5mwP}*TzSi(?ffO+GxY6jZelM)57Yy_Q1k$w9r3$Fsu?Aqf?tJ@wq3R+PLTGO&>2uo!_f'
        'W?g-'
        'DW%ntjO9i1zlnx222noP!=#$+;jg!_(;D2?(Qe?GQwD2vzk)$4kHef>zQ@kpGuR^K~%%;2A{i}Drym~7Xxu`AmVRc@$WG8z}V`ie'
        'sX{X1%385=BZsQ%4pLpnR`S$1t)IJkXXcI9J|=Pp4Z?CN%H&2|&**;A8^amUnj@<?+fe>SplvUDF9>&{pB`!-'
        'EJ;h7e8Y_rF*o!E*^*;AdkxS}`in3Arj-(9Q-E8X;P-'
        'fd&O>!zQ(tbK0rRkgdvx(2Q<_pNDeKBIMb>m_ZCcQ$k`s5EBx1e+gR)%?`Fd+yp2o!F4vRxEVSOk27hTs3{qyuodGDd&a0yrcix$'
        '$QJ>+qH|v4&AL?l}@IKl0T^LB`!-}S#BI`+4Ki%qRrokwzqv_^UAjDuKn$+rtZ0HUDvHyD})w%V^r*Y<0bj$b1E-'
        'c*L!Q+)%(UQU7_=N$+_#g^8L-4eD+LDR@6u0ne|bAdYFf$o4Si}n$4(#wT^?G`JQ-'
        'p?e_8P9`=;*{Xp+z9%t6`IH8_LXZ^WaYiRLO@AUNW`aUhop`mj4&<l%&ja!NbYqjx1b^O8Jr}I6<<fxjK+?V&{qQPzXSYDLxJ1?s'
        'oSuW)LR=PFIee&Dx%BGO^`JqQP^`H05`3Kt8#Eb8I*S#UG{N`EJx@2vd&H3K2&L5iBCx(C7eMI)mVZ}p}_XX2WjN_eQ{<l=ay+()'
        '+*)xh)jvN(N!aYb9JF>X&SpB&~oL_JHf#Le~e*4+jk;&Y=r{+|CS<3FlT9fmhsg3>OIa0>qn_rLRJG^Ak-'
        'k$2?BUx)4z4s^eePG+(A7#;|_r6W<Zj3|Qtq(K!)XIIEr*zKS(>@r!>3_1`=1<h0O0-t1!{<G-bL`PIcWz&{`p(<#+&-'
        'r#yHZqnEd6TQp3lJZo_TQWn^|eL-`hC!AJY77`l+<B^F_&=d)qcQhH~GR#hmb|sn`}G%y|d08FIuujm6npW`uk3tQ<%0$<j7-'
        '&U<pQJP*~&^SNis^FS!irm_F^d*yj&`le^g(=+yw=Pb{b^oF!4yxx%BU)mXZ{j{We%aNUhCufJ2Ypre_?hZSv?*6EFUtd<1IeW5i'
        'XFfGqlJlN<!PuR@chyVM^PauxDP!B8<Ekr@uC#m0G2trn^Q)A8=PI-JWZ$+vdzEQpxBSjkj!9-ddyTQt-siYRHX=qx4@(=uYVq27'
        'i{1Eai_IKv9o!b;(3GU7eylmn!}~VJUHA26^LKjZ3zNJwn;JXMs`u3yp&#O|w!YKyk+-'
        'zcQ~gxfO`nvc+1|ZU40B{wl7>6HtW2LAUHcqmIwF~q#w&{bv!5;d2S(3(j&#|W{gct@)z2IluibTEWqDU<on8G|xtcl;tGu8zu{i'
        '3<o;poQ+9#hyBvJK?2cExfVsTf`>To;`JN?H;mapsTxh?d^9fzV@<$-'
        ';Z(e3_yhoZs<_szQ}4pDK*vr+MHhfk=_jGNLdUeCy%olnc3^@g=(QIs|<n&^m^#o-?0hJ#-W`{?#kUt8&|!&?iTSA<oiWoxwL6-'
        'nE=W#LZerOC8%IlR6k8Lz#1qEH;(IJeYr{M$D+cFZZZRX=oaR@iqmb}USzD4Xxu+<)uYt?{u}MbAD{$YM$1%E@OAS$sLR{tV-'
        'x!=fmQF`xN*6weKLZ9VvO`RR3~^*;@Bx!4u=o!8fu$Jp#%=|^j(SO0h<d-spw-CZMT{dW;vc?A83{0^rfeKLyz{ZEu978iP!hc?`'
        '^E~>mQ-F0+JSHm5xi+8>}>O4I;JioVET$$)NV_8$E|NOD6*2h-'
        'HYqf(D9pBD>H;~oxnPcXinXRr(9Um=ji`uFuAIy#v*2l$Z?NLWpUldlgbt8okwX?g@rjXz1d49jlpM#Y8I{PorcMQAwvfr_UeOJC'
        'uXdhfzf0A%`Nb~V}kKJDT=ZUai2zN%4u|Mu8gpnL|v=k4k{&=EcFe`gQc3)lW?C%&V^);r4uJOa#sl$^s>Ug$BpB&9<G%wWX-JwQ'
        '<^&0(gd3a-'
        '7ES{Ow=zXQO>Q~3_Di?pJK0h6PXFe{^32k>u^21tG&wJ6cdA~K!dw$5fJLG*^J@0ML=KY7Irj9Vbs_z@$`g^&5ZupI*V;AqdYP|O'
        'SgZ+6Qb%yIimAQM587wY~w#Ij6Bepl4Jy<+*=Z<ZK=+PU}c(5t2dz4(4_T=klc2_*-'
        ';N)*23i*?^DV6IcpL2$9rW~9I_XhL23f<lH)%EK98RLTV73GG!gf9;zYzQShfBe$CgqMcTjp6e-'
        '<Lkob()w%<m6f?SFY}edYr^+U;ro-vFIv~sQSE+lX-fEX+<4deuy0sDcWC9hY*+ZL+Rw)i{my0eny}}ot{i@0eT-'
        '&3U+VAbnOHno-+Mz1Pb+6NoU;4b`c)oIyGpAzMJKjYihmj{`c(h&wej)u`&RXRy?1e`p|@*IRGiftAODNqIrlDF)7E!i-'
        'vfOs&zjYH(we5l;rQUrmp663A>6q&gfTL!_lESa_6L_``??D&*}c|_l5cK_Ph6GU9`;o)Os)y{HRmMr!br@X#y@`aMAuneZJ}SXQ'
        'M|jhFT}%TNn^UZ_EdOx^0VvM+eeNMb3B`?+4F*v|9*0QKd(Ng9|*@k&@g#VkUgW!o>gXZ`{eNNWsgPqz9EYX7v37hw{Q8zmg&{E9'
        'Go|}Gk*$}J*%Ewk2)bz<x!_4IlOafWoqc#V(7#1+LH09VNUM5aAI+>=hW<pd8IM@Y)k%Q9*1|%tmkuB^8GxYsmX8hn40HN4E-'
        '=8oZFQ2Y?^$o(9`?$)^DxLp4E5tyeY*0-'
        'L;j&*~r<QJx2+zlfOl3sQ*T6M)iW>uAZ%7Z+PV3zK)e!r&sq*?5<sqKlA+J<gPHRHRp7+ZJJ)~3E#{g&Y#8Qc{Hb=%2OPf9LlR>c'
        'vhNSwdvU-ZF%lfp3URM6Ho8&>bW%>Ili`Mcv;6c;=Z<B*JPuqBX5T|UqhbG?-'
        '8<?zO4J0!IfLHo}GM>H8r%&cy0TEdByD8;f>k%+3}f`JM!Ol9#-'
        'k<xirk3OF|i5TmAHSR4n$!>1(U^jNiWY?Q53x{7KvPweKhmt(uv%-'
        '4l0Q(x3evd2j!Hn<t+zP7M+2?(w*o_PsrQ^V+86L!m5f*<DG0+t9B5H>F$FP6@|mhhtIwSX(~s8j|nU&K!Pi8s)VP_Z1VbPT#OL4'
        'rv!>X^*=oq`j!GZRk7U^<Di_dao&MC{M0vGkPa~GnHmhH@{Y?@4L0R!;>Y7@)E5X|4HAu=@n~_4EZfcuE-'
        '<673E@o_T(;39_o+N;r<mHH*I`Hd41Spzq}qP@@JAsVPj$I_S$Wu3)8i0FDV`!a%fDtx}#&)ty`L2uy$ei948kS|9$`YYa8<SadA'
        'p|-rB~z<{@3NE$kh#@|?ZqjMCX_m-Wm#YgSufGG#|oddAw8{C(7MUYOxsJ+ngZRl;4xcWWn)e0zUb*;f=hquuXG<3C&Qsw<)oo<D'
        'QWi;igPIQEnsU1#h#^PC+!UU<TZ%U^TD>w34|w(*Z{{=;{y8ma9Wy*YiV_QnGn(;wD;HrAUSU*8MG#RqTtLG7}M*QAfv{$c#O^cS'
        '^%JGegmb?wQ6SEc8K7P=yRvbJLM^7N;*k&(;Nxca7vOVeN0K0o}D^j~Y!hc8SIuYO{@9MYuYFHWmr?yL^^JTkE|om{iCIiJt-qvH'
        '76VXc4gnkec!DvH{sM)46-'
        'Cx365Ju|p!!{quudSYvSFL7q|hOvd|g6exl7Nn<E7aeR%!(HluBhqhIuQ@O$EtZ;kKU2MBWJdal>h)vO((l%eIxsc;ZuRE}o6;%O'
        '7mUa0-`BQGOlhBzb{uzP`N-0(wZA_wKaEd0JnT)n#=`N=;f+Tov+KWweZ~F<-'
        'xPI@RX%f5HUkP{#W4FX+8>>g?X;SQvttKG$2Uf&{4Dv+e|zy)_1~R-'
        'I@BdAum2ha000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '00000000000000000000000000000000000000000091v_TZ2J0000$(Er!oFaQ7m00000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
        '000000000000000000000000000000000000000000000000000000F0iusX<N'
    )
    EVENTS = list(bytes.fromhex('000000675455642a37343150655b30383532528a6323393633006653'))

    def fixture(self, shift=0, ram_shift=0):
        import base64
        import zlib
        image = bytearray(b'\0'*shift + zlib.decompress(base64.b85decode(self.FIXTURE)))
        literal_sites = ((0xa06b8,2),(0xe19a6,4),(0xe1da8,4),(0x115354,1),
                         (0xf1c16,1),(0xf2a86,0),(0xf2a42,0),(0xf35b0,7),
                         (0xf91cc,0),(0xf91ca,7),(0x11529a,7))
        if ram_shift:
            changed_slots = set()
            for pc,register in literal_sites:
                slot = self.slot(image,pc+shift)
                if slot in changed_slots:
                    continue
                changed_slots.add(slot)
                value = struct.unpack_from('<I',image,slot)[0]
                struct.pack_into('<I',image,slot,value+ram_shift)
        matrix = {'producer':{'family':'filtered-byte-ring4-v1','ring':0x10c7f00+ram_shift},
                  'queue_sink':hex(0xa06d8+shift),'event_codes':self.EVENTS.copy()}
        return image,matrix

    @staticmethod
    def slot(image,pc):
        return ((pc+4)&~3)+(struct.unpack_from('<H',image,pc)[0]&255)*4

    def test_closed_menu_and_rom_ram_relocation(self):
        for shift,ram_shift in ((0,0),(0x1000,0),(0x1000,0x10000)):
            with self.subTest(shift=shift,ram_shift=ram_shift):
                image,matrix = self.fixture(shift,ram_shift)
                mappings,metadata = input_halfword._mapped_physical_menu(bytes(image),matrix)
                self.assertEqual(metadata['menu_mapping_status'],'accepted-provisional')
                self.assertEqual((mappings[0]['event'],mappings[0]['row'],mappings[0]['column']),
                                 (0x5b,6,1))
                self.assertEqual(mappings[0]['global_key'],0x11050f8+ram_shift)
                self.assertEqual(mappings[0]['consumer'],0xf0a60+shift)
                self.assertTrue(mappings[0]['physical_only'])

    def test_mutations_reject_menu(self):
        for kind in ('queue','global','branch','table','call','poll-call','outer-alias','duplicate','duplicate-newline','event','truncated'):
            with self.subTest(kind=kind):
                image,matrix = self.fixture()
                if kind in ('queue','global'):
                    slot = self.slot(image,0xa06b8 if kind=='queue' else 0xf1c16)
                    struct.pack_into('<I',image,slot,struct.unpack_from('<I',image,slot)[0]+0x100)
                elif kind=='branch': image[0xf28f0] ^= 1
                elif kind=='table': image[0x11725f] ^= 1
                elif kind=='call': MappedRowTests.bl(image,0xf2900,len(image)+0x100)
                elif kind=='poll-call': MappedRowTests.bl(image,0xf0c16,0xf3674)
                elif kind=='outer-alias':
                    struct.pack_into('<I',image,self.slot(image,0x11529a),0x11050f8)
                elif kind=='duplicate': MappedRowTests.bl(image,0x100,0xa06b8)
                elif kind=='duplicate-newline':
                    pc = 0xa06b8-4-0xa000
                    MappedRowTests.bl(image,pc,0xa06b8)
                    self.assertEqual(image[pc],0x0a)
                elif kind=='event': matrix['event_codes'][0]=0x5b
                else: image=image[:0xa06d4]
                mappings,metadata = input_halfword._mapped_physical_menu(bytes(image),matrix)
                self.assertIsNone(mappings)
                self.assertEqual(metadata['menu_mapping_status'],'rejected')
                self.assertTrue(metadata['menu_mapping_reject_reasons'])

    def test_unrelated_scanner_keeps_numeric_cells(self):
        image = MappedRowTests().image()
        profile,status,_ = resolve_indirect_matrix_input(bytes(image))
        self.assertEqual(status,'static-candidate')
        self.assertEqual(profile['menu_mapping_status'],'rejected')
        self.assertNotIn('provisional_mappings',profile)
        self.assertEqual({c['token'] for c in profile['token_cells']},set('123456789*0#'))


class MappedFunctionalConfirmTests(unittest.TestCase):
    # Sparse compiler-class scaffold: 720 opcode bytes, explicit calls and literals.
    # Reuse the existing queue/MENU scaffold; no complete firmware fixture.
    SPANS = (
        (0xFD6B4, 'f0b5ffb0a8b0002630abef481e823390', ()),
        (0xFDA48, '11490868602800d161e166dc372800d1e5e052dc322800d1e1e041dc232800d1dde02a2800d1dae0302800d1d7e03128c1d1d4e0fa2a0e01a7f8310040410e01205e000158521001f8501001c062000020c700016cc70001301a0000205b0e01e0300000d05f0000503e0e01d0bd0001b0bf130160082501204b0e01e0520000a8ce0001d4c60001d0180000b01d0000a8c60001701700009d5d0001409c0000332800d19be0342800d198e0352800d195e0362800d0f7e691e0522800d190e10cdc382800d18ae0392800d187e0502800d184e05128eed105e122e0532800d122e1', ()),
        (0xFDD70, '6648694ec06830303060000000006348704b8069984215d16049c868002803d1ff200530000000000a2801d13020f9e70b2801d12a20f5e70c2801d0000000002320efe7594a5549904203d1c8680928f6d0f3e7604a904205d1c8680928e9d00a28edd0eae75d4a904205d1c8680a28dcd00b28ded0e1e7594a904204d1c8680628dbd15020cde7564b984205d1c8680a28cbd00b28cdd0d0e7534a9042cdd1c868012802d1ff205430bbe7022802d1ff205530b6e72e30b4e7', ((10, 158760), (36, 6682), (60, 29122))),
        (0x124998, '90b5114ce71dff375a37f878002807d10e480078002814d10d480078002810d1002200210120000000000a490020c87109496118ca78002a03d0fa78002a00d1c87090bc08bc1847', ((38, -1119888),)),
        (0x13308, 'b0b50f1c051c141c00000000002809d008210171c4608760057400000000b0bc08bc1847002ffad00c21201c00000000f5e7', ((8, -6136), (26, -6080), (44, 2381174))),
        (0x11B10, '80b50a4800000000071c04d1084909480000000005e02021381c0000000017203871381c80bc08bc1847', ((4, 2385252), (16, 537100), (26, 2388456))),
        (0x11B48, '80b5071c011c00000000391c044800000000022103480000000080bc08bc1847', ((6, 203854), (14, 2385220), (22, 2385208))),
        (0xFF78A, '306095e5', ()),
        (0xFF2BA, '00000000', ((0, 23672),)),
        (0x104F28, '00000000ba49552008600220f8e7', ((0, 1682),)),
        (0x1055BA, '24490872e6e4', ()),
        (0xF91C8, '90b5114f0f48114cb8614068211c7861ff20d030000000000020810009186118c978ff2904d001300006000e0c28f4db054900202c310860f8610120387290bc08bc1847', ((20, 165900),)),
    )
    LITERALS = (
        (0xFDA90, 0x11050F8),
        (0xFDF0C, 0x10E4140),
        (0xFDF18, 0x11050F8),
        (0xFDF44, 0x1006944),
        (0xF9210, 0x10E4140),
        (0xF920C, 0x1006944),
        (0x1249E0, 0x11050F8),
        (0x1249E4, 0x1012376),
        (0x1249E8, 0x1012377),
        (0x1249EC, 0x1007D44),
        (0x1249F0, 0x6390),
        (0x11B3C, 0x1015368),
        (0x11B40, 0x300A82),
        (0x11B44, 0x405),
        (0x11B68, 0x101535C),
        (0x11B6C, 0x102618C),
        (0x105218, 0x11050F8),
        (0x10564C, 0x10E4140),
    )

    def fixture(self, shift=0, ram_shift=0):
        image, matrix = MappedPhysicalMenuTests().fixture(shift, ram_shift)
        image.extend(b"\0" * max(0, 0x310000 + shift - len(image)))
        for at, code, calls in self.SPANS:
            data = bytes.fromhex(code)
            image[at + shift:at + shift + len(data)] = data
            for offset, relative in calls:
                MappedRowTests.bl(image, at + shift + offset, at + shift + relative)
        for slot, value in self.LITERALS:
            relocated = (value + ram_shift if value >= 0x01000000 else
                         value if value in (0x6390, 0x405) else value + shift)
            struct.pack_into('<I', image, slot + shift, relocated)
        mappings, metadata = input_halfword._mapped_physical_menu(bytes(image), matrix)
        self.assertEqual(metadata['menu_mapping_status'], 'accepted-provisional')
        matrix.update(metadata)
        matrix.update(grammar='indirect-halfword-mapped-row-v1', rows=7, columns=4,
                      provisional_mappings=mappings,
                      token_cells=[dict(token='M', event=0x5B, row=6, column=1)])
        return image, matrix

    def test_selected_confirm_relocates_with_menu_and_independent_ram(self):
        for shift, delta in ((0, 0), (0x1000, 0), (0x1000, 0x10000)):
            with self.subTest(shift=shift, delta=delta):
                image, matrix = self.fixture(shift, delta)
                result, metadata = input_halfword._mapped_functional_confirm(bytes(image), matrix)
                self.assertEqual(metadata['ok_mapping_status'], 'accepted-provisional')
                self.assertEqual((result[5]['event'], result[5]['row'], result[5]['column']),
                                 (0x53, 6, 3))
                self.assertEqual(result[5]['rule'], 'same-image-mapped-functional-confirm-v1')
                self.assertTrue(result[5]['functional_only'])
                self.assertFalse(result[5]['physical_keycap_proven'])
                self.assertEqual(result[5]['global_key'], 0x11050F8 + delta)
                self.assertEqual(result[5]['consumer'], 0xFD6B4 + shift)

    def test_contract_mutations_reject_without_changing_parent_menu(self):
        mutations = {
            'raw53-arm': (0xFDB24, b'\x57\x28'),
            'selected-branch': (0xFDB28, b'\x00\xe0'),
            'selection-load': (0xFDD74, b'\x80\x68'),
            'global104-store': (0xFF78A, b'\x70\x60'),
            'mode-byte': (0x1055BC, b'\x48\x72'),
            'consumer-global': (0xFDA90, struct.pack('<I', 0x1105100)),
            'installer-active': (0xF920C, struct.pack('<I', 0x1006950)),
            'helper-global': (0x1249E0, struct.pack('<I', 0x1105100)),
            'allocation-publisher-identity': (0x11B3C, struct.pack('<I', 0x1015380)),
        }
        for name, (at, data) in mutations.items():
            with self.subTest(name=name):
                image, matrix = self.fixture()
                original = dict(matrix['provisional_mappings'][0])
                image[at:at + len(data)] = data
                result, metadata = input_halfword._mapped_functional_confirm(bytes(image), matrix)
                self.assertEqual(result, {})
                self.assertEqual(metadata['ok_mapping_status'], 'rejected')
                self.assertEqual(matrix['provisional_mappings'][0], original)
        for name, at, calls in self.SPANS:
            for offset, relative in calls:
                with self.subTest(call=name, offset=offset):
                    image, matrix = self.fixture()
                    MappedRowTests.bl(image, name + offset, name + relative + 2)
                    result, metadata = input_halfword._mapped_functional_confirm(bytes(image), matrix)
                    self.assertEqual(result, {})
                    self.assertEqual(metadata['ok_mapping_status'], 'rejected')

    def test_namespace_alias_truncation_and_malformed_parent_reject(self):
        from copy import deepcopy
        image, matrix = self.fixture()
        variants = []
        for field, value in (('producer', None), ('provisional_mappings', None),
                             ('rows', True), ('columns', 3), ('menu_mapping_status', 'rejected')):
            changed = deepcopy(matrix); changed[field] = value; variants.append(changed)
        for field in ('application', 'consumer', 'global_key', 'descriptor', 'secondary_ring',
                      'inner_state', 'outer_state'):
            for value in (None, True, -2):
                changed = deepcopy(matrix); changed['provisional_mappings'][0][field] = value
                variants.append(changed)
        changed = deepcopy(matrix); changed['event_codes'][0] = 0x53; variants.append(changed)
        changed = deepcopy(matrix); changed['token_cells'].append(dict(token='O',event=0x53,row=6,column=3)); variants.append(changed)
        changed = deepcopy(matrix); changed['provisional_mappings'][5] = {}; variants.append(changed)
        for changed in variants:
            result, metadata = input_halfword._mapped_functional_confirm(bytes(image), changed)
            self.assertEqual(result, {})
            self.assertEqual(metadata['ok_mapping_status'], 'rejected')
        for length in (0, 1, 0xFDD80, 0x1249C0, 0x258000, 0x300A82):
            result, _ = input_halfword._mapped_functional_confirm(bytes(image[:length]), matrix)
            self.assertEqual(result, {})
        # Move all linked selected-object literals coherently into the parent's global span.
        alias = bytearray(image)
        for slot, value in self.LITERALS:
            if value == 0x10E4140:
                struct.pack_into('<I', alias, slot, 0x11050F8)
        result, metadata = input_halfword._mapped_functional_confirm(bytes(alias), matrix)
        self.assertEqual(result, {})
        self.assertIn('ram-alias', metadata['ok_mapping_reject_reasons'][0])

    def test_actual_selected_confirm_and_optional_rejection_keep_numeric_menu(self):
        import os
        root = Path(os.environ.get('MSM5XXX_TEST_FIRMWARE_ROOT', ROOT / 'firmwares'))
        firmware = root / 'SPH-X7700.bin'
        if not firmware.is_file():
            self.skipTest('local firmware corpus unavailable')
        image = bytearray(firmware.read_bytes())
        before, status, _ = resolve_indirect_matrix_input(bytes(image))
        self.assertEqual(status, 'static-candidate')
        self.assertEqual(before['ok_mapping_status'], 'accepted-provisional')
        self.assertEqual(before['provisional_mappings'][5]['event'], 0x53)
        self.assertEqual([c for c in before['token_cells'] if c['token'] == 'O'],
                         [dict(token='O', event=0x53, row=6, column=3)])
        image[0xFDD74] ^= 1
        after, status, _ = resolve_indirect_matrix_input(bytes(image))
        self.assertEqual(status, 'static-candidate')
        self.assertEqual(after['ok_mapping_status'], 'rejected')
        self.assertNotIn(5, after['provisional_mappings'])
        self.assertEqual(after['provisional_mappings'][0], before['provisional_mappings'][0])
        self.assertEqual(after['token_cells'], [c for c in before['token_cells'] if c['token'] != 'O'])


if __name__ == '__main__':
    unittest.main()
