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
        self.assertEqual({c['token'] for c in profile['token_cells']},set('123456789*0#'))
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


if __name__ == '__main__':
    unittest.main()
