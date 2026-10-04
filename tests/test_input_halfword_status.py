"""Static status grammar and fail-closed candidate checks, without firmware."""
import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.input_halfword_status import resolve_indirect_board_status


class IndirectStatusTests(unittest.TestCase):
    @staticmethod
    def _bl(image, site, target):
        delta = target - site - 4
        struct.pack_into('<HH', image, site,
                         0xF000 | ((delta >> 12) & 0x7FF),
                         0xF800 | ((delta >> 1) & 0x7FF))

    def _image(self):
        image = bytearray(b'\xff' * 0x600)
        image[0x100:0x11E] = bytes.fromhex(
            '3b48406800880423184000260028004d02d001202e7001e000202e70c046')
        struct.pack_into('<I', image, 0x1F0, 0x01001000)
        for site, threshold, event in ((0x130, 2, 0x5F), (0x150, 3, 0x60)):
            struct.pack_into('<HH', image, site, 0x2800 | threshold,
                             0xDB00 | ((0x170 - site - 6) // 2))
            struct.pack_into('<HH', image, site + 8, 0x2700 | event, 0x1C38)
            self._bl(image, site + 12, 0x500)
        image[0x170:0x176] = bytes.fromhex('f0bc08bc1847')
        self._bl(image, 0x300, 0x100)
        image[0x304:0x308] = bytes.fromhex('002800d0')
        struct.pack_into('<H', image, 0x308, 0xE000 | ((0x420 - 0x30C) // 2))
        return image

    def _resolve(self, image):
        matrix = dict(presence_site=0x380, sense_site=0x400,
                      descriptor=0x01001000, queue_sink='0x500')
        with patch('msm5xxx_emulator.detection.input_halfword_status.'
                   'resolve_indirect_matrix_input', return_value=(matrix, 'static-candidate', [])):
            return resolve_indirect_board_status(bytes(image))

    def test_candidate_and_structural_rejections(self):
        image = self._image()
        candidate, status, _ = self._resolve(image)
        self.assertEqual(status, 'static-candidate')
        self.assertEqual(candidate['read_site'], 0x104)
        self.assertFalse(candidate['runtime_admitted'])
        self.assertIsNone(candidate['default_level'])
        self.assertIsNone(candidate['physical_role'])
        for site in (0x1F0, 0x104, 0x106, 0x110, 0x114,
                     0x130, 0x133, 0x138, 0x13A, 0x150, 0x158, 0x304):
            with self.subTest(site=hex(site)):
                changed = image.copy()
                changed[site] ^= 1
                self.assertIsNone(self._resolve(changed)[0])
        changed = image.copy()
        self._bl(changed, 0x300, -0x100)
        self.assertIsNone(self._resolve(changed)[0])
        changed = image.copy()
        struct.pack_into('<H', changed, 0x30A, 0x4770)  # fallthrough returns before scanner
        self.assertIsNone(self._resolve(changed)[0])
        changed = image.copy()
        self._bl(changed, 0x2E0, 0x100)
        changed[0x2E4:0x2E8] = bytes.fromhex('002800d0')
        struct.pack_into('<H', changed, 0x2E8, 0xE000 | ((0x420 - 0x2EC) // 2))
        self.assertEqual(self._resolve(changed)[1], 'ambiguous-status-helpers')

    def test_shared_backward_queue_tail(self):
        image = self._image()
        struct.pack_into('<H', image, 0x15A, 0xE000 | ((0x13A - 0x15E) // 2 & 0x7FF))
        self.assertIsNotNone(self._resolve(image)[0])
        struct.pack_into('<H', image, 0x13A, 0x2700)  # clobbered event
        self.assertIsNone(self._resolve(image)[0])



# Synthetic relocated exact instruction fixtures, not firmware-dependent tests.
_SEGMENTS = (
    ('recurring', 0x440bb8, 0x1000, (
        'f0b59af727f82d4f0120f8712c4f7868008810231840032400282a4d15d0fff7f1fc264fb878032802d1ff20fff7bafc'
        '0620fff7b7fcff20fff7b4fcb878012800d0bc702a1c002131e067f233fbb98d1d4e490949011e221143b985b98db185'
        '3a6a1180002801d167f230fb67f222fbb98920221143b981b989b1813a681180002801d167f222fb0c4fb878032802d1'
        'ff20fff787fc0820fff784fcff20fff781fcb878012800d0bc702a1c0121042043f006fff0bc08bc18470000fc1a0001'
        'bc050001b90b440000e07f01'
    )),
    ('startup', 0x440fa4, 0x1400, (
        'b3b581b000ab18790f1c012809d12248c07a002805d0214c201c67f2d3f9002803d10020bebc08bc18471a2101740021'
        '816044608761fff7cfff194c062061680988490900d2082000ab1870009867f2e6fcff2500ab1d70009867f2e0fc7920'
        '00ab1870009867f2dafc00ab1d70009867f2d5fc606b0088400905d26f2000ab1870009867f2cbfcfff794fa00ab1870'
        '0028f6d10120c5e7301b000164a60e01bc050001'
    )),
    ('assignment', 0x558564, 0x4000, (
        'b0b51027792885b000d164e019dcdd4d062800d1c2e0082800d183e1782800d0ade10120fbf78efdfbf71cfd002837d0'
        '0021002000f094fe0021022000f090fe32e0d14fd14c7e2800d15be07f2800d095e14ff159fea18901231b039943a181'
        'a189b98122681180002801d14ff158fe002201210120f7f72df878f755f9002804d1fbf7e1ff3e21f6f7d2fff9f77af8'
        '002800d171e041210220f6f780ff71e00021012000f05cfe012041f7b3fb0121f8f7b2fb012809d1fbf7d4fc002805d0'
        '3b1c80220021002050f1d0f8012005b0b0bc08bc18470020fbf734fd012041f799fb0121f8f798fb012809d1fbf7bafc'
        '002805d03b1c80220021002050f1b6f80120e4e750f77cf901280ed14ff1fcfda189012212031143a181a189b9812268'
        '1180002801d14ff1fbfd002201210120f6f7d0ff78f7f8f8002804d1fbf784ffa521f6f775fff9f71df8002804d0a421'
        '0220f6f724ff04e0fbf7b2fea421f6f71efffbf7d3ffa221f6f73efffbf70affa321f6f781ff0120a9e7fbf7a1fe4121'
        'f6f70dfffbf7c2ffa121f6f72dfffbf7f9fe4021f6f770ff012098e77df762fdfdf718fc012800d068e0fdf713fc3df7'
        '71fd3df74ffef8f7affd782800d05de0032042f791ff071c002041f723fb8783002041f71ffb103002248473032042f7'
        '83ff071c002041f715fb0783002041f711fb8476002041f70dfb9022009280273b1c0022002141f765fa402000abd880'
        '00209880502058811f81002041f7fafa20300471faf72af8071c002041f7f2fac784faf737f8071c002041f7ebfa0785'
        '6f20000100f00afa071c002041f7e2fa3b1c0922520201a941f71cff7920c00000f0fcf9071cff20243000f0f7f9b722'
        '0092aa22b323391cfff7b4fd0120fbf7f7fb012041f7c6fa0121f8f7c5fa0223e85e431c04d064f705fd0020c0436880'
        '012046f7fdfff9f701fff9f7abfe0121002000f04dfe012000f0f4fdf8f72cfd071cfaf78df900281ad10b2f28d0162f'
        '26d0b9f70ffa002812d150f7a5f803ac0021201cfcf738fb012050f7bbf8fbf7a9ff51f739fd011c0022201c51f76efc'
        '7e2f0dd100217e2000f022fe012807d10121002000f024fd00217e2000f0fafd0120d4e60223e85e431c06d1154b0022'
        '02330c20164964f739fc0020fbf798fbfdf748fb012803d13df7a4fc3df782fd002000f0a7fd022000f0a4fd00210120'
        '00f0fefcf7f788fa8af7a8fafdf786f9032802d10120fdf769f90120a7e60020a5e6000094db000100e07f01bc050001'
        'd1815500'
    )),
    ('registration', 0x5589b0, 0x2000, (
        '08b50c48e8f648fb0b484178002906d100680a49e8f6eefa01b008bc18474ff1c3fc00220023ab208000009204a1daf6'
        '49fbf1e705825500f0623a013d825500'
    )),
    ('callback', 0x55823c, 0x3000, (
        '81b51e48007900280cd000ab1878512808d01878062805d01878082802d01878ff2828d150f104f8154a00045178000c'
        '17784b1cdb06db0ebb4214d000ab1b7889188b70517800ab0131c906c90e51701978062902d01978082904d1d11d1931'
        '8a7801328a70002801d14ff1edff0221044850f145f888bc08bc184794db0001f2623a01d4410401'
    )),
    ('dequeue', 0x5582c4, 0x2800, (
        '0c4b59781878814201d100207047c0188078062801d0082806d1da1d19329178002901d00139917019780131c906c90e'
        '19707047f2623a01'
    )),
    ('dispatch', 0x558a08, 0x2400, (
        'f0b5fff75bfc071c00d1c9e0664d674e062f01d0082f03d1a878002800d0bae0ff2f09d0624c2078002805d008216148'
        '4ff17afc00202070381cfff78ffdff2f00d18be0f8f716fc041cfbf7b9fa002844d00021022000f031fc012c06d10020'
        '00f062fd002801d1f7f7b4f9062f21d00021002000f022fc07281bd1012c03d0022c01d0162c0bd1f81f2938092811d9'
        '2a2f0fd0232f0dd0162c01d1512f09d0f8f71efe002802d1381cfff721ff0020308070e0fef758fa3780f9f78bfc062f'
        '03d00122011cf9f70df800220021381cf7f79af9381cfff70bff5ce0882f05d0872f03d0892f01d0842f25d1fef73cfa'
        '0021012000f0e2fb07280dd1162c01d1842f09d000203080f8f7eafd002842d1381cfff7edfe3ee03780f9f75bfc0122'
        '011cf8f7dfff00220021381cf7f76cf9381cfff7ddfe2ee0082f03d07e2f01d07f2f08d1fef710fa00220021381c3780'
        'f7f75af91fe0002030801ce0fbf748fa002809d0124c2078002805d1082111484ff1e0fb01202070308800280bd00020'
        '3080f8f7c7ff381cfff70dff00220021ff20f7f739f9fff791fb071c00d037e7f0bc08bc1847000012633a0194db0001'
        '8c613a01a81f020101498000'
    )),
    ('submit', 0x440f7c, 0x1800, (
        '80b5071c011ca0f706f9391c044867f2f3f90421034867f2d3f980bc08bc184758a60e01a8120201'
    )),
    ('install', 0x440a30, 0x1a00, (
        'feb50421584867f27bfc58495848029101909fe0387cbd68fe681b2800d37ee001a31b5c5b009f448585858585858585'
        '85850d8585113d8585857a7a85857a7a5c627000387dfff771fd73e078694749041c0198302200782070601c603967f2'
        '5bfce01d414929303039098e0b0a41708370e01d3d492c303022303967f24cfce01d3a4959303039498ec1700b0a0371'
        '02990979417136492039898b81710b0ac37147e0387d324920390871002841d067f2c4fb04042e49240c203988780328'
        '02d1ff20fff732fd29490120203988700421284867f21afc002c2bd167f2bafb28e02549087800280ad1012004e02349'
        '0878002804d10220087000234b7019e000230b700220487014e01b490120087000234b701649b869203988620ae067f2'
        '03fc00220023192000923a7c80011449f2f788fa7868002802d0391c67f202fc002d03d0311c281c67f2e0fb01204002'
        'f2f7bafb0b4867f2effb071c00d059e7febc08bc18470000a8120201a0a80e011c1b0001a81f02011d1b00011f1b0001'
        'd807440058a60e01'
    )),
)


class LoopStatusTests(unittest.TestCase):
    def _image(self, shift=0, ram_shift=0):
        from msm5xxx_emulator.detection.arm import thumb_bl_target
        image = bytearray(b'\xff' * (0x6000+shift))
        locations = {old: new+shift for _, old, new, _ in _SEGMENTS}
        locations.update({0x4405bc: 0x5000+shift, 0x553fc8: 0x5100+shift,
                          0x553fd4: 0x5120+shift, 0x44055c: 0x5200+shift,
                          0x6a89c2: 0x5300+shift, 0x6a826c: 0x5400+shift,
                          0x6a8284: 0x5500+shift})
        def mapped(value):
            if value & ~1 in locations:
                return locations[value & ~1] | (value & 1)
            if 0x1000000 <= value < 0x2000000:
                return value+ram_shift
            return value
        for name, old, new, data in _SEGMENTS:
            raw = bytes.fromhex(data)
            start = new+shift
            image[start:start+len(raw)] = raw
            # The literal pools move with their bodies; only stored pointers change.
            pools = {'recurring':0xbc,'startup':0x98,'assignment':0x384,
                     'registration':0x34,'callback':0x7c,'dequeue':0x34,'dispatch':0x1a4,
                     'submit':0x20,'install':0x168}
            for off in range(pools[name], len(raw)-3, 4):
                word = struct.unpack_from('<I', raw, off)[0]
                replacement = mapped(word)
                if replacement != word:
                    struct.pack_into('<I', image, start+off, replacement)
            for off in range(0, len(raw)-3, 2):
                target = thumb_bl_target(raw, off)
                if target is not None:
                    absolute = old+target
                    IndirectStatusTests._bl(image, start+off,
                        locations.get(absolute, 0x5600+shift))
        getter, setter = 0x5100+shift, 0x5120+shift
        image[getter:getter+6] = bytes.fromhex('014800787047')
        image[setter:setter+6] = bytes.fromhex('014908707047')
        struct.pack_into('<I', image, getter+8, 0x100daf0+ram_shift)
        struct.pack_into('<I', image, setter+8, 0x100daf0+ram_shift)
        image[0x5300+shift:0x5302+shift] = bytes.fromhex('3847')
        for pc, target in ((0x5002,0x5100), (0x5224,0x5400), (0x524e,0x5500),
                           (0x5824,0x5000), (0x58e8,0x5100)):
            IndirectStatusTests._bl(image, pc+shift, target+shift)
        matrix = dict(grammar='indirect-halfword-loop-six-row-v1',
                      descriptor=0x10005bc+ram_shift, copied_descriptor=0x17fe000+ram_shift,
                      scanner_state=0x1001afc+ram_shift,
                      row_selection={'mode_byte':0x100daf0+ram_shift},
                      contact_site=0x581a+shift, queue_sink=hex(0x5200+shift))
        return image, matrix

    def _resolve(self, image, matrix):
        with patch('msm5xxx_emulator.detection.input_halfword_status.resolve_indirect_matrix_input',
                   return_value=(matrix,'static-candidate',[])):
            return resolve_indirect_board_status(bytes(image))

    def test_loop_candidate_and_relocation(self):
        for shift, ram_shift in ((0,0),(0x180,0x80)):
            with self.subTest(shift=shift):
                image, matrix = self._image(shift,ram_shift)
                result, status, _ = self._resolve(image,matrix)
                self.assertEqual(status,'static-candidate')
                self.assertEqual(result['mask'],0x10)
                self.assertEqual(result['width'],2)
                self.assertEqual(result['pointer_offset'],4)
                self.assertEqual(result['read_sites'],[0x1440+shift,0x1010+shift])
                self.assertEqual(result['polarity'],{'mask_set':6,'mask_clear':8})
                self.assertEqual(result['consumer']['event_values'],{6:1,8:0})
                self.assertFalse(result['runtime_admitted'])
                self.assertIsNone(result['default_level'])
                self.assertIsNone(result['physical_role'])

    def test_deleted_bl_cannot_match_zero_normalized_immediates(self):
        image, matrix = self._image()
        for pc in (0x1002,0x141a,0x4024,0x2004,0x3024,0x2402,0x1806,0x1a06):
            with self.subTest(deleted_call=hex(pc)):
                changed=image.copy();changed[pc:pc+4]=b'\0'*4
                self.assertIsNone(self._resolve(changed,matrix)[0])

    def test_loop_rejects_broken_descriptor_bit_event_call_queue_and_consumer(self):
        image, matrix = self._image()
        for pc in (0x1010,0x1012,0x101c,0x1030,0x1096,0x10c0,
                   0x1440,0x1444,0x1446,0x14a0,0x203c,0x3080,
                   0x2834,0x427c,0x433a,0x5128,0x1820,0x1b0a,0x1b12,0x1b84,0x1a70):
            with self.subTest(pc=hex(pc)):
                changed=image.copy();changed[pc]^=1
                self.assertIsNone(self._resolve(changed,matrix)[0])
        for pc in (0x101e,0x1032,0x1098,0x2014,0x427e,0x433c,0x2402,0x243a,0x1436,0x180e,0x1816,0x1b56):
            with self.subTest(edge=hex(pc)):
                changed=image.copy()
                IndirectStatusTests._bl(changed,pc,0x5700)
                self.assertIsNone(self._resolve(changed,matrix)[0])
        for field in ('descriptor','copied_descriptor','scanner_state','row_selection',
                      'contact_site','queue_sink'):
            with self.subTest(field=field):
                changed=dict(matrix);changed[field]=None
                self.assertIsNone(self._resolve(image,changed)[0])
        changed=image.copy()
        changed[0x3600:0x367c]=changed[0x3000:0x307c]
        self.assertIn('ambiguous-callback',self._resolve(changed,matrix)[1])


if __name__ == '__main__':
    unittest.main()
