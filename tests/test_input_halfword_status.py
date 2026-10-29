"""Static status grammar and fail-closed candidate checks, without firmware."""
from corpus import snippet
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
def _segments():
    return (
    ('recurring', 0x440bb8, 0x1000, (
        snippet("test_input_halfword_status", "recurring").hex()
    )),
    ('startup', 0x440fa4, 0x1400, (
        snippet("test_input_halfword_status", "startup").hex()
    )),
    ('assignment', 0x558564, 0x4000, (
        snippet("test_input_halfword_status", "assignment").hex()
    )),
    ('registration', 0x5589b0, 0x2000, (
        snippet("test_input_halfword_status", "registration").hex()
    )),
    ('callback', 0x55823c, 0x3000, (
        snippet("test_input_halfword_status", "callback").hex()
    )),
    ('dequeue', 0x5582c4, 0x2800, (
        snippet("test_input_halfword_status", "dequeue").hex()
    )),
    ('dispatch', 0x558a08, 0x2400, (
        snippet("test_input_halfword_status", "dispatch").hex()
    )),
    ('submit', 0x440f7c, 0x1800, (
        snippet("test_input_halfword_status", "submit").hex()
    )),
    ('install', 0x440a30, 0x1a00, (
        snippet("test_input_halfword_status", "install").hex()
    )),
)


class LoopStatusTests(unittest.TestCase):
    def _image(self, shift=0, ram_shift=0):
        from msm5xxx_emulator.detection.arm import thumb_bl_target
        image = bytearray(b'\xff' * (0x6000+shift))
        locations = {old: new+shift for _, old, new, _ in _segments()}
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
        for name, old, new, data in _segments():
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
