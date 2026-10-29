"""Static descriptor gate; private corpus is optional and never bundled."""
import hashlib
from pathlib import Path
import struct
import unittest

from msm5xxx_emulator.detection.audio_irq import find_audio_irq_candidate
from corpus import FIRMWARE_ROOT


class TestAudioIRQCandidate(unittest.TestCase):
    def test_empty_and_truncated_images_reject(self):
        for image in (b'', bytes(19), bytes.fromhex('f0b51d4f00247879002834d0')):
            self.assertEqual(find_audio_irq_candidate(image)['status'], 'rejected')

    def test_real_descriptor_and_mutations(self):
        corpus = FIRMWARE_ROOT
        path = corpus / 'SCH-X350_UJ08_JTAG.bin'
        if not path.is_file():
            self.skipTest('private regression corpus unavailable')
        image = path.read_bytes()
        self.assertEqual(hashlib.sha256(image).hexdigest(),
                         '429d3ccc501a9b2b62fb90fa25416099e358a431885d72d85ca5ca58f1c97712')
        candidate = find_audio_irq_candidate(image)
        self.assertEqual(candidate['status'], 'candidate')
        self.assertEqual(candidate['reason'], 'live-handler-and-consumer-unverified')
        self.assertEqual(candidate['descriptor_address'], 0x01383224)
        self.assertEqual(candidate['words'][:3], [0x03000624, 0x0300062c, 2])
        self.assertEqual(candidate['callback_linkage'], {
            'state_address': 0x0138c32c, 'table_address': 0x01438998,
            'callback_offset': 0x17c934, 'data_read_offset': 0x17b200})
        wrong_table = bytearray(image)
        struct.pack_into('<I', wrong_table, 0x17bb04, 0x0143899c)
        self.assertNotIn('callback_linkage', find_audio_irq_candidate(bytes(wrong_table)))
        mutations = [(candidate['file_offset'] + 8, 3),  # not one bit
                     (candidate['file_offset'] + 4, 0x03000628),
                     (candidate['file_offset'] + 12, 0x03000628),
                     (candidate['file_offset'] + 24, 1),
                     (candidate['scatter_offset'] + 8, 1),
                     (candidate['dispatcher_offset'], 0)]
        for offset, value in mutations:
            with self.subTest(offset=offset):
                damaged = bytearray(image)
                struct.pack_into('<I', damaged, offset, value)
                self.assertEqual(find_audio_irq_candidate(bytes(damaged))['status'],
                                 'rejected')
        ambiguous = bytearray(image)
        start = candidate['scatter_offset']
        ambiguous[0x100:0x114] = image[start:start + 20]
        self.assertEqual(find_audio_irq_candidate(bytes(ambiguous))['status'], 'rejected')
        negative_thunk = bytearray(image) + b'\x00\x47\x00\x00'
        call = candidate['dispatcher_offset'] + 0x38
        displacement = (-4 - call - 4) & 0x7fffff
        struct.pack_into('<HH', negative_thunk, call,
                         0xf000 | (displacement >> 12 & 0x7ff),
                         0xf800 | (displacement >> 1 & 0x7ff))
        self.assertEqual(find_audio_irq_candidate(bytes(negative_thunk))['status'], 'rejected')


if __name__ == '__main__':
    unittest.main()
