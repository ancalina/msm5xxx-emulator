"""Detector checks for alternate MA5 reset and readback producers."""
import unittest

from corpus import firmware_path
from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.registry import device_domain
find_ma5_readback_candidate = device_domain('audio.rules').find_ma5_readback_candidate
from msm5xxx_emulator.detection.registry import device_domain
find_ma5_gpio_irq_candidate = device_domain('audio.ma5_gpio_irq').find_ma5_gpio_irq_candidate
from msm5xxx_emulator.qemu.transport import qemu_ma5_temporary_auto_property


class AlternateReadbackTests(unittest.TestCase):
    def test_candidate_remains_diagnostic(self):
        config = detect(firmware_path('SPH-E3900.bin'))
        self.assertEqual(config.audio_transport['static_status'], 'candidate')
        self.assertFalse(any('Yamaha MA5 structural readback candidate' in note
                             for note in config.detection_notes))

    def test_duplicate_producers_are_rejected_as_ambiguous(self):
        image = firmware_path('SPH-E3900.bin').read_bytes()
        result = find_ma5_readback_candidate(image + image)
        self.assertEqual(result['static_status'], 'rejected')
        self.assertEqual(result['reject_reason'], 'structural-ambiguous')

    def test_candidates_require_closed_reset_read_and_fifo(self):
        cases = (
            ('SPH-E3900.bin', 0x2b8184, 0x2b8ec6, 0x2b8c9c,
             0x02840000, 'alternate-reset-readback-v1'),
            ('SPH-X9700.bin', 0x2d9de8, 0x2da77a, 0x2da5a0,
             0x02c00000, 'alternate-direct-reset-readback-v1'),
        )
        for name, checker, reset, fifo, base, shape in cases:
            image = firmware_path(name).read_bytes()
            with self.subTest(image=name):
                candidate = find_ma5_readback_candidate(image)
                self.assertEqual(candidate['static_status'], 'candidate')
                self.assertEqual(candidate['base'], base)
                self.assertEqual(candidate['data_offset'], 2)
                self.assertEqual(candidate['structural_evidence']['transport_class'], shape)
                irq = find_ma5_gpio_irq_candidate(image, candidate)
                expected_rejection = (None if shape == 'alternate-direct-reset-readback-v1'
                                      else 'audio-class-irq-unverified')
                self.assertEqual(irq['reject_reason'], expected_rejection)
                self.assertFalse(irq['runtime_admitted'])
                for offset in (checker + 0x16, checker + 0x1e,
                               checker + 0x30, reset - 0xc, reset + 0xc, fifo):
                    with self.subTest(mutation=hex(offset)):
                        changed = bytearray(image)
                        changed[offset] ^= 1
                        self.assertNotEqual(find_ma5_readback_candidate(changed)['static_status'],
                                            'candidate')
                # A direct candidate still requires a mapped primary NOR.
                reason = ('primary-nor-unmapped'
                          if shape == 'alternate-direct-reset-readback-v1' else None)
                self.assertEqual(qemu_ma5_temporary_auto_property(
                    image, object(), audio_pcm=True), (None, reason))


if __name__ == '__main__':
    unittest.main()
