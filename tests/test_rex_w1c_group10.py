"""Closed group-10 callback/W1C route and native property regression."""
import struct
import unittest
from types import SimpleNamespace

from corpus import firmware_path
from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.rex import find_rex_static_controller_callback_candidate
from msm5xxx_emulator.qemu.transport import w1c_rex_irq_profile
from test_rex_controller_candidate import _bl


class W1CGroup10Tests(unittest.TestCase):
    def test_synthetic_missing_and_ambiguous_evidence_rejected(self):
        self.assertIsNone(find_rex_static_controller_callback_candidate(
            bytes(0x1000), ram_base=0x01000000, ram_size=0x800000))
        for candidate in (None, {}, {'accepted': True}, {
                'controller_class': 'legacy-msm5000-620-two-bank-w1c-group10-v1',
                'accepted': True, 'group_row_size': 12}):
            self.assertIsNone(w1c_rex_irq_profile(SimpleNamespace(
                rex_static_controller_candidate=candidate)))

    def test_corpus_property_and_closed_route_mutations(self):
        path = firmware_path('SCH-X270.bin')
        config = detect(path)
        candidate = config.rex_static_controller_candidate
        self.assertTrue(candidate['accepted'])
        self.assertEqual(candidate['controller_class'],
                         'legacy-msm5000-620-two-bank-w1c-group10-v1')
        self.assertEqual(candidate['handler_validation_size'], 0x15A)
        self.assertEqual(candidate['descriptor_file_offset'], 0x394858)
        self.assertEqual(candidate['callback_file_offset'], 0xCEB8)
        self.assertEqual(candidate['pending_ack_semantics'], 'write-one-to-clear')
        self.assertIsNone(config.rex_idle_address)
        self.assertEqual(w1c_rex_irq_profile(config),
                         '3000620:3000628:30006e0:200:4c4b40')
        image = path.read_bytes()
        handler = candidate['handler_file_offset']
        registrar = candidate['registrar_file_offset']
        callback = candidate['callback_file_offset']
        literal_at = handler + 0xC8
        pool = ((literal_at + 4) & ~3) + (struct.unpack_from('<H', image, literal_at)[0] & 255) * 4
        mutations = {
            'group-stride': (handler + 0x46, struct.pack('<H', 0x230C)),
            'bank0-ack': (handler + 0xCC, struct.pack('<H', 0x8048)),
            'bank1-ack': (handler + 0xF6, struct.pack('<H', 0x8008)),
            'pending-literal': (pool, struct.pack('<I', 0x03000624)),
            'callback-target': (handler + 0xB6, _bl(handler + 0xB6, handler)),
            'registrar-body': (registrar + 0x28, bytes(2)),
            'timer-delta': (callback + 0x28, bytes(2)),
            'descriptor-mask': (candidate['descriptor_file_offset'] + 8, struct.pack('<I', 0x400)),
            'timer-group-membership': (candidate['descriptor_file_offset'] + 28 + 28, bytes(2)),
            'irq-lock-body': (0x1B7448 + 12, bytes(4)),
        }
        for label, (offset, replacement) in mutations.items():
            with self.subTest(label=label):
                changed = bytearray(image)
                changed[offset:offset + len(replacement)] = replacement
                result = find_rex_static_controller_callback_candidate(
                    changed, ram_base=config.ram_base, ram_size=config.ram_size)
                self.assertTrue(result is None or not result['accepted'])
                if result is not None:
                    self.assertIn('reject_reason', result)

    def test_sibling_keeps_idle_route(self):
        config = detect(firmware_path('x350_VC22.bin'))
        self.assertEqual((config.rex_irq_status_address,
                          config.rex_irq_enable_address,
                          config.rex_irq_arm_address, config.rex_irq_mask,
                          config.rex_tick_ms, config.rex_idle_address),
                         (0x03000620, 0x03000628, 0x030006E0, 0x200, 5, 0x8335E))
