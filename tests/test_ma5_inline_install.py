"""Synthetic inline GPIO interrupt installer."""
import unittest
from msm5xxx_emulator.detection.registry import device_domain
ma5_gpio_irq = device_domain('audio.ma5_gpio_irq')
from test_legacy_keypad import branch, literal


class InlineInstallTests(unittest.TestCase):
    def test_inline_installer_closes_calls_callback_and_pin(self):
        image = bytearray(0x500)
        entry = 0x100
        code = bytes.fromhex('012000000000071c00210020004a00000000002f03d0')
        image[entry:entry + len(code)] = code
        branch(image, entry + 2, 0x300)
        branch(image, entry + 14, 0x320)
        literal(image, entry + 12, 2, 0x180, 0x341)
        image[entry + 10] = 5
        result = ma5_gpio_irq._span(image, entry, 'install_inline')
        self.assertEqual((result['calls'][14], result['literals'][12], result['pins'][10]),
                         (0x320, 0x341, 5))
        for offset in (0, 2, 14, 18):
            altered = bytearray(image)
            altered[entry + offset] ^= 0x80
            with self.assertRaises(ma5_gpio_irq._Reject):
                ma5_gpio_irq._span(altered, entry, 'install_inline')

    def test_hashed_parent_span_checks_calls_and_literals(self):
        import hashlib
        from unittest.mock import patch
        role = 'parent_register'
        size, _, anchor_offset, anchor, calls, literals, pins = ma5_gpio_irq._HASH_SPANS[role]
        image = bytearray(0x1000)
        entry = 0x100
        image[entry:entry + size] = bytes((17 * i + 13) & 255 for i in range(size))
        image[entry + anchor_offset:entry + anchor_offset + len(anchor)] = anchor
        for off in calls:
            branch(image, entry + off, 0x700)
        for i, off in enumerate(literals):
            literal(image, entry + off, i % 7, 0x300 + i * 4, 0x01001000 + 4 * i)
        normalized = bytearray(image[entry:entry + size])
        for off in calls:
            normalized[off:off + 4] = bytes(4)
        for off in literals:
            normalized[off] = 0
        replacement = (size, hashlib.sha256(normalized).hexdigest(), anchor_offset,
                       anchor, calls, literals, pins)
        with patch.dict(ma5_gpio_irq._HASH_SPANS, {role: replacement}):
            self.assertEqual(ma5_gpio_irq._span(image, entry, role)['size'], size)
            self.assertIn(entry, [row['entry'] for row in ma5_gpio_irq._scan(image, role)])
            image[entry + 0x1c] ^= 1
            with self.assertRaises(ma5_gpio_irq._Reject):
                ma5_gpio_irq._span(image, entry, role)
