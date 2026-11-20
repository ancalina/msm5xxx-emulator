import struct
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.eeprom import rules

class EEPROMFallbackTests(TestCase):
    def test_legacy_pins_do_not_require_unrelated_status_literal(self):
        image = bytearray(b'\xff' * 0x3000)
        read, write, geometry = 0x100, 0x900, 0x01000000
        image[read:read + 4] = b'\x12\x34\x56\x78'
        for start in (read, write):
            struct.pack_into('<II', image, start + 0x100, 0x03000660, 0x03000670)
        image[0x1fec:0x1ffe] = bytes.fromhex('01210448c9030180012181700021c170f746')
        struct.pack_into('<I', image, 0x2000, geometry)
        config = SimpleNamespace(load_address=0, eeprom_read_address=read,
                                 eeprom_write_address=write, eeprom_geometry_address=geometry)
        with patch.object(rules, 'EEPROM_24LCXX_READ_SIGNATURE', b'\x12\x34\x56\x78'), \
             patch.object(rules, 'eeprom_24lcxx_write_at', return_value=True):
            self.assertEqual(rules._select_eeprom_gpio_profile(bytes(image), config),
                             ((0x03000660, 8, 8, 0xc, 1, 0x1c, 0x8000), None))
