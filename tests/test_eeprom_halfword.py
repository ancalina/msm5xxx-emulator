"""Synthetic pairing checks and optional private-corpus GPIO provenance checks."""
import struct
import unittest
from corpus import firmware_path
from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.storage import (
    EEPROM_24LCXX_HALFWORD_READ_PREFIX,
    EEPROM_24LCXX_X430_WRITE_PREFIX,
    EEPROM_24LCXX_X430_INIT_SIGNATURE,
    find_24lcxx_halfword_driver,
)
from msm5xxx_emulator.qemu.transport import eeprom_gpio_profile


class HalfwordEEPROMTests(unittest.TestCase):
    def synthetic(self):
        image = bytearray(0x3000)
        image[0x40:0x4b] = b'nv24lcxx.c\0'
        read, write, init, geometry = 0x1000, 0x400, 0x2000, 0x1000400
        for at, code in ((read, EEPROM_24LCXX_HALFWORD_READ_PREFIX),
                         (write, EEPROM_24LCXX_X430_WRITE_PREFIX),
                         (init, EEPROM_24LCXX_X430_INIT_SIGNATURE)):
            image[at:at + len(code)] = code
        for at in (read + 0x3e8, write + 0x3e8, init + 0x14):
            struct.pack_into('<I', image, at, geometry)
        return image, (read, write, geometry), init

    def test_pair_uses_shared_initialized_geometry(self):
        image, expected, init = self.synthetic()
        self.assertEqual(find_24lcxx_halfword_driver(bytes(image)), expected)
        for at in (expected[0] + 0x3e8, expected[1] + 0x3e8, init + 0x14):
            changed = bytearray(image)
            struct.pack_into('<I', changed, at, expected[2] + 4)
            self.assertIsNone(find_24lcxx_halfword_driver(bytes(changed)))

    def test_duplicate_evidence_rejected(self):
        image, expected, init = self.synthetic()
        for code in (EEPROM_24LCXX_HALFWORD_READ_PREFIX,
                     EEPROM_24LCXX_X430_WRITE_PREFIX,
                     EEPROM_24LCXX_X430_INIT_SIGNATURE):
            changed = bytearray(image)
            changed[0x2500:0x2500 + len(code)] = code
            self.assertIsNone(find_24lcxx_halfword_driver(bytes(changed)))

    def test_missing_or_unsupported_initializer_rejected(self):
        image, _, init = self.synthetic()
        image[init + 4] ^= 1
        self.assertIsNone(find_24lcxx_halfword_driver(bytes(image)))

    def test_private_halfword_gpio_and_corruptions(self):
        path = firmware_path('SPH-X8500-fulldump.bin')
        image = path.read_bytes()
        config = detect(path)
        profile = (0x03000720, 0, 0x20, 0, 0x40, 0xc, 0x8000)
        self.assertEqual(eeprom_gpio_profile(image, config), (profile, None))
        read, write = config.eeprom_read_address, config.eeprom_write_address
        # Page size, 16-bit wire address, ACK polarity and pin ownership.
        for at in (write + 0x92, write + 0x16a,
                   write - 0x1fe + 0x46, write - 0x160 + 0x1a):
            changed = bytearray(image)
            changed[at] ^= 1
            self.assertEqual(eeprom_gpio_profile(bytes(changed), config),
                             (None, 'gpio-line-shape-mismatch'))
        # Every byte-level reader reload, ACK clock operation and loop bound
        # belongs to the admitted transport, even between the pin signatures.
        mutations = (
            (write - 0x78 + 0x32, 0x4800),  # reader reload loses GPIO literal
            (write - 0x1fe + 0x24, 0x2280),  # ACK drives the wrong SCL bit high
            (write - 0x1fe + 0x5a, 0x2380),  # ACK drives the wrong SCL bit low
            (write - 0x78 + 0x64, 0x2c09),  # reader clocks nine bits
            (write - 0x160 + 0xd8, 0xd597),  # writer byte loop backedge changes
            (write - 0x1fe + 0x2c, 0x68a2),  # ACK SCL writes direction pointer
            (write - 0x1fe + 0x62, 0x68a2),
            (write - 0x78 + 0x2e, 0x0070),  # reader shifts the wrong register
            (write - 0x1fe + 0x90, 0xbcb8),  # ACK restores the wrong result register
        )
        for at, operation in mutations:
            with self.subTest(operation=hex(operation), site=hex(at)):
                changed = bytearray(image)
                struct.pack_into('<H', changed, at, operation)
                self.assertEqual(eeprom_gpio_profile(bytes(changed), config),
                                 (None, 'gpio-line-shape-mismatch'))
        # Branch destinations must keep their lock/unlock/delay/ACK roles too.
        changed = bytearray(image)
        changed[write - 0x1fe + 2] ^= 1
        self.assertEqual(eeprom_gpio_profile(bytes(changed), config),
                         (None, 'gpio-line-shape-mismatch'))
        # The GPIO descriptor is admitted only through unique scatter metadata.
        from msm5xxx_emulator.detection.memory_layout import find_linker_layout
        layout = find_linker_layout(image, required_span=(0x10009f8, 12))
        # Relocate only the GPIO descriptor and its literal references inside
        # the same proven scatter span; offsets and model identity are irrelevant.
        descriptor, relocated = 0x10009f8, 0x1000af8
        changed = bytearray(image)
        source = layout.data_source + descriptor - layout.data_target
        destination = layout.data_source + relocated - layout.data_target
        changed[destination:destination + 12] = image[source:source + 12]
        old, new = struct.pack('<I', descriptor), struct.pack('<I', relocated)
        for at in range(write - 0x200, write, 4):
            if image[at:at + 4] == old:
                changed[at:at + 4] = new
        self.assertEqual(eeprom_gpio_profile(bytes(changed), config), (profile, None))
        changed = bytearray(image)
        table = image[layout.table_offset:layout.table_offset + 20]
        changed[0x1f000:0x1f014] = table
        self.assertEqual(eeprom_gpio_profile(bytes(changed), config),
                         (None, 'gpio-descriptor-linkage-mismatch'))
        changed = bytearray(image)
        rom = layout.data_source + 0x10009f8 - layout.data_target
        struct.pack_into('<I', changed, rom + 8, 0x03000728)
        self.assertEqual(eeprom_gpio_profile(bytes(changed), config),
                         (None, 'gpio-descriptor-linkage-mismatch'))

    def test_private_existing_halfword_gpio_unchanged(self):
        path = firmware_path('SPH-X7700.bin')
        config = detect(path)
        self.assertEqual(eeprom_gpio_profile(path.read_bytes(), config),
                         ((0x03000720, 0, 0x20, 0, 0x40, 0xc, 0x8000), None))

    def test_private_shared_byte_leaf_class(self):
        for name in ('SPH-X6000.bin', 'SPH-X8500.bin'):
            with self.subTest(name=name):
                path = firmware_path(name)
                config = detect(path)
                self.assertEqual(eeprom_gpio_profile(path.read_bytes(), config),
                                 ((0x03000720, 0, 0x20, 0, 0x40, 0xc, 0x8000), None))

    def test_private_other_byte_leaf_classes_stay_closed(self):
        for name in ('sch-x750.bin', 'incoming-20260914/X600_XC29 (1).bin'):
            with self.subTest(name=name):
                path = firmware_path(name)
                config = detect(path)
                self.assertIsNotNone(config.eeprom_read_address)
                self.assertEqual(eeprom_gpio_profile(path.read_bytes(), config),
                                 (None, 'gpio-line-shape-mismatch'))

    def test_private_other_writer_class_keeps_existing_notes(self):
        config = detect(firmware_path('SCH-E150.bin'))
        self.assertFalse(any('halfword EEPROM candidate' in note
                             for note in config.detection_notes))
