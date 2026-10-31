"""CPU-free EEPROM persistence shared with the native transport."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
import struct
from msm5xxx_emulator.detection.firmware import detect
from msm5xxx_emulator.detection.storage import (
    EEPROM_24LC64_CLASS_B_WRITE_PREFIX, EEPROM_24LC64_CLASS_B_READ_PREFIX)
from msm5xxx_emulator.qemu.decoder import QemuDecoder

from msm5xxx_emulator.devices.storage.eeprom import EepromMixin


class EEPROMTests(unittest.TestCase):
    def device(self, state):
        device = EepromMixin()
        device.eeprom_state_path = state
        device.eeprom_capacity = 0x2000
        device.eeprom_original = b'\xff' * device.eeprom_capacity
        loaded = state.read_bytes() if state.is_file() else device.eeprom_original
        device.eeprom_loaded = loaded
        device.eeprom_data = bytearray(loaded)
        device.eeprom_operations = []
        return device

    def test_cold_write_and_warm_persistence(self):
        with TemporaryDirectory() as directory:
            state = Path(directory) / 'eeprom.bin'
            device = self.device(state)
            device.eeprom_data[0x1fff] = 0x12
            device.eeprom_operations.append((0x1fff, b'\x12'))
            device._save_eeprom()
            warm = self.device(state)
            self.assertEqual(warm.eeprom_data[-1], 0x12)
            self.assertEqual(warm.eeprom_data[:-1], b'\xff' * 0x1fff)
            self.assertEqual(device.eeprom_operations, [])

    def test_independent_sessions_merge_persistent_writes(self):
        with TemporaryDirectory() as directory:
            state = Path(directory) / 'eeprom.bin'
            first, second = self.device(state), self.device(state)
            for device, offset, payload in ((first, 0x20, b'one'),
                                             (second, 0x30, b'two')):
                device.eeprom_data[offset:offset + len(payload)] = payload
                device.eeprom_operations.append((offset, payload))
                device._save_eeprom()
            self.assertEqual(self.device(state).eeprom_data[0x20:0x33],
                             b'one' + b'\xff' * 13 + b'two')

    def test_direct_image_changes_are_saved_and_erased_state_is_removed(self):
        with TemporaryDirectory() as directory:
            state = Path(directory) / 'eeprom.bin'
            device = self.device(state)
            device.eeprom_data[3:5] = b'\x12\x34'
            device._save_eeprom()
            self.assertEqual(state.read_bytes()[3:5], b'\x12\x34')
            device.eeprom_data[:] = device.eeprom_original
            device._save_eeprom()
            self.assertFalse(state.exists())
            self.assertFalse(device.eeprom_loaded_from_state)

    def test_invalid_existing_capacity_is_rejected_without_overwrite(self):
        with TemporaryDirectory() as directory:
            state = Path(directory) / 'eeprom.bin'
            device = self.device(state)
            state.write_bytes(b'bad')
            device.eeprom_operations.append((0, b'X'))
            with self.assertRaisesRegex(ValueError, 'expected 0x2000'):
                device._save_eeprom()
            self.assertEqual(state.read_bytes(), b'bad')

    def test_class_b_detection_initializes_cpu_free_state(self):
        image = bytearray(b'\xff' * 0x3000)
        for offset in range(0, 32, 4):
            struct.pack_into('<I', image, offset, 0xEA000000)
        image[0x100:0x100 + len(EEPROM_24LC64_CLASS_B_WRITE_PREFIX)] = EEPROM_24LC64_CLASS_B_WRITE_PREFIX
        image[0x800:0x800 + len(EEPROM_24LC64_CLASS_B_READ_PREFIX)] = EEPROM_24LC64_CLASS_B_READ_PREFIX
        image[0x2f00:0x2f0b] = b'nv24lcxx.c\0'
        with TemporaryDirectory() as directory:
            root = Path(directory)
            firmware = root / 'class-b.bin'
            firmware.write_bytes(image)
            config = detect(firmware)
            config.flash_state = str(root / 'flash.json')
            config.secondary_flash_state = str(root / 'secondary.json')
            self.assertEqual(config.eeprom_read_address, 0x800)
            self.assertEqual(config.eeprom_write_address, 0x100)
            self.assertEqual(config.eeprom_static_capacity, 0x2000)
            decoder = QemuDecoder(config)
            try:
                self.assertTrue(decoder.eeprom_enabled)
                self.assertEqual(decoder.eeprom_state_path, root / 'flash.json.eeprom.bin')
            finally:
                decoder.close()
