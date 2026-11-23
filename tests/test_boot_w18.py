import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from msm5xxx_emulator.detection.devices.storage.boot_w18 import (
    _BUS_INIT, _CHIP, _CLOCK, _DESCRIPTOR, _POWER_REASON, _PROGRAM, _RAM_TEST,
    boot_legacy_ram_size, has_boot_legacy_clock, has_boot_w18)
from msm5xxx_emulator.devices.storage.nor import NORFlash
from msm5xxx_emulator.qemu.transport import Transport


class BootW18Tests(unittest.TestCase):
    def test_signature_and_persisted_media(self):
        seed = bytearray(b'\xff' * 0x800000)
        seed[128:128 + len(_PROGRAM)] = _PROGRAM
        seed[256:256 + len(_DESCRIPTOR)] = _DESCRIPTOR
        self.assertTrue(has_boot_w18(bytes(seed)))
        seed[128] ^= 1
        self.assertFalse(has_boot_w18(bytes(seed)))
        seed[128] ^= 1
        seed[512:512 + len(_CLOCK)] = _CLOCK
        seed[558:570] = bytes.fromhex('08400088c4400088c0400088')
        seed[1024:1024 + len(_CHIP)] = _CHIP
        seed[1204:1208] = bytes.fromhex('40070080')
        seed[1400:1400 + len(_POWER_REASON)] = _POWER_REASON
        seed[1472:1476] = bytes.fromhex('40070080')
        self.assertTrue(has_boot_legacy_clock(bytes(seed)))
        seed[558] ^= 1
        self.assertFalse(has_boot_legacy_clock(bytes(seed)))
        seed[558] ^= 1
        seed[2000:2000 + len(_RAM_TEST)] = _RAM_TEST
        seed[2228:2232] = (0x1fffff).to_bytes(4, 'little')
        seed[3000:3000 + len(_BUS_INIT)] = _BUS_INIT
        self.assertEqual(boot_legacy_ram_size(bytes(seed)), 0x204000)
        seed[2228:2232] = (0x3fffff).to_bytes(4, 'little')
        self.assertEqual(boot_legacy_ram_size(bytes(seed)), 0x404000)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flash = NORFlash(bytes(seed), root / 'state.json')
            workdir = tempfile.TemporaryDirectory(dir=root)
            working = Path(workdir.name) / 'boot-w18.raw'
            modified = bytearray(seed)
            modified[0x600000] = 0x42
            working.write_bytes(modified)
            transport = Transport.__new__(Transport)
            transport._network_monitor = None
            transport._native_nand_lock = None
            transport._stop_uis_idle_observer = Mock()
            transport._stop_rex_idle_candidate_observer = Mock()
            transport._close_audio_channel = Mock()
            transport._terminate_process = Mock()
            transport.lcd_socket = Mock()
            transport.input_socket = Mock()
            transport.stderr = Mock()
            transport.decoder = Mock(flash=flash)
            transport.decoder.close.side_effect = flash.save
            transport.temporary = workdir
            transport._w18_working = working
            transport.close()
            self.assertEqual(NORFlash(bytes(seed), root / 'state.json').data[0x600000], 0x42)
            self.assertFalse(working.exists())

    def test_failed_state_save_preserves_working_media(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            working = root / 'working.raw'
            working.write_bytes(b'\xff' * 16)
            transport = Transport.__new__(Transport)
            transport._network_monitor = transport._native_nand_lock = None
            transport._stop_uis_idle_observer = Mock()
            transport._stop_rex_idle_candidate_observer = Mock()
            transport._close_audio_channel = Mock()
            transport._terminate_process = Mock()
            transport.lcd_socket = transport.input_socket = transport.stderr = Mock()
            transport.decoder = Mock(flash=NORFlash(b'\xff' * 16, root / 'state.json'))
            transport.decoder.close.side_effect = OSError('disk error')
            transport.temporary = tempfile.TemporaryDirectory(dir=root)
            transport._w18_working = working
            with self.assertRaisesRegex(RuntimeError, 'working image preserved'):
                transport.close()
            self.assertEqual(working.read_bytes(), b'\xff' * 16)
            transport.temporary.cleanup()


if __name__ == '__main__':
    unittest.main()
