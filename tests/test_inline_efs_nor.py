"""Inline EFS source admission; private firmware is never embedded in fixtures."""
import struct
from pathlib import Path
import tempfile
from unittest.mock import patch
from types import SimpleNamespace
import unittest

from corpus import firmware_path
from msm5xxx_emulator.detection.efs_nor import (
    _Unclosed, _thumb_body, find_inline_efs_nor_profile,
)
from msm5xxx_emulator.qemu.transport import qemu_amd_bank_profile


def profile(image, **kwargs):
    return find_inline_efs_nor_profile(
        image, kwargs.get('load', 0), kwargs.get('flash', 0x1000000),
        kwargs.get('ram', 0x1000000), kwargs.get('ram_size', 0x800000),
    )


class InlineEfsSyntheticTests(unittest.TestCase):
    def test_empty_and_unowned_candidate(self):
        self.assertEqual(profile(bytes(1024)), (None, None))
        image = bytearray(1024)
        struct.pack_into('<10H', image, 0x100, 0x4906, 0x2000, 0x4a06,
                         0x6008, 0x6010, 0x1d10, 0x6010, 0x2000, 0x7108, 0x4770)
        # A shared initializer alone must leave the older driver class alone.
        self.assertEqual(profile(image, flash=len(image)), (None, None))
        struct.pack_into('<3H', image, 0x300, 0x0409, 0x1808, 0x0040)
        found, reason = profile(image, flash=len(image))
        self.assertIsNone(found)
        self.assertIsNotNone(reason)
        image[0x200:0x214] = image[0x100:0x114]
        self.assertEqual(profile(image, flash=len(image)),
                         (None, 'inline-efs-initializers-ambiguous'))

    def test_thumb_relocations_resolve_and_preserve_registers(self):
        # ldr r1,[pc,#12]; BL to 0x30; bx lr; literal pool at 0x10.
        image = bytearray(64)
        struct.pack_into('<4H', image, 0, 0x4903, 0xf000, 0xf815, 0x4770)
        struct.pack_into('<I', image, 16, 0x12345678)
        digest, calls, literals, pools = _thumb_body(image, 0, 8)
        self.assertEqual(calls, {2: 0x30})
        self.assertEqual(literals, {0: 0x12345678})
        self.assertEqual(pools, [(16, 20)])
        struct.pack_into('<H', image, 0, 0x4904)
        struct.pack_into('<I', image, 20, 0x87654321)
        self.assertEqual(_thumb_body(image, 0, 8)[0], digest)
        self.assertEqual(_thumb_body(image, 0, 8)[2], {0: 0x87654321})
        struct.pack_into('<H', image, 0, 0x4a04)
        self.assertNotEqual(_thumb_body(image, 0, 8)[0], digest)
        with self.assertRaises(_Unclosed):
            _thumb_body(image, 1, 8)
        with self.assertRaises(_Unclosed):
            _thumb_body(image, 62, 8)


class InlineEfsCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = firmware_path('SPH-X8500-fulldump.bin').read_bytes()[:0x1000000]

    def test_descriptor_geometry_and_transport_binding(self):
        found, reason = profile(self.image)
        self.assertIsNone(reason)
        self.assertEqual(tuple(found[key] for key in
                               ('base', 'size', 'sector_size', 'backing_size', 'id0', 'id1')),
                         (0xc00000, 0x3f0000, 0x10000, 0x400000, 0x98, 0x9c))
        config = SimpleNamespace(image_kind='firmware', entry=0, load_address=0,
                                 flash_size=len(self.image), ram_base=0x1000000,
                                 ram_size=0x800000)
        self.assertEqual(qemu_amd_bank_profile(self.image, self.image, config), (found, None))
        self.assertIsNone(qemu_amd_bank_profile(self.image, self.image, config, nor_claimed=True)[0])
        persistent = bytearray(self.image)
        persistent[0xc01234] ^= 1
        self.assertEqual(qemu_amd_bank_profile(self.image, bytes(persistent), config), (found, None))
        persistent[found['descriptor']] ^= 1
        self.assertEqual(qemu_amd_bank_profile(self.image, bytes(persistent), config)[1],
                         'amd-bank-loaded-source-mismatch')

    def test_existing_fixed_unlock_classes_remain_absent(self):
        for name in ('SPH-X7700.bin', 'SPH-X5900.bin', 'SCH-X430.bin'):
            with self.subTest(name=name):
                self.assertEqual(profile(firmware_path(name).read_bytes()), (None, None))

    def test_generated_storage_arguments_without_launch(self):
        from msm5xxx_emulator.detection import detect
        from msm5xxx_emulator.qemu import transport
        firmware = firmware_path('SPH-X8500-fulldump.bin')
        config = detect(firmware)
        captured = {}

        class CommandCaptured(Exception):
            pass

        def capture(argv, **kwargs):
            machine = argv[argv.index('-M') + 1]
            self.assertIn(',record-x16-nor=c00000:3f0000:10000:98:9c', machine)
            self.assertIn(',eeprom-24lcxx-gpio=3000720:0:20:0:40:c:8000', machine)
            drives = [argv[i + 1] for i, arg in enumerate(argv) if arg == '-drive']
            eeprom = next(arg for arg in drives if 'if=mtd' in arg)
            self.assertIn('format=raw', eeprom)
            eeprom_state = Path(eeprom.split(',', 1)[0].removeprefix('file='))
            self.assertEqual(eeprom_state.stat().st_size, 0x8000)
            nor = next(arg for arg in drives if 'record-x16.raw' in arg)
            self.assertIn('if=pflash,format=raw,unit=0', nor)
            state = Path(nor.split(',', 1)[0].removeprefix('file='))
            backing = state.read_bytes()
            self.assertEqual(len(backing), 0x400000)
            self.assertEqual(backing[:0x3f0000], self.image[0xc00000:0xff0000])
            self.assertEqual(backing[0x3f0000:], b'\xff' * 0x10000)
            loaders = [arg for arg in argv if arg.startswith('loader,file=')]
            spans = []
            for arg in loaders:
                parts = dict(field.split('=', 1) for field in arg.split(',')[1:])
                address = int(parts['addr'], 0)
                data = Path(parts['file']).read_bytes()
                spans.append((address, address + len(data)))
                self.assertFalse(address < 0xff0000 and 0xc00000 < address + len(data))
                if address == 0xff0000:
                    self.assertEqual(data, self.image[0xff0000:0x1000000])
            self.assertIn((0xff0000, 0x1000000), spans)
            captured['ok'] = True
            raise CommandCaptured()

        with tempfile.TemporaryDirectory() as directory, \
             patch.object(transport.subprocess, 'Popen', side_effect=capture):
            with self.assertRaises(CommandCaptured):
                transport.Transport(Path('/never-executed-qemu'), firmware,
                                    Path(directory), config=config, audio_pcm=False)
        self.assertTrue(captured.get('ok'))

    def test_geometry_is_derived_and_label_is_not_identity(self):
        found, _ = profile(self.image)
        changed = bytearray(self.image)
        descriptor = found['descriptor']
        # Same callback class, relocated logical aperture and a different count.
        struct.pack_into('<I', changed, descriptor + 4, 62)
        struct.pack_into('<I', changed, descriptor + 8 + 62 * 4, 0)
        struct.pack_into('<2I', changed, descriptor + 0x130, 0xb00000, 0x3e0000)
        label = struct.unpack_from('<I', changed, descriptor)[0]
        end = changed.index(0, label)
        changed[label:end] = b'X' * (end - label)
        other, reason = profile(changed)
        self.assertIsNone(reason)
        self.assertEqual((other['base'], other['size']), (0xb00000, 0x3e0000))

    def test_corrupted_graph_rejects_with_reason(self):
        found, _ = profile(self.image)
        d = found['descriptor']
        # Reset, copy producer, source tuple, selection, EFS owner, geometry,
        # command bytes, unlock constants, callbacks, DQ6, suspend and resume.
        offsets = (0, 0x1218, 0xaac, 0x4028, 0x6ba1a, 0x6596c,
                   d - 4, d + 4, d + 8, d + 0x104, d + 0x128, d + 0x12c,
                   d + 0x130, d + 0x134, d + 0x13c, 0x6defc,
                   0x6df14, 0x6e2dc, 0x6e2de, 0x6e448, 0x6e44c,
                   0x6e30a, 0x6dd2e, 0x6dd60, 0x6dcf4, 0x6e476,
                   0x6e4be, 0x6de7a, 0x6ddea)
        for offset in offsets:
            with self.subTest(offset=hex(offset)):
                changed = bytearray(self.image)
                changed[offset] ^= 1
                rejected, reason = profile(changed)
                self.assertIsNone(rejected)
                self.assertIsNotNone(reason)
        # Redirect initializer arrays or poll scratch onto the selected object.
        for pool in (0x6ba68, 0x6ba6c, 0x6598c, 0x65990, 0x6dd04, 0x6ddb4, 0x6e440, 0x6e26c):
            with self.subTest(overlap_pool=hex(pool)):
                changed = bytearray(self.image)
                struct.pack_into('<I', changed, pool, found['selection_cell'])
                self.assertIsNone(profile(changed)[0])
        # A unique but unexecuted scatter tuple must not replace reset provenance.
        changed = bytearray(self.image)
        changed[0x18000:0x18014] = changed[0x4028:0x403c]
        struct.pack_into('<I', changed, 0x18000, 0x400000)
        self.assertIsNone(profile(changed)[0])
        duplicate = bytearray(self.image)
        init = found['initializer']
        duplicate[0x400000:0x400014] = self.image[init:init + 20]
        self.assertEqual(profile(duplicate)[1], 'inline-efs-initializers-ambiguous')
        for kwargs in ({'load': 4}, {'flash': 0x2000000}, {'ram_size': 0x1000}):
            self.assertIsNone(profile(self.image, **kwargs)[0])


if __name__ == '__main__':
    unittest.main()
