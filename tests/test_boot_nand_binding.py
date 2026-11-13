"""Synthetic checks for NAND plan projection and private media setup."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from msm5xxx_emulator.detection.devices.storage.boot_nand_projection import project, word_claims
from msm5xxx_emulator.devices.storage.boot_media import prepare_boot_media


def plan_for(*, main=0x4000, raw=None, high=0x2000, cpu='arm926,reset-hivecs=on',
             properties=None, count=1):
    if raw is None:
        raw = main + main // 32
    capability = SimpleNamespace(
        name='high-linked-nand-bootstrap',
        parameters=(('cpu', cpu), ('raw_size', raw), ('main_size', main),
                    ('high_code_size', high)),
        properties=(('bootstrap-nand-main-size', main),) if properties is None else properties,
    )
    return SimpleNamespace(capabilities=(capability,) * count)


class BootNandProjectionTests(unittest.TestCase):
    def test_word_interface_requires_matching_geometry_and_property(self):
        plan = plan_for(main=0x04000000,
            properties=(('bootstrap-nand-main-size', 0x04000000),
                        ('bootstrap-nand-word-interface', 1),
                        ('bootstrap-nand-id-status', 0x4c3b0000),
                        ('bootstrap-nand-word-peripherals', 7),
                        ('bootstrap-nand-lcd-id', 0x7068),
                        ('bootstrap-nand-lcd-data-port', 0x20080000)))
        capability = plan.capabilities[0]
        capability.parameters += (('word_interface', True),
                                  ('identity_status', 0x4c3b0000),
                                  ('peripherals', 7), ('control_windows', ()),
                                  ('lcd_data_port', 0x20080000),
                                  ('lcd_identity', 0x7068))
        capability.claims = word_claims((), 7, 0x20080000)
        self.assertIn('bootstrap-nand-word-interface=1', project(plan).machine)
        capability.parameters = tuple((key, 1 if key == 'word_interface' else value)
                                     for key, value in capability.parameters)
        with self.assertRaises(ValueError):
            project(plan)

    def test_large_word_controller_has_independent_identity_and_no_peripherals(self):
        properties = (('bootstrap-nand-main-size', 0x08000000),
                      ('bootstrap-nand-word-interface', 1),
                      ('bootstrap-nand-id-status', 0x76198000),
                      ('bootstrap-nand-word-peripherals', 0))
        plan = plan_for(main=0x08000000, properties=properties)
        plan.capabilities[0].parameters += (('word_interface', True),
            ('identity_status', 0x76198000), ('peripherals', 0), ('control_windows', ()),
            ('lcd_data_port', 0), ('lcd_identity', 0))
        plan.capabilities[0].claims = word_claims((), 0)
        binding = project(plan)
        self.assertEqual(binding.raw_size, 0x08400000)
        self.assertIn('bootstrap-nand-id-status=1981382656', binding.machine)
        self.assertIn('bootstrap-nand-word-peripherals=0', binding.machine)

    def test_lcd_identity_is_emitted_only_with_lcd_and_allowed_value(self):
        capability = plan_for(main=0x04000000).capabilities[0]
        capability.parameters += (('word_interface', True),
            ('identity_status', 0x4c3b0000), ('peripherals', 1),
            ('control_windows', ()), ('lcd_data_port', 0x20040000),
            ('lcd_identity', 0))
        capability.properties += (('bootstrap-nand-word-interface', 1),
            ('bootstrap-nand-id-status', 0x4c3b0000),
            ('bootstrap-nand-word-peripherals', 1),
            ('bootstrap-nand-lcd-data-port', 0x20040000))
        capability.claims = word_claims((), 1, 0x20040000)
        binding = project(SimpleNamespace(capabilities=(capability,)))
        self.assertNotIn('bootstrap-nand-lcd-id=', binding.machine)

        capability.parameters = tuple((key, 0x7068 if key == 'lcd_identity' else value)
                                      for key, value in capability.parameters)
        capability.properties += (('bootstrap-nand-lcd-id', 0x7068),)
        self.assertIn('bootstrap-nand-lcd-id=28776', project(
            SimpleNamespace(capabilities=(capability,))).machine)
        for invalid in (0x4b15, 0x7069, True):
            capability.parameters = tuple((key, invalid if key == 'lcd_identity' else value)
                                           for key, value in capability.parameters)
            with self.subTest(identity=invalid), self.assertRaises(ValueError):
                project(SimpleNamespace(capabilities=(capability,)))

    def test_lcd_identity_without_panel_is_rejected(self):
        capability = plan_for(main=0x04000000).capabilities[0]
        capability.parameters += (('word_interface', True),
            ('identity_status', 0x4c3b0000), ('peripherals', 0),
            ('control_windows', ()), ('lcd_data_port', 0),
            ('lcd_identity', 0x7068))
        capability.properties += (('bootstrap-nand-word-interface', 1),
            ('bootstrap-nand-id-status', 0x4c3b0000),
            ('bootstrap-nand-word-peripherals', 0))
        capability.claims = word_claims((), 0)
        with self.assertRaises(ValueError):
            project(SimpleNamespace(capabilities=(capability,)))

    def test_projection_preserves_supported_geometry(self):
        binding = project(plan_for(main=0x20000))
        self.assertEqual(binding.cpu, 'arm926,reset-hivecs=on')
        self.assertEqual(binding.raw_size, 0x21000)
        self.assertEqual(binding.main_size, 0x20000)
        self.assertEqual(binding.high_code_size, 0x2000)
        self.assertEqual(binding.machine, ',bootstrap-nand-main-size=131072')

    def test_projection_rejects_unsupported_parameters(self):
        invalid = (
            plan_for(main=0),
            plan_for(main=0x4001),
            plan_for(main=0x08000000 + 0x4000),
            plan_for(raw=0x4100),
            plan_for(high=0x4000),
            plan_for(cpu='arm926'),
            plan_for(properties=(('bootstrap-nand-main-size', 0x8000),)),
            plan_for(main=True),
            plan_for(count=2),
        )
        for plan in invalid:
            with self.subTest(parameters=plan.capabilities[0].parameters):
                with self.assertRaises(ValueError):
                    project(plan)

    def test_projection_without_profile_is_empty(self):
        self.assertIsNone(project(SimpleNamespace(capabilities=())))


class BootNandMediaTests(unittest.TestCase):
    def test_supplied_media_is_the_immutable_image_that_was_planned(self):
        binding = project(plan_for())
        planned = bytes([0x69]) * binding.raw_size
        later = bytes([0x96]) * binding.raw_size
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            source = directory / 'original.raw'
            source.write_bytes(later)
            with self.assertRaisesRegex(ValueError, 'supplied media'):
                prepare_boot_media(binding, source, directory, source_image=planned[:-1])
            self.assertFalse((directory / 'bootstrap-nand.raw').exists())
            prepare_boot_media(binding, source, directory, source_image=planned)
            self.assertEqual((directory / 'bootstrap-nand.raw').read_bytes(), planned)
            self.assertEqual((directory / 'bootstrap-high.raw').read_bytes(), planned[:0x2000])
            self.assertEqual(source.read_bytes(), later)

    def test_private_media_and_high_loader_keep_source_unchanged(self):
        source_bytes = bytes((index * 17) & 0xff for index in range(0x4200))
        with tempfile.TemporaryDirectory(prefix='nand,media,') as root:
            directory = Path(root)
            source = directory / 'original.raw'
            source.write_bytes(source_bytes)
            binding = project(plan_for(main=0x4000, raw=len(source_bytes)))

            arguments = prepare_boot_media(binding, source, directory)

            self.assertEqual(source.read_bytes(), source_bytes)
            working = directory / 'bootstrap-nand.raw'
            high = directory / 'bootstrap-high.raw'
            self.assertEqual(working.read_bytes(), source_bytes)
            self.assertEqual(high.read_bytes(), source_bytes[:0x2000])
            self.assertEqual(len(arguments), 2)
            self.assertEqual(arguments[0][0], '-device')
            self.assertEqual(arguments[1][0], '-drive')
            loader = arguments[0][1]
            drive = arguments[1][1]
            self.assertIn(str(high).replace(',', ',,'), loader)
            self.assertIn('addr=0xffff0000,force-raw=on', loader)
            self.assertIn(str(working).replace(',', ',,'), drive)
            self.assertIn('if=none,format=raw,id=msm5xxx-bootstrap-nand', drive)

    def test_media_size_mismatch_fails_before_copy(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            source = directory / 'original.raw'
            source.write_bytes(bytes(0x4000))
            binding = project(plan_for(main=0x4000))
            with self.assertRaisesRegex(ValueError, 'source size changed'):
                prepare_boot_media(binding, source, directory)
            self.assertFalse((directory / 'bootstrap-nand.raw').exists())


if __name__ == '__main__':
    unittest.main()
