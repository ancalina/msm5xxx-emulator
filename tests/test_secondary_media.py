"""Private erased media is bounded and never replaces an existing file."""
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from msm5xxx_emulator.devices.storage.secondary_media import prepare_secondary_media


class SecondaryMediaTests(unittest.TestCase):
    def test_erased_private_backend_and_option_parser_escaping(self):
        with TemporaryDirectory(prefix='array,') as directory:
            temporary = Path(directory)
            binding = SimpleNamespace(raw_size=0x20000)
            arguments = prepare_secondary_media(binding, temporary)
            self.assertEqual((temporary / 'secondary-array.raw').read_bytes(),
                             b'\xff' * binding.raw_size)
            self.assertEqual(arguments[0], '-drive')
            self.assertIn(str(temporary).replace(',', ',,'), arguments[1])
            self.assertIn('id=msm5xxx-protected-nor-state,cache=unsafe', arguments[1])
            with self.assertRaises(FileExistsError):
                prepare_secondary_media(binding, temporary)

    def test_eight_megabyte_source_aperture_is_fully_erased(self):
        with TemporaryDirectory() as directory:
            temporary = Path(directory)
            prepare_secondary_media(SimpleNamespace(raw_size=0x800000), temporary)
            working = temporary / 'secondary-array.raw'
            self.assertEqual(working.stat().st_size, 0x800000)
            with working.open('rb') as source:
                source.seek(0x7F0000)
                self.assertEqual(source.read(), b'\xff' * 0x10000)

    def test_invalid_extents_create_no_files(self):
        with TemporaryDirectory() as directory:
            temporary = Path(directory)
            for length in (True, 0, -1, 0x10001, 0x810000):
                with self.assertRaises(ValueError):
                    prepare_secondary_media(SimpleNamespace(raw_size=length), temporary)
                self.assertEqual(list(temporary.iterdir()), [])

    def test_source_bank_is_copied_without_sharing_mutations(self):
        source = b'\x33' * 0x10000 + bytes(range(256)) * 256
        binding = SimpleNamespace(raw_size=0x10000, source_offset=0x10000,
                                  firmware_size=len(source))
        with TemporaryDirectory() as directory:
            temporary = Path(directory)
            prepare_secondary_media(binding, temporary, source_image=source)
            working = temporary / 'secondary-array.raw'
            self.assertEqual(working.read_bytes(), source[0x10000:])
            with working.open('r+b') as target:
                target.write(b'\x00\x00')
            self.assertEqual(source[0x10000:0x10002], b'\x00\x01')

    def test_invalid_source_binding_creates_no_file(self):
        for changes in ({'source_offset': True}, {'source_offset': -1},
                        {'source_offset': 0x10001}, {'firmware_size': 0x10001}):
            binding = SimpleNamespace(raw_size=0x10000, source_offset=0,
                                      firmware_size=0x10000)
            binding.__dict__.update(changes)
            with TemporaryDirectory() as directory:
                temporary = Path(directory)
                with self.assertRaises(ValueError):
                    prepare_secondary_media(binding, temporary,
                                            source_image=bytes(0x10000))
                self.assertEqual(list(temporary.iterdir()), [])
