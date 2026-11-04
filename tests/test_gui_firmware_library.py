from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from msm5xxx_emulator.gui.firmware_library import FirmwareLibrary, display_name, source_size_limit


class FirmwareLibraryTest(unittest.TestCase):
    def test_scan_deduplicates_and_reuses_sha_cache(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / 'files'
            folder.mkdir()
            (folder / 'a.bin').write_bytes(b'a')
            (folder / 'b.bin').write_bytes(b'a')
            (folder / 'c.bin').write_bytes(b'c')
            (folder / 'nested').mkdir()
            (folder / 'nested' / 'nested.bin').write_bytes(b'n')
            detector = Mock(return_value=SimpleNamespace(model='Model', chipset='MSM5xxx'))
            lib = FirmwareLibrary(root / 'library.json', detector=detector)
            lib.add_folder(folder)
            self.assertEqual(len(lib.scan()), 2)
            self.assertEqual(detector.call_count, 2)
            self.assertEqual(len(lib.scan()), 2)
            self.assertEqual(detector.call_count, 2)
            (folder / 'c.bin').write_bytes(b'changed')
            lib.scan()
            self.assertEqual(detector.call_count, 3)

    def test_scan_ignores_oversize_and_unreadable(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / 'files'
            folder.mkdir()
            huge = folder / 'large.bin'
            with huge.open('wb') as f:
                f.truncate(source_size_limit(huge) + 1)
            bad = folder / 'unreadable.bin'
            bad.write_bytes(b'x')
            lib = FirmwareLibrary(root / 'library.json', detector=Mock())
            lib.add_folder(folder)
            with patch('msm5xxx_emulator.gui.firmware_library.source_hash', side_effect=PermissionError()):
                rows = lib.scan()
            self.assertEqual(rows, [])

    def test_missing_entry_remains_available_for_removal(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'missing.bin'
            lib = FirmwareLibrary(root / 'library.json')
            lib.add_file(path)
            rows = lib.scan()
            self.assertEqual(len(rows), 1)
            self.assertFalse(rows[0]['available'])
            lib.remove(path)
            self.assertEqual(lib.scan(), [])

    def test_remove_preserves_external_and_deletes_private_import(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            private = root / 'private'
            private.mkdir()
            owned = private / 'copy.bin'
            external = root / 'source.bin'
            owned.write_bytes(b'copy')
            external.write_bytes(b'source')
            lib = FirmwareLibrary(root / 'library.json', private_root=private)
            lib.add_file(owned, imported=True)
            lib.add_file(external)
            lib.remove(external)
            self.assertTrue(external.exists())
            lib.remove(owned)
            self.assertFalse(owned.exists())
            lib.add_file(external, imported=True)
            with self.assertRaises(ValueError):
                lib.remove(external)
            self.assertTrue(external.exists())

    def test_fallback_name(self):
        self.assertEqual(display_name(None, 'filename.bin'), 'filename.bin')
        self.assertEqual(display_name('  detected  ', 'filename.bin'), 'detected')


@unittest.skipUnless(__import__('os').environ.get('DISPLAY'), 'Tk display unavailable')
class LibraryViewTest(unittest.TestCase):
    def test_select_boot_and_remove_without_starting_emulator(self):
        import tkinter as tk
        from msm5xxx_emulator.gui.library_view import LibraryDialog
        root = tk.Tk()
        self.addCleanup(root.destroy)
        library = Mock()
        library.scan.return_value = [{'path': '/tmp/demo', 'name': 'Example',
                                      'chipset': 'MSM5xxx', 'size': 10, 'available': True}]
        dialog = LibraryDialog(root, library, 'en')
        dialog.window.update()
        dialog.poll()
        self.assertEqual(len(dialog.list.get_children()), 1)
        dialog.list.selection_set('0')
        dialog.boot()
        self.assertEqual(dialog.selected, Path('/tmp/demo'))
