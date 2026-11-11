import msm5xxx_emulator.detection.plan as boot_plan
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from msm5xxx_emulator.gui.firmware_library import FirmwareLibrary, display_name, source_size_limit, source_hash


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

    def test_remove_folder_preserves_files_and_explicit_entries(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / 'sources'
            folder.mkdir()
            scanned = folder / 'scanned.bin'
            explicit = folder / 'explicit.bin'
            scanned.write_bytes(b'scanned')
            explicit.write_bytes(b'explicit')
            lib = FirmwareLibrary(root / 'library.json', detector=Mock(return_value=SimpleNamespace(model=None, chipset=None)))
            lib.add_folder(folder)
            lib.scan()
            lib.add_file(explicit)
            lib.remove_folder(folder)
            reloaded = FirmwareLibrary(root / 'library.json', detector=lib.detector)
            self.assertEqual(reloaded.folders, [])
            self.assertEqual([row['path'] for row in reloaded.scan()], [str(explicit)])
            self.assertTrue(scanned.exists())
            self.assertTrue(explicit.exists())
            reloaded.add_folder(folder)
            self.assertEqual({row['path'] for row in reloaded.scan()}, {str(scanned), str(explicit)})

    def test_remove_folder_for_symlinked_child(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            folder = root / 'sources'
            folder.mkdir()
            source = root / 'image.bin'
            source.write_bytes(b'synthetic')
            (folder / 'link.bin').symlink_to(source)
            lib = FirmwareLibrary(root / 'library.json', detector=Mock(return_value=SimpleNamespace(model=None, chipset=None)))
            lib.add_folder(folder)
            self.assertEqual(len(lib.scan()), 1)
            lib.remove_folder(folder)
            self.assertEqual(lib.scan(), [])
            self.assertTrue(source.exists())

    def test_groups_only_detected_models(self):
        from msm5xxx_emulator.gui.library_view import group_rows
        rows = [{'model': ' Example ', 'name': 'one'}, {'model': 'example', 'name': 'two'},
                {'model': None, 'name': 'example'}, {'model': None, 'name': 'example'}]
        self.assertEqual(group_rows(rows), [[0, 1], [2], [3]])

    def test_library_session_settings_preserve_other_preferences(self):
        import json
        from msm5xxx_emulator.gui.library_view import save_session_settings
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / 'settings.json'
            path.write_text('{"profiles": {"test": {}}}', encoding='utf-8')
            save_session_settings(path, True, False, '2024-01-02 03:04', False)
            values = json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(values['profiles'], {'test': {}})
            self.assertEqual(values['network_start_time'], '2024-01-02 03:04')
            self.assertTrue(values['virtual_network'])
            self.assertFalse(values['persistent_state'])
            with self.assertRaises(ValueError):
                save_session_settings(path, True, False, 'bad', True)
            self.assertEqual(json.loads(path.read_text(encoding='utf-8')), values)

    def test_hash_read_is_bounded(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / 'sample.bin'
            path.write_bytes(b'1234')
            with self.assertRaises(ValueError):
                source_hash(path, 3)

    def test_size_formatting(self):
        from msm5xxx_emulator.gui.library_view import format_size
        self.assertEqual(format_size(4259824), "4.1 MiB")
        self.assertEqual(format_size(42), "42 B")

    def test_fallback_name(self):
        self.assertEqual(display_name(None, 'filename.bin'), 'filename.bin')
        self.assertEqual(display_name('  detected  ', 'filename.bin'), 'detected')


@unittest.skipUnless(__import__('os').environ.get('DISPLAY'), 'Tk display unavailable')
class LibraryViewTest(unittest.TestCase):
    def test_group_expands_and_selects_a_file(self):
        import tkinter as tk
        from msm5xxx_emulator.gui.library_view import LibraryDialog
        root = tk.Tk()
        self.addCleanup(root.destroy)
        library = Mock()
        library.scan.return_value = [
            {'path': '/tmp/first.bin', 'model': 'Example', 'name': 'Example', 'available': True},
            {'path': '/tmp/second.bin', 'model': 'example', 'name': 'example', 'available': True},
            {'path': '/tmp/third.bin', 'model': None, 'name': 'third.bin', 'available': True},
        ]
        dialog = LibraryDialog(root, library, 'en')
        dialog.window.update()
        dialog.poll()
        self.assertEqual(len(dialog.list.get_children()), 2)
        group = dialog.list.get_children()[0]
        self.assertEqual(len(dialog.list.get_children(group)), 2)
        dialog.list.selection_set(group)
        dialog.boot()
        self.assertTrue(dialog.list.item(group, 'open'))
        dialog.list.selection_set(dialog.list.get_children(group)[1])
        dialog.boot()
        self.assertEqual(dialog.selected, Path('/tmp/second.bin'))

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
        self.assertEqual(dialog.window.title(), 'Firmware library — MSM5XXX Emulator')
        self.assertEqual(dialog.list['columns'], ('chipset', 'size', 'last'))
        self.assertEqual(len(dialog.buttons), 5)
        self.assertEqual(len(dialog.list.get_children()), 1)
        dialog.list.selection_set('0')
        dialog.boot()
        self.assertEqual(dialog.selected, Path('/tmp/demo'))

class MobileLibraryBridgeTest(unittest.TestCase):
    def test_descriptor_path_uses_shared_metadata_rules(self):
        import importlib.util
        import json
        import os
        from msm5xxx_emulator.detection.registry import device_domain
        firmware = boot_plan
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location('fd_android_runtime', root / 'android/app/src/main/python/msm5xxx_android_runtime.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / 'synthetic.bin'
            source.write_bytes(b'synthetic descriptor')
            with source.open('rb') as handle, patch.object(firmware, 'detect', return_value=SimpleNamespace(model='Detected', chipset='MSM5xxx')):
                descriptor = Path('/proc/self/fd') / str(handle.fileno())
                if not descriptor.exists():
                    self.skipTest('descriptor filesystem unavailable')
                result = json.loads(runtime.library_describe(json.dumps({'path': str(descriptor),
                    'cache': str(Path(tmp) / 'cache.json'), 'name': 'original.bin'})))
            self.assertEqual(result['name'], 'Detected')
            self.assertEqual(result['size'], len(b'synthetic descriptor'))

    def test_bridge_rejects_oversize_and_invalid_requests(self):
        import importlib.util
        import json
        from msm5xxx_emulator.detection.registry import device_domain
        firmware = boot_plan
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location('limit_android_runtime', root / 'android/app/src/main/python/msm5xxx_android_runtime.py')
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / 'large.bin'
            with source.open('wb') as output:
                output.truncate(source_size_limit(source) + 1)
            request = json.dumps({'path': str(source), 'cache': str(Path(tmp) / 'cache.json'), 'name': 'large.bin'})
            with patch.object(firmware, 'detect') as detect, self.assertRaises(ValueError):
                runtime.library_describe(request)
            detect.assert_not_called()
            with self.assertRaises(ValueError):
                runtime.library_describe('{}')

    def test_shared_bridge_uses_cache_and_preserves_filename_fallback(self):
        import importlib.util
        import json
        import sys
        from msm5xxx_emulator.detection.registry import device_domain
        firmware = boot_plan
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location('library_android_runtime', root / 'android/app/src/main/python/msm5xxx_android_runtime.py')
        android = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(android)
        with TemporaryDirectory() as tmp:
            source = Path(tmp) / 'sample.bin'
            source.write_bytes(b'synthetic data')
            request = json.dumps({'path': str(source), 'cache': str(Path(tmp) / 'cache.json'), 'name': 'Original'})
            with patch.object(firmware, 'detect', return_value=SimpleNamespace(model=None, chipset='MSM5xxx')) as detect:
                first = json.loads(android.library_describe(request))
                second = json.loads(android.detect_profile('library-v1:' + request))
            self.assertEqual(first, second)
            self.assertEqual(first['name'], 'Original')
            self.assertEqual(first['chipset'], 'MSM5xxx')
            self.assertEqual(detect.call_count, 1)
            limit = json.loads(android.detect_profile('library-v1:' + json.dumps({'limit_name': 'capture.hex'})))
            self.assertEqual(limit['limit'], source_size_limit(Path('capture.hex')))
            with patch.dict(sys.modules, {'msm5xxx_android_runtime': android}):
                ios_spec = importlib.util.spec_from_file_location('library_ios_runtime', root / 'ios/python/msm5xxx_ios_runtime.py')
                ios = importlib.util.module_from_spec(ios_spec)
                ios_spec.loader.exec_module(ios)
                self.assertEqual(json.loads(ios.library_describe(request)), first)

@unittest.skipUnless(__import__('os').environ.get('DISPLAY'), 'Tk display unavailable')
class LibraryControlsTest(unittest.TestCase):
    def test_key_geometry_and_tool_labels(self):
        import tkinter as tk
        from msm5xxx_emulator.qemu.live_display import LiveWindow
        root = tk.Tk()
        self.addCleanup(root.destroy)
        with patch.object(LiveWindow, '_restart'), \
             patch.object(LiveWindow, '_load_persistent_state', return_value=True), \
             patch.object(LiveWindow, '_load_virtual_network', return_value=False), \
             patch.object(LiveWindow, '_load_network_start_time', return_value=''), \
             patch.object(LiveWindow, '_load_config', return_value={}), \
             patch.object(LiveWindow, '_load_ui_language', return_value='en'):
            view = LiveWindow(root, Path('/tmp/unused'), Path('/tmp/unused'))
        root.update_idletasks()
        volume = view.key_buttons['볼륨-']
        self.assertEqual(view.fold_button.cget('style'), volume.cget('style'))
        self.assertEqual(view.fold_button.winfo_width(), volume.winfo_width())
        self.assertEqual(view.fold_button.winfo_height(), volume.winfo_height())
        self.assertEqual(view.fold_button.grid_info()['row'], volume.grid_info()['row'] + 1)
        self.assertEqual(view.fold_button.cget('text'), 'Open')
        self.assertEqual(view.settings_button.cget('text'), '•••')
        self.assertEqual(view.capture_button.cget('text'), 'Capture')
        for timer in root.tk.splitlist(root.tk.call('after', 'info')):
            root.after_cancel(timer)
