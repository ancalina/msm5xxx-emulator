"""Timed NAND image binding and qualified host-state shutdown without QEMU."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
from msm5xxx_emulator.qemu import transport
from msm5xxx_emulator import GenericMSMEmulator, native_nand_state
from msm5xxx_emulator.detection.bootstrap_sdram import reset_copy_ram_profile
from msm5xxx_emulator.detection.firmware import detect
from msm5xxx_emulator.detection.small_page_nand import small_page_nand_profile
from msm5xxx_emulator.state_io import exclusive_path_lock
from test_small_page_nand_detection import _nand_fixture


def _config(image):
    ram = reset_copy_ram_profile(image)
    return SimpleNamespace(
        native_nand_profile=small_page_nand_profile(image), nand_enabled=True,
        flash_size=len(image), load_address=0, ram_base=ram['ram_base'],
        ram_size=ram['ram_size'], ram_bootstrap_profile=ram,
        nand_data_size=0x2000000, nand_page_size=512, nand_spare_size=16,
        nand_pages_per_block=32, nand_bus_width=2,
        firmware_sha256=hashlib.sha256(image).hexdigest(),
        detection_notes=[], nand_image=None,
    )


class NativeNandProfileBindingTests(unittest.TestCase):
    def setUp(self):
        image, self.layout = _nand_fixture()
        self.image = bytes(image)
        self.config = _config(self.image)

    def test_same_loaded_bytes_and_explicit_disabled(self):
        expected = self.config.native_nand_profile
        self.assertEqual(transport.qemu_native_nand_profile(self.image, self.config), (expected, None))
        self.assertEqual(transport.qemu_native_nand_profile(self.image + b'\xff' * 128, self.config), (expected, None))
        self.config.nand_enabled = False
        self.assertEqual(transport.qemu_native_nand_profile(b'changed', self.config), (None, None))

    def test_geometry_ram_profile_and_program_changes_reject(self):
        cases = [('nand_data_size', 0x1000000), ('nand_page_size', 2048),
                 ('nand_spare_size', 64), ('nand_pages_per_block', 64),
                 ('nand_bus_width', 1), ('nand_bus_width', 2.0),
                 ('ram_size', self.config.ram_size + 0x1000),
                 ('ram_base', self.config.ram_base + 0x1000), ('load_address', 0x1000)]
        for field, value in cases:
            config = deepcopy(self.config)
            setattr(config, field, value)
            with self.subTest(field=field, value=value):
                profile, reason = transport.qemu_native_nand_profile(self.image, config)
                self.assertIsNone(profile)
                self.assertIsNotNone(reason)
        for field in ('native_nand_profile', 'ram_bootstrap_profile'):
            config = deepcopy(self.config)
            config.__dict__[field]['experimental'] = False
            with self.subTest(field=field):
                self.assertIsNone(transport.qemu_native_nand_profile(self.image, config)[0])
        image = bytearray(self.image)
        image[self.layout['program'] + 0x68] ^= 1
        self.assertEqual(transport.qemu_native_nand_profile(bytes(image), self.config),
                         (None, 'producer-shape-mismatch'))


class NativeNandTransportStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = bytes(_nand_fixture()[0])
        cls.blank = b'\xff' * native_nand_state.RAW_BYTES
        raw = bytearray(cls.blank)
        raw[:2] = b'\x34\x12'
        raw[512:514] = b'\x00\xff'
        cls.qualified = bytes(raw)
        cls.seed_hash = hashlib.sha256(cls.blank).hexdigest()
        cls.firmware_hash = hashlib.sha256(cls.image).hexdigest()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.seed = self.root / 'seed.raw'
        self.seed.write_bytes(self.blank)
        self.firmware = self.root / 'firmware.bin'
        self.firmware.write_bytes(self.image)
        self.state_dir = self.root / 'state'
        self.state_path = self.state_dir / 'native-nand.json'
        native_nand_state.save_state(self.state_path, self.qualified, self.firmware_hash, self.seed_hash)
        self.previous = self.state_path.read_bytes()
        self.run_number = 0

    def prepare(self):
        value = transport.Transport.__new__(transport.Transport)
        value.config = _config(self.image)
        value.config.nand_image = str(self.seed)
        for name in ('_native_nand_lock', '_native_nand_listener',
                     '_native_nand_socket', '_native_nand_reader'):
            setattr(value, name, None)
        value._native_nand_id = 0
        value.native_nand_status = 'disabled'
        self.latest_transport = value
        self.addCleanup(value._discard_native_nand)
        temporary = self.root / f'run-{self.run_number}'
        self.run_number += 1
        temporary.mkdir()
        listener = Mock()
        listener.getsockname.return_value = ('127.0.0.1', 12345)
        with patch.object(transport, 'loopback_listener', return_value=listener):
            args = value._prepare_native_nand(
                value.config.native_nand_profile, temporary, self.state_dir,
                self.root / 'legacy', self.firmware, self.root / 'secondary', None)
        self.assertIn('chardev=nandqmp,mode=control', args)
        value.process = Mock()
        value.process.poll.return_value = None
        value.process.wait.return_value = 0
        return value

    def monitor(self, value, snapshot=None, running=False):
        snapshot = snapshot if snapshot is not None else {
            'enabled': 1, 'initialized': 1, 'trusted': 1, 'safe_to_save': 1,
            'pending': 0, 'generation': 2, 'persisted': 2,
        }
        value._native_nand_events = []

        def connect():
            value._native_nand_events.append('connect')
            value._native_nand_reader = io.BytesIO()

        def command(name, arguments=None):
            value._native_nand_events.append(name)
            if name == 'query-status':
                return {'running': running}
            if name == 'qom-get':
                self.assertEqual(arguments['property'], 'experimental-small-page-nand-state')
                return snapshot if isinstance(snapshot, str) else json.dumps(snapshot)
            if name in ('stop', 'quit'):
                return {}
            raise AssertionError(name)

        value._connect_native_nand_monitor = Mock(side_effect=connect)
        value._native_nand_command = Mock(side_effect=command)

    def assert_released_and_previous_preserved(self, value):
        self.assertIsNone(value._native_nand_lock)
        self.assertEqual(self.state_path.read_bytes(), self.previous)
        self.assertEqual(hashlib.sha256(self.seed.read_bytes()).hexdigest(), self.seed_hash)
        with exclusive_path_lock(self.state_path, timeout=0.1):
            pass

    def test_clone_isolation_qualified_close_and_fresh_restore(self):
        value = self.prepare()
        self.assertEqual(value._native_nand_working.read_bytes(), self.qualified)
        self.assertEqual(value.native_nand_status, 'qualified-state-restored')
        with value._native_nand_working.open('r+b') as raw:
            raw.write(b'\x78\x56')
            raw.seek(528 + 512)
            raw.write(b'\x00\xa5')
        expected = value._native_nand_working.read_bytes()
        self.assertEqual(self.state_path.read_bytes(), self.previous)
        self.monitor(value)
        value._finish_native_nand()
        self.assertEqual(value._native_nand_events,
                         ['connect', 'stop', 'query-status', 'qom-get', 'quit'])
        value.process.wait.assert_called_once_with(2)
        self.assertEqual(value.native_nand_status, 'qualified-state-saved')
        self.assertIsNone(value._native_nand_lock)
        self.assertEqual(native_nand_state.load_state(self.state_path, self.firmware_hash, self.seed_hash), expected)
        self.assertEqual(hashlib.sha256(self.seed.read_bytes()).hexdigest(), self.seed_hash)
        restored = self.prepare()
        self.assertEqual(restored._native_nand_working.read_bytes(), expected)
        restored._discard_native_nand()

    def test_unqualified_snapshots_preserve_previous_and_release_lock(self):
        for changes in ({'trusted': 0}, {'safe_to_save': 0}, {'enabled': 0},
                        {'initialized': 0}, {'pending': 2}, {'pending': 3},
                        {'generation': 3}, {'generation': True, 'persisted': True}):
            with self.subTest(changes=changes):
                value = self.prepare()
                snapshot = dict(enabled=1, initialized=1, trusted=1, safe_to_save=1,
                                pending=0, generation=2, persisted=2)
                snapshot.update(changes)
                self.monitor(value, snapshot)
                value._finish_native_nand()
                self.assertTrue(value.native_nand_status.startswith('discarded:'))
                self.assertNotIn('quit', [call.args[0] for call in value._native_nand_command.call_args_list])
                self.assert_released_and_previous_preserved(value)

    def test_state_symlink_keeps_target_and_lock_namespace_after_save(self):
        target = self.state_dir / 'qualified-target.json'
        self.state_path.rename(target)
        try:
            self.state_path.symlink_to(target.name)
        except (OSError, NotImplementedError):
            self.skipTest('file symlinks unavailable')
        value = self.prepare()
        self.assertEqual(value._native_nand_state_path, target.resolve())
        with self.assertRaises(TimeoutError):
            with exclusive_path_lock(target, timeout=0.01):
                pass
        with value._native_nand_working.open('r+b') as raw:
            raw.seek(512)
            raw.write(b'\x00\x00')
        expected = value._native_nand_working.read_bytes()
        self.monitor(value)
        value._finish_native_nand()
        self.assertEqual(value.native_nand_status, 'qualified-state-saved')
        self.assertTrue(self.state_path.is_symlink())
        self.assertEqual(self.state_path.resolve(), target.resolve())
        self.assertEqual(native_nand_state.load_state(target, self.firmware_hash, self.seed_hash), expected)
        with exclusive_path_lock(self.state_path, timeout=0.1):
            pass

    def test_monitor_errors_running_process_and_crash_do_not_save(self):
        for failure in ('json', 'timeout', 'running', 'crash', 'exit', 'wait-timeout'):
            with self.subTest(failure=failure):
                value = self.prepare()
                self.monitor(value, '{' if failure == 'json' else None, running=failure == 'running')
                if failure == 'timeout':
                    value._native_nand_command.side_effect = TimeoutError('own monitor timeout')
                if failure == 'crash':
                    value.process.poll.return_value = 7
                if failure == 'exit':
                    value.process.wait.return_value = 1
                if failure == 'wait-timeout':
                    value.process.wait.side_effect = subprocess.TimeoutExpired('own native mock', 2)
                value._finish_native_nand()
                self.assertTrue(value.native_nand_status.startswith('discarded:'))
                self.assert_released_and_previous_preserved(value)
                if failure == 'crash':
                    value._native_nand_command.assert_not_called()

    def test_wrong_working_size_and_atomic_error_keep_last_good(self):
        for failure in ('size', 'replace'):
            with self.subTest(failure=failure):
                value = self.prepare()
                self.monitor(value)
                if failure == 'size':
                    value._native_nand_working.write_bytes(b'short')
                    value._finish_native_nand()
                else:
                    with patch('msm5xxx_emulator.state_io.os.replace', side_effect=OSError('own pre-replace failure')):
                        value._finish_native_nand()
                self.assertTrue(value.native_nand_status.startswith('discarded:'))
                self.assert_released_and_previous_preserved(value)

    def test_discard_and_concurrent_finish_are_idempotent(self):
        value = self.prepare()
        self.monitor(value)
        with patch.object(native_nand_state, 'save_state', wraps=native_nand_state.save_state) as save:
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(value._finish_native_nand) for _ in range(2)]
                for future in futures:
                    future.result(timeout=10)
            value._finish_native_nand()
            value._discard_native_nand()
            save.assert_called_once()
        self.assertEqual(value._native_nand_events,
                         ['connect', 'stop', 'query-status', 'qom-get', 'quit'])
        self.assertIsNone(value._native_nand_lock)
        with exclusive_path_lock(self.state_path, timeout=0.1):
            pass

    def test_prepare_corrupt_state_then_caller_discard_releases_lock(self):
        self.state_path.write_bytes(b'{')
        corrupt = self.state_path.read_bytes()
        with self.assertRaises(ValueError):
            self.prepare()
        # The constructor's existing exception path calls discard; emulate that owner.
        self.latest_transport._discard_native_nand()
        self.assertEqual(self.state_path.read_bytes(), corrupt)
        with exclusive_path_lock(self.state_path, timeout=0.1):
            pass

    def test_real_handshake_and_failed_startup_discard_boundary(self):
        for frames, failure in (
                (b'{"QMP":{}}\n{"return":{},"id":1}\n', None),
                (b'{}\n', ValueError),
                (b'{"QMP":{}}\n{"error":{"class":"OwnFixture"},"id":1}\n', RuntimeError)):
            with self.subTest(failure=failure):
                value = self.prepare()
                listener = value._native_nand_listener
                connection = Mock()
                connection.makefile.return_value = io.BytesIO(frames)
                value._accept_qemu = Mock(return_value=connection)
                if failure is None:
                    value._connect_native_nand_monitor()
                    self.assertEqual(json.loads(connection.sendall.call_args.args[0]),
                                     {'execute': 'qmp_capabilities', 'id': 1})
                else:
                    with self.assertRaises(failure):
                        value._connect_native_nand_monitor()
                value._accept_qemu.assert_called_once_with(listener, 'timed NAND monitor')
                listener.close.assert_called_once()
                connection.settimeout.assert_called_once_with(2)
                self.assertIsNone(value._native_nand_listener)
                # The constructor owns this ordering; exercise the failure-helper boundary.
                value._discard_native_nand()
                if failure is not None:
                    value._native_nand_command = Mock(side_effect=AssertionError('no startup publication'))
                    with io.StringIO('own startup monitor failure') as stderr:
                        value.stderr = stderr
                        error = value._startup_error(RuntimeError('own handshake failure'))
                    self.assertIn('QEMU startup failed', str(error))
                    value._native_nand_command.assert_not_called()
                    value.process.terminate.assert_called_once()
                    value.process.wait.assert_called_once_with(2)
                self.assert_released_and_previous_preserved(value)


class NativeNandMonitorFramingTests(unittest.TestCase):
    def monitor(self, data):
        value = transport.Transport.__new__(transport.Transport)
        value._native_nand_id = 0
        value._native_nand_socket = Mock()
        value._native_nand_reader = io.BytesIO(data)
        return value

    def test_events_then_matching_reply_and_bounded_frames(self):
        value = self.monitor(b'{"event":"STOP"}\n{"return":{"running":false},"id":1}\n')
        self.assertEqual(value._native_nand_command('query-status'), {'running': False})
        self.assertEqual(json.loads(value._native_nand_socket.sendall.call_args.args[0]),
                         {'execute': 'query-status', 'id': 1})
        for invalid in (b'', b'{}', b'[]\n', b'{\n', b' ' * 65536 + b'\n'):
            with self.subTest(length=len(invalid)), self.assertRaises(ValueError):
                self.monitor(invalid)._native_nand_receive()
        events = b'{"return":null,"id":true}\n' * 32
        with self.assertRaisesRegex(RuntimeError, 'response limit'):
            self.monitor(events)._native_nand_command('stop')


class NativeNandDecoderOwnershipTests(unittest.TestCase):
    def test_actual_nor_decoder_keeps_config_without_legacy_nand(self):
        corpus = Path(os.environ.get('MSM5XXX_TEST_FIRMWARE_ROOT', ROOT / 'firmwares'))
        path = corpus / 'incoming-20261020-audio-agent/SCH-X850_NOR_00000000_len_01000000(1).bin'
        if not path.is_file():
            self.skipTest('optional original NOR ownership witness unavailable')
        before = hashlib.sha256(path.read_bytes()).digest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = detect(path)
            self.assertTrue(config.nand_enabled)
            config.flash_state = str(root / 'legacy')
            config.secondary_flash_state = str(root / 'secondary')
            config.upper_flash_state = str(root / 'upper')
            with patch('unicorn.Uc.emu_start', side_effect=AssertionError('no CPU execution')) as execute:
                decoder = GenericMSMEmulator(config, native_nand=True, approximate_audio=False)
                try:
                    self.assertTrue(config.nand_enabled)
                    self.assertFalse(decoder._legacy_nand_enabled)
                    self.assertEqual(decoder.nand_image, bytearray())
                    self.assertEqual(decoder.instructions, 0)
                finally:
                    decoder.close()
                execute.assert_not_called()
            self.assertFalse((root / 'legacy.nand.bin').exists())
            self.assertFalse((root / 'legacy.nand.json').exists())
        self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)


if __name__ == '__main__':
    unittest.main()
