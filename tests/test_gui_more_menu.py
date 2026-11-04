import os
from pathlib import Path
from types import SimpleNamespace
import tkinter as tk
import unittest
from unittest.mock import Mock, patch

from msm5xxx_emulator.qemu.live_display import LiveWindow


@unittest.skipUnless(os.environ.get('DISPLAY'), 'Tk display unavailable')
class MoreMenuTest(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.addCleanup(self.root.destroy)
        self.view = LiveWindow.__new__(LiveWindow)
        v = self.view
        v.root = self.root
        v.library = Mock()
        v.ui_language = 'en'
        v.settings_button = tk.Button(self.root)
        v.settings_button.pack()
        v.editing_input_mapping = False
        v.virtual_network_var = tk.BooleanVar(value=False)
        v.network_host_time_enabled = True
        v.network_host_time_var = tk.BooleanVar(value=True)
        v.network_start_time = ''
        v.network_start_time_var = tk.StringVar(value='')
        v.virtual_network_enabled = False
        v._active_virtual_network = False
        v.transport = None
        v.held = {}
        v.pending_key_releases = {}
        v.keyboard_sources = set()
        v.keyboard_bits = {}
        v._restart = Mock()
        v._stop_transport = Mock()
        v._settings = Mock()
        v._save_config = Mock()

    def test_entries_and_session_states(self):
        for running in (False, True):
            self.view.transport = object() if running else None
            with patch.object(tk.Menu, 'tk_popup'):
                self.view._show_more()
            menu = self.view._more_menu
            self.assertEqual([menu.entrycget(i, 'label') for i in range(8)],
                ['Virtual network', 'Boot', 'Power off', 'Reboot',
                 'Open firmware…', 'Edit key layout', 'Network time', 'Settings…'])
            self.assertEqual(menu.entrycget(1, 'state'), 'disabled' if running else 'normal')
            self.assertEqual(menu.entrycget(2, 'state'), 'normal' if running else 'disabled')
            self.assertEqual(menu.entrycget(3, 'state'), 'normal' if running else 'disabled')
            sub = self.root.nametowidget(menu.entrycget(6, 'menu'))
            self.assertEqual([sub.entrycget(i, 'label') for i in range(2)], ['Use device clock', 'Set manually…'])

    def test_edit_mode_and_prompt(self):
        self.view._set_editing_input(True)
        self.assertEqual(self.view.settings_button.cget('text'), 'Done')
        with patch.object(tk.Menu, 'tk_popup') as popup:
            self.view._show_more()
        popup.assert_not_called()
        self.assertEqual(self.view.settings_button.cget('text'), '•••')
        self.assertEqual(self.view._text('key_prompt'), 'Enter a key value (leave blank for the default).')

    def test_edit_mode_opens_short_popup_without_guest_press(self):
        v = self.view
        v.emulator = SimpleNamespace(config=SimpleNamespace(firmware_sha256='test'))
        v._manual_key_event = Mock(return_value=None)
        v._key = Mock()
        v._set_editing_input(True)
        with patch('msm5xxx_emulator.gui.controls.simpledialog.askstring', return_value=None) as prompt:
            v._mouse_key_press('1')
            v._mouse_key_release('1')
        self.assertEqual(prompt.call_args.args[1], 'Enter a key value (leave blank for the default).')
        v._key.assert_not_called()

    def test_time_validation_and_restart(self):
        v = self.view
        v.transport = object()
        v.virtual_network_enabled = True
        with patch('msm5xxx_emulator.qemu.live_display.simpledialog.askstring', return_value='bad'), \
             patch('msm5xxx_emulator.qemu.live_display.messagebox.showerror') as error:
            v._choose_network_time(False)
        error.assert_called_once()
        v._restart.assert_not_called()
        with patch('msm5xxx_emulator.qemu.live_display.simpledialog.askstring', return_value='2024-01-02 03:04'):
            v._choose_network_time(False)
        self.assertFalse(v.network_host_time_enabled)
        v._restart.assert_not_called()
        v._choose_network_time(True)
        self.assertTrue(v.network_host_time_enabled)
        self.assertEqual(v.network_start_time, '')
        v._restart.assert_not_called()

    def test_running_firmware_switch_can_be_cancelled(self):
        v = self.view
        v.transport = object()
        with patch('msm5xxx_emulator.qemu.live_display.messagebox.askokcancel', return_value=False), \
             patch('msm5xxx_emulator.qemu.live_display.choose_from_library', return_value=Path('/tmp/new.bin')):
            v._choose_firmware_from_menu()
        v._restart.assert_not_called()

    def test_firmware_change_stops_before_start(self):
        v = self.view
        events = []
        v.transport = object()
        v.firmware = Path('/tmp/old.bin')
        v.overrides = {}
        v._prepared_profile = None
        v._active_firmware = v.firmware
        v._active_overrides = {}
        v.generation = 0
        import threading
        v.stop = threading.Event()
        v.qemu = Path('/tmp/qemu')
        v.state_dir = None
        v.persistent_state_enabled = False
        v.experimental_c80 = False
        v._active_virtual_network = False
        v._active_network_host_time = True
        v._active_network_start_time = ''
        v._load_config = Mock(return_value={})
        v._stop_transport = Mock(side_effect=lambda: events.append('stop'))
        v._activate_transport = Mock(side_effect=lambda *args: events.append('start'))
        v._restart = LiveWindow._restart.__get__(v)
        with patch('msm5xxx_emulator.qemu.live_display.messagebox.askokcancel', return_value=True), \
             patch('msm5xxx_emulator.qemu.live_display.choose_from_library', return_value=Path('/tmp/new.bin')), \
             patch('msm5xxx_emulator.qemu.live_display.detect_profile', return_value=(object(), {})), \
             patch('msm5xxx_emulator.qemu.live_display.Transport', side_effect=lambda *args, **kwargs: object()), \
             patch('msm5xxx_emulator.qemu.live_display.virtual_cell_scenario', return_value=None):
            v._choose_firmware_from_menu()
        self.assertEqual(events, ['stop', 'start'])
        self.assertEqual(v.firmware, Path('/tmp/new.bin'))

    def test_firmware_selection_uses_restart_path(self):
        v = self.view
        v.transport = object()
        v._load_config = Mock(return_value={})
        with patch('msm5xxx_emulator.qemu.live_display.messagebox.askokcancel', return_value=True), \
             patch('msm5xxx_emulator.qemu.live_display.choose_from_library', return_value=Path('/tmp/new.bin')):
            v._choose_firmware_from_menu()
        self.assertEqual(v.firmware, Path('/tmp/new.bin'))
        v._restart.assert_called_once()
