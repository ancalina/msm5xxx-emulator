import os
from pathlib import Path
from types import SimpleNamespace
import tkinter as tk
import unittest
from unittest.mock import patch

from msm5xxx_emulator.gui.controls import ControlsMixin, SETTINGS_SECTIONS


@unittest.skipUnless(os.environ.get('DISPLAY'), 'Tk display unavailable')
class SettingsWindowTest(unittest.TestCase):
    def test_main_and_more_preserve_all_fields(self):
        root = tk.Tk()
        self.addCleanup(root.destroy)
        view = ControlsMixin()
        view.root, view.emulator = root, SimpleNamespace(config=object())
        view.firmware, view.overrides = Path('/tmp/firmware.bin'), {}
        view.ui_language = 'en'
        view.ui_language_preference = 'auto'
        values = {name: '' for _, fields in SETTINGS_SECTIONS for name, _ in fields}
        values['firmware'] = str(view.firmware)
        with patch('msm5xxx_emulator.gui.controls.settings_values', return_value=values):
            view._settings()
        dialog = next(w for w in root.winfo_children() if isinstance(w, tk.Toplevel))
        def descendants(widget):
            return [widget] + [child for w in widget.winfo_children() for child in descendants(w)]
        widgets = descendants(dialog)
        notebooks = [w for w in widgets if w.winfo_class() == 'TNotebook']
        self.assertEqual(len(notebooks), 2)
        self.assertEqual(len(notebooks[0].tabs()), 2)
        self.assertEqual(len(notebooks[1].tabs()), len(SETTINGS_SECTIONS))
        fields = [w for w in widgets if w.winfo_class() in ('TEntry', 'TCombobox')]
        self.assertEqual(len(fields), len(values) + 1)  # language selector
