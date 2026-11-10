import msm5xxx_emulator.detection as detector
import argparse
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from msm5xxx_emulator.gui import settings
from msm5xxx_emulator.detection.registry import device_domain

path = Path(__file__).resolve().parents[1] / 'android/app/src/main/python/msm5xxx_android_runtime.py'
spec = importlib.util.spec_from_file_location('mobile_settings_runtime', path)
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class MobileSettingsTest(unittest.TestCase):
    def test_validation_and_detector_receive_user_edits(self):
        baseline = object()
        effective = SimpleNamespace(width=240, flash_state='/tmp/state')
        with patch.object(settings, 'settings_values', return_value={'width': '128', 'flash_state': '/tmp/state'}), \
             patch.object(settings, 'parse_settings_values', return_value={'width': 240, 'flash_state': '/tmp/state'}), \
             patch.object(settings, 'validate_settings_values') as validate, \
             patch.object(detector, 'detect', return_value=effective) as detect:
            result = runtime._apply_settings(Path('/tmp/fake'), baseline, {'width': '240'})
        self.assertIs(result, effective)
        self.assertEqual(detect.call_args.args[1].width, 240)
        self.assertEqual(validate.call_args.args[3], {'width'})

    def test_validator_failure_is_propagated(self):
        effective = SimpleNamespace(width=1, flash_state='/tmp/state')
        with patch.object(settings, 'settings_values', return_value={'width': '128', 'flash_state': '/tmp/state'}), \
             patch.object(settings, 'parse_settings_values', return_value={'width': 1, 'flash_state': '/tmp/state'}), \
             patch.object(settings, 'validate_settings_values', side_effect=ValueError('invalid width')), \
             patch.object(detector, 'detect', return_value=effective):
            with self.assertRaisesRegex(ValueError, 'invalid width'):
                runtime._apply_settings(Path('/tmp/fake'), object(), {'width': '1'})

    def test_rejects_unknown_and_non_string_values(self):
        for edits in ({'unknown': '1'}, {'width': 5}):
            with self.assertRaises(ValueError):
                runtime._apply_settings(Path('/tmp/fake'), object(), edits)

    def test_no_edits_leave_detected_config_unchanged(self):
        config = object()
        self.assertIs(runtime._apply_settings(Path('/tmp/fake'), config, {}), config)
