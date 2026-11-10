import os
import copy
from pathlib import Path
from types import SimpleNamespace
import unittest

from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.registry import device_domain
sv130_keypad_source = device_domain('input.sv130').sv130_keypad_source
from msm5xxx_emulator.qemu.decoder import QemuDecoder


class SV130KeypadTest(unittest.TestCase):
    def test_scanner_timer_and_overlay_source(self):
        root = Path(os.environ.get("MSM5XXX_TEST_FIRMWARE_ROOT", "/nonexistent"))
        path = root / "LG-SV130.bin"
        if not path.exists():
            self.skipTest("private SV130 firmware not available")
        image = path.read_bytes()
        config = detect(path)
        config.model = None
        decoder = QemuDecoder(config)
        profile = decoder.direct_input_profile
        self.assertTrue(sv130_keypad_source(image, config, profile))
        self.assertFalse(sv130_keypad_source(image, SimpleNamespace(model='LG-SD810'), profile))
        changed_config = copy.copy(config)
        changed_config.overlays = []
        self.assertFalse(sv130_keypad_source(image, changed_config, profile))
        changed_config.overlays = config.overlays + config.overlays
        self.assertFalse(sv130_keypad_source(image, changed_config, profile))
        changed_config = copy.copy(config)
        changed_config.rex_tick_address += 2
        self.assertFalse(sv130_keypad_source(image, changed_config, profile))
        for offset in (0x18, 0x6064, 0x00da1530, 0xe414, 0x82098,
                       0x820b2, 0x8218c, 0x82194, 0x822ba, 0x822d8):
            changed = bytearray(image)
            changed[offset] ^= 1
            self.assertFalse(sv130_keypad_source(changed, config, profile), hex(offset))
        altered = dict(profile)
        altered['timer_bridge'] = {**profile['timer_bridge'], 'irq_route': {}}
        self.assertFalse(sv130_keypad_source(image, config, altered))
