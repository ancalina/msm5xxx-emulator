import os
from pathlib import Path
import copy
import unittest

from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.qemu.decoder import QemuDecoder
from msm5xxx_emulator.qemu.transport import (
    c80_rex_irq_profile, qemu_low5_matrix_property, qemu_lg_matrix_irq_property, qemu_matching_lg_irq, qemu_sd9210_low5_contacts,
    qemu_sd840_numeric_profile,
)


class SD9210KeypadTest(unittest.TestCase):
    def test_numeric_contact_source_and_mutations(self):
        root = Path(os.environ.get("MSM5XXX_TEST_FIRMWARE_ROOT", "/nonexistent"))
        path = root / "lg-sd9210.bin"
        if not path.exists():
            self.skipTest("private SD9210 firmware not available")
        image = path.read_bytes()
        config = detect(path)
        config.model = None
        existing_route = c80_rex_irq_profile(config, False)
        decoder = QemuDecoder(config)
        profile = decoder.direct_input_profile
        self.assertEqual(decoder.direct_input_detection, "accepted")
        self.assertEqual(qemu_sd9210_low5_contacts(image, config, profile),
                         (0x78784, 0x787aa))
        self.assertTrue(qemu_lg_matrix_irq_property(config, profile).startswith('3000c80:3000c94:200:'))
        route = qemu_lg_matrix_irq_property(config, profile)
        self.assertTrue(qemu_matching_lg_irq(existing_route, route))
        self.assertTrue(qemu_matching_lg_irq(route, route))
        pieces = route.split(':')
        pieces[8] = '1b6'
        self.assertTrue(qemu_matching_lg_irq(':'.join(pieces), route))
        pieces[9] = '0'
        self.assertFalse(qemu_matching_lg_irq(':'.join(pieces), route))
        numeric = qemu_sd840_numeric_profile(profile)
        self.assertEqual(set(decoder._direct_matrix_positions(numeric)), set(range(11, 23)))
        prop, reason = qemu_low5_matrix_property(image, config, numeric)
        self.assertIsNone(reason)
        self.assertEqual(prop, "matrix-low5=1816618:787be:78906:78784:787aa")
        for offset in (0x3a, 0x3e, 0x48, 0x60, 0x64):
            changed = bytearray(image)
            changed[profile["function"] + offset] ^= 1
            self.assertIsNone(qemu_sd9210_low5_contacts(changed, config, profile))
        altered = dict(profile, row_order=[0, 1, 2, 3, 4, 5])
        self.assertIsNone(qemu_sd9210_low5_contacts(image, config, altered))
        altered = dict(profile)
        altered['timer_bridge'] = {**profile['timer_bridge'], 'irq_route': {}}
        self.assertIsNone(qemu_sd9210_low5_contacts(image, config, altered))
        wrong_model = copy.copy(config)
        wrong_model.model = "LG-SD810"
        self.assertIsNotNone(qemu_sd9210_low5_contacts(image, wrong_model, profile))
