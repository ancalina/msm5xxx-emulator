"""Watchdog property emission is tied to the loaded instruction graph."""
import unittest

from msm5xxx_emulator.detection.watchdog import find_watchdog_profile
from msm5xxx_emulator.qemu.transport import qemu_watchdog_property
from test_watchdog import fixture


class WatchdogTransportTests(unittest.TestCase):
    def test_source_bound_properties_and_timeout(self):
        image, _, _ = fixture()
        profile, reason = find_watchdog_profile(bytes(image))
        self.assertIsNotNone(profile, reason)
        self.assertEqual(qemu_watchdog_property(profile, bytes(image)),
                         ('watchdog-register=50333440,watchdog-mask=1,'
                          'watchdog-timeout-ms=30000', None))
        # Appended secondary bytes do not enlarge the detected primary window.
        extra, _, _ = fixture(len(image))
        self.assertEqual(qemu_watchdog_property(profile, bytes(image) + bytes(extra)),
                         qemu_watchdog_property(profile, bytes(image)))
        profile['timeout_ms'] = 60000
        self.assertIn('timeout-ms=60000', qemu_watchdog_property(profile, bytes(image))[0])
        for timeout in (False, 0, 999, 3600001, '30000'):
            self.assertIsNone(qemu_watchdog_property({**profile, 'timeout_ms': timeout}, bytes(image))[0])

    def test_firmware_config_reaches_property_emission(self):
        from corpus import firmware_path
        from msm5xxx_emulator.detection import detect
        from msm5xxx_emulator.detection.firmware_image import load_firmware_image
        path = firmware_path('SPH-X7700.bin')
        config = detect(path)
        image = load_firmware_image(path).image[config.image_offset:]
        wire, reason = qemu_watchdog_property(config.watchdog, image[:config.flash_size])
        self.assertIsNotNone(wire, reason)
        self.assertIn('watchdog-register=50333440', wire)
        self.assertTrue(any(note.startswith('watchdog admitted:')
                            for note in config.detection_notes))

    def test_missing_forged_and_changed_source_fail_closed(self):
        image, service, _ = fixture()
        profile, _ = find_watchdog_profile(bytes(image))
        self.assertEqual(qemu_watchdog_property(None, bytes(image)), (None, None))
        for key, value in (('register', 0x03000600), ('mask', 2),
                           ('service_address', service + 2), ('signature', 'unknown')):
            self.assertIsNone(qemu_watchdog_property({**profile, key: value}, bytes(image))[0])
        image[service + 0x26] ^= 1
        self.assertIsNone(qemu_watchdog_property(profile, bytes(image))[0])
        self.assertIsNone(qemu_watchdog_property(profile, b'')[0])
        self.assertIsNone(qemu_watchdog_property({}, bytes(image))[0])
