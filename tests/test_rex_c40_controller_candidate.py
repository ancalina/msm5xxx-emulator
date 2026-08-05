"""C40 static observations stay telemetry-only and fail closed."""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from msm5xxx_emulator.detection.firmware import detect
from msm5xxx_emulator.detection.rex import find_rex_static_c40_controller_observation


def _bl(source: int, target: int) -> bytes:
    delta = target - source - 4
    return struct.pack("<2H", 0xF000 | (delta >> 12 & 0x7FF),
                       0xF800 | (delta >> 1 & 0x7FF))


def _arm_b(source: int, target: int) -> int:
    return 0xEA000000 | ((target - source - 8) >> 2 & 0xFFFFFF)


def _copied_image() -> tuple[bytearray, dict[str, int]]:
    image = bytearray(0x5000)
    source, wrapper, descriptor = 0x1000, 0x800, 0x1200
    handler_table, handler = 0x1400, 0x1800
    callback, registrar, arm = 0x2000, 0x2400, 0x3000
    callback_base = 0x01000400
    struct.pack_into("<I", image, 0x18, _arm_b(0x18, 0x01000000))
    struct.pack_into("<4I", image, 0x40, source, 0x01000000,
                     0x400, 0x01000400)
    struct.pack_into("<I", image, source, _arm_b(0x01000000, wrapper))
    struct.pack_into("<6I", image, wrapper,
                     0xE59F3010, 0xE5933000, 0xE12FFF13,
                     0xE59F3008, 0xE5933000, 0xE12FFF13)
    struct.pack_into("<2I", image, wrapper + 0x18,
                     0x01000100, 0x01000104)
    descriptor_runtime = 0x01000000 + descriptor - source
    struct.pack_into("<4I", image, descriptor,
                     0x03000C40, 0x03000C54, 0x0200,
                     descriptor_runtime - 8)
    struct.pack_into("<4I", image, handler_table, descriptor_runtime,
                     0x03000C60, 0x03000FD0, handler | 1)
    struct.pack_into("<H", image, handler, 0xB5F0)
    struct.pack_into("<6H", image, callback,
                     0xB590, 0x2105, 0x2005, 0x3905, 0x6001, 0x2105)
    struct.pack_into("<10H", image, registrar,
                     0xB5F0, 0x1C05, 0x1C0F, 0xF000, 0xF800,
                     0x1C04, 0, 0x2F00, 0xD100, 0x1C37)
    _literal(image, registrar + 0x0C, 6, handler | 1, registrar + 0xF8)
    _literal(image, registrar + 0x14, 0, callback_base, registrar + 0xFC)
    struct.pack_into("<H", image, registrar + 0x46, 0x664F)
    _literal(image, arm, 1, 0x030006E0, arm + 0x40)
    struct.pack_into("<2H", image, arm + 2, 0x2002, 0x7008)
    _literal(image, arm + 6, 1, callback | 1, arm + 0x44)
    struct.pack_into("<H", image, arm + 8, 0x2000)
    image[arm + 10:arm + 14] = _bl(arm + 10, registrar)
    return image, {"callback": callback, "arm": arm,
                   "callback_slot": callback_base - 0x18}


def _literal(image: bytearray, at: int, register: int, value: int, pool: int) -> None:
    base = (at + 4) & ~3
    struct.pack_into("<H", image, at, 0x4800 | register << 8 | (pool - base) // 4)
    struct.pack_into("<I", image, pool, value)


def _image(revision: int) -> tuple[bytearray, dict[str, int]]:
    image = bytearray(0x1000)
    handler, wrapper, descriptor = 0x100 + revision, 0x600 + revision, 0x900
    shadow, table, slot = 0x01004000 + revision, 0x010041F0 + revision, 0x01007000
    struct.pack_into("<I", image, 0x18, 0xEA4DFFF8)
    struct.pack_into("<4I", image, descriptor, 0x03000C40, 0x03000C54, 0x0200, shadow)
    struct.pack_into("<4I", image, wrapper, 0xE24EE004, 0xE92D540F,
                     0xE14F0000, 0xE92D0001)
    struct.pack_into("<I", image, wrapper + 0x28, 0xE59F3000)
    struct.pack_into("<I", image, wrapper + 0x30, slot)
    struct.pack_into("<H", image, handler, 0xB5F0)
    tick, tail, clear = handler + 0x112, handler + 0x396, handler + 0x2BC
    _literal(image, handler + 0x0A, 6, shadow, 0x4D4)
    _literal(image, handler + 0x0C, 7, 0x03000C40, 0x4D8)
    struct.pack_into("<2H", image, tick, 0x0A8A, 0xD30A)
    _literal(image, tick + 4, 0, table, 0x4DC)
    struct.pack_into("<H", image, tick + 6, 0x6980)
    image[tick + 8:tick + 12] = _bl(tick + 8, 0x1254)
    struct.pack_into("<2H", image, tick + 0x14, 0x2001, 0x0240)
    delta = clear - (tick + 0x1C)
    struct.pack_into("<H", image, tick + 0x18, 0xE000 | (delta >> 1 & 0x7FF))
    _literal(image, clear, 1, 0x03000C40, 0x4E0)
    struct.pack_into("<H", image, clear + 2, 0x8008)
    _literal(image, tail, 2, shadow, 0x4E4)
    _literal(image, tail + 2, 1, 0x03000C40, 0x4E8)
    struct.pack_into("<8H", image, tail + 4, 0x8810, 0x880B, 0x4018, 0x0400,
                     0x4E15, 0x0C00, 0x8430, 0x8852)
    struct.pack_into("<H", image, handler + 0x3CE, 0xBDF0)
    walker, client = 0x500 + revision, 0x5C0 + revision
    struct.pack_into("<18H", image, walker,
                     0xB5F8, 0x1C0C, 0x1C07, 0xF000, 0xF800,
                     0x9000, 0x6878, 0x2800, 0xD000, 0x6881, 0x1B09,
                     0x6081, 0xE000, 0x6878, 0x1C04, 0x6900, 0x68A1,
                     0x1A45)
    struct.pack_into("<4H", image, client, 0x2201, 0x9200, 0x2219, 0x2319)
    image[client + 8:client + 12] = _bl(client + 8, walker)
    dispatcher, registration, callback = 0x740 + revision, 0x800 + revision, 0x850 + revision
    struct.pack_into("<3H", image, dispatcher, 0xB5F0, 0x1C05, 0x1C0F)
    image[dispatcher + 6:dispatcher + 10] = _bl(dispatcher + 6, 0x120)
    struct.pack_into("<5H", image, dispatcher + 10,
                     0x1C04, 0x2F00, 0x4E00, 0xD100, 0x1C37)
    _literal(image, dispatcher + 0x14, 1, table + 0x7C, dispatcher + 0x70)
    struct.pack_into("<H", image, dispatcher + 0x24, 0xE01E)
    struct.pack_into("<H", image, dispatcher + 0x64, 0x6187)
    _literal(image, registration, 1, callback | 1, registration + 0x20)
    struct.pack_into("<H", image, registration + 2, 0x2000)
    image[registration + 4:registration + 8] = _bl(registration + 4, dispatcher)
    struct.pack_into("<H", image, callback, 0xB590)
    struct.pack_into("<H", image, callback + 0x30, 0x2105)
    image[callback + 0x32:callback + 0x36] = _bl(callback + 0x32, walker)
    arm = 0x40 + revision
    _literal(image, arm, 1, 0x030006E0, 0x60)
    struct.pack_into("<2H", image, arm + 2, 0x2002, 0x7008)
    return image, {"descriptor": descriptor, "handler": handler,
                   "wrapper": wrapper, "clear": clear, "slot": slot,
                   "registration": registration, "callback": callback, "arm": arm}


class C40ObservationTests(unittest.TestCase):
    def test_copied_vector_selector0_delta5_accepts_and_fails_closed(self) -> None:
        image, offsets = _copied_image()
        result = find_rex_static_c40_controller_observation(image)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertTrue(result["accepted"])
        self.assertEqual(result["controller_class"],
                         "c40-copied-vector-selector0-delta5-v1")
        self.assertEqual(result["vector_target"], 0x01000000)
        self.assertEqual(result["callback_slot"], offsets["callback_slot"])
        self.assertEqual(result["callback_file_offset"], offsets["callback"])
        self.assertEqual(result["time_tick_control_file_offset"], offsets["arm"])

        changed = bytearray(image)
        struct.pack_into("<H", changed, offsets["callback"] + 6, 0)
        rejected = find_rex_static_c40_controller_observation(changed)
        self.assertIsNotNone(rejected)
        assert rejected is not None
        self.assertFalse(rejected["accepted"])
        self.assertEqual(rejected["reject_reason"],
                         "selector0-time-tick-registration-not-unique")

    def test_two_relocated_fixtures_accept_and_mutations_reject(self) -> None:
        for revision in (0, 4):
            image, offsets = _image(revision)
            result = find_rex_static_c40_controller_observation(image)
            self.assertIsNotNone(result)
            assert result is not None
            self.assertTrue(result["accepted"])
            self.assertFalse(result["active"])
            self.assertEqual(result["promotion"], "telemetry-only")
            self.assertEqual(result["status_banks"], (0x03000C40, 0x03000C44))
            self.assertEqual(result["enable_banks"], (0x03000C54, 0x03000C58))
            self.assertEqual(result["vector_target"], 0x01380000)
            self.assertEqual(result["time_tick_arm_value"], 2)
            for at, value, width, reason in (
                    (offsets["descriptor"] + 8, 0x100, 4, None),
                    (offsets["clear"] + 2, 0, 2, "c40-handler-not-unique"),
                    (offsets["wrapper"] + 0x30, 0, 4, "irq-wrapper-not-unique"),
                    (offsets["registration"] + 2, 1, 2, "selector0-registration-not-unique"),
                    (offsets["callback"] + 0x30, 0, 2, "callback-delta5-walker-not-closed"),
                    (0x764 + revision, 0, 2, "selector0-registration-not-unique"),
                    (0x50A + revision, 0, 2, "callback-delta5-walker-not-closed"),
                    (0x18, 0, 4, "runtime-vector-target-mismatch")):
                changed = bytearray(image)
                struct.pack_into("<I" if width == 4 else "<H", changed, at, value)
                observed = find_rex_static_c40_controller_observation(changed)
                if reason is None:
                    self.assertIsNone(observed)
                    continue
                self.assertIsNotNone(observed)
                assert observed is not None
                self.assertFalse(observed["accepted"])
                self.assertEqual(observed["reject_reason"], reason)
            changed = bytearray(image)
            struct.pack_into("<H", changed, offsets["arm"] + 2, 0x2001)
            observed = find_rex_static_c40_controller_observation(changed)
            self.assertIsNotNone(observed)
            assert observed is not None
            self.assertEqual(observed["reject_reason"], "time-tick-arm-not-unique")
            struct.pack_into("<I", changed, 0x18, 0)
            observed = find_rex_static_c40_controller_observation(changed)
            self.assertIsNotNone(observed)
            assert observed is not None
            self.assertEqual(observed["reject_reason"],
                             "runtime-vector-target-mismatch")

    def test_detect_records_only_dedicated_telemetry(self) -> None:
        accepted = {"accepted": True, "active": False,
                    "promotion": "telemetry-only"}
        rejected = {"accepted": False, "active": False,
                    "promotion": "telemetry-only", "reject_reason": "c40-handler-not-unique"}
        with tempfile.TemporaryDirectory() as directory:
            firmware = Path(directory) / "firmware.bin"
            firmware.write_bytes(b"\xff" * 0x100)
            for observation, note in ((accepted, "observation detected"),
                                      (rejected, "c40-handler-not-unique")):
                with patch("msm5xxx_emulator.detection.firmware."
                           "find_rex_static_c40_controller_observation",
                           return_value=observation):
                    config = detect(firmware)
                self.assertIs(config.rex_static_c40_controller_observation, observation)
                self.assertIn(note, " ".join(config.detection_notes))
                self.assertEqual((config.rex_tick_address, config.rex_irq_wrapper_address,
                                  config.rex_irq_handler_address, config.rex_irq_mask,
                                  config.rex_tick_ms), (None, None, None, 0, 1000))


if __name__ == "__main__":
    unittest.main()
