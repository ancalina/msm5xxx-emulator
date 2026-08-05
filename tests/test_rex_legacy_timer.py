"""Legacy timer registration must retain the scanner-specific ABI closure."""
from __future__ import annotations

import struct
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.rex import (
    _legacy_software_timer_target,
    _legacy_timer_registration_at,
    find_rex_legacy_5ms_irq_route,
    find_rex_legacy_5ms_timer_bridge,
    find_rex_idle_address,
    rex_legacy_5ms_callback_shape_at,
)
from msm5xxx_emulator.detection.arm import thumb_literal_value


def _bl(source: int, target: int) -> bytes:
    displacement = target - source - 4
    return struct.pack("<2H", 0xF000 | (displacement >> 12 & 0x7FF),
                       0xF800 | (displacement >> 1 & 0x7FF))


class LegacyTimerRegistrationTests(unittest.TestCase):
    def test_legacy_software_timer_accepts_exact_arm_veneer(self) -> None:
        image = bytearray(0x100)
        veneer, walker = 0x20, 0x60
        struct.pack_into(
            "<6HI", image, veneer,
            0x4778, 0x46C0, 0xC000, 0xE59F, 0xFF1C, 0xE12F,
            walker | 1,
        )
        words = [0] * 28
        words[:3] = (0xB5F8, 0x1C04, 0x1C0F)
        words[8:12] = (0x6860, 0x2800, 0xD025, 0x6881)
        words[12:16] = (0x1BC9, 0x6081, 0xE01E, 0x6867)
        words[16:20] = (0x6938, 0x68B9, 0x1A46, 0x1C38)
        words[24:28] = (0x2800, 0xD008, 0x6138, 0x60B8)
        struct.pack_into("<28H", image, walker, *words)

        self.assertEqual(
            _legacy_software_timer_target(bytes(image), veneer), walker
        )
        image[veneer] ^= 1
        self.assertIsNone(
            _legacy_software_timer_target(bytes(image), veneer)
        )

    def test_legacy_callback_runtime_shape_does_not_follow_sliced_bl(self) -> None:
        words = [0] * 34
        fixed = {
            0: 0xB580, 3: 0x0407, 4: 0x0C3F, 5: 0x2105,
            12: 0x0880, 13: 0xD301, 15: 0xE000,
            17: 0x6808, 18: 0x3805, 19: 0x6008, 20: 0x2005,
            23: 0x2105, 27: 0x2F00, 28: 0xD101,
            31: 0xBC80, 32: 0xBC08, 33: 0x4718,
        }
        for index, value in fixed.items():
            words[index] = value
        for index in (6, 9, 14, 16, 24):
            words[index] = 0x4800
        for index in (21, 25):
            words[index:index + 2] = (0xF000, 0xF800)
        callback = bytearray(struct.pack("<34H", *words))

        self.assertEqual(
            rex_legacy_5ms_callback_shape_at(callback, 0), (21, 25)
        )
        struct.pack_into("<H", callback, 42, 0)
        self.assertIsNone(rex_legacy_5ms_callback_shape_at(callback, 0))

    def test_legacy_irq_route_requires_each_static_edge(self) -> None:
        image = bytearray(0x4000)
        outer, registrar, loop, drain = 0x100, 0x300, 0x1000, 0x1100
        handler, wrapper, seed_at, base, slot = loop - 0x17E, 0x2000, 0x2800, 0x24B8, 0x01003600
        index = 0x1E
        struct.pack_into("<7I", image, seed_at, 0x03000C80, 0x03000C94,
                         0x200, base - 0xC, base - 6, 0x701, 0)
        group_final = base + (index + 1) * 0x1C + 4 + 3 * 10
        image[group_final:group_final + 10] = struct.pack(
            "<4H2B", 0x200, 0, 0x200, 4, index, index)
        struct.pack_into("<56H", image, registrar,
                         0xB5F0, 0x1C04, 0x1C0F, *([0] * 53))
        words = list(struct.unpack_from("<56H", image, registrar))
        words[5:14] = (0x1C05, 0x2F00, 0x4E1C, 0xD100, 0x1C37,
                       0x2C00, 0xDB01, 0x2C1F, 0xDB06)
        words[21:25] = (0x201C, 0x4916, 0x4360, 0x1840)
        words[28:31] = (0x630F, 0xE000, 0x6147)
        struct.pack_into("<56H", image, registrar, *words)
        struct.pack_into("<2H", image, handler, 0xB5F0, 0xB087)
        struct.pack_into("<H", image, handler + 0x40, 0x6978)
        image[handler + 0x42:handler + 0x46] = _bl(handler + 0x42, 0x180)
        image[0x180:0x182] = b"\x00\x47"
        handler_registration, setter = 0x1300, 0x1400
        struct.pack_into("<H", image, handler_registration + 2, 0x2000)
        image[setter:setter + 14] = struct.pack(
            "<7H", 0x4A03, 0x2800, 0xD101, 0x6291, 0x4770, 0x62D1, 0x4770)
        image[loop:loop + 4] = _bl(loop, drain)
        struct.pack_into("<2H", image, loop + 4, 0x2800, 0xD1FB)
        struct.pack_into("<4I", image, wrapper, 0xE24EE004, 0xE92D540F,
                         0xE14F0000, 0xE92D0001)
        struct.pack_into("<I", image, wrapper + 0x28, 0xE59F3000)
        struct.pack_into("<I", image, wrapper + 0x30, slot)
        struct.pack_into("<I", image, 0x18, 0xEA000000)
        bridge = {"outer_callback_file_offset": outer,
                  "drain_loop_caller_file_offset": loop,
                  "drain_file_offset": drain}
        registrations = {0x200, 0x220, 0x240}
        def literals(_image, position, register):
            if register == 1 and position in registrations:
                return outer | 1
            if register == 1 and position == registrar + 44:
                return base
            if register == 6 and position == registrar + 14:
                return 0x701
            if register == 1 and position == handler_registration:
                return handler | 1
            if register == 2 and position == setter:
                return slot - 40
            if position == handler + 2:
                return 0x03000C80
            if position == handler + 4:
                return base
            return None
        def targets(_image, position):
            if position in {site + 4 for site in registrations}:
                return registrar
            if position == handler + 0x42:
                return 0x180
            if position == handler_registration + 4:
                return setter
            if position == loop:
                return drain
            return None
        for site in registrations:
            struct.pack_into("<H", image, site + 2, 0x201E)
        struct.pack_into("<I", image, 0x250, outer | 1)
        struct.pack_into("<I", image, 0x1350, handler | 1)
        class FullAddressSpaceImage(bytearray):
            def __len__(self) -> int:
                return 0x02000000
        with (patch("msm5xxx_emulator.detection.rex.thumb_literal_value", side_effect=literals),
              patch("msm5xxx_emulator.detection.rex.thumb_bl_target", side_effect=targets)):
            result = find_rex_legacy_5ms_irq_route(
                FullAddressSpaceImage(image), bridge
            )
        self.assertIsNotNone(result)
        self.assertEqual(result["handler"], handler)
        self.assertEqual(result["callback_slot"], base + index * 0x1C + 0x14)
        self.assertEqual(result["enable"], 0x03000C94)
        self.assertEqual(
            result["controller_class"],
            "legacy-c80-two-bank-group10-v1",
        )
        self.assertEqual(
            (result["status_bank_count"], result["group_row_size"]), (2, 10)
        )
        self.assertEqual(result["status_banks"], (0x03000C80, 0x03000C84))
        self.assertEqual(result["clear_banks"], (0x03000C80, 0x03000C84))
        self.assertEqual(
            result["controller_write_banks"], (0x03000C94, 0x03000C98)
        )

        compact = bytearray(image)
        compact_words = list(struct.unpack_from("<56H", compact, registrar))
        compact_words[20:25] = (0x201C, 0x4916, 0x4360, 0x1840, 0)
        compact_words[27:31] = (0x630F, 0xE000, 0x6147, 0)
        struct.pack_into("<56H", compact, registrar, *compact_words)

        def compact_literals(_image, position, register):
            if register == 1 and position == registrar + 42:
                return base
            if register == 1 and position == registrar + 44:
                return None
            return literals(_image, position, register)

        with (patch("msm5xxx_emulator.detection.rex.thumb_literal_value",
                    side_effect=compact_literals),
              patch("msm5xxx_emulator.detection.rex.thumb_bl_target", side_effect=targets)):
            self.assertIsNotNone(find_rex_legacy_5ms_irq_route(
                compact, bridge
            ))

        newer = bytearray(compact)
        newer_handler = loop - 0x150
        struct.pack_into("<2H", newer, handler, 0, 0)
        struct.pack_into("<3H", newer, handler + 0x40, 0, 0, 0)
        struct.pack_into("<2H", newer, newer_handler, 0xB5F0, 0xB086)
        struct.pack_into("<H", newer, newer_handler + 0x40, 0x6978)
        newer[newer_handler + 0x42:newer_handler + 0x46] = _bl(
            newer_handler + 0x42, 0x180
        )
        struct.pack_into("<I", newer, 0x1350, newer_handler | 1)

        def newer_literals(_image, position, register):
            if register == 1 and position == handler_registration:
                return newer_handler | 1
            if position == newer_handler + 2:
                return 0x03000C80
            if position == newer_handler + 4:
                return base
            if handler <= position < handler + 6:
                return None
            return compact_literals(_image, position, register)

        def newer_targets(_image, position):
            if position == newer_handler + 0x42:
                return 0x180
            return targets(_image, position)

        with (patch("msm5xxx_emulator.detection.rex.thumb_literal_value",
                    side_effect=newer_literals),
              patch("msm5xxx_emulator.detection.rex.thumb_bl_target",
                    side_effect=newer_targets)):
            result = find_rex_legacy_5ms_irq_route(newer, bridge)
        self.assertIsNotNone(result)
        self.assertEqual(result["handler"], newer_handler)

        struct.pack_into("<H", newer, newer_handler + 2, 0xB085)
        with (patch("msm5xxx_emulator.detection.rex.thumb_literal_value",
                    side_effect=newer_literals),
              patch("msm5xxx_emulator.detection.rex.thumb_bl_target",
                    side_effect=newer_targets)):
            self.assertIsNone(find_rex_legacy_5ms_irq_route(newer, bridge))

        for offset, value, width in ((registrar + 60, 0, 2),
                                     (handler + 0x40, 0, 2),
                                     (setter + 6, 0, 2),
                                     (wrapper, 0, 4),
                                     (group_final, 0, 2),
                                     (seed_at + 8, 0x100, 4)):
            changed = bytearray(image)
            if width == 2:
                struct.pack_into("<H", changed, offset, value)
            else:
                struct.pack_into("<I", changed, offset, value)
            with (patch("msm5xxx_emulator.detection.rex.thumb_literal_value", side_effect=literals),
                  patch("msm5xxx_emulator.detection.rex.thumb_bl_target", side_effect=targets)):
                self.assertIsNone(find_rex_legacy_5ms_irq_route(changed, bridge))
    def test_idle_loop_accepts_backward_branch_displacement(self) -> None:
        words = [0] * 30
        fixed = {
            0: 0x0BC1, 1: 0xD306, 2: 0x2108, 6: 0x2101, 7: 0x0389,
            8: 0xE007, 9: 0x0B81, 10: 0xD309, 11: 0x2108,
            15: 0x2101, 16: 0x0349, 21: 0x0A80, 22: 0xD302,
        }
        for index, value in fixed.items():
            words[index] = value
        for index in (3, 12, 17):
            words[index] = 0x1C20
        for index in (4, 13, 18, 23, 26):
            words[index:index + 2] = (0xF000, 0xF800)
        words[20], words[25], words[28] = 0xE7D7, 0xE7D2, 0xE7D0
        image = bytearray(struct.pack("<30H", *words))

        self.assertEqual(find_rex_idle_address(image), 52)
        struct.pack_into("<H", image, 40, 0xE017)
        self.assertIsNone(find_rex_idle_address(image))

    def test_newer_idle_loop_requires_all_same_loop_backedges(self) -> None:
        image = bytearray(0x200)
        function, anchor = 0x20, 0x20 + 84
        setup = [0] * 42
        setup_fixed = {
            0: 0xB5B0, 1: 0x4D21, 2: 0x4C21, 3: 0x2201,
            4: 0x1C29, 5: 0x1C20, 8: 0x2201, 9: 0x0252,
            10: 0x1DE0, 11: 0x3015, 12: 0x491B, 15: 0x1DE0,
            16: 0x3015, 21: 0x1C22, 22: 0x210F, 23: 0x2001,
            26: 0x27FF, 27: 0x37A0, 28: 0xE007, 29: 0x1C28,
            32: 0x0841, 33: 0xD307, 34: 0x200F,
            37: 0x1C39, 38: 0x1C20, 41: 0xE7F2,
        }
        for index, value in setup_fixed.items():
            setup[index] = value
        for index in (6, 13, 17, 19, 24, 30, 35, 39):
            setup[index:index + 2] = (0xF000, 0xF800)
        stages = [0] * 25
        stage_fixed = {
            0: 0x0BC1, 1: 0xD304, 4: 0x2101, 5: 0x0389,
            6: 0xE005, 7: 0x0B81, 8: 0xD307, 11: 0x2101,
            12: 0x0349, 13: 0x1C28, 16: 0xE7E1,
            17: 0x0A80, 18: 0xD302, 21: 0xE7DC, 24: 0xE7D9,
        }
        for index, value in stage_fixed.items():
            stages[index] = value
        for index in (2, 9, 14, 19, 22):
            stages[index:index + 2] = (0xF000, 0xF800)
        struct.pack_into("<42H", image, function, *setup)
        struct.pack_into("<25H", image, anchor, *stages)

        self.assertEqual(find_rex_idle_address(image), anchor + 44)
        struct.pack_into("<H", image, anchor + 48, 0xE7DA)
        self.assertIsNone(find_rex_idle_address(image))

    def test_exact_abi_accepts_and_stack_flag_mutation_rejects(self) -> None:
        image = bytearray(0x100)
        scanner, callback = 0x80, 0x40
        struct.pack_into("<H", image, callback, 0x4903)  # LDR R1, scanner|1
        struct.pack_into("<2H", image, callback - 10, 0x2201, 0x9200)
        struct.pack_into("<2H", image, callback - 6, 0x2219, 0x2319)
        struct.pack_into("<H", image, callback - 2, 0x1C20)  # MOV R0,R4
        struct.pack_into("<H", image, 0x2C, 0x4C09)  # LDR R4, timer
        struct.pack_into("<H", image, 0x2E, 0x3404)  # ADD R4,#4
        image[callback + 2:callback + 6] = _bl(callback + 2, 0x64)
        struct.pack_into("<2I", image, 0x50, scanner | 1, 0x01100000)

        result = _legacy_timer_registration_at(bytes(image), scanner, callback)

        self.assertEqual(result, {
            "callback_literal_file_offset": 0x50,
            "registration_callsite_file_offset": 0x42,
            "timer_object": 0x01100004,
            "registrar_file_offset": 0x64,
            "initial": 0x19,
            "reload": 0x19,
            "stack_flag": 1,
        })
        image[callback - 10] = 0
        self.assertIsNone(_legacy_timer_registration_at(
            bytes(image), scanner, callback))

    def test_adjusted_callee_saved_timer_survives_init_call(self) -> None:
        image = bytearray(0x100)
        scanner, callback = 0x80, 0x42
        struct.pack_into("<H", image, 0x2C, 0x4C10)  # LDR R4, timer
        struct.pack_into("<H", image, 0x2E, 0x74F8)  # STRB R0,[R7,#0x13]
        struct.pack_into("<H", image, 0x30, 0x3CCC)  # SUBS R4,#0xCC
        struct.pack_into("<H", image, 0x32, 0x1C20)  # MOV R0,R4
        image[0x34:0x38] = _bl(0x34, 0x6C)           # BL timer_init
        struct.pack_into("<2H", image, 0x38, 0x2201, 0x9200)
        struct.pack_into("<2H", image, callback - 6, 0x2219, 0x2319)
        struct.pack_into("<H", image, callback - 2, 0x1C20)  # MOV R0,R4
        struct.pack_into("<H", image, callback, 0x490A)  # LDR R1, scanner|1
        image[callback + 2:callback + 6] = _bl(callback + 2, 0x70)
        struct.pack_into("<2I", image, 0x6C, scanner | 1, 0x011000CC)

        self.assertEqual(_legacy_timer_registration_at(
            bytes(image), scanner, callback)["timer_object"], 0x01100000)
        r0_timer = bytearray(image)
        struct.pack_into("<H", r0_timer, 0x2C, 0x4811)  # LDR R0, timer
        struct.pack_into("<H", r0_timer, 0x30, 0x38CC)  # SUBS R0,#0xCC
        struct.pack_into("<H", r0_timer, 0x32, 0x1C00)  # MOV R0,R0
        struct.pack_into("<H", r0_timer, callback - 2, 0x1C00)
        self.assertIsNone(_legacy_timer_registration_at(
            bytes(r0_timer), scanner, callback))
        for word in (0x4687, 0x4487, 0xF000, 0xF800):
            malformed = bytearray(image)
            struct.pack_into("<H", malformed, 0x2E, word)
            self.assertIsNone(_legacy_timer_registration_at(
                bytes(malformed), scanner, callback))
        struct.pack_into("<H", image, 0x30, 0x46C0)  # non-adjacent no-adjust
        self.assertIsNone(_legacy_timer_registration_at(
            bytes(image), scanner, callback))

    def test_exact_no_adjust_saved_register_shape_is_preserved(self) -> None:
        image = bytearray(0x100)
        scanner, callback = 0x80, 0x42
        struct.pack_into("<H", image, 0x30, 0x4C0F)  # LDR R4, timer
        struct.pack_into("<H", image, 0x32, 0x1C20)  # MOV R0,R4
        image[0x34:0x38] = _bl(0x34, 0x6C)           # BL timer_init
        struct.pack_into("<2H", image, 0x38, 0x2201, 0x9200)
        struct.pack_into("<2H", image, callback - 6, 0x2219, 0x2319)
        struct.pack_into("<H", image, callback - 2, 0x1C20)  # MOV R0,R4
        struct.pack_into("<H", image, callback, 0x490A)  # LDR R1, scanner|1
        image[callback + 2:callback + 6] = _bl(callback + 2, 0x70)
        struct.pack_into("<2I", image, 0x6C, scanner | 1, 0x01100000)

        self.assertEqual(_legacy_timer_registration_at(
            bytes(image), scanner, callback)["timer_object"], 0x01100000)

    def test_outer_callback_binds_scanner_and_backward_drain_loop(self) -> None:
        image = bytearray(0x240)
        outer, scanner, software, drain = 0x100, 0x80, 0x140, 0x1D0
        image[outer:outer + 2] = b"\x80\xb5"
        image[drain:drain + 2] = b"\x80\xb5"
        struct.pack_into("<H", image, 0x40, 0x4903)
        struct.pack_into("<I", image, 0x50, scanner | 1)
        struct.pack_into("<2H", image, software + 0x4E, 0x1DF8, 0x3019)
        struct.pack_into("<H", image, 0x1B0, 0x1C39)
        for callsite in (software + 0x52, 0x1B4, 0x1E0):
            image[callsite:callsite + 4] = b"\x00\xf0\x00\xf8"
        struct.pack_into("<H", image, 0x1B2, 0x4802)
        struct.pack_into("<I", image, 0x1BC, 0x01110000)
        struct.pack_into("<2H", image, 0x1E4, 0x2800, 0xD1FB)
        self.assertEqual(thumb_literal_value(image, 0x40, 1), scanner | 1)
        registration = {
            "callback_literal_file_offset": 0x50,
            "registration_callsite_file_offset": 0x42,
            "timer_object": 0x01100004,
            "registrar_file_offset": 0x64,
            "initial": 0x19, "reload": 0x19, "stack_flag": 1,
        }
        def detect(dispatcher: int = 0x1A0) -> dict[str, object] | None:
            with (patch("msm5xxx_emulator.detection.rex.rex_legacy_5ms_callback_at",
                        side_effect=lambda _image, position:
                        (0x120, software) if position == outer else None),
                  patch("msm5xxx_emulator.detection.rex._legacy_timer_registration_at",
                        side_effect=lambda _image, candidate, position:
                        registration if candidate == scanner and position == 0x40
                        else None),
                  patch("msm5xxx_emulator.detection.rex.rex_timer_callback_drain_at",
                        side_effect=lambda _image, position:
                        0x01110000 if position == drain else None),
                  patch("msm5xxx_emulator.detection.rex.thumb_bl_target",
                        side_effect=lambda _image, position: {
                            software + 0x52: dispatcher, 0x1B4: 0x1C0,
                            0x1E0: drain, len(image) - 4: drain,
                        }.get(position))):
                return find_rex_legacy_5ms_timer_bridge(image, scanner)

        result = detect()
        self.assertIsNotNone(result)
        self.assertEqual(result["outer_callback"], outer)
        self.assertEqual(result["outer_callback_file_offset"], outer)
        self.assertIsNone(detect(len(image) - 0x50))
        image[-4:] = b"\x00\xf0\x00\xf8"
        self.assertIsNotNone(detect())
        struct.pack_into("<H", image, 0x1E6, 0xD1FF)
        self.assertIsNone(detect())


if __name__ == "__main__":
    unittest.main()
