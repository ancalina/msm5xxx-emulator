"""Synthetic composition of a scanner timer and its interrupt route."""
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.detection.registry import device_domain

MODULE = device_domain("input.row_timer")
from msm5xxx_emulator.detection.devices.input.row_timer import _leading_literal_entry


class RowTimerTests(unittest.TestCase):
    def setUp(self):
        self.image = bytearray(0x200)
        struct.pack_into("<H", self.image, 0x20, 0xb510)
        self.matrix = {"grammar": "sparse-halfword-six-row-v1", "presence_site": 0x40}
        self.config = SimpleNamespace(load_address=0, flash_size=0x180, linker=None,
            overlays=[SimpleNamespace(source=0x100, target=0x1001000, size=0x20)])
        self.bridge = {"scanner": 0x20, "scanner_file_offset": 0x20, "tick_ms": 5,
                       "outer_callback": 0x60, "drain": 0x80, "drain_loop_caller": 0x90}
        status, enable = 0x03000c80, 0x03000c94
        self.route = {"controller_class": "legacy-c80-three-bank-group14-v1",
            "status": status, "enable": enable, "mask": 0x200,
            "vector_target": 0x1000000, "wrapper": 0xa0,
            "handler_slot": 0x1000040, "handler": 0x1001000,
            "handler_validation_size": 0x20, "callback_slot": 0x1000080,
            "outer_callback": 0x60, "drain": 0x80, "drain_loop": 0x90,
            "status_banks": (status, status + 4, status + 0x30),
            "clear_banks": (status, status + 4, enable + 0x38),
            "controller_write_banks": (enable, enable + 4, enable + 0x30),
            "controller_aperture": (status, enable + 0x3a),
            "status_bank_count": 3, "group_row_size": 14}
        self.encoded = "3000c80:3000c94:200:4c4b40:1000000:a0:1000040:1001000:20:1000080:60:3"

    def check(self, bridge=None, route=None, encoded=None):
        with patch.object(MODULE, "find_rex_legacy_5ms_timer_bridge",
                          return_value=self.bridge if bridge is None else bridge), \
             patch.object(MODULE, "find_rex_legacy_5ms_irq_route",
                          return_value=self.route if route is None else route), \
             patch.object(MODULE, "c80_rex_irq_profile",
                          return_value=self.encoded if encoded is None else encoded):
            return MODULE.row_timer_profile(bytes(self.image), self.config, self.matrix)

    def test_source_route_matches_the_same_scanner_callback_and_copy(self):
        encoded, profile = self.check()
        self.assertEqual(encoded, self.encoded)
        self.assertEqual(profile["timer_bridge"], self.bridge)
        def timer(source, scanner, forward, reverse):
            self.assertEqual(len(source), 0x180)
            self.assertEqual(scanner, 0x20)
            self.assertEqual(forward(0x108), 0x1001008)
            self.assertEqual(reverse(0x1001008), 0x108)
            self.assertIsNone(reverse(0x200))
            return self.bridge
        with patch.object(MODULE, "find_rex_legacy_5ms_timer_bridge", side_effect=timer), \
             patch.object(MODULE, "find_rex_legacy_5ms_irq_route", return_value=self.route), \
             patch.object(MODULE, "c80_rex_irq_profile", return_value=self.encoded):
            self.assertEqual(MODULE.row_timer_profile(bytes(self.image), self.config,
                                                    self.matrix)[0], self.encoded)

    def test_independent_or_incomplete_routes_do_not_enable_a_controller(self):
        for field, value in (("scanner", 0x22), ("tick_ms", 10)):
            self.assertEqual(self.check(bridge={**self.bridge, field: value}), (None, None))
        for field, value in (("outer_callback", 0x62), ("drain", 0x82),
                             ("drain_loop", 0x92), ("mask", 0x400),
                             ("status_bank_count", 2)):
            self.assertEqual(self.check(route={**self.route, field: value}), (None, None))
        self.assertEqual(self.check(encoded="different"), (None, None))
        self.matrix["presence_site"] = 0x180
        self.assertEqual(self.check(), (None, None))

    def test_registered_leading_literal_entry_is_linked_to_its_field_use(self):
        image = bytearray(0x100)
        # LDR r0, [PC, #0x5c]; PUSH; LDRB r1, [r0, #4].
        struct.pack_into("<H", image, 0x20, 0x4817)
        struct.pack_into("<HH", image, 0x22, 0xB510, 0x7901)
        for address in range(0x26, 0x42, 2):
            struct.pack_into("<H", image, address, 0x46C0)
        struct.pack_into("<H", image, 0x42, 0x4770)
        struct.pack_into("<I", image, 0x80, 0x01000000)
        self.assertEqual(_leading_literal_entry(bytes(image), 0x22, 0x40), 0x20)

        matrix = {**self.matrix, "presence_site": 0x40}
        bridge = {**self.bridge, "scanner": 0x20,
                  "scanner_file_offset": 0x20}
        def timer(source, scanner, forward, reverse):
            return bridge if scanner == 0x20 else None
        with patch.object(MODULE, "find_rex_legacy_5ms_timer_bridge",
                          side_effect=timer), \
             patch.object(MODULE, "find_rex_legacy_5ms_irq_route",
                          return_value=self.route), \
             patch.object(MODULE, "c80_rex_irq_profile",
                          return_value=self.encoded):
            encoded, profile = MODULE.row_timer_profile(bytes(image), self.config,
                                                         matrix)
        self.assertEqual(encoded, self.encoded)
        self.assertEqual(profile["timer_bridge"], bridge)

        # A nearby literal-load instruction does not recover the function
        # entry when the same function no longer uses that loaded pointer.
        bad = bytearray(image)
        struct.pack_into("<H", bad, 0x24, 0x7909)  # LDRB r1, [r1, #4].
        self.assertIsNone(_leading_literal_entry(bytes(bad), 0x22, 0x40))

    def test_indexed_slot_route_is_input_owned_and_uses_two_status_banks(self):
        matrix = {**self.matrix, "grammar": "pair-row-halfword-seven-v1"}
        self.config.ram_base, self.config.ram_size = 0x1000000, 0x8000
        route = {**self.route, "period": 5, "bank_count": 2, "group_row_size": 10,
                 "group_count": 3, "handler": 0xc0}
        encoded = "3000c80:3000c94:200:4c4b40:1000000:a0:1000040:c0:20:1000080:60"
        with patch.object(MODULE, "find_rex_legacy_5ms_timer_bridge", return_value=self.bridge), \
             patch.object(MODULE, "source_slot_controller_candidate", return_value=route) as candidate:
            actual, profile = MODULE.row_timer_profile(bytes(self.image), self.config, matrix)
        self.assertEqual(actual, encoded)
        self.assertEqual(profile["route_source"], "indexed-slot-controller-v1")
        self.assertEqual(candidate.call_args.args, (bytes(self.image[:0x180]), self.config))
        self.assertFalse(hasattr(self.config, "rex_static_controller_candidate"))
        for field, value in (("bank_count", 3), ("outer_callback", 0x62),
                             ("handler_slot", 0x1008000), ("wrapper", 0xa2),
                             ("handler_validation_size", 0x100), ("period", 25),
                             ("group_row_size", 12)):
            with self.subTest(field=field), \
                 patch.object(MODULE, "find_rex_legacy_5ms_timer_bridge", return_value=self.bridge), \
                 patch.object(MODULE, "source_slot_controller_candidate",
                              return_value={**route, field: value}):
                self.assertEqual(MODULE.row_timer_profile(bytes(self.image), self.config, matrix),
                                 (None, None))

    def test_loaded_indexed_slot_clock_reproves_the_same_source_plan(self):
        timer = {"route_source": "indexed-slot-controller-v1", "timer_bridge": self.bridge}
        plan = SimpleNamespace(matrix_input_profile={**self.matrix, "scanner_timer": timer},
                               config=self.config, rex_c80_profile=self.encoded)
        with patch.object(MODULE, "row_timer_profile", return_value=(self.encoded, timer)) as prove:
            self.assertTrue(MODULE.loaded_row_timer_matches(plan, bytes(self.image), 0x180))
            self.assertEqual(prove.call_args.args[0], bytes(self.image[:0x180]))
        for result in ((None, None), ("changed", timer),
                       (self.encoded, {**timer, "timer_bridge": {}})):
            with patch.object(MODULE, "row_timer_profile", return_value=result):
                self.assertFalse(MODULE.loaded_row_timer_matches(plan, bytes(self.image), 0x180))
        self.assertFalse(MODULE.loaded_row_timer_matches(plan, bytes(self.image), 0x202))
