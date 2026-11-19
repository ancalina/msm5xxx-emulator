"""Synthetic source-closure tests for the two-bank row timer route."""
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.detection.registry import device_domain

rule = device_domain("input.two_bank_row_timer")


class _Copy:
    def __init__(self, source, target, size, evidence):
        self.source = source
        self.target = target
        self.size = size
        self.evidence = tuple(evidence)

    def source_address(self, address, size):
        if (type(address) is not int or type(size) is not int or size < 0
                or address < self.target or address + size > self.target + self.size):
            return None
        return self.source + address - self.target


class TwoBankRowTimerTests(unittest.TestCase):
    def setUp(self):
        self.image = bytearray(0x400)
        # Independent Thumb scanner entry; the timer bridge finder is stubbed
        # so this fixture only exercises the route's additional ownership.
        struct.pack_into("<H", self.image, 0x20, 0x4770)
        self.handler_file = 0x80
        for address, word in ((0x80, 0xB500),       # PUSH {lr}
                              (0x82, 0x4803),       # LDR r0, [PC, #12]
                              (0x84, 0x46C0),       # MOV r8, r8
                              (0x86, 0x46C0),       # MOV r8, r8
                              (0x88, 0x4F02),       # LDR r7, [PC, #8]
                              (0x8A, 0x4770)):      # BX lr
            struct.pack_into("<H", self.image, address, word)
        self.ram_base = 0x01000000
        self.vector = self.ram_base
        self.mask_table = self.ram_base + 0x1100
        self.group_table = self.ram_base + 0x1120
        struct.pack_into("<II", self.image, 0x90, self.group_table, self.mask_table)
        self.config = SimpleNamespace(flash_size=len(self.image),
            ram_base=self.ram_base, ram_size=0x4000, overlays=[], linker=None)
        self.bridge = {"scanner": 0x20, "scanner_file_offset": 0x20,
            "tick_ms": 5, "outer_callback": 0x60, "drain": 0x70,
            "drain_loop_caller": 0x72}
        status, enable = 0x03000C80, 0x03000C94
        self.route = {
            "controller_class": "legacy-c80-two-bank-group10-v1",
            "status": status, "enable": enable, "mask": 0x0200,
            "vector_target": self.vector, "wrapper": 0xA0,
            "wrapper_file_offset": 0xA0, "wrapper_validation_size": 0x20,
            "handler_slot": self.ram_base + 0x40,
            "handler": self.ram_base + self.handler_file,
            "handler_file_offset": self.handler_file,
            "handler_validation_size": 0x20,
            "callback_slot": self.ram_base + 0x1174,
            "outer_callback": 0x60, "drain": 0x70, "drain_loop": 0x72,
            "rom_seed": 0x2A0, "handler_setter_file_offset": 0xB0,
            "registrar_file_offset": 0xC0,
            "status_banks": (status, status + 4),
            "clear_banks": (status, status + 4),
            "controller_write_banks": (enable, enable + 4),
            "controller_aperture": (status, enable + 6),
            "status_bank_count": 2, "group_row_size": 10,
            "index": 30,
        }
        vector_branch = 0xEA000000 | ((self.route["wrapper"] - self.vector - 8) // 4 & 0xFFFFFF)
        struct.pack_into("<I", self.image, 0x180, vector_branch)
        self.group_proof = {
            "group_row_size": 10, "group_count": 3, "timer_group": 3,
            "group_table": self.group_table,
            "group_table_source": 0x26A,
            "group_records": ((1, 1, 1, 1, 1, 28),
                              (1, 2, 3, 4, 29, 29),
                              (0x200, 0, 0x200, 4, 30, 30)),
            "source_sites": ((0xD0, 2), (0xD2, 2), (0xD4, 2),
                             (0xD6, 2), (0xD8, 2), (0xDA, 2), (0xDC, 2)),
        }

    def _copy(self, target, _requested_size):
        if target == self.vector:
            return _Copy(0x180, target, 0x140, ((0x150, 4), (0x160, 8)))
        return _Copy(0x240, target, 0x80, ((0x240, 0x50),))

    def check(self, *, route=None, vector_copy=True, data_copy=True,
              group_result="valid", changed_mask_load=None, vector_word=None):
        image = bytearray(self.image)
        if changed_mask_load is not None:
            struct.pack_into("<H", image, self.handler_file + 8, changed_mask_load)
        if vector_word is not None:
            struct.pack_into("<I", image, 0x180, vector_word)
        active_route = self.route if route is None else route

        def copy_for(source, spans, **kwargs):
            target, size = spans[0]
            if target == self.vector:
                return self._copy(target, size) if vector_copy else None
            return self._copy(target, size) if data_copy else None

        if group_result == "valid":
            proof = lambda _image, _handler, table, _copy, *_args: (
                dict(self.group_proof) if table == self.group_table else None)
        elif group_result == "ambiguous":
            proof = lambda _image, _handler, table, _copy, *_args: (
                {**self.group_proof, "group_table": table,
                 "group_table_source": 0x240 + table - self.mask_table + 10} if table in
                (self.group_table, self.mask_table) else None)
        else:
            proof = lambda *_args: None

        with patch.object(rule, "find_rex_legacy_5ms_timer_bridge",
                          return_value=self.bridge), \
             patch.object(rule, "find_rex_legacy_5ms_irq_route",
                          return_value=active_route), \
             patch.object(rule, "reset_linked_input_copy", side_effect=copy_for), \
             patch.object(rule, "two_bank_handler_source", return_value=True), \
             patch.object(rule, "group_stride_proof", side_effect=proof):
            return rule.reset_owned_two_bank_route(bytes(image), self.config,
                                                   self.bridge, active_route)

    def test_source_closed_route_exposes_only_two_bank_five_ms_contract(self):
        result = self.check()
        self.assertIsNotNone(result)
        self.assertEqual((result["status"], result["enable"], result["mask"]),
                         (0x03000C80, 0x03000C94, 0x0200))
        self.assertEqual((result["period"], result["bank_count"],
                          result["group_row_size"], result["group_count"]),
                         (5, 2, 10, 3))
        self.assertEqual(result["mask_table"], self.mask_table)
        self.assertEqual(result["group_table"], self.group_table)
        self.assertEqual(result["vector_copy_target"], self.vector)
        self.assertEqual(result["route_source"], "reset-owned-two-bank-group10-v1")

    def test_rejects_wrong_mask_register_missing_vector_or_unowned_data(self):
        self.assertIsNone(self.check(changed_mask_load=0x4E02))  # LDR r6, [PC]
        self.assertIsNone(self.check(vector_copy=False))
        self.assertIsNone(self.check(data_copy=False))

    def test_rejects_predicated_handler_and_unproved_or_ambiguous_group_table(self):
        image = bytearray(self.image)
        struct.pack_into("<H", image, 0x84, 0xBF08)  # IT EQ
        with patch.object(rule, "find_rex_legacy_5ms_timer_bridge",
                          return_value=self.bridge), \
             patch.object(rule, "find_rex_legacy_5ms_irq_route",
                          return_value=self.route), \
             patch.object(rule, "reset_linked_input_copy",
                          side_effect=lambda _image, spans, **_kw:
                              self._copy(*spans[0])), \
             patch.object(rule, "two_bank_handler_source", return_value=True):
            self.assertIsNone(rule.reset_owned_two_bank_route(bytes(image),
                self.config, self.bridge, self.route))
        self.assertIsNone(self.check(group_result="none"))
        self.assertIsNone(self.check(group_result="ambiguous"))

    def test_rederives_route_and_checks_controller_metadata(self):
        self.assertIsNone(self.check(route={**self.route, "mask": 0x0400}))
        self.assertIsNone(self.check(route={**self.route, "group_row_size": 12}))
        self.assertIsNone(self.check(route={**self.route, "drain_loop": 0x74}))
        self.assertIsNone(self.check(route={**self.route, "rom_seed": 0x2A4}))

    def test_copied_vector_must_branch_to_the_same_wrapper(self):
        branch = struct.unpack_from("<I", self.image, 0x180)[0]
        for word in (0, 0xEAFFFFFE, branch + 1, branch & 0x0FFFFFFF | 0x10000000):
            with self.subTest(word=word):
                self.assertIsNone(self.check(vector_word=word))


if __name__ == "__main__":
    unittest.main()
