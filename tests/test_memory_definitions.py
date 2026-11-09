"""Synthetic reaching stores and conservative memory alias boundaries."""
import struct
import unittest

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts

CELL = 0x01000100


def words(*values):
    return struct.pack('<' + 'H' * len(values), *values)


def function(image, initial=None):
    facts = FirmwareFacts(image)
    result = facts.function(CodeAddress(0), initial_registers={
        a.ARM_REG_R4: CELL, **(initial or {}),
    }, symbolic_registers={})
    return facts, result


class MemoryDefinitionTests(unittest.TestCase):
    def test_exact_store_survives_disjoint_store_but_unknown_alias_does_not(self):
        # MOV r0,#1; STRB r0,[r4]; STRB r0,[r5]; LDRB r1,[r4]; BX LR.
        image = words(0x2001, 0x7020, 0x7028, 0x7821, 0x4770)
        facts, local = function(image, {a.ARM_REG_R5: CELL + 4})
        self.assertTrue(local.complete)
        self.assertEqual(facts.memory_definitions(local, CodeAddress(6), CELL, width=1),
                         (CodeAddress(2),))
        facts, local = function(image)
        self.assertIsNone(facts.memory_definitions(local, CodeAddress(6), CELL, width=1))

    def test_branch_alternatives_retain_distinct_reaching_stores(self):
        image = words(0x2001, 0x2900, 0xD001, 0x7020, 0xE000,
                      0x7022, 0x7823, 0x4770)
        facts, local = function(image)
        self.assertEqual(facts.memory_definitions(local, CodeAddress(12), CELL, width=1),
                         (CodeAddress(6), CodeAddress(10)))
        # One branch now leaves the cell's entry value untouched.
        image = bytearray(image)
        struct.pack_into('<H', image, 10, 0x46C0)
        facts, local = function(bytes(image))
        self.assertIsNone(facts.memory_definitions(local, CodeAddress(12), CELL, width=1))
        self.assertEqual(facts.memory_definitions(
            local, CodeAddress(12), CELL, width=1, include_entry=True),
            (None, CodeAddress(6)))

    def test_partial_wider_and_opaque_writes_do_not_establish_a_cell(self):
        for store in (0x8020, 0x6020, 0xC503):  # STRH; STR; STMIA unknown r5.
            facts, local = function(words(0x2001, 0x7020, store, 0x7821, 0x4770))
            self.assertTrue(local.complete)
            self.assertIsNone(facts.memory_definitions(local, CodeAddress(6), CELL, width=1))
        # An opaque direct call can change the cell after its scalar store.
        facts, local = function(words(0x2001, 0x7020, 0xF000, 0xF808, 0x7821, 0x4770) + bytes(32))
        self.assertIsNone(facts.memory_definitions(local, CodeAddress(8), CELL, width=1))

    def test_separately_closed_read_only_call_can_preserve_a_cell(self):
        image = bytearray(words(0x2001, 0x7020, 0xF000, 0xF806, 0x7821, 0x4770) + bytes(24))
        struct.pack_into('<H', image, 20, 0x4770)
        facts, local = function(bytes(image))
        callee = facts.function(CodeAddress(20), symbolic_registers={})
        self.assertTrue(callee.complete)
        self.assertEqual(facts.unmodelled_memory(callee), ())
        self.assertFalse(callee.calls or callee.symbolic_accesses)
        self.assertIsNone(facts.memory_definitions(local, CodeAddress(8), CELL, width=1))
        self.assertEqual(facts.memory_definitions(local, CodeAddress(8), CELL, width=1,
                                                 allowed_calls=(CodeAddress(4),)),
                         (CodeAddress(2),))

    def test_query_before_a_store_and_foreign_context_are_unknown(self):
        facts, local = function(words(0x7821, 0x7020, 0x4770))
        self.assertIsNone(facts.memory_definitions(local, CodeAddress(0), CELL, width=1))
        self.assertEqual(facts.memory_definitions(local, CodeAddress(0), CELL, width=1,
                                                 include_entry=True), (None,))
        self.assertIsNone(FirmwareFacts(bytes(8)).memory_definitions(local, CodeAddress(0), CELL, width=1))


if __name__ == '__main__':
    unittest.main()
