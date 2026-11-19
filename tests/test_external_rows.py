"""Synthetic source-shape checks for external-latch six-row keypads."""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from capstone import arm as a

from msm5xxx_emulator.detection.devices.input.external_rows import (
    _event_codes, _event_handlers, _handlers_share_row_index,
    _row_wire_order,
)
from msm5xxx_emulator.detection.facts import CodeAddress
from msm5xxx_emulator.detection.values import SymbolicValue


class ExternalRowsTests(unittest.TestCase):
    def test_row_order_uses_both_output_ports(self):
        self.assertEqual(_row_wire_order((0x8000, 0x800, 0x40, 0x10,
                                         0x10000, 0x20000)), [3, 2, 1, 0, 4, 5])
        self.assertEqual(_row_wire_order((0x40, 0x800, 0x10, 0x8000,
                                         0x10000, 0x20000)), [1, 2, 0, 3, 4, 5])
        self.assertIsNone(_row_wire_order((0x8000, 0x800, 0x40, 0x10,
                                          0x10000, 0x10000)))
        self.assertIsNone(_row_wire_order((0x8000, 0x800, 0x40, 0x10,
                                          0x10000, 0x20004)))

    def test_low_five_sense_selects_active_low_column_and_row_cell(self):
        from msm5xxx_emulator.detection.devices.input.external_rows_cells import _sense_capture_matches
        table = 0x3000
        self.assertTrue(_sense_capture_matches(0x1e, 2, table + 2, table))
        self.assertTrue(_sense_capture_matches(0x1d, 4, table + 6 + 4, table))
        # A reversed bit order or active-high interpretation points elsewhere.
        self.assertFalse(_sense_capture_matches(0x1e, 2, table + 4 * 6 + 2, table))
        self.assertFalse(_sense_capture_matches(0x01, 2, table + 2, table))
        self.assertFalse(_sense_capture_matches(0x1d, 4, table + 4, table))

    def test_event_table_is_bounded_and_numeric(self):
        table = b"0123456789*#abcdefghijklmnopqr"
        self.assertEqual(_event_codes(table, 0, 0), list(table))
        self.assertIsNone(_event_codes(table[:-1], 0, 0))
        self.assertIsNone(_event_codes(bytes(30), 0, 0))

    @staticmethod
    def _calls(press_event_register="r0", release_event_register="r1",
               release_auxiliary=0xff, same_target=True):
        # Symbolic load sites model the event byte propagated from LDRB.
        press_load = SymbolicValue("load", width=1,
                                   site=SimpleNamespace(address=0x100))
        release_load = SymbolicValue("load", width=1,
                                     site=SimpleNamespace(address=0x200))
        press_regs = ((a.ARM_REG_R0, press_load), (a.ARM_REG_R1,
                       SymbolicValue.const(0)))
        release_regs = ((a.ARM_REG_R0,
                         SymbolicValue.const(release_auxiliary)),
                        (a.ARM_REG_R1, release_load))
        press = SimpleNamespace(site=SimpleNamespace(address=0x300),
                                target=SimpleNamespace(address=0x500),
                                registers=press_regs)
        release = SimpleNamespace(site=SimpleNamespace(address=0x400),
                                  target=SimpleNamespace(address=0x500 if same_target else 0x600),
                                  registers=release_regs)
        return SimpleNamespace(call_sites=(press, release))

    def test_event_handlers_preserve_distinct_call_abis(self):
        handlers = _event_handlers(self._calls())
        self.assertEqual([(h["event_register"], h["auxiliary_register"],
                           h["auxiliary_value"], h["event_load"])
                          for h in handlers],
                         [(0, 1, 0, 0x100), (1, 0, 0xff, 0x200)])

    def test_event_handlers_reject_unlinked_or_malformed_calls(self):
        self.assertIsNone(_event_handlers(self._calls(same_target=False)))
        self.assertIsNone(_event_handlers(self._calls(release_auxiliary=0)))

    def test_call_event_loads_must_share_scanned_row_index(self):
        handlers = _event_handlers(self._calls())
        matching_load = SimpleNamespace(
            id=a.ARM_INS_LDRB,
            operands=[SimpleNamespace(type=a.ARM_OP_REG),
                      SimpleNamespace(type=a.ARM_OP_MEM,
                                      mem=SimpleNamespace(index=a.ARM_REG_R5))])
        wrong_index_load = SimpleNamespace(
            id=a.ARM_INS_LDRB,
            operands=[SimpleNamespace(type=a.ARM_OP_REG),
                      SimpleNamespace(type=a.ARM_OP_MEM,
                                      mem=SimpleNamespace(index=a.ARM_REG_R4))])
        sites = {CodeAddress(h["event_load"]): matching_load for h in handlers}
        facts = SimpleNamespace(decode=lambda site: sites[site])
        self.assertTrue(_handlers_share_row_index(handlers, facts, a.ARM_REG_R5))
        facts.decode = lambda site: wrong_index_load
        self.assertFalse(_handlers_share_row_index(handlers, facts, a.ARM_REG_R5))


if __name__ == "__main__":
    unittest.main()

class ExternalRowsFlowTests(unittest.TestCase):
    @staticmethod
    def _instruction(address, ident, operands, reads=(), writes=()):
        return CodeAddress(address), SimpleNamespace(
            id=ident, operands=operands,
            regs_access=lambda: (tuple(reads), tuple(writes)))

    @staticmethod
    def _reg(reg):
        return SimpleNamespace(type=a.ARM_OP_REG, reg=reg)

    @staticmethod
    def _imm(value):
        return SimpleNamespace(type=a.ARM_OP_IMM, imm=value)

    @staticmethod
    def _mem(base, disp=0, index=0):
        return SimpleNamespace(type=a.ARM_OP_MEM,
                               mem=SimpleNamespace(base=base, disp=disp,
                                                   index=index))

    def test_candidate_table_base_must_match_the_linked_literal(self):
        from msm5xxx_emulator.detection.devices.input.external_rows import _same_row_counter
        from msm5xxx_emulator.detection.devices.input.external_rows_cells import _linked_table_base
        site = CodeAddress(0x180)
        sub = SimpleNamespace(id=a.ARM_INS_SUB,
            operands=[self._reg(a.ARM_REG_R1), self._imm(0x38)])
        function = object()
        facts = SimpleNamespace(decode=lambda address: sub,
            register_value=lambda function, address, register: 0x2000)
        self.assertEqual(_linked_table_base(function, facts, site,
                                             0x2000, 0x1fc8), a.ARM_REG_R1)
        self.assertIsNone(_linked_table_base(function, facts, site,
                                              0x3000, 0x2fc8))
        self.assertIsNone(_linked_table_base(function, facts, site,
                                              0x2000, 0x1f00))
        self.assertTrue(_same_row_counter(a.ARM_REG_R5, a.ARM_REG_R5))
        self.assertFalse(_same_row_counter(a.ARM_REG_R5, a.ARM_REG_R4))

    def test_row_counter_copy_stays_live_for_both_tuple_halves(self):
        from msm5xxx_emulator.detection.devices.input.external_rows import _row_index_live
        row, derived, pointer, output = (a.ARM_REG_R5, a.ARM_REG_R4,
                                        a.ARM_REG_R6, a.ARM_REG_R3)
        init_site, copy_site = CodeAddress(0x400), CodeAddress(0x404)
        first_load, high_add, second_load = (CodeAddress(pc) for pc in
                                             (0x408, 0x420, 0x424))
        def inst(ident, operands, reads=(), writes=()):
            return SimpleNamespace(id=ident, operands=operands,
                regs_access=lambda: (tuple(reads), tuple(writes)))
        code = {
            init_site: inst(a.ARM_INS_MOV,
                [self._reg(row), self._imm(0)], (), (row,)),
            copy_site: inst(a.ARM_INS_LSL,
                [self._reg(derived), self._reg(row), self._imm(2)],
                (row,), (derived,)),
            first_load: inst(a.ARM_INS_LDRH,
                [self._reg(output), self._mem(pointer, index=derived)],
                (pointer, derived), (output,)),
            high_add: inst(a.ARM_INS_ADD,
                [self._reg(output), self._reg(pointer), self._reg(derived)],
                (pointer, derived), (output,)),
            second_load: inst(a.ARM_INS_LDRH,
                [self._reg(output), self._mem(output, 2)], (output,), (output,)),
        }
        class Function:
            instructions = tuple(code)
            dominates = staticmethod(lambda _first, _second: True)
        facts = SimpleNamespace(decode=lambda site: code[site])
        self.assertTrue(_row_index_live(Function(), facts, first_load,
                                        derived, row, first_load))
        self.assertTrue(_row_index_live(Function(), facts, high_add,
                                        derived, row, second_load))
        stale_site = CodeAddress(0x406)
        code[stale_site] = inst(a.ARM_INS_MOV,
            [self._reg(row), self._imm(1)], (row,), (row,))
        Function.instructions = tuple(sorted(code, key=lambda site: site.address))
        self.assertFalse(_row_index_live(Function(), facts, first_load,
                                         derived, row, first_load))
        del code[stale_site]
        stale_site = CodeAddress(0x41e)
        code[stale_site] = inst(a.ARM_INS_MOV,
            [self._reg(row), self._imm(1)], (row,), (row,))
        Function.instructions = tuple(sorted(code, key=lambda site: site.address))
        self.assertFalse(_row_index_live(Function(), facts, high_add,
                                         derived, row, second_load))

    def test_loop_multiply_must_use_the_proven_counter(self):
        from msm5xxx_emulator.detection.devices.input.external_rows_cells import _indexed_mul
        multiply = CodeAddress(0x120)
        ins = SimpleNamespace(id=a.ARM_INS_MUL, mnemonic="muls",
            operands=[self._reg(a.ARM_REG_R2), self._reg(a.ARM_REG_R2),
                      self._reg(a.ARM_REG_R3)])
        function = SimpleNamespace(instructions=(multiply,))
        facts = SimpleNamespace(decode=lambda site: ins,
            register_value=lambda function, site, reg:
                6 if reg == a.ARM_REG_R3 else None)
        loop = {"target": 0x100, "counter": a.ARM_REG_R0,
                "compare": CodeAddress(0x140)}
        self.assertIsNone(_indexed_mul(function, facts, loop))
        loop["counter"] = a.ARM_REG_R2
        self.assertEqual(_indexed_mul(function, facts, loop), multiply)

    def test_register_and_saved_stack_source_must_survive_until_use(self):
        from msm5xxx_emulator.detection.devices.input.external_rows_cells import (
            _register_unchanged, _stack_slot_survives)
        start, overwrite, sink = (CodeAddress(pc) for pc in (0x200, 0x208, 0x210))
        reg = a.ARM_REG_R4
        clobber = SimpleNamespace(id=a.ARM_INS_MOV,
            operands=[self._reg(reg), self._imm(0)],
            regs_access=lambda: ((reg,), (reg,)))
        good = SimpleNamespace(id=a.ARM_INS_ADD,
            operands=[self._reg(reg), self._reg(a.ARM_REG_R1), self._reg(a.ARM_REG_R2)],
            regs_access=lambda: ((a.ARM_REG_R1, a.ARM_REG_R2), (reg,)))
        class CodeFunction:
            instructions = (start, sink)
        decoded = {start: good, sink: good}
        facts = SimpleNamespace(decode=lambda site: decoded[site])
        self.assertTrue(_register_unchanged(CodeFunction(), facts, reg, start, sink))
        CodeFunction.instructions = (start, overwrite, sink)
        decoded[overwrite] = clobber
        self.assertFalse(_register_unchanged(CodeFunction(), facts, reg, start, sink))

        def store(site):
            return SimpleNamespace(id=a.ARM_INS_STR, mnemonic="str",
                operands=[self._reg(a.ARM_REG_R0), self._mem(a.ARM_REG_SP, 40)])
        first = CodeAddress(0x300)
        later = CodeAddress(0x308)
        final = CodeAddress(0x310)
        decoded.update({first: store(first), later: store(later), final: good})
        CodeFunction.instructions = (first, final)
        self.assertTrue(_stack_slot_survives(CodeFunction(), facts, first, 40,
                                             [final]))
        CodeFunction.instructions = (first, later, final)
        self.assertFalse(_stack_slot_survives(CodeFunction(), facts, first, 40,
                                              [final]))

    def test_row_tuple_mask_and_shadow_must_reach_port_store(self):
        from msm5xxx_emulator.detection.devices.input.external_rows import _tainted_port_store
        r0, r1, r2, r3, r4, r5, r6 = (a.ARM_REG_R0 + i for i in range(7))
        encoded = [
            self._instruction(0x100, a.ARM_INS_LDR, [self._reg(r1), self._mem(r4, 4)], (r4,), (r1,)),
            self._instruction(0x102, a.ARM_INS_MVN, [self._reg(r3), self._reg(r7 := a.ARM_REG_R7)], (r7,), (r3,)),
            self._instruction(0x104, a.ARM_INS_AND, [self._reg(r1), self._reg(r3)], (r1, r3), (r1,)),
            self._instruction(0x106, a.ARM_INS_LDRH, [self._reg(r2), self._mem(r5, index=r6)], (r5, r6), (r2,)),
            self._instruction(0x108, a.ARM_INS_LDR, [self._reg(r3), self._mem(a.ARM_REG_PC)], (), (r3,)),
            self._instruction(0x10a, a.ARM_INS_AND, [self._reg(r2), self._reg(r3)], (r2, r3), (r2,)),
            self._instruction(0x10c, a.ARM_INS_ORR, [self._reg(r1), self._reg(r2)], (r1, r2), (r1,)),
            self._instruction(0x10e, a.ARM_INS_STR, [self._reg(r1), self._mem(r4, 4)], (r1, r4), ()),
            self._instruction(0x110, a.ARM_INS_LDR, [self._reg(r5), self._mem(a.ARM_REG_PC)], (), (r5,)),
            self._instruction(0x112, a.ARM_INS_STR, [self._reg(r1), self._mem(r5)], (r1, r5), ()),
        ]
        rows = dict(encoded)
        class Function:
            instructions = tuple(site for site, _ in encoded)
            accesses = (SimpleNamespace(operation="write", address=0x14000004,
                                       instruction=encoded[7][0]),
                        SimpleNamespace(operation="write", address=0x09000000,
                                       instruction=encoded[9][0]))
        class Facts:
            def decode(self, site): return rows[site]
            def register_value(self, function, site, reg):
                if reg == r4: return 0x14000000
                if reg == r7: return 0x8850
                if reg == r3 and site.address == 0x10a: return 0x8850
                return None
        self.assertTrue(_tainted_port_store(Function(), Facts(), encoded[3][0],
                                             0x09000000, 0x8850))
        self.assertFalse(_tainted_port_store(Function(), Facts(), encoded[3][0],
                                              0x09000000, 0x0800))
        shifted = list(encoded)
        shifted[5] = self._instruction(0x10a, a.ARM_INS_LSL,
            [self._reg(r2), self._reg(r2), self._imm(30)], (r2,), (r2,))
        shifted.insert(6, self._instruction(0x10b, a.ARM_INS_LSR,
            [self._reg(r2), self._reg(r2), self._imm(30)], (r2,), (r2,)))
        shifted[7] = self._instruction(0x10c, a.ARM_INS_ORR,
            [self._reg(r1), self._reg(r2)], (r1, r2), (r1,))
        shifted[8] = self._instruction(0x10e, a.ARM_INS_STR,
            [self._reg(r1), self._mem(r4, 4)], (r1, r4), ())
        shifted[9] = self._instruction(0x110, a.ARM_INS_LDR,
            [self._reg(r5), self._mem(a.ARM_REG_PC)], (), (r5,))
        shifted[10] = self._instruction(0x112, a.ARM_INS_STR,
            [self._reg(r1), self._mem(r5)], (r1, r5), ())
        rows.clear()
        rows.update(shifted)
        class ShiftedFunction(Function):
            instructions = tuple(site for site, _ in shifted)
            accesses = (SimpleNamespace(operation="write", address=0x14000004,
                                       instruction=shifted[8][0]),
                        SimpleNamespace(operation="write", address=0x09000000,
                                       instruction=shifted[10][0]))
        self.assertFalse(_tainted_port_store(ShiftedFunction(), Facts(),
            shifted[3][0], 0x09000000, 0x8850))
        rows.clear()
        rows.update(encoded)
        clobbered = list(encoded)
        clobbered.insert(-1, self._instruction(0x111, a.ARM_INS_MOV,
            [self._reg(r1), self._imm(0)], (r1,), (r1,)))
        rows = dict(clobbered)
        class ClobberedFunction(Function):
            instructions = tuple(site for site, _ in clobbered)
        self.assertFalse(_tainted_port_store(ClobberedFunction(), Facts(),
            encoded[3][0], 0x09000000, 0x8850))

        for clobber_register in (r1, r2):
            mutated = list(encoded)
            orr_index = next(index for index, (site, _) in enumerate(mutated)
                             if site.address == 0x10c)
            mutated.insert(orr_index, self._instruction(0x10b, a.ARM_INS_MOV,
                [self._reg(clobber_register), self._imm(0)],
                (clobber_register,), (clobber_register,)))
            rows.clear()
            rows.update(mutated)
            class PreCombineClobberFunction(Function):
                instructions = tuple(site for site, _ in mutated)
            self.assertFalse(_tainted_port_store(PreCombineClobberFunction(),
                Facts(), encoded[3][0], 0x09000000, 0x8850))
        rows.clear()
        rows.update(encoded)
