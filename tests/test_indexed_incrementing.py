import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress
from msm5xxx_emulator.detection.registry import device_domain

indexed = device_domain("external_bus.indexed")


class IncrementingClearTest(unittest.TestCase):
    def test_nested_clear_rejects_counter_clobber(self):
        def reg(n): return NS(type=a.ARM_OP_REG, reg=n)
        def imm(n): return NS(type=a.ARM_OP_IMM, imm=n)
        def ins(op, *args, cc=None, writes=()):
            return NS(id=op, operands=args, cc=cc, regs_access=lambda: ((), writes))
        outer, inner = a.ARM_REG_R1, a.ARM_REG_R2
        code = {
            0x1e: ins(a.ARM_INS_MOV, reg(outer), imm(0)),
            0x2e: ins(a.ARM_INS_MOV, reg(inner), imm(0)),
            0x4c: ins(a.ARM_INS_ADD, reg(inner), imm(1)),
            0x4e: ins(a.ARM_INS_CMP, reg(inner), imm(176)),
            0x50: ins(a.ARM_INS_B, cc=a.ARM_CC_LO),
            0x5c: ins(a.ARM_INS_ADD, reg(outer), imm(1)),
            0x5e: ins(a.ARM_INS_CMP, reg(outer), imm(220)),
            0x60: ins(a.ARM_INS_B, cc=a.ARM_CC_LO),
            0x32: ins(a.ARM_INS_MOV, writes=(inner,)),
        }
        facts = NS(decode=lambda pc: code[pc.address])
        body = NS(back_edges=((0x50, 0x30), (0x60, 0x20)), instructions=())
        store = NS(value=0xffff, instruction=CodeAddress(0x40))
        with patch.object(indexed.indexed44_writer, '_writes', return_value=(store,)):
            self.assertEqual(indexed._increment_clear_counts(facts, body, 0x18000010), (176, 220))
            body.instructions = (CodeAddress(0x32),)
            self.assertIsNone(indexed._increment_clear_counts(facts, body, 0x18000010))
