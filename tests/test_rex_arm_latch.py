"""Focused tests for detector-closed REX timer arm writes."""
from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from unittest.mock import patch

from msm5xxx_emulator.core.emulator import GenericMSMEmulator
from unicorn import UC_ARCH_ARM
from unicorn import UC_MODE_ARM
from unicorn import Uc


ARM = 0x030006E0


def config() -> SimpleNamespace:
    return SimpleNamespace(
        rex_tick_address=0x2000,
        rex_tick_ms=5,
        rex_irq_wrapper_address=0x3000,
        rex_irq_handler_address=0x3100,
        rex_irq_status_address=0x03000620,
        rex_irq_enable_address=0x03000628,
        rex_irq_mask=0x0200,
        rex_irq_arm_address=ARM,
    )


class RexArmLatchTest(unittest.TestCase):
    def test_exact_byte_write_enables_otherwise_valid_tick(self) -> None:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = config()
        emulator.rex_idle_entries = 0
        emulator.rex_ticks = 0
        emulator.rex_elapsed_ms = 0
        emulator.rex_next_instruction = 0
        emulator.instructions = 100
        emulator._rex_irq_pending = [0, 0]
        emulator._rex_tick_return_address = None
        emulator._rex_tick_context = None
        emulator._rex_irq_arm_required = True
        emulator._rex_irq_armed = False
        emulator.rex_irq_arm_writes = 0
        emulator.rex_irq_arm_accepts = 0
        emulator.rex_irq_arm_last_value = None
        emulator.rex_irq_arm_instruction = None
        emulator._original_runtime_bytes = lambda address, size: b"\0" * size
        emulator._rex_firmware_matches = lambda *args, **kwargs: True
        emulator._rex_irq_route_valid = lambda *args, **kwargs: True

        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x3000)
        with patch("msm5xxx_emulator.soc.rex.rex_sleep_call_at", return_value=42):
            emulator._rex_tick(uc, 0x102E, 2, None)
            self.assertEqual(emulator.rex_ticks, 0)

            emulator._rex_irq_arm_write(uc, 0, ARM + 1, 1, 0x02, None)
            emulator._rex_irq_arm_write(uc, 0, ARM, 2, 0x02, None)
            emulator._rex_irq_arm_write(uc, 0, ARM, 1, 0x01, None)
            self.assertFalse(emulator._rex_irq_armed)
            emulator._rex_irq_arm_write(uc, 0, ARM, 1, 0x02, None)
            emulator._rex_tick(uc, 0x102E, 2, None)

        self.assertTrue(emulator._rex_irq_armed)
        self.assertEqual(emulator.rex_irq_arm_writes, 3)
        self.assertEqual(emulator.rex_irq_arm_accepts, 1)
        self.assertEqual(emulator.rex_ticks, 1)
        self.assertEqual(emulator._rex_irq_pending, [0x0200, 0])

    def test_install_requires_complete_detected_route(self) -> None:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.uc = Mock()
        complete = config()
        emulator._install_rex_irq_arm_hook(complete)
        self.assertTrue(emulator._rex_irq_arm_required)
        emulator.uc.hook_add.assert_called_once()

        emulator.uc.reset_mock()
        incomplete = config()
        incomplete.rex_irq_handler_address = None
        emulator._install_rex_irq_arm_hook(incomplete)
        self.assertFalse(emulator._rex_irq_arm_required)
        self.assertTrue(emulator._rex_irq_armed)
        emulator.uc.hook_add.assert_not_called()


if __name__ == "__main__":
    unittest.main()
