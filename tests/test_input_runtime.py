"""Runtime evidence gate for candidate GPIO keypad profiles."""
from __future__ import annotations

from collections import Counter
from types import SimpleNamespace
import unittest

from msm5xxx import GenericMSMEmulator


class InputRuntimeTests(unittest.TestCase):
    def _emulator(self) -> GenericMSMEmulator:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(key_register=0x03000738)
        emulator.key_register_reads = 0
        emulator.key_read_epoch = 0
        emulator.key_register_read_pcs = Counter()
        emulator.key_press_read_epochs = {2: 0}
        emulator.held_keys = {2}
        emulator.input_events = 0
        emulator.firmware_key_events = 0
        emulator.input_error = "pending"
        return emulator

    def test_candidate_register_requires_read_after_press_before_consumer(self) -> None:
        emulator = self._emulator()

        emulator._input_entry_observed(None, 0, 0, None)
        self.assertEqual(emulator.input_events, 1)
        self.assertEqual(emulator.firmware_key_events, 0)

        emulator._record_key_register_read(0x03000738, 4, 0x1234)
        emulator._input_entry_observed(None, 0, 0, None)
        self.assertEqual(emulator.key_register_reads, 1)
        self.assertEqual(emulator.key_register_read_pcs, Counter({0x1234: 1}))
        self.assertEqual(emulator.firmware_key_events, 1)
        self.assertEqual(emulator.input_error, "")

    def test_unrelated_read_cannot_confirm_candidate_register(self) -> None:
        emulator = self._emulator()

        emulator._record_key_register_read(0x0300073C, 4, 0x1234)
        emulator._input_entry_observed(None, 0, 0, None)

        self.assertEqual(emulator.key_register_reads, 0)
        self.assertEqual(emulator.firmware_key_events, 0)


if __name__ == "__main__":
    unittest.main()
