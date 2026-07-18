"""Tests for non-fault control-sink diagnostics."""
from __future__ import annotations

from collections import deque
import unittest

from msm5xxx import GenericMSMEmulator


class ControlSinkTests(unittest.TestCase):
    def test_sustained_single_block_is_reported(self) -> None:
        self.assertEqual(
            GenericMSMEmulator._control_sink_from_tail(
                deque([0x832AC] * 32), bytes.fromhex("fee70000")
            ),
            0x832AC,
        )

    def test_short_or_mixed_tail_is_not_a_sink(self) -> None:
        self.assertIsNone(GenericMSMEmulator._control_sink_from_tail(
            [0x1000] * 31, bytes.fromhex("fee70000")
        ))
        self.assertIsNone(
            GenericMSMEmulator._control_sink_from_tail(
                [0x1000] * 31 + [0x1002], bytes.fromhex("fee70000")
            )
        )
        self.assertIsNone(
            GenericMSMEmulator._control_sink_from_tail(
                [0x2002] * 32, bytes.fromhex("08c903701b0a4370")
            )
        )


if __name__ == "__main__":
    unittest.main()
