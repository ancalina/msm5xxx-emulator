"""Instruction event order follows control flow rather than file offsets."""
import struct
import unittest

from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts


def fixture(*words):
    facts = FirmwareFacts(struct.pack('<' + 'H' * len(words), *words))
    return facts, facts.function(CodeAddress(0))


class OrderedEventTests(unittest.TestCase):
    def test_reordered_basic_blocks_keep_the_execution_order(self):
        # Branch to first event at8, then back to event at2, then return at12.
        facts, function = fixture(0xE002, 0x2002, 0xE002, 0x46C0,
                                  0x2001, 0xE7FA, 0x4770)
        self.assertEqual(facts.ordered_events(function, (CodeAddress(2), CodeAddress(8))),
                         (CodeAddress(8), CodeAddress(2)))

    def test_optional_event_or_early_return_does_not_close_sequence(self):
        facts, function = fixture(0x2800, 0xD001, 0x2101, 0x46C0, 0x2202, 0x4770)
        self.assertIsNone(facts.ordered_events(function, (CodeAddress(4), CodeAddress(8))))
        facts, function = fixture(0x2800, 0xD001, 0x2101, 0x4770, 0x2202, 0x4770)
        self.assertIsNone(facts.ordered_events(function, (CodeAddress(4),)))

    def test_event_cycle_requires_an_exact_separately_justified_cut(self):
        facts, function = fixture(0x2001, 0x2900, 0xD1FC, 0x2202, 0x4770)
        sites = (CodeAddress(0), CodeAddress(6))
        self.assertIsNone(facts.ordered_events(function, sites))
        self.assertEqual(facts.ordered_events(function, sites,
                                              repeat_edges=((CodeAddress(4), CodeAddress(0)),)), sites)
        self.assertIsNone(facts.ordered_events(function, sites,
                                               repeat_edges=((CodeAddress(6), CodeAddress(0)),)))

    def test_foreign_or_incomplete_cfg_has_no_proved_order(self):
        facts, function = fixture(0x2001, 0x4770)
        self.assertIsNone(FirmwareFacts(bytes(16)).ordered_events(function, (CodeAddress(0),)))
        incomplete = facts.function(CodeAddress(0), budget=1)
        self.assertIsNone(facts.ordered_events(incomplete, (CodeAddress(0),)))


if __name__ == '__main__':
    unittest.main()
