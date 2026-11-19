"""Synthetic event labels projected onto independent row and sense wiring."""
from copy import deepcopy
from types import SimpleNamespace
import unittest

from msm5xxx_emulator.detection.devices.input.event_projection import _matrix_input_position
from msm5xxx_emulator.detection.devices.input.transport_projection.halfword import matrix_input_command
from msm5xxx_emulator.detection.registry import device_domain

HOST_INPUT = device_domain("input.transport_projection").HOST_INPUT


class PairProjectionTests(unittest.TestCase):
    def setUp(self):
        self.cells = [(6, 3), (4, 2), (0, 0), (1, 1), (3, 2), (2, 3),
                      (5, 0), (0, 1), (1, 2), (2, 2), (3, 3), (4, 0)]
        self.events = list(b"123456789*0#")
        table = [0] * 28
        for event, (row, column) in zip(self.events, self.cells):
            table[column * 7 + row] = event
        self.profile = dict(grammar="pair-row-halfword-seven-v1", rows=7,
            columns=4, no_key=15, event_codes=table,
            row_wire_order=[6, 0, 3, 1, 5, 2, 4],
            single_key_column_sense=[11, 7, 14, 13])
        self.owner = SimpleNamespace(matrix_input_profile=self.profile)

    def test_numeric_contacts_use_both_source_permutations(self):
        expected_rows = [4, 5, 6, 0, 1, 3, 2, 6, 0, 3, 1, 5]
        expected_senses = [13, 14, 11, 7, 14, 13, 11, 7, 14, 14, 13, 11]
        for bit, event, cell, row, sense in zip(range(11, 23), self.events,
                self.cells, expected_rows, expected_senses):
            with self.subTest(event=event):
                position = _matrix_input_position(self.owner, bit, None)
                self.assertEqual(position, (event, *cell))
                self.assertEqual(matrix_input_command(self.profile, position, True),
                                 bytes((HOST_INPUT, 1, row, sense)))

    def test_unknown_or_ambiguous_event_is_unavailable(self):
        self.assertIsNone(_matrix_input_position(self.owner, 0, None))
        self.assertIsNone(_matrix_input_position(self.owner, 11, 0x91))
        self.profile["event_codes"][1] = ord("1")
        self.assertIsNone(_matrix_input_position(self.owner, 11, None))

    def test_invalid_row_permutation_rejects(self):
        profile = deepcopy(self.profile)
        profile["row_wire_order"] = [0] * 7
        with self.assertRaises(ValueError):
            matrix_input_command(profile, (ord("1"), 6, 3), True)

    def test_release_preserves_idle_packet(self):
        self.assertEqual(matrix_input_command(self.profile, None, False),
                         bytes((HOST_INPUT, 0, 0, 0)))


if __name__ == "__main__":
    unittest.main()
