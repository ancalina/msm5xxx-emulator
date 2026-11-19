"""Synthetic numeric contacts on a permuted seven-row halfword matrix."""
from types import SimpleNamespace
import unittest

from msm5xxx_emulator.detection.devices.input.event_projection import _matrix_input_position
from msm5xxx_emulator.detection.devices.input.transport_projection.halfword import matrix_input_command
from msm5xxx_emulator.detection.registry import device_domain

HOST_INPUT = device_domain("input.transport_projection").HOST_INPUT


class MappedProjectionTests(unittest.TestCase):
    def setUp(self):
        self.indices = [2, 10, 18, 26, 6, 14, 22, 0, 8, 16, 24, 4]
        self.events = list(b"123456789*0#")
        table = [0xa0] * 28
        for index, event in zip(self.indices, self.events):
            table[index] = event
        self.order = [6, 0, 1, 2, 3, 4, 5]
        self.profile = dict(grammar="mapped-halfword-seven-row-v1",
            rows=7, columns=4, no_key=15, event_codes=table,
            row_wire_order=self.order, single_key_column_sense=[14, 13, 11, 7])
        self.owner = SimpleNamespace(matrix_input_profile=self.profile)

    def test_numeric_events_follow_source_row_permutation(self):
        for bit, event, index in zip(range(11, 23), self.events, self.indices):
            with self.subTest(event=event):
                row, column = index % 7, index // 7
                position = _matrix_input_position(self.owner, bit, None)
                self.assertEqual(position, (event, row, column))
                self.assertEqual(matrix_input_command(self.profile, position, True),
                    bytes((HOST_INPUT, 1, self.order[row], 15 ^ (1 << column))))

    def test_unknown_or_ambiguous_events_do_not_inject(self):
        self.assertIsNone(_matrix_input_position(self.owner, 0, None))
        self.assertIsNone(_matrix_input_position(self.owner, 11, 0xa0))
        self.profile["event_codes"][1] = ord("1")
        self.assertIsNone(_matrix_input_position(self.owner, 11, None))
        self.profile["row_wire_order"] = [0] * 7
        with self.assertRaises(ValueError):
            matrix_input_command(self.profile, (ord("2"), 3, 2), True)


if __name__ == "__main__":
    unittest.main()
