"""Synthetic numeric contacts on a permuted five-column matrix."""
from types import SimpleNamespace
import unittest

from msm5xxx_emulator.detection.devices.input.event_projection import _matrix_input_position
from msm5xxx_emulator.detection.devices.input.transport_projection.halfword import matrix_input_command
from msm5xxx_emulator.detection.registry import device_domain

HOST_INPUT = device_domain("input.transport_projection").HOST_INPUT


class FiveColumnProjectionTests(unittest.TestCase):
    def setUp(self):
        self.indices = [2, 7, 12, 17, 22, 27, 4, 9, 14, 19, 24, 29]
        self.events = list(b"123456789*0#")
        table = [0xa0] * 30
        for index, event in zip(self.indices, self.events):
            table[index] = event
        self.order = [2, 3, 4, 5, 1, 0]
        self.profile = dict(grammar="halfword-five-column-rows-v1",
            rows=6, columns=5, no_key=31, event_codes=table,
            row_wire_order=self.order, single_key_column_sense=[30, 29, 27, 23, 15])
        self.owner = SimpleNamespace(matrix_input_profile=self.profile)

    def test_numeric_contacts_follow_all_five_columns_and_row_permutation(self):
        for bit, event, index in zip(range(11, 23), self.events, self.indices):
            with self.subTest(event=event):
                row, column = index % 6, index // 6
                position = _matrix_input_position(self.owner, bit, None)
                self.assertEqual(position, (event, row, column))
                self.assertEqual(matrix_input_command(self.profile, position, True),
                    bytes((HOST_INPUT, 1, self.order[row], 31 ^ (1 << column))))
        self.assertEqual(matrix_input_command(self.profile, None, False),
                         bytes((HOST_INPUT, 0, 0, 0)))

    def test_unknown_ambiguous_and_invalid_physical_positions_reject(self):
        self.assertIsNone(_matrix_input_position(self.owner, 0, None))
        self.assertIsNone(_matrix_input_position(self.owner, 11, 0xa0))
        self.profile["event_codes"][1] = ord("1")
        self.assertIsNone(_matrix_input_position(self.owner, 11, None))
        self.profile["row_wire_order"] = [0] * 6
        with self.assertRaises(ValueError):
            matrix_input_command(self.profile, (ord("2"), 3, 4), True)
        with self.assertRaises(ValueError):
            matrix_input_command(self.profile, (ord("2"), 3, 5), True)
