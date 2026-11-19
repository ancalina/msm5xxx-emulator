"""Synthetic physical contacts for a source-resolved row jump table."""
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.detection.devices.input.event_projection import _matrix_input_position
from msm5xxx_emulator.detection.devices.input.transport_projection.halfword import matrix_input_command
from msm5xxx_emulator.detection.registry import device_domain

HOST_INPUT = device_domain("input.transport_projection").HOST_INPUT


class HalfwordOffsetProjectionTests(unittest.TestCase):
    def test_source_row_permutation_selects_physical_wires(self):
        events = list(b"123456789*0#abcdefghijkl")
        order = [2, 0, 4, 1, 5, 3]
        senses = [14, 13, 11, 7]
        source = {"grammar": "halfword-offset-six-row-v1", "rows": 6,
                  "columns": 4, "event_codes": events, "no_key": 15,
                  "row_wire_order": order,
                  "single_key_column_sense": senses}
        owner = SimpleNamespace(matrix_input_profile=source)
        for index, event in enumerate(events[:12]):
            with self.subTest(event=event):
                position = _matrix_input_position(owner, 0, event)
                self.assertEqual(position, (event, index % 6, index // 6))
                self.assertEqual(matrix_input_command(source, position, True),
                                 bytes((HOST_INPUT, 1, order[index % 6],
                                        senses[index // 6])))
        self.assertEqual(matrix_input_command(source, None, False),
                         bytes((HOST_INPUT, 0, 0, 0)))
        # A user-entered event with no proven key still maps to its one table cell.
        self.assertEqual(_matrix_input_position(owner, 0, ord("a")), (ord("a"), 0, 2))
        source["row_wire_order"] = [0] * 6
        with self.assertRaises(ValueError):
            matrix_input_command(source, (ord("1"), 0, 0), True)
