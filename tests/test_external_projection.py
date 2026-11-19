"""Synthetic numeric labels on two external row banks and five senses."""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.input.event_projection import _matrix_input_position
from msm5xxx_emulator.detection.devices.input.transport_projection.halfword import matrix_input_command
from msm5xxx_emulator.detection.registry import device_domain
from msm5xxx_emulator.detection.devices.input import machine as input_machine


HOST_INPUT = device_domain("input.transport_projection").HOST_INPUT


class ExternalProjectionTests(unittest.TestCase):
    def setUp(self):
        self.indices = [29, 0, 7, 14, 21, 28, 5, 12, 19, 26, 3, 10]
        self.events = list(b"123456789*0#")
        table = [0] * 30
        for index, event in zip(self.indices, self.events):
            table[index] = event
        self.profile = dict(grammar="external-latches-six-row-low5-v1",
            rows=6, columns=5, no_key=31, event_codes=table,
            row_wire_order=[1, 2, 0, 4, 5, 3],
            single_key_column_sense=[30, 29, 27, 23, 15])
        self.owner = SimpleNamespace(matrix_input_profile=self.profile)

    def test_numeric_contacts_reach_both_banks_and_all_five_senses(self):
        for bit, event, index in zip(range(11, 23), self.events, self.indices):
            with self.subTest(event=event):
                row, column = index % 6, index // 6
                position = _matrix_input_position(self.owner, bit, None)
                self.assertEqual(position, (event, row, column))
                self.assertEqual(matrix_input_command(self.profile, position, True),
                    bytes((HOST_INPUT, 1, [1, 2, 0, 4, 5, 3][row],
                           31 & ~(1 << column))))

    def test_unknown_labels_and_ambiguous_wiring_reject(self):
        self.assertIsNone(_matrix_input_position(self.owner, 0, None))
        self.assertIsNone(_matrix_input_position(self.owner, 11, 0x91))
        self.profile["event_codes"][1] = ord("1")
        self.assertIsNone(_matrix_input_position(self.owner, 11, None))
        profile = deepcopy(self.profile)
        profile["row_wire_order"] = [0] * 6
        with self.assertRaises(ValueError):
            matrix_input_command(profile, (ord("1"), 5, 4), True)

    def test_external_bus_admission_precedes_keypad_composition(self):
        owner = SimpleNamespace(matrix_input_profile=None,
            decoder=SimpleNamespace(direct_input_profile=None),
            config=SimpleNamespace(detection_notes=[]), row734_source_profile=None)
        prop = "matrix-external-wires=9000070:1f:1:9000000:8850:9000004:3"
        with patch.object(input_machine, "external_row_property",
                          return_value=(prop, self.profile)) as source:
            early = "msm5xxx-poc,input-chardev=input"
            self.assertEqual(input_machine.project_external_input(owner, early, b""), early)
            source.assert_not_called()
            late = early + ",external-cs09=on"
            with patch.object(input_machine, "qemu_row734_property",
                              return_value=(None, None)):
                projected = input_machine.project_row734(
                    owner, late, b"", None, None, False, False, None, None)
            self.assertEqual(projected, late + "," + prop)
            self.assertIs(owner.matrix_input_profile, self.profile)
            source.assert_called_once()
            self.assertEqual(input_machine.project_external_input(owner, projected, b""), projected)
            source.assert_called_once()


if __name__ == "__main__":
    unittest.main()
