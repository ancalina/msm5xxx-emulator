"""Synthetic code-to-port mappings for a two-port encoded keypad."""
import unittest
from types import SimpleNamespace

from msm5xxx_emulator.detection.devices.input.event_projection import _matrix_input_position
from msm5xxx_emulator.detection.devices.input.transport_projection.halfword import matrix_input_command
from msm5xxx_emulator.detection.registry import device_domain

HOST_INPUT = device_domain("input.transport_projection").HOST_INPUT


def profile():
    return {"grammar": "encoded-two-port-keypad-v1",
            "event_tokens": list(b"123456789*0#"),
            "event_codes": [2 + 17 * index for index in range(12)]}


class EncodedProjectionTests(unittest.TestCase):
    def test_inline_events_keep_the_source_encoded_contact(self):
        source = profile()
        source["grammar"] = "encoded-inline-two-port-keypad-v1"
        owner = SimpleNamespace(matrix_input_profile=source)
        for event, code in zip(source["event_tokens"], source["event_codes"]):
            with self.subTest(event=event):
                position = _matrix_input_position(owner, 0, event)
                self.assertEqual(position, (event, code >> 5, code & 31))
                self.assertEqual(matrix_input_command(source, position, True),
                                 bytes((HOST_INPUT, 1, code >> 5, code & 31)))
        with self.assertRaises(ValueError):
            matrix_input_command(source, (ord("1"), 1, 2), True)
        source["event_tokens"].append(ord("1"))
        source["event_codes"].append(0xE2)
        self.assertIsNone(_matrix_input_position(owner, 11, None))

    def test_numeric_events_use_their_code_in_both_registers(self):
        source = profile()
        owner = SimpleNamespace(matrix_input_profile=source)
        for bit, event, code in zip(range(11, 23), source["event_tokens"], source["event_codes"]):
            with self.subTest(event=event):
                position = _matrix_input_position(owner, bit, None)
                self.assertEqual(position, (event, code >> 5, code & 31))
                self.assertEqual(matrix_input_command(source, position, True),
                                 bytes((HOST_INPUT, 1, code >> 5, code & 31)))
        self.assertIsNone(_matrix_input_position(owner, 0, None))
        self.assertIsNone(_matrix_input_position(owner, 11, ord("A")))
        self.assertEqual(matrix_input_command(source, None, False),
                         bytes((HOST_INPUT, 0, 0, 0)))

    def test_invalid_or_ambiguous_source_codes_do_not_make_contacts(self):
        for value in (-1, 256, True, 0x2F):
            source = profile()
            source["event_codes"][0] = value
            owner = SimpleNamespace(matrix_input_profile=source)
            with self.subTest(value=value):
                self.assertIsNone(_matrix_input_position(owner, 11, None))
        source = profile()
        source["event_tokens"].append(ord("1"))
        source["event_codes"].append(0xE2)
        owner = SimpleNamespace(matrix_input_profile=source)
        self.assertIsNone(_matrix_input_position(owner, 11, None))

    def test_command_must_match_the_resolved_code(self):
        source = profile()
        for position in ((ord("1"), 7, 2), (ord("1"), 0, 3), (ord("A"), 0, 2)):
            with self.subTest(position=position), self.assertRaises(ValueError):
                matrix_input_command(source, position, True)
