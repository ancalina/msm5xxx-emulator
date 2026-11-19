"""A static scanner candidate cannot mask a matching electrical proof."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch
import unittest

from msm5xxx_emulator.detection.devices.input.machine import (
    project_five_column_fallback,
)


class FiveColumnFallbackTests(unittest.TestCase):
    def setUp(self):
        self.profile = dict(descriptor=0x01002000, sense_address=0x0300072c,
            rows=6, columns=5, event_table=0x800,
            event_codes=list(b"123456789*0#") + [0] * 18,
            single_key_column_sense=[30, 29, 27, 23, 15])
        direct = deepcopy(self.profile)
        direct["descriptor_pointer"] = direct.pop("descriptor")
        direct["register"] = direct.pop("sense_address")
        self.owner = SimpleNamespace(matrix_input_profile=None,
            decoder=SimpleNamespace(direct_input_profile=direct),
            config=SimpleNamespace(detection_notes=[]))

    def project(self, **options):
        with patch("msm5xxx_emulator.detection.devices.input.machine.five_column_row_property",
                   return_value=("matrix-halfword-five-wires=synthetic", self.profile)):
            return project_five_column_fallback(self.owner, "machine", b"",
                                                **options)

    def test_matching_unadmitted_candidate_uses_source_proven_wiring(self):
        self.assertEqual(self.project(),
            "machine,matrix-halfword-five-wires=synthetic")
        self.assertIs(self.owner.matrix_input_profile, self.profile)

    def test_admitted_input_and_explicit_claim_retain_precedence(self):
        self.assertEqual(self.project(input_claimed=True), "machine")
        self.owner.matrix_input_profile = {"grammar": "existing"}
        self.assertEqual(self.project(), "machine")
        self.assertEqual(self.owner.matrix_input_profile, {"grammar": "existing"})
        self.owner.matrix_input_profile = None
        self.owner.config.board_status_input = object()
        self.assertEqual(self.project(), "machine")

    def test_different_static_descriptor_or_events_cannot_be_replaced(self):
        for field in tuple(self.owner.decoder.direct_input_profile):
            with self.subTest(field=field):
                saved = deepcopy(self.owner.decoder.direct_input_profile)
                self.owner.decoder.direct_input_profile[field] = None
                self.assertEqual(self.project(), "machine")
                self.assertIsNone(self.owner.matrix_input_profile)
                self.owner.decoder.direct_input_profile = saved

    def test_clock_needs_matching_loaded_proof_and_no_existing_owner(self):
        timer = {"route_source": "reset-owned-two-bank-group-v1"}
        with patch("msm5xxx_emulator.detection.devices.input.machine.row_timer_profile",
                   return_value=("source-clock", timer)):
            machine = self.project(loaded_image=b"synthetic loaded bytes")
        self.assertIn(",rex-static-c80=source-clock", machine)
        self.assertEqual(self.owner.matrix_input_profile["scanner_timer"], timer)

    def test_changed_loaded_route_or_claimed_irq_does_not_enable_clock(self):
        with patch("msm5xxx_emulator.detection.devices.input.machine.row_timer_profile",
                   side_effect=[("source-clock", {}), (None, None)]):
            self.assertNotIn("rex-static-c80", self.project(loaded_image=b"changed"))
        self.assertFalse(hasattr(self.owner, "rex_c80_profile"))
        self.owner.matrix_input_profile = None
        self.owner.rex_w1c_profile = "existing-owner"
        with patch("msm5xxx_emulator.detection.devices.input.machine.row_timer_profile",
                   side_effect=AssertionError("existing IRQ keeps its owner")):
            self.assertNotIn("rex-static-c80", self.project(loaded_image=b"loaded"))
        self.assertEqual(self.owner.rex_w1c_profile, "existing-owner")


if __name__ == "__main__":
    unittest.main()
