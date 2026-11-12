"""Host side-key projection requires a linked scanner and converter."""
import unittest
from unittest.mock import patch

from msm5xxx_emulator.detection.devices.input import selection


class SideKeyProjectionTests(unittest.TestCase):
    def test_cells_and_linkage(self):
        events = list(range(24))
        events[6], events[19] = 0x63, 0x64
        events[22:] = [0x54, 0x55]
        profile = dict(event_sink_family="ring", grammar="direct-low-nibble-6-row-v1",
                       rows=6, columns=4, no_key=15, register=0x03000694,
                       event_sink_validation="required-queue-features", event_sink=0x80,
                       single_key_column_sense=[14, 13, 11, 7], event_codes=events,
                       raw_dequeue=0x100, provisional_mappings={5: {
                           "rule": "same-image-ring32-confirm-consumer-v1",
                           "raw_dequeue": 0x100, "converter": 0x200}})
        with patch.object(selection, "SAMSUNG_RING32", "ring", create=True), \
             patch.object(selection, "SAMSUNG_DUAL_PLANE_RING32", "dual", create=True), \
             patch.object(selection, "UNCLASSIFIED", "unknown", create=True):
            positions = selection.direct_matrix_positions(profile)
            self.assertEqual(positions[10], (0x54, 4, 3))
            self.assertEqual(positions[8], (0x55, 5, 3))
            alternate = {**profile, "provisional_mappings": {},
                         "side_key_converter": profile["provisional_mappings"][5]}
            self.assertEqual(selection.direct_matrix_positions(alternate)[10], (0x54, 4, 3))
            for change in ({"raw_dequeue": 0x102}, {"register": 0x03000690},
                           {"event_codes": events[:-1] + [0x54]},
                           {"event_codes": events[:6] + [0x62] + events[7:]},
                           {"single_key_column_sense": [14, 13, 7, 11]}):
                with self.subTest(change=change):
                    positions = selection.direct_matrix_positions({**profile, **change})
                    self.assertNotIn(8, positions)
                    self.assertNotIn(10, positions)


if __name__ == "__main__":
    unittest.main()
