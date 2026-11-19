"""Synthetic composition of boot-contact and keypad source contracts."""
from __future__ import annotations

import unittest
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch

from msm5xxx_emulator.detection.registry import device_domain

wire_boot_contact_property = device_domain("input.wire_boot_contact").wire_boot_contact_property


def _fixture(*, address=0x0300066c, read_pc=0x80, mask=4, width=1,
             grammar="sparse-halfword-six-row-v1"):
    profile = {
        "address": address, "mask": mask, "width": width,
        "read_pcs": [read_pc], "code_intervals": [[0, 4]],
        "literal_intervals": [[8, 12]], "display_source_intervals": [[16, 20]],
        "ram_intervals": [[0x01000000, 0x01000040]],
        "display_ram_intervals": [[0x01000100, 0x01000200]],
    }
    config = SimpleNamespace(load_address=0, image_offset=0, entry=0,
        flash_size=0x100, ram_base=0x01000000, ram_size=0x1000,
        image_kind="firmware", chipset="MSM5105")
    original = bytes(0x100)
    matrix = {"grammar": grammar, "rows": 6 if "six" in grammar else 7,
        "columns": 4, "no_key": 15, "sense_address": 0x0300066c,
        "presence_site": 0x90, "sense_site": 0xa0,
        "source_sites": [{"presence_site": 0x94, "sense_site": 0xa4}]}
    return profile, config, original, matrix


class WireBootContactTests(unittest.TestCase):
    def _bind(self, profile, config, original, matrix, **kwargs):
        with patch("msm5xxx_emulator.detection.devices.external_bus.boot_contact_5100.find_boot_contact_release",
                   return_value=(deepcopy(profile), "synthetic")):
            return wire_boot_contact_property(config, original, original, matrix, **kwargs)

    def test_composes_same_address_and_independent_read_for_allowed_matrices(self):
        expected = "experimental-boot-contact=300066c:80:4:1"
        for grammar in ("sparse-halfword-six-row-v1",
                        "sparse-halfword-seven-row-v1",
                        "table-row-halfword-seven-v1"):
            profile, config, original, matrix = _fixture(grammar=grammar)
            prop, result = self._bind(profile, config, original, matrix)
            self.assertEqual(prop, expected)
            self.assertEqual(result, {"address": 0x0300066c, "read_pc": 0x80,
                                      "mask": 4, "width": 1})

    def test_rejects_matrix_shape_and_aliases(self):
        profile, config, original, matrix = _fixture()
        for field, value in (("grammar", "matrix-encoded-ports-v1"),
                             ("columns", 5), ("no_key", 31),
                             ("sense_address", 0x0300072c)):
            mutated = dict(matrix, **{field: value})
            with self.subTest(field=field):
                self.assertIsNone(self._bind(profile, config, original, mutated)[0])
        matrix = dict(matrix, presence_site=0x80)
        self.assertIsNone(self._bind(profile, config, original, matrix)[0])
        profile, config, original, matrix = _fixture()
        matrix["source_sites"][0]["sense_site"] = 0x80
        self.assertIsNone(self._bind(profile, config, original, matrix)[0])

    def test_rejects_boot_address_mask_width_and_source_bounds(self):
        for options in ({"address": 0x0300072c}, {"mask": 0x10},
                        {"mask": 3}, {"width": 3}):
            profile, config, original, matrix = _fixture(**options)
            with self.subTest(options=options):
                self.assertIsNone(self._bind(profile, config, original, matrix)[0])
        profile, config, original, matrix = _fixture()
        profile["code_intervals"] = [[0xf8, 0x108]]
        self.assertIsNone(self._bind(profile, config, original, matrix)[0])

    def test_preserves_existing_layout_eeprom_and_loaded_source_gates(self):
        profile, config, original, matrix = _fixture()
        self.assertIsNone(self._bind(profile, config, original, matrix,
                                     layout_claimed=True)[0])
        self.assertIsNone(self._bind(profile, config, original, matrix,
                                     eeprom_window=(0x0300066f, 1))[0])
        self.assertIsNotNone(self._bind(profile, config, original, matrix,
                                        eeprom_window=(0x03000670, 32))[0])
        with patch("msm5xxx_emulator.detection.devices.external_bus.boot_contact_5100.find_boot_contact_release",
                   return_value=(profile, "synthetic")):
            self.assertIsNone(wire_boot_contact_property(
                config, original, original[:-1] + b"1", matrix)[0])


if __name__ == "__main__":
    unittest.main()
