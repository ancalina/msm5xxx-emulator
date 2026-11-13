"""Synthetic source checks for the indexed external register bank."""
from __future__ import annotations

import copy
import unittest

from msm5xxx_emulator.detection.registry import device_domain
find_indexed_18 = device_domain("external_bus.indexed").find_indexed_18
detect_external_bus = device_domain("external_bus.rules").detect_external_bus
external_bus_plan = device_domain("external_bus.projection").external_bus_plan
from test_external_devices import _thumb_bl, ldr_literal, put16, put32


def _indexed_image(*, reader_selector=0x18080000,
                   reader_data=0x180C0000, reader_load=0x8810,
                   second_selector=None, include_writer_call=True) -> bytes:
    image = bytearray(0x4000)
    reader, writer, caller = 0x1000, 0x1020, 0x1100
    reader_selector_pool, reader_data_pool = 0x1400, 0x1404
    writer_selector_pool, writer_data_pool = 0x1408, 0x140C
    shared_selector_pool, other_selector_pool = 0x1410, 0x1414

    put16(image, reader,
          ldr_literal(2, reader, reader_selector_pool), 0x8010,
          ldr_literal(2, reader + 4, reader_data_pool), reader_load, 0x4770)
    put16(image, writer,
          ldr_literal(2, writer, writer_selector_pool), 0x8010,
          ldr_literal(2, writer + 4, writer_data_pool), 0x8011, 0x4770)

    if second_selector is None:
        second_selector = shared_selector_pool
    else:
        second_selector = other_selector_pool
    reader_hi, reader_lo = _thumb_bl(caller + 4, reader)
    write_hi, write_lo = _thumb_bl(caller + 12, writer)
    body = [0xB500,
            ldr_literal(0, caller + 2, shared_selector_pool),
            reader_hi, reader_lo,
            ldr_literal(0, caller + 8, second_selector),
            0x215A]
    if include_writer_call:
        body.extend((write_hi, write_lo, 0xBD00))
    else:
        body.append(0xBD00)
    put16(image, caller, *body)

    put32(image, reader_selector_pool, reader_selector)
    put32(image, reader_data_pool, reader_data)
    put32(image, writer_selector_pool, 0x18080000)
    put32(image, writer_data_pool, 0x180C0000)
    put32(image, shared_selector_pool, 0x1234)
    put32(image, other_selector_pool, 0x1235)
    return bytes(image)


class IndexedExternalTests(unittest.TestCase):
    def test_indexed_helpers_and_shared_caller_project_two_exact_claims(self):
        image = _indexed_image()
        indexed = find_indexed_18(image)
        self.assertIsNotNone(indexed)

        profile, reason = detect_external_bus(image)
        self.assertEqual(reason, "accepted")
        self.assertTrue(profile["machine_properties"]["external-indexed-18"])
        resolution, reason = external_bus_plan(profile, image, None, None)
        self.assertIsNone(reason)
        self.assertIn(("external-indexed-18", True), resolution.plan.properties)
        self.assertEqual({(claim.start, claim.end)
                          for claim in resolution.plan.claims},
                         {(0x18080000, 0x18080002),
                          (0x180C0000, 0x180C0002)})

        changed = copy.deepcopy(profile)
        changed["capabilities"]["indexed_18"]["parameters"]["width"] = 4
        _, reason = external_bus_plan(changed, image, None, None)
        self.assertEqual(reason, "indexed-contract-parameter-mismatch")

        changed_image = bytearray(image)
        changed_image[0x1000] ^= 2
        _, reason = external_bus_plan(profile, bytes(changed_image), None, None)
        self.assertEqual(reason, "source-guard-mismatch")

    def test_indexed_detector_rejects_broken_reader_and_unlinked_calls(self):
        mutations = (
            ("missing reader", _indexed_image(reader_load=0x8010)),
            ("wrong access width", _indexed_image(reader_load=0x6810)),
            ("wrong data port", _indexed_image(reader_data=0x180C0002)),
            ("wrong selector port", _indexed_image(reader_selector=0x18080002)),
            ("caller changes selector", _indexed_image(second_selector=0x1414)),
            ("writer call absent", _indexed_image(include_writer_call=False)),
        )
        for name, image in mutations:
            with self.subTest(name=name):
                self.assertIsNone(find_indexed_18(image))


if __name__ == "__main__":
    unittest.main()
