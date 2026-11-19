"""Synthetic source closure for an inactive active-low matrix contact."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace

from test_sparse_rows import _linked_copy_reset_fixture, _put16, _put32, _branch, _unconditional, _bl
from msm5xxx_emulator.detection.devices.input.released_contact import released_contact_property


def _literal(image, site, register, pool, value):
    pc = (site + 4) & ~3
    delta = pool - pc
    assert delta >= 0 and delta % 4 == 0 and delta // 4 < 256
    _put16(image, site, 0x4800 | register << 8 | delta // 4)
    _put32(image, pool, value)


def _fixture(*, field8=0x0300072c, field34=0x0300072c,
             status_mask=0x10, event=0x5e, queue=True,
             counter_offsets=(7, 8)):
    image = _linked_copy_reset_fixture()
    descriptor, state = 0x01000100, 0x01000300
    source_descriptor = 0x1100
    _put32(image, source_descriptor + 8, field8)
    _put32(image, source_descriptor + 0x34, field34)
    image[source_descriptor:source_descriptor + 4] = b"DESC"

    # A relocated status helper. Its only external data addresses are literal
    # pools, and its bit-high edge clears both counters before returning.
    entry = 0x2200
    _put16(image, entry, 0xb590)                         # PUSH {r4,r7,lr}
    _literal(image, entry + 2, 0, 0x2280, descriptor)
    _put16(image, entry + 4, 0x6b40)                    # LDR r0,[r0,#0x34]
    _put16(image, entry + 6, 0x8800)                    # LDRH r0,[r0]
    _put16(image, entry + 8, 0x2110 if status_mask == 0x10 else 0x2108)
    _put16(image, entry + 10, 0x4001)                   # ANDS r1,r0
    _literal(image, entry + 12, 2, 0x2284, 0x01000200)
    _literal(image, entry + 14, 7, 0x2288, state)
    _branch(image, entry + 16, 1, entry + 0x50)          # BNE high/reset

    p = entry + 18
    first, second = counter_offsets
    _put16(image, p, 0x7800 | first << 6 | 7 << 3); p += 2
    _put16(image, p, 0x3001); p += 2                    # ADDS r0,#1
    _put16(image, p, 0x7000 | first << 6 | 7 << 3); p += 2
    _put16(image, p, 0x7800 | second << 6 | 7 << 3); p += 2
    _put16(image, p, 0x3001); p += 2
    _put16(image, p, 0x7000 | second << 6 | 7 << 3); p += 2
    _put16(image, p, 0x7800 | first << 6 | 7 << 3); p += 2
    _put16(image, p, 0x2805); p += 2                    # CMP r0,#5
    gate5 = p; _branch(image, p, 1, entry + 0x5c); p += 2
    _put16(image, p, 0x7800 | second << 6 | 7 << 3); p += 2
    _put16(image, p, 0x280a); p += 2                    # CMP r0,#10
    gate10 = p; _branch(image, p, 1, entry + 0x5c); p += 2
    event_site = p
    _put16(image, p, 0x2400 | event); p += 2            # MOVS r4,#event
    _put16(image, p, 0x1c20); p += 2                    # ADDS r0,r4,#0
    queue_site = p
    if queue:
        _bl(image, p, 0x2300)
    else:
        _bl(image, p, 0x2320)
    p += 4
    _unconditional(image, p, entry + 0x5c); p += 2       # B end

    reset = entry + 0x50
    _put16(image, reset, 0x2000)
    _put16(image, reset + 2, 0x7000 | first << 6 | 7 << 3)
    _put16(image, reset + 4, 0x7000 | second << 6 | 7 << 3)
    # These adjacent byte accesses use a distinct nearby RAM literal. They
    # must not make that unrelated object look like the status counter.
    _put16(image, reset + 6, 0x7000 | 22 << 6 | 2 << 3)  # STRB r0,[r2,#22]
    _put16(image, reset + 8, 0x7000 | 23 << 6 | 2 << 3)  # STRB r0,[r2,#23]
    _put16(image, reset + 10, 0x4770)
    _put16(image, entry + 0x5c, 0x4770)

    # Queue stub copies its input byte to a ring slot.
    _put16(image, 0x2300, 0x4601)                       # MOV r1,r0
    _put16(image, 0x2302, 0x7011)                       # STRB r1,[r2]
    _put16(image, 0x2304, 0x4770)
    _put16(image, 0x2320, 0x4770)
    config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                             ram_size=0x00800000, flash_size=len(image))
    matrix = {"grammar": "sparse-halfword-seven-row-v1", "rows": 7,
              "columns": 4, "no_key": 15,
              "single_key_column_sense": [14, 13, 11, 7],
              "descriptor": descriptor, "sense_address": 0x0300072c}
    return bytes(image), config, matrix, {"event": event_site, "queue": queue_site,
                                         "gate5": gate5, "gate10": gate10,
                                         "status": entry + 6}


class ReleasedContactTests(unittest.TestCase):
    def test_unrelated_ram_literal_with_adjacent_byte_accesses_is_not_counter(self):
        image, config, matrix, sites = _fixture()
        property_value, profile = released_contact_property(image, config, matrix)
        self.assertEqual(property_value, f"experimental-matrix-contact={sites['status']:x}:10")
        self.assertEqual(profile["thresholds"], [5, 10])

    def test_linked_status_contact_and_queue_are_relocatable(self):
        for delta, ram_delta, counter_offsets in ((0, 0, (7, 8)), (0x80, 0x100, (7, 8)),
                                                   (0, 0, (6, 7))):
            image, config, matrix, sites = _fixture(counter_offsets=counter_offsets)
            if delta:
                moved = bytearray(len(image) + delta)
                moved[:0x2200] = image[:0x2200]
                moved[0x2200 + delta:] = image[0x2200:]
                # This test's helper code and pools are relocated together;
                # copy/table/data fixtures remain at their original addresses.
                start, end = 0x2200 + delta, 0x2308 + delta
                moved[start:end] = image[0x2200:0x2308]
                # Update status literal values to the moved pool positions.
                _put32(moved, 0x2280 + delta, 0x01000100)
                _put32(moved, 0x2288 + delta, 0x01000300 + ram_delta)
                # The 0x2284 pool is unrelated but remains distinct.
                # Descriptor and counter addresses are distinct literals.
                config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                    ram_size=0x00800000, flash_size=len(moved))
                image = bytes(moved)
            property_value, profile = released_contact_property(image, config, matrix)
            self.assertEqual(property_value, f"experimental-matrix-contact={sites['status'] + delta:x}:10")
            self.assertEqual(profile["inactive_level"], 0x10)
            self.assertEqual(profile["event"], 0x5e)
            self.assertEqual(profile["thresholds"], [5, 10])
            self.assertEqual(profile["sense_address"], matrix["sense_address"])

    def test_rejects_mismatched_fields_event_sink_and_five_bit_grammar(self):
        image, config, matrix, _ = _fixture(field8=0x03000728)
        self.assertEqual(released_contact_property(image, config, matrix), (None, None))
        image, config, matrix, _ = _fixture(field34=0x03000728)
        self.assertEqual(released_contact_property(image, config, matrix), (None, None))
        image, config, matrix, _ = _fixture(event=0x60)
        self.assertEqual(released_contact_property(image, config, matrix), (None, None))
        image, config, matrix, _ = _fixture(queue=False)
        self.assertEqual(released_contact_property(image, config, matrix), (None, None))
        image, config, matrix, _ = _fixture()
        matrix["grammar"] = "matrix-encoded-ports-v1"
        self.assertEqual(released_contact_property(image, config, matrix), (None, None))

    def test_rejects_unlinked_mask_counter_threshold_and_ram_bound(self):
        image, config, matrix, _ = _fixture(status_mask=0x08)
        self.assertEqual(released_contact_property(image, config, matrix), (None, None))

        image, config, matrix, _ = _fixture()
        changed = bytearray(image)
        _put16(changed, 0x2254, 0x7230)  # reset writes offset 0, not counter +8
        self.assertEqual(released_contact_property(bytes(changed), config, matrix), (None, None))

        image, config, matrix, _ = _fixture()
        changed = bytearray(image)
        _put16(changed, 0x2220, 0x2806)  # compare 6, not linked threshold 5
        self.assertEqual(released_contact_property(bytes(changed), config, matrix), (None, None))

        image, config, matrix, _ = _fixture()
        changed = bytearray(image)
        _put32(changed, 0x2288, 0x01800000)  # state literal is outside configured RAM
        self.assertEqual(released_contact_property(bytes(changed), config, matrix), (None, None))


if __name__ == "__main__":
    unittest.main()
