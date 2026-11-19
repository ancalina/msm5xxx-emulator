"""Synthetic source closure for a stack-staged released matrix contact."""
from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace

from test_sparse_rows import _image, _put16, _put32, _branch, _unconditional, _bl
from msm5xxx_emulator.detection.devices.input.sparse_rows import find_sparse_row_scanners
from msm5xxx_emulator.detection.devices.input.stack_contact import stack_contact_property


def _literal(image, site, register, pool, value):
    pc = (site + 4) & ~3
    delta = pool - pc
    assert delta >= 0 and delta % 4 == 0 and delta // 4 < 256
    _put16(image, site, 0x4800 | register << 8 | delta // 4)
    _put32(image, pool, value)


def _fixture(*, event=0x73, mismatch=False):
    image = _image()
    descriptor = 0x01000100
    source_descriptor = 0x1100
    _put32(image, source_descriptor + 8, 0x03000728 if mismatch else 0x0300072c)
    _put32(image, source_descriptor + 0x34, 0x0300072c)

    entry = 0x2800
    _put16(image, entry, 0xb590)              # PUSH {r4,r7,lr}
    _put16(image, entry + 2, 0xb082)          # SUB sp,#8
    _literal(image, entry + 4, 4, 0x2880, descriptor)
    _put16(image, entry + 6, 0x6b61)          # LDR r1,[r4,#0x34]
    _put16(image, entry + 8, 0x8809)          # LDRH r1,[r1]
    _put16(image, entry + 10, 0x0949)         # LSRS r1,r1,#5
    _branch(image, entry + 12, 2, entry + 0x30)  # BHS released/high path
    _put16(image, entry + 14, 0x2200 | event) # MOVS r2,#event
    _put16(image, entry + 16, 0xab00)         # ADD r3,sp,#0
    _put16(image, entry + 18, 0x701a)         # STRB r2,[r3]
    _unconditional(image, entry + 20, entry + 0x50)

    clear = 0x2a00
    _bl(image, entry + 0x30, clear)
    _put16(image, entry + 0x34, 0x6b60)       # LDR r0,[r4,#0x34]
    _put16(image, entry + 0x36, 0x8800)       # selected presence_site: LDRH r0,[r0]
    _put16(image, entry + 0x38, 0x8801)       # selected sense_site: LDRH r1,[r0]
    _unconditional(image, entry + 0x3a, entry + 0x50)

    _put16(image, entry + 0x50, 0xa800)       # ADD r0,sp,#0
    _bl(image, entry + 0x52, 0x2b00)
    _put16(image, entry + 0x56, 0xb082)       # ADD sp,#8
    _put16(image, entry + 0x58, 0xbd90)       # POP {r4,r7,pc}

    _literal(image, clear, 7, 0x2a40, descriptor)
    _put16(image, clear + 2, 0x89b8)          # LDRH r0,[r7,#0xc]
    _put16(image, clear + 4, 0x2101)          # MOVS r1,#1
    _put16(image, clear + 6, 0x4388)          # BIC r0,r1
    _put16(image, clear + 8, 0x81b8)          # STRH r0,[r7,#0xc]
    _put16(image, clear + 10, 0x4770)         # BX lr
    _put16(image, 0x2b00, 0x7801)             # LDRB r1,[r0]
    _put16(image, 0x2b02, 0x4770)

    config = SimpleNamespace(load_address=0, ram_base=0x01000000,
                             ram_size=0x00800000, flash_size=len(image))
    matrix = find_sparse_row_scanners(image)[0]
    matrix = dict(matrix, presence_site=entry + 0x36, sense_site=entry + 0x38,
                  event_codes=list(matrix["event_codes"]))
    return image, config, matrix, {"read": entry + 8, "branch": entry + 12,
                                    "store": entry + 18, "call": entry + 0x52}


class StackContactTests(unittest.TestCase):
    def test_linked_stack_contact_requires_both_paths_and_same_copy(self):
        image, config, matrix, sites = _fixture()
        prop, profile = stack_contact_property(image, config, matrix)
        self.assertEqual(prop, f"experimental-matrix-contact={sites['read']:x}:10")
        self.assertEqual(profile["event"], 0x73)
        self.assertEqual(profile["event_store"], sites["store"])
        self.assertEqual(profile["consumer_site"], sites["call"])
        self.assertEqual(profile["inactive_level"], 0x10)
        self.assertEqual(profile["sense_address"], matrix["sense_address"])
        self.assertIn((profile["descriptor"], 0x38), profile["ram_dependencies"])

    def test_rejects_unlinked_event_copy_and_out_of_bounds_code(self):
        image, config, matrix, _ = _fixture(mismatch=True)
        self.assertEqual(stack_contact_property(image, config, matrix), (None, None))
        image, config, matrix, _ = _fixture(event=ord("1"))
        self.assertEqual(stack_contact_property(image, config, matrix), (None, None))
        image, config, matrix, _ = _fixture()
        changed = bytearray(image)
        _put16(changed, 0x280c, 0xd10f)  # BNE does not prove released polarity.
        self.assertEqual(stack_contact_property(bytes(changed), config, matrix), (None, None))
        config.flash_size = 0x2850
        self.assertEqual(stack_contact_property(image, config, matrix), (None, None))

    def test_rejects_missing_clear_stack_transfer_and_scan_link(self):
        image, config, matrix, _ = _fixture()
        changed = bytearray(image)
        _put16(changed, 0x2a08, 0x80f8)  # Store shadow at another descriptor offset.
        self.assertEqual(stack_contact_property(bytes(changed), config, matrix), (None, None))

        image, config, matrix, _ = _fixture()
        changed = bytearray(image)
        _put16(changed, 0x2b00, 0x7811)  # Callee reads [r2], not stack argument [r0].
        self.assertEqual(stack_contact_property(bytes(changed), config, matrix), (None, None))

        image, config, matrix, _ = _fixture()
        matrix["presence_site"] = 0x2812
        self.assertEqual(stack_contact_property(image, config, matrix), (None, None))


if __name__ == "__main__":
    unittest.main()
