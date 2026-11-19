"""Synthetic composition checks for reset-installed wrapped copy sources."""
import struct
import unittest

from msm5xxx_emulator.detection.startup_wrapped_copy import (
    reset_linked_wrapped_copies,
)
from test_startup_copy_wrapper import fixture as wrapper_fixture
from test_startup_reset_cfg_copy import _branched_copy_fixture


RAM_BASE = 0x01000000
RAM_SIZE = 0x00800000
FLASH_SIZE = 0x2000
OVERLAY = 0x03800000
OVERLAY_SOURCE = 0x800
ROW_SOURCE = 0x0c00
ROW_DESTINATION = 0x01002000
ROW_SIZE = 0x20
WRAPPER_BASE = 0x420
WRAPPER_LEAF = 0x580


def _thumb_ldr_literal(site, register, pool):
    pc = (site + 4) & ~3
    delta = pool - pc
    assert delta >= 0 and delta <= 1020 and delta % 4 == 0
    return 0x4800 | (register << 8) | (delta // 4)


def _thumb_bl(site, target):
    delta = target - (site + 4)
    return (0xf000 | ((delta >> 12) & 0x7ff),
            0xf800 | ((delta >> 1) & 0x7ff))


def _append_call(image, *, destination=ROW_DESTINATION,
                 source=ROW_SOURCE, size=ROW_SIZE, clobber=False):
    pc = 0x134
    pool = 0x350
    if clobber:
        struct.pack_into("<H", image, pc, _thumb_ldr_literal(pc, 3, 0x370))
        struct.pack_into("<H", image, pc + 2, 0x2000)  # MOVS R0,#0.
        struct.pack_into("<H", image, pc + 4, 0x6018)  # STR R0,[R3].
        struct.pack_into("<I", image, 0x370, OVERLAY)
        pc += 6
        pool = 0x374
    for register, value in enumerate((destination, source, size)):
        struct.pack_into("<H", image, pc, _thumb_ldr_literal(pc, register, pool))
        struct.pack_into("<I", image, pool, value)
        pc += 2
        pool += 4
    high, low = _thumb_bl(pc, WRAPPER_BASE)
    struct.pack_into("<HHH", image, pc, high, low, 0x4770)  # BL; BX LR.


def _leaf_copy_words():
    # A bounded word loop with one saved callee register and an exact byte tail.
    words = (
        0xe92d4010,  # PUSH {R4,LR}.
        0xe4913004,  # LDR R3,[R1],#4.
        0xe4803004,  # STR R3,[R0],#4.
        0xe2522004,  # SUBS R2,R2,#4.
        0x1afffffb,  # BNE back to the load.
        0xe8bd4010,  # POP {R4,LR}.
        0xe12fff1e,  # BX LR.
    )
    return b"".join(struct.pack("<I", word) for word in words)


def wrapped_copy_fixture(*, orphan=False, clobber=False,
                         destination=ROW_DESTINATION,
                         source=ROW_SOURCE, size=ROW_SIZE,
                         bad_reset_target=False):
    # The linked Thumb loop installs an auxiliary block. The only later call
    # receives literal-loaded arguments and enters a separately checked wrapper.
    image = bytearray(_branched_copy_fixture(orphan=orphan))
    image.extend(bytes(max(0, FLASH_SIZE - len(image))))
    struct.pack_into("<III", image, 0x300,
                     OVERLAY_SOURCE, OVERLAY, 0x200)
    _append_call(image, destination=destination, source=source, size=size,
                 clobber=clobber)

    wrapper_image, _, _ = wrapper_fixture()
    image[WRAPPER_BASE:WRAPPER_BASE + 0x104] = wrapper_image[0x20:0x124]
    # Thumb BX-PC / ARM LDR-IP/BX-IP veneer, then the copied ARM word loop.
    struct.pack_into("<H", image, WRAPPER_LEAF, 0x4778)
    struct.pack_into("<II", image, WRAPPER_LEAF + 4,
                     0xe59fc000, 0xe12fff1c)
    struct.pack_into("<I", image, WRAPPER_LEAF + 12, OVERLAY + 0x20)
    image[OVERLAY_SOURCE + 0x20:OVERLAY_SOURCE + 0x20 + len(_leaf_copy_words())] = _leaf_copy_words()
    image[ROW_SOURCE:ROW_SOURCE + ROW_SIZE] = bytes(range(ROW_SIZE))
    if bad_reset_target:
        struct.pack_into("<I", image, 0x84, 0x181)
    return bytes(image)


class ResetLinkedWrappedCopyTests(unittest.TestCase):
    def prove(self, **options):
        image = wrapped_copy_fixture(**options)
        return reset_linked_wrapped_copies(
            image, RAM_BASE, RAM_SIZE, FLASH_SIZE)

    def test_composes_reset_installer_wrapper_veneer_and_source_copy(self):
        copies = self.prove()
        self.assertEqual(len(copies), 1)
        copy = copies[0]
        self.assertEqual((copy.source, copy.target, copy.size),
                         (ROW_SOURCE, ROW_DESTINATION, ROW_SIZE))
        self.assertIn((ROW_SOURCE, ROW_SIZE), copy.evidence)
        self.assertTrue(all(address < FLASH_SIZE
                            for address, _size in copy.evidence))
        self.assertFalse(any(ROW_DESTINATION <= address < ROW_DESTINATION + ROW_SIZE
                             for address, _size in copy.evidence))

    def test_orphan_installer_and_reset_target_mismatch_reject(self):
        self.assertEqual(self.prove(orphan=True), ())
        self.assertEqual(self.prove(bad_reset_target=True), ())

    def test_code_clobber_after_install_rejects_copy_composition(self):
        self.assertEqual(self.prove(clobber=True), ())

    def test_changed_source_bounds_and_destination_bounds_reject(self):
        self.assertEqual(self.prove(source=FLASH_SIZE - 4), ())
        self.assertEqual(self.prove(destination=RAM_BASE + RAM_SIZE - 4), ())

    def test_combined_stack_spill_cannot_alias_destination(self):
        # The wrapper and leaf use 20+8 bytes below SVC SP. This destination
        # overlaps that physical stack even though the row itself is in RAM.
        self.assertEqual(self.prove(destination=0x01000ff0, size=ROW_SIZE), ())


if __name__ == "__main__":
    unittest.main()
