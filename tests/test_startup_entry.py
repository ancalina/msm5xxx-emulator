"""Synthetic reset/vector and ARM/Thumb manual-call evidence tests."""
import struct
import unittest

from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts
from msm5xxx_emulator.detection.startup_entry import (
    manual_interworking_entries, reset_vector_entry, startup_copy_contexts,
)


def reset_entry_fixture(*, bad_stack_path=False, missing_return=False,
                        wrong_target_isa=False):
    image = bytearray(0x180)
    struct.pack_into('<I', image, 0, 0xEA00000E)  # B reset at 0x40
    words = (
        0xE321F0D3,  # MSR CPSR_c,#SVC
        0xE59FD034,  # LDR SP,[PC,#0x34] -> 0x80
        0xE59F4034,  # LDR r4,[PC,#0x34] -> 0x84
        0xE3140001,  # TST r4,#1
        0x159FE030,  # LDRNE LR,[PC,#0x30] -> 0x88
        0x059FE024 if missing_return else 0x059FE030,
        0xE12FFF14,  # BX r4
    )
    struct.pack_into('<7I', image, 0x40, *words)
    struct.pack_into('<H', image, 0x5C, 0x4778)  # Thumb BX PC trampoline
    struct.pack_into('<I', image, 0x60, 0xEAFFFFFE)  # ARM loop after return
    struct.pack_into('<I', image, 0x80, 0x01001000)
    target = 0x100 if not wrong_target_isa else 0x100
    struct.pack_into('<I', image, 0x84, target | (0 if wrong_target_isa else 1))
    struct.pack_into('<I', image, 0x88, 0x5D)
    struct.pack_into('<I', image, 0x8C, 0x60)
    struct.pack_into('<H', image, 0x100, 0x4770)  # Thumb BX LR
    if bad_stack_path:
        struct.pack_into('<I', image, 0x48, 0xE59FD030)  # SP is reset after its source
    return bytes(image)


class StartupEntryTests(unittest.TestCase):
    def test_reset_vector_and_interworking_entry_carry_mode_stack(self):
        facts = FirmwareFacts(reset_entry_fixture())
        self.assertEqual(reset_vector_entry(facts), CodeAddress(0x40, 'arm'))
        entries = manual_interworking_entries(facts)
        self.assertIs(entries, manual_interworking_entries(facts))
        self.assertEqual(len(entries), 1)
        proof = entries[0]
        self.assertEqual(proof.target, CodeAddress(0x100, 'thumb'))
        self.assertEqual(proof.transfer, CodeAddress(0x58, 'arm'))
        self.assertEqual((proof.stack_pointer, proof.processor_mode),
                         (0x01001000, 0x13))
        self.assertIn((0x80, 0x84), proof.source_spans)
        ranges = ((0x01000000, 0x01800000),)
        contexts = startup_copy_contexts(facts, target_ranges=ranges)
        self.assertIs(contexts, startup_copy_contexts(
            facts, target_ranges=ranges))

    def test_interworking_entry_requires_mode_and_stack_closure(self):
        self.assertEqual(manual_interworking_entries(
            FirmwareFacts(reset_entry_fixture(bad_stack_path=True))), ())
        self.assertEqual(manual_interworking_entries(
            FirmwareFacts(reset_entry_fixture(missing_return=True))), ())
        self.assertEqual(manual_interworking_entries(
            FirmwareFacts(reset_entry_fixture(wrong_target_isa=True))), ())


if __name__ == '__main__':
    unittest.main()
