"""Synthetic forwarding, frame, and flag checks for Thumb copy wrappers."""
import struct
import unittest

from msm5xxx_emulator.detection.startup_copy_wrapper import copy_wrapper_call


def fixture(*, wrong_length=False, corrupt_return=False, wrong_source=False,
            extra_call=False, unknown_carry=False, early_return=False):
    image = bytearray(0x2000)
    entry, leaf, pulse = 0x20, 0x180, 0x03000700
    pc = entry
    def emit(word):
        nonlocal pc
        struct.pack_into('<H', image, pc, word);pc += 2
    def call():
        nonlocal pc
        delta = leaf - (pc + 4)
        emit(0xf000 | (delta >> 12 & 0x7ff))
        emit(0xf800 | (delta >> 1 & 0x7ff))
    if unknown_carry:
        emit(0x2300)  # MOVS r3,#0 preserves the unknown entry carry.
        at = pc
        emit(0xd200 | ((0x100 - at - 4) // 2 & 255))  # BHS no-copy return.
        struct.pack_into('<H', image, 0x100, 0x4770)
    emit(0xb587)  # PUSH {r0,r1,r2,r7,lr} in architectural order.
    if early_return:
        emit(0x46f7)  # MOV pc,lr must terminate execution, not fall through.
    emit(0x1c17)  # ADDS r7,r2,#0.
    emit(0x2001)
    at = pc
    emit(0x4900 | ((0x120 - ((at + 4) & ~3)) // 4))
    emit(0x7008)  # STRB r0,[r1].
    emit(0x2000)
    emit(0x7008)
    if corrupt_return:
        emit(0x9004)  # STR r0,[sp,#16] overwrites saved LR.
    emit(0x1c7a if wrong_length else 0x1c3a)  # ADDS r2,r7,#1/0.
    emit(0xa900)  # ADD r1,sp,#0.
    emit(0xc905 if wrong_source else 0xc903)  # LDM r1,{r0,r1}.
    call()
    if extra_call:
        call()
    emit(0xbc8e)  # POP {r1,r2,r3,r7}.
    emit(0xbc08)
    emit(0x4718)
    struct.pack_into('<I', image, 0x120, pulse)
    return bytes(image), entry, leaf


class CopyWrapperTests(unittest.TestCase):
    def check(self, **options):
        image, entry, leaf = fixture(**options)
        result = copy_wrapper_call(image, entry, 0x01002000, 0x1000, 64,
                                   stack_pointer=0x01008000)
        return result, leaf

    def test_proves_forwarded_arguments_and_frame_obligations(self):
        result, leaf = self.check()
        self.assertIsNotNone(result)
        self.assertEqual(result.target.address, leaf)
        self.assertEqual(result.frame_bytes, 20)
        self.assertEqual(result.stack_pointer, 0x01008000 - 20)
        self.assertEqual(result.effects, ((0x03000700, 1),))
        self.assertEqual(len(result.required_preserved_registers), 8)

    def test_wrong_arguments_corrupted_link_and_multiple_calls_reject(self):
        for option in ('wrong_length', 'wrong_source', 'corrupt_return', 'extra_call', 'early_return'):
            with self.subTest(option=option):
                self.assertIsNone(self.check(**{option: True})[0])

    def test_entry_carry_is_not_invented_by_movs(self):
        self.assertIsNone(self.check(unknown_carry=True)[0])

    def test_payload_cannot_alias_saved_frame(self):
        image, entry, _ = fixture()
        self.assertIsNone(copy_wrapper_call(
            image, entry, 0x01008000 - 20, 0x1000, 64,
            stack_pointer=0x01008000))
        self.assertIsNone(copy_wrapper_call(
            image, entry, 0x01002000, 0x1000, 64,
            stack_pointer=0x1014))

    def test_only_bounded_word_aligned_copies_are_proved(self):
        image, entry, _ = fixture()
        for destination, source, size, sp in ((0x1002001, 0x1000, 64, 0x1008000),
                (0x1002000, 0x1001, 64, 0x1008000),
                (0x1002000, 0x1000, 63, 0x1008000),
                (0x1002000, 0x1000, 0, 0x1008000),
                (0x1002000, 0x1000, 0x100004, 0x1008000),
                (0x1002000, 0x1000, 64, 0x1008001)):
            with self.subTest(arguments=(destination, source, size, sp)):
                self.assertIsNone(copy_wrapper_call(image, entry, destination, source,
                                                    size, stack_pointer=sp))
