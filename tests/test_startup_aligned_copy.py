import struct
import unittest

from msm5xxx_emulator.detection.startup_aligned_copy import aligned_copy_evidence


BASE = 0x100
SOURCE = 0x300
DESTINATION = 0x800


def _dp_imm(opcode, rd, rn, value, *, set_flags=False):
    return (0xe2000000 | (opcode << 21) | (int(set_flags) << 20)
            | (rn << 16) | (rd << 12) | value)


def _dp_reg(opcode, rd, rn, rm):
    return 0xe0000000 | (opcode << 21) | (rn << 16) | (rd << 12) | rm


def _multiple(load, base, registers, *, user_bank=False):
    mask = sum(1 << register for register in registers)
    return (0xe8800000 | (int(load) << 20) | (base << 16) | mask
            | (1 << 23) | (1 << 21) | (int(user_bank) << 22))


class _Program:
    def __init__(self, base=BASE):
        self.base = base
        self.items = []
        self.labels = {}

    def emit(self, word):
        self.items.append(("word", word))

    def label(self, name):
        self.labels[name] = len(self.items)

    def branch(self, label, condition=0xe):
        self.items.append(("branch", label, condition))

    def bytes(self):
        words = []
        for index, item in enumerate(self.items):
            pc = self.base + 4 * index
            if item[0] == "word":
                words.append(item[1])
                continue
            target = self.base + 4 * self.labels[item[1]]
            delta = (target - (pc + 8)) // 4
            words.append((item[2] << 28) | 0x0a000000 | (delta & 0xffffff))
        return b"".join(struct.pack("<I", word) for word in words)


def _chunked_copy(*, swap=False, clobber=False, zero_clobber=False,
                  unknown_carry=False, forged_link=False, write_pc=False,
                  read_pc=False, transform=False, user_bank=False,
                  sp_guard=False):
    p = _Program()
    if clobber:
        p.emit(_dp_reg(13, 4, 0, 0))  # MOV R4,R0 before saving the caller value.
    if zero_clobber:
        p.emit(_dp_imm(13, 4, 0, 0))  # MOV R4,#0 before saving the caller value.
    if unknown_carry:
        p.emit(_dp_imm(13, 3, 0, 0, set_flags=True))
        p.branch("copy_start", 0x3)  # BCC must reject unknown inherited C.
        p.emit(0xe12fff1e)
        p.label("copy_start")
    if write_pc:
        p.emit(_dp_reg(13, 15, 0, 0))  # MOV PC,R0.
    if read_pc:
        p.emit(_dp_imm(4, 3, 15, 0))   # ADD R3,PC,#0.
    if sp_guard:
        p.emit(_dp_reg(13, 3, 0, 0))   # MOV R3,R0 (copy destination).
        p.emit(0xe15d0003)             # CMP SP,R3.
        p.branch("early_return", 0x0) # BEQ returns without copying.
    p.emit(0xe92d4010)              # PUSH {R4,LR}.
    p.emit(_dp_imm(10, 0, 2, 8, set_flags=True))
    p.branch("tail", 0x3)           # BLO tail.
    p.label("loop")
    p.emit(_multiple(True, 1, (3, 4), user_bank=user_bank))
    if swap:
        p.emit(_dp_reg(13, 5, 0, 3))
        p.emit(_dp_reg(13, 3, 0, 4))
        p.emit(_dp_reg(13, 4, 0, 5))
    if transform:
        p.emit(0xe1a03083)            # MOV R3,R3,LSL #1 changes copied bytes.
    p.emit(_multiple(False, 0, (3, 4), user_bank=user_bank))
    p.emit(_dp_imm(2, 2, 2, 8, set_flags=True))
    p.emit(_dp_imm(10, 0, 2, 8, set_flags=True))
    p.branch("loop", 0x2)            # BHS loop.
    p.label("tail")
    p.emit(_dp_imm(10, 0, 2, 0, set_flags=True))
    p.branch("done", 0x0)            # BEQ done.
    p.emit(0xe4913004)               # LDR R3,[R1],#4.
    p.emit(0xe4803004)               # STR R3,[R0],#4.
    p.label("done")
    p.emit(0xe8bd4010)               # POP {R4,LR}.
    if forged_link:
        p.emit(_dp_reg(13, 14, 0, 0)) # MOV LR,R0 attempts to forge return.
    p.emit(0xe12fff1e)               # BX LR.
    if sp_guard:
        p.label("early_return")
        p.emit(0xe12fff1e)
    return p.bytes()


def _image(code, *, code_start=BASE, source=SOURCE, image_size=0x500):
    image = bytearray(image_size)
    image[code_start:code_start + len(code)] = code
    return bytes(image)


def _prove(image, *, entry=BASE, source=SOURCE, destination=DESTINATION,
           size=12, code_start=BASE, code_size=0x100,
           stack_pointer=0x70000000):
    return aligned_copy_evidence(image, entry, source, destination, size,
                                 code_start=code_start, code_size=code_size,
                                 stack_pointer=stack_pointer)


class StartupAlignedCopyTests(unittest.TestCase):
    def test_chunk_and_tail_copy_preserves_frame_and_registers(self):
        proof = _prove(_image(_chunked_copy()))
        self.assertIsNotNone(proof)
        self.assertEqual(proof["transfer_spans"],
                         ((0, 4, 0), (4, 4, 4), (8, 4, 8)))
        self.assertEqual(proof["copied_bytes"], 12)
        self.assertEqual(proof["stack_frame_bytes"], 8)
        self.assertGreater(proof["steps"], 0)

    def test_thumb_interworking_entry_is_source_traced(self):
        code = struct.pack("<H", 0x4778)  # BX PC, then align into ARM code.
        code += b"\x00\x00" + _chunked_copy()
        image = _image(code)
        proof = _prove(image, entry=BASE | 1, code_size=len(code))
        self.assertIsNotNone(proof)
        self.assertIn((BASE, 2), proof["code_spans"])

    def test_reordered_payload_is_rejected(self):
        self.assertIsNone(_prove(_image(_chunked_copy(swap=True)), size=8))

    def test_shifted_move_cannot_preserve_payload_provenance(self):
        self.assertIsNone(_prove(_image(_chunked_copy(transform=True)), size=8))

    def test_user_bank_multiple_transfer_is_rejected(self):
        self.assertIsNone(_prove(_image(_chunked_copy(user_bank=True)), size=8))

    def test_preserved_register_clobber_is_rejected(self):
        self.assertIsNone(_prove(_image(_chunked_copy(clobber=True))))

    def test_zero_write_cannot_fake_entry_register_preservation(self):
        self.assertIsNone(_prove(_image(_chunked_copy(zero_clobber=True))))

    def test_unknown_inherited_carry_is_not_assumed(self):
        self.assertIsNone(_prove(_image(_chunked_copy(unknown_carry=True))))

    def test_entry_link_constant_cannot_forge_return(self):
        self.assertIsNone(_prove(_image(_chunked_copy(forged_link=True)),
                                 destination=0xffff0000))

    def test_unmodeled_pc_reads_and_writes_are_rejected(self):
        self.assertIsNone(_prove(_image(_chunked_copy(write_pc=True))))
        self.assertIsNone(_prove(_image(_chunked_copy(read_pc=True))))

    def test_stack_restore_to_wrong_register_is_rejected(self):
        code = bytearray(_chunked_copy())
        # The final POP restores the saved value into R5, leaving R4 clobbered.
        code[-8:-4] = struct.pack("<I", 0xe8bd4020)
        self.assertIsNone(_prove(_image(bytes(code))))

    def test_early_return_cannot_claim_full_extent(self):
        p = _Program()
        p.emit(0xe4913004)
        p.emit(0xe4803004)
        p.emit(0xe12fff1e)
        self.assertIsNone(_prove(_image(p.bytes()), size=8))

    def test_wrong_transfer_width_is_rejected(self):
        p = _Program()
        p.emit(0xe1d130b0)  # LDRH R3,[R1].
        p.emit(0xe1c030b0)  # STRH R3,[R0].
        p.emit(0xe12fff1e)
        self.assertIsNone(_prove(_image(p.bytes()), size=4))

    def test_unaligned_arguments_and_out_of_bounds_source_are_rejected(self):
        image = _image(_chunked_copy())
        self.assertIsNone(_prove(image, source=SOURCE + 1))
        self.assertIsNone(_prove(image, source=len(image) - 4, size=8))

    def test_destination_cannot_overlap_modeled_stack(self):
        image = _image(_chunked_copy())
        self.assertIsNone(_prove(image, destination=0x70000000 - 20,
                                 size=32))

    def test_source_path_uses_the_supplied_stack_pointer(self):
        image = _image(_chunked_copy(sp_guard=True))
        destination = 0x20000
        self.assertIsNone(_prove(image, destination=destination,
                                 stack_pointer=destination))
        self.assertIsNotNone(_prove(
            image, destination=destination, stack_pointer=destination + 0x10100))

    def test_entry_outside_closed_code_region_is_rejected(self):
        image = _image(_chunked_copy())
        self.assertIsNone(_prove(image, entry=BASE + 0x100, code_size=0x40))


if __name__ == "__main__":
    unittest.main()
