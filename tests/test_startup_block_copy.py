"""Synthetic tests for reset-linked paired block-copy evidence."""
import struct
import unittest

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, FirmwareFacts
from msm5xxx_emulator.detection.fact_models import FunctionFacts, MemoryAccess
from msm5xxx_emulator.detection.startup_block_copy import (
    ResetLinkedBlockCopy, _arm_memcpy_body, _call_stack_effect,
    _copied_helper_source, _copied_helper_entry,
    _paired_copy, _path_preserves_copy, _register_definition_survives,
    _register_load_survives, _signed_transfer_extent, _stack_pointer_at_call,
    reset_linked_block_copies,
)
from msm5xxx_emulator.detection.startup_block_copy_patterns import arm_memset_body


def paired_copy_fixture(*, source=0x80, destination=0x1000, size=20,
                        source_cursor=0, destination_cursor=1,
                        branch=0xDBFB, register_list=0xF8):
    image = bytearray(0x200)
    # Three PC-relative descriptor pointers followed by field dereferences.
    words = (
        0x4B0F, 0x6818,  # *[0x40] -> source field -> r0
        0x4B0F, 0x6819,  # *[0x44] -> destination field -> r1
        0x4B0F, 0x681A,  # *[0x48] -> length field -> r2
        0x188A,           # end = r1 + r2 -> r2
        (0xC800 | (source_cursor << 8) | register_list),
        (0xC000 | (destination_cursor << 8) | register_list),
        0x4291, branch,   # CMP dst,end; BLT LDMIA
        0xE7FE,            # closed terminal self-loop
    )
    struct.pack_into('<' + 'H' * len(words), image, 0, *words)
    struct.pack_into('<III', image, 0x40, 0x60, 0x64, 0x68)
    struct.pack_into('<III', image, 0x60, source, destination, size)
    return bytes(image)


def arm_branch(condition, address, target):
    displacement = (target - (address + 8)) // 4
    return (condition << 28) | 0x0A000000 | (displacement & 0xFFFFFF)


def arm_memcpy_fixture(*, bad_store_list=False, bad_counter=False,
                       bad_header=False, bad_tail=False, extra_write=False,
                       early_return=False, wrong_mode=False, alias_list=False,
                       conditional_arithmetic=False):
    image = bytearray(0x100)
    words = (
        0xE92D0FFF,  # PUSH {r0-r11}
        (0x12522024 if conditional_arithmetic else 0xE2522024),
        arm_branch(4, 8, 0x1C),
        (0xE9110FF8 if wrong_mode else
         0xE8B10FFA if alias_list else 0xE8B10FF8),
        0xE8A00FF8, 0xE2522024, arm_branch(5, 0x18, 0x0C),
        0xE2922018,
        arm_branch(4, 0x20, 0x1C if bad_header else 0x34),
        0xE8B10038, 0xE8A00038,
        0xE252200C, arm_branch(5, 0x30, 0x24),
        (0xE5803000 if extra_write else
         0xE2922008 if bad_tail else 0xE292200C),
        arm_branch(0, 0x38, 0x4C),
        0xE8B10010,
        (0xE8A00018 if bad_store_list else 0xE8A00010),
        (0xE2522008 if bad_counter else 0xE2522004),
        arm_branch(1, 0x48, 0x3C),
        (0xE12FFF1E if early_return else 0xE8BD0FFF),
        0xE12FFF1E,
    )
    struct.pack_into('<' + 'I' * len(words), image, 0, *words)
    return bytes(image)


def arm_memset_fixture(*, bad_header=False, bad_tail=False, extra_write=False,
                       early_return=False, bad_store=False):
    image = bytearray(0x100)
    words = [0xE92D0FFF]
    words.extend(0xE3A00000 | (register << 12) for register in range(2, 12))
    words.extend((
        0xE2511028, arm_branch(4, 0x30, 0x54 if bad_header else 0x40),
        0xE8A00FFC, 0xE2511028, arm_branch(5, 0x3C, 0x34),
        0xE2911018,
        arm_branch(4, 0x44, 0x40 if bad_header else 0x54),
        (0xE5802000 if extra_write else 0xE8A0003C),
        0xE2511010, arm_branch(5, 0x50, 0x48),
        (0xE2911008 if bad_tail else 0xE2911010),
        arm_branch(0, 0x58, 0x68),
        0xE8A00004 if not bad_store else 0xE8A00008,
        0xE2511004, arm_branch(1, 0x64, 0x5C),
        0xE12FFF1E if early_return else 0xE8BD0FFF,
        0xE12FFF1E,
    ))
    struct.pack_into('<' + 'I' * len(words), image, 0, *words)
    return bytes(image)


class StartupBlockCopyTests(unittest.TestCase):
    def prove(self, image, *, ram_end=0x1100, flash_end=0x200):
        return _paired_copy(FirmwareFacts(image), image,
                            CodeAddress(0, 'thumb'), flash_end=flash_end,
                            ram_base=0x1000, ram_end=ram_end,
                            initial_sp=0x10F0)

    def test_descriptor_and_five_word_loop_prove_actual_burst(self):
        copies = self.prove(paired_copy_fixture(size=24))
        self.assertEqual([(row[0], row[1], row[2]) for row in copies],
                         [(0x80, 0x1000, 24)])
        self.assertIn((0x80, 40), copies[0][3])

    def test_rejects_wrong_source_register_and_loop_target(self):
        self.assertEqual(self.prove(paired_copy_fixture(source_cursor=6)), ())
        self.assertEqual(self.prove(paired_copy_fixture(register_list=0xF1)), ())
        self.assertEqual(self.prove(paired_copy_fixture(register_list=0x7C)), ())
        self.assertEqual(self.prove(paired_copy_fixture(branch=0xDBFC)), ())
        self.assertEqual(self.prove(paired_copy_fixture(branch=0xD3FB)), ())

    def test_rejects_unlinked_descriptor_and_clobbered_geometry(self):
        changed = bytearray(paired_copy_fixture())
        struct.pack_into('<I', changed, 0x40, 0x61)
        self.assertEqual(self.prove(bytes(changed)), ())
        changed = bytearray(paired_copy_fixture())
        struct.pack_into('<H', changed, 0x0C, 0x2200)  # MOVS r2,#0
        self.assertEqual(self.prove(bytes(changed)), ())

    def test_bounds_include_full_rounded_last_burst(self):
        image = paired_copy_fixture(source=0x1E0, size=24)
        self.assertEqual(self.prove(image, flash_end=0x200), ())
        image = paired_copy_fixture(destination=0x10F0, size=24)
        self.assertEqual(self.prove(image, ram_end=0x1100), ())

    def test_public_api_requires_a_reset_root(self):
        image = paired_copy_fixture()
        self.assertEqual(reset_linked_block_copies(image, 0x1000, 0x100, 0x200), ())

    def test_signed_loop_and_written_extent_are_explicit(self):
        self.assertTrue(_signed_transfer_extent(0x1000, 0x2000, 0x18, 0x28, 0x4000))
        self.assertFalse(_signed_transfer_extent(
            0x7FFFFFF0, 0x2000, 0x18, 0x28, 0x80000000))
        copy = ResetLinkedBlockCopy(0x7732D4, 0x03800000, 0xD7CC, (), 0xD7DC)
        self.assertEqual(copy.size, 0xD7CC)
        self.assertEqual(copy.mapped_size, 0xD7DC)

    def test_veneer_requires_aligned_arm_state_target(self):
        image = bytearray(0x40)
        struct.pack_into('<H', image, 0x20, 0x4778)  # BX PC
        struct.pack_into('<I', image, 0x24, 0xE59FF000)  # LDR PC,[PC]
        struct.pack_into('<I', image, 0x2C, 0x3804)
        facts = FirmwareFacts(bytes(image))
        target = CodeAddress(0x20, 'thumb')
        copy = ResetLinkedBlockCopy(0x1000, 0x3800, 0x100, (), 0x100)
        self.assertEqual(_copied_helper_source(facts, None, target, copy)[0], 0x1004)
        self.assertIsNone(_copied_helper_source(
            facts, None, CodeAddress(0x20, 'arm'), copy))
        struct.pack_into('<I', image, 0x24, 0x159FF000)  # LDRNE PC,[PC]
        self.assertIsNone(_copied_helper_source(
            FirmwareFacts(bytes(image)), None, target, copy))
        struct.pack_into('<I', image, 0x24, 0xE59FF000)
        struct.pack_into('<I', image, 0x2C, 0x3805)
        facts = FirmwareFacts(bytes(image))
        self.assertIsNone(_copied_helper_source(facts, None, target, copy))

    def test_register_exchange_veneer_preserves_target_state(self):
        image = bytearray(0x40)
        struct.pack_into('<H', image, 0x20, 0x4778)
        struct.pack_into('<III', image, 0x24,
                         0xE59FC000, 0xE12FFF1C, 0x3805)
        target = CodeAddress(0x20, 'thumb')
        copy = ResetLinkedBlockCopy(0x1000, 0x3800, 0x100, (), 0x100)
        def prove():
            return _copied_helper_entry(FirmwareFacts(bytes(image)), None,
                                        target, copy)
        self.assertEqual(prove()[0], CodeAddress(0x1004, 'thumb'))
        self.assertIsNone(_copied_helper_source(
            FirmwareFacts(bytes(image)), None, target, copy))
        for branch, pointer in ((0x112FFF1C, 0x3805),
                                (0xE12FFF1B, 0x3805),
                                (0xE12FFF1C, 0x3802),
                                (0xE12FFF1C, 0x3901)):
            with self.subTest(branch=branch, pointer=pointer):
                struct.pack_into('<II', image, 0x28, branch, pointer)
                self.assertIsNone(prove())

    def test_intervening_calls_need_bounded_disjoint_write_effects(self):
        sites = tuple(CodeAddress(address, 'thumb') for address in range(0, 8, 2))
        function = FunctionFacts(
            entry=sites[0], instructions=sites,
            calls=((sites[2], CodeAddress(0x20, 'arm')),
                   (sites[3], CodeAddress(0x24, 'arm'))),
            literals=(), accesses=(), back_edges=(), mode_stacks=(), unresolved=(),
            complete=True, control_edges=tuple(zip(sites, sites[1:])))
        facts = FirmwareFacts(bytes(0x40))
        self.assertTrue(_path_preserves_copy(
            facts, function, sites[1], sites[3], 0x3800, 0x100,
            {sites[2]: (0x1800, 0x20), sites[3]: (0x1800, 0x20)}))
        self.assertFalse(_path_preserves_copy(
            facts, function, sites[1], sites[3], 0x3800, 0x100,
            {sites[2]: (0x3808, 4), sites[3]: (0x1800, 0x20)}))
        self.assertFalse(_path_preserves_copy(
            facts, function, sites[1], sites[3], 0x3800, 0x100, {}))

    def test_postloop_store_and_current_call_effect_are_checked(self):
        sites = tuple(CodeAddress(address, 'thumb') for address in range(0, 10, 2))
        edges = tuple(zip(sites, sites[1:]))
        image = bytearray(10)
        struct.pack_into('<H', image, 2, 0x6008)  # STR r0,[r1]
        facts = FirmwareFacts(bytes(image))
        call = CodeAddress(0x20, 'arm')
        base = dict(entry=sites[0], instructions=sites,
                    calls=((sites[4], call),), literals=(), back_edges=(),
                    mode_stacks=(), unresolved=(), complete=True,
                    control_edges=edges)
        # The first instruction after the loop is a store into the installed
        # code; it must be included in the path scan.
        store = MemoryAccess(sites[1], 'write', 0x3808, 4, None, (0x3808,))
        function = FunctionFacts(**base, accesses=(store,))
        self.assertFalse(_path_preserves_copy(
            facts, function, sites[1], sites[4], 0x3800, 0x100,
            {sites[4]: (0x1800, 0x20)}))
        clean = FunctionFacts(**base, accesses=(
            MemoryAccess(sites[1], 'write', 0x3000700, 4, None, (0x3000700,)),))
        self.assertFalse(_path_preserves_copy(
            facts, clean, sites[1], sites[4], 0x3800, 0x100,
            {sites[4]: (0x3808, 4)}))
        self.assertTrue(_path_preserves_copy(
            facts, clean, sites[1], sites[4], 0x3800, 0x100,
            {sites[4]: (0x1800, 0x20)}))

    def test_unlocated_push_and_push_alias_reject(self):
        image = bytearray(12)
        struct.pack_into('<I', image, 4, 0xE92D000F)  # PUSH {r0-r3}
        sites = tuple(CodeAddress(address, 'arm') for address in (0, 4, 8))
        function = FunctionFacts(
            entry=sites[0], instructions=sites,
            calls=((sites[2], CodeAddress(0x20, 'arm')),), literals=(),
            accesses=(), back_edges=(), mode_stacks=(), unresolved=(),
            complete=True, control_edges=((sites[0], sites[1]),
                                          (sites[1], sites[2])))
        facts = FirmwareFacts(bytes(image))
        effect = {sites[2]: ((0x1800, 4), (0x1880, 16))}
        self.assertFalse(_path_preserves_copy(
            facts, function, sites[1], sites[2], 0x3800, 0x100, effect))
        located = FunctionFacts(
            entry=sites[0], instructions=sites,
            calls=function.calls, literals=(),
            accesses=(MemoryAccess(sites[1], 'write', 0x1800, 16,
                                   None, (0x1800,)),),
            back_edges=(), mode_stacks=(), unresolved=(), complete=True,
            control_edges=function.control_edges)
        self.assertTrue(_path_preserves_copy(
            facts, located, sites[1], sites[2], 0x3800, 0x100, effect))
        aliased = FunctionFacts(
            entry=sites[0], instructions=sites,
            calls=function.calls, literals=(),
            accesses=(MemoryAccess(sites[1], 'write', 0x3808, 16,
                                   None, (0x3808,)),),
            back_edges=(), mode_stacks=(), unresolved=(), complete=True,
            control_edges=function.control_edges)
        self.assertFalse(_path_preserves_copy(
            facts, aliased, sites[1], sites[2], 0x3800, 0x100, effect))

    def test_callee_save_frame_uses_callsite_sp_and_avoids_copy(self):
        sites = tuple(CodeAddress(address, 'thumb') for address in (0, 2, 4))
        image = bytearray(6)
        struct.pack_into('<HHH', image, 0, 0xB510, 0xB084, 0x46C0)
        facts = FirmwareFacts(bytes(image))
        function = FunctionFacts(
            entry=sites[0], instructions=sites,
            calls=((sites[2], CodeAddress(0x20, 'arm')),), literals=(),
            accesses=(), back_edges=(), mode_stacks=(), unresolved=(),
            complete=True, control_edges=((sites[0], sites[1]),
                                          (sites[1], sites[2])))
        sp = _stack_pointer_at_call(facts, function, sites[2], 0x1801000)
        self.assertEqual(sp, 0x1800FE8)
        args = (0x1800000, 0x1880000, 0x3800000, 0x1000)
        self.assertEqual(_call_stack_effect(
            sp, *args, 0x1820000, 0x100, 48),
            (0x1800FB8, 48))
        struct.pack_into('<HHH', image, 0, 0xB510, 0xB090, 0x46C0)
        facts = FirmwareFacts(bytes(image))
        low_sp = _stack_pointer_at_call(facts, function, sites[2], 0x1800030)
        self.assertEqual(low_sp, 0x17FFFE8)
        self.assertIsNone(_call_stack_effect(
            low_sp, *args, 0x1820000, 0x100, 48))
        self.assertIsNone(_call_stack_effect(
            sp, *args, 0x1800FC0, 0x20, 48))

    def test_incomplete_copy_path_and_call_clobbered_registers_reject(self):
        sites = tuple(CodeAddress(address, 'thumb') for address in range(0, 8, 2))
        facts = FirmwareFacts(bytes(8))
        call = CodeAddress(0x20, 'arm')
        edges = tuple(zip(sites, sites[1:]))
        common = dict(entry=sites[0], instructions=sites,
                      calls=((sites[2], call), (sites[3], call)), literals=(),
                      accesses=(), back_edges=(), mode_stacks=(), unresolved=(),
                      control_edges=edges)
        incomplete = FunctionFacts(**common, complete=False)
        self.assertFalse(_path_preserves_copy(
            facts, incomplete, sites[1], sites[3], 0x3800, 0x100,
            {sites[3]: (0x1800, 0x20)}))
        for register in (0, 1, 2, 3):
            image = bytearray(8)
            struct.pack_into('<H', image, 0,
                             0x2001 | (register << 8))  # MOVS rN,#1
            local_facts = FirmwareFacts(bytes(image))
            function = FunctionFacts(**common, complete=True)
            self.assertFalse(_register_definition_survives(
                local_facts, function, sites[0], register, sites[3]))
        image = bytearray(8)
        struct.pack_into('<H', image, 0, 0x4800)  # LDR r0,[PC,#0]
        self.assertFalse(_register_load_survives(
            FirmwareFacts(bytes(image)),
            FunctionFacts(**common, complete=True), sites[0], 0, sites[3]))

    def test_intervening_store_must_be_located_and_disjoint(self):
        image = bytearray(8)
        struct.pack_into('<H', image, 4, 0x6008)  # STR r0,[r1]
        sites = tuple(CodeAddress(address, 'thumb') for address in range(0, 8, 2))
        write = MemoryAccess(sites[2], 'write', 0x3808, 4, None, (0x3808,))
        edges = tuple(zip(sites, sites[1:]))
        base = dict(entry=sites[0], instructions=sites,
                    calls=((sites[3], CodeAddress(0x20, 'arm')),), literals=(),
                    back_edges=(), mode_stacks=(), unresolved=(), complete=True,
                    control_edges=edges)
        facts = FirmwareFacts(bytes(image))
        overlaps = FunctionFacts(**base, accesses=(write,))
        disjoint = FunctionFacts(**base, accesses=(
            MemoryAccess(sites[2], 'write', 0x3000700, 4, None, (0x3000700,)),))
        unknown = FunctionFacts(**base, accesses=())
        self.assertFalse(_path_preserves_copy(
            facts, overlaps, sites[1], sites[3], 0x3800, 0x100,
            {sites[3]: (0x1800, 4)}))
        self.assertTrue(_path_preserves_copy(
            facts, disjoint, sites[1], sites[3], 0x3800, 0x100,
            {sites[3]: (0x1800, 4)}))
        self.assertFalse(_path_preserves_copy(
            facts, unknown, sites[1], sites[3], 0x3800, 0x100,
            {sites[3]: (0x1800, 4)}))

    def test_installed_arm_helper_requires_three_bounded_transfer_shapes(self):
        image = arm_memcpy_fixture()
        facts = FirmwareFacts(image)
        copy = ResetLinkedBlockCopy(0, 0x3800, 0x100, ())
        proof = _arm_memcpy_body(facts, CodeAddress(0, 'arm'), copy)
        self.assertIsNotNone(proof)
        self.assertEqual(len(proof[0].instructions), 21)
        for changed in (arm_memcpy_fixture(bad_store_list=True),
                        arm_memcpy_fixture(bad_counter=True),
                        arm_memcpy_fixture(bad_header=True),
                        arm_memcpy_fixture(bad_tail=True),
                        arm_memcpy_fixture(extra_write=True),
                        arm_memcpy_fixture(early_return=True),
                        arm_memcpy_fixture(wrong_mode=True),
                        arm_memcpy_fixture(alias_list=True),
                        arm_memcpy_fixture(conditional_arithmetic=True)):
            self.assertIsNone(_arm_memcpy_body(
                FirmwareFacts(changed), CodeAddress(0, 'arm'), copy))

    def test_intervening_arm_zero_helper_requires_closed_write_grammar(self):
        image = arm_memset_fixture()
        copy = ResetLinkedBlockCopy(0, 0x3800, 0x100, (), 0x100)
        self.assertIsNotNone(arm_memset_body(
            FirmwareFacts(image), CodeAddress(0, 'arm'), copy))
        for changed in (arm_memset_fixture(bad_header=True),
                        arm_memset_fixture(bad_tail=True),
                        arm_memset_fixture(extra_write=True),
                        arm_memset_fixture(early_return=True),
                        arm_memset_fixture(bad_store=True)):
            self.assertIsNone(arm_memset_body(
                FirmwareFacts(changed), CodeAddress(0, 'arm'), copy))


if __name__ == '__main__':
    unittest.main()
