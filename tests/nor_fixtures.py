"""Synthetic semantic evidence for AMD x16 command callbacks."""
import struct
import unittest
from dataclasses import replace

from capstone import arm as a

from msm5xxx_emulator.detection.facts import (
    CodeAddress, FirmwareFacts, FunctionFacts, ScatterCandidate,
    SymbolicValue,
)
from msm5xxx_emulator.detection.image_view import ImageView
from msm5xxx_emulator.detection.startup_facts import (
    CopyLoopTransfer, OrderedCopyTransfer, StartupCopyRow, VectorCopyRow,
    _compose_ordered_transfers, _definition_reaches, _state_initializer,
    _stride_exit, prove_ordered_copy_transfer,
    prove_reset_prefix_completion, prove_startup_copy_consumer,
    prove_copy_consumer, proven_startup_rows,
)
from msm5xxx_emulator.detection.registry import device_domain
CopyConsumerProof = device_domain('storage.nor_protocol').CopyConsumerProof
known_amd_x16_profile = device_domain('storage.nor_protocol').known_amd_x16_profile
prove_amd_x16_hardware_contract = device_domain('storage.nor_protocol').prove_amd_x16_hardware_contract
summarize_amd_x16 = device_domain('storage.nor_protocol').summarize_amd_x16


_ARGUMENTS = {
    a.ARM_REG_R0: SymbolicValue.arg(0),
    a.ARM_REG_R1: SymbolicValue.arg(1),
    a.ARM_REG_R6: SymbolicValue.arg(2),
}


def arm_function(entry, words, symbols=None):
    image = struct.pack('<' + 'I' * len(words), *words)
    return FirmwareFacts(image, base=entry).function(
        CodeAddress(entry, 'arm'), symbolic_registers=symbols or _ARGUMENTS)


def command_function(entry, events, *, payload=False):
    # Each command forms its address from a symbolic window base and a literal
    # offset. Code and literal words are generated independently of any image.
    words = []
    for _offset, value in events:
        words.extend((0, 0xE0803004, 0xE3A02000 | value, 0xE1C320B0))
    if payload:
        words.append(0xE1C160B0)  # STRH r6,[r1]
    words.append(0xE12FFF1E)  # BX lr
    pool_start = len(words) * 4
    literals = []
    for index, (offset, _value) in enumerate(events):
        instruction = index * 16
        literal = pool_start + index * 4
        displacement = literal - (instruction + 8)
        words[index * 4] = 0xE59F4000 | displacement  # LDR r4,[pc,#imm]
        literals.append(offset)
    words.extend(literals)
    return arm_function(entry, words)


def callback_fixture():
    starts = {
        'read': CodeAddress(0x100, 'arm'),
        'program': CodeAddress(0x200, 'arm'),
        'erase': CodeAddress(0x300, 'arm'),
        'bypass-enter': CodeAddress(0x500, 'arm'),
    }
    callbacks = {
        'read': arm_function(0x100, (0xE1D020B0, 0xE12FFF1E)),
        'program': command_function(0x200, ((0xAA0, 0xAA), (0x540, 0x55),
                                            (0xAA0, 0xA0)), payload=True),
        'erase': command_function(0x300, ((0xAA0, 0xAA), (0x540, 0x55),
                                          (0xAA0, 0x80), (0xAA0, 0xAA),
                                          (0x540, 0x55), (0xAA0, 0x30))),
        'bypass-enter': command_function(0x500, ((0xAA0, 0xAA), (0x540, 0x55),
                                                 (0xAA0, 0x20))),
    }
    return starts, callbacks


def copy_consumer_fixture(*, wrong_destination=False, reverse_bound=False,
                          bypass_store=False, extra_unknown_store=False,
                          separate_zero=False, side_effect_store=False,
                          invariant_zero_register=False,
                          outside_store_address=None,
                          stack_temporary=False,
                          bypass_row=False,
                          outside_call=False,
                          saved_lr_call=False,
                          overwrite_saved_lr=False,
                          bypass_copy_loop=False,
                          bypass_zero_loop=False):
    base, pool, table = 0x100, 0x180, 0x200
    zero_table = table + 0x20 if separate_zero else table + 12
    halfwords, labels, fixups, literal_values = [], {}, [], []

    def emit(value):
        halfwords.append(value)

    def literal(register, address):
        slot = len(literal_values)
        literal_values.append(address)
        index = len(halfwords)
        emit(0)
        fixups.append(('literal', index, register, slot))

    def branch(label, condition=None):
        index = len(halfwords)
        emit(0)
        fixups.append(('branch', index, label, condition))

    if bypass_row:
        emit(0x2F00)                     # CMP r7,#0
        branch('early-return', 1)        # BNE skips both transfer loops
    if stack_temporary:
        emit(0xB480)                     # PUSH {r7}
    if saved_lr_call:
        emit(0xB580)                     # PUSH {r7,lr}
    if bypass_copy_loop:
        emit(0x2F00)                     # CMP r7,#0
        branch('zero-init', 1)           # BNE joins the real copy-loop exit
    literal(0, table + 4)
    emit(0x6800)                         # LDR r0,[r0]
    literal(1, table + 8)
    emit(0x6809)                         # LDR r1,[r1]
    emit(0x1842)                         # ADDS r2,r0,r1
    literal(3, table)
    emit(0x681D)                         # LDR r5,[r3]
    literal(3, table + 4)
    emit(0x681C)                         # LDR r4,[r3]
    labels['copy-compare'] = base + len(halfwords) * 2
    emit(0x42A2 if reverse_bound else 0x4294)  # CMP r4,r2
    branch('copy-body', 3)               # BLO copy-body
    branch('zero-init')
    labels['copy-body'] = base + len(halfwords) * 2
    emit(0x6828)                         # LDR r0,[r5]
    if bypass_store:
        branch('copy-increment', 0)      # unknown EQ path can skip store
    emit(0x6000 | ((6 if wrong_destination else 4) << 3))
    if side_effect_store:
        emit(0x2601)                     # MOVS r6,#1
        literal(7, 0x03000620)
        emit(0x603E)                     # STR r6,[r7] to declared device range
    if extra_unknown_store:
        emit(0x6030)                     # STR r0,[r6], destination unresolved
    if bypass_store:
        labels['copy-increment'] = base + len(halfwords) * 2
    emit(0x3404)                         # ADDS r4,#4
    emit(0x3504)                         # ADDS r5,#4
    branch('copy-compare')

    labels['zero-init'] = base + len(halfwords) * 2
    if bypass_zero_loop:
        emit(0x2F00)
        branch('end', 1)                 # BNE joins the real zero-loop exit
    literal(0, zero_table)
    emit(0x6800)
    literal(1, zero_table + 4)
    emit(0x6809)
    emit(0x1842)
    literal(3, zero_table)
    emit(0x681C)
    if invariant_zero_register:
        emit(0x2000)                     # MOVS r0,#0 before loop entry
        emit(0x1C05)                     # ADDS r5,r0,#0; invariant zero value
    labels['zero-compare'] = base + len(halfwords) * 2
    emit(0x42A2 if reverse_bound else 0x4294)
    branch('zero-body', 3)
    branch('end')
    labels['zero-body'] = base + len(halfwords) * 2
    if not invariant_zero_register:
        emit(0x2000)                     # MOVS r0,#0
    emit(0x6025 if invariant_zero_register else 0x6020)
    emit(0x3404)                         # ADDS r4,#4
    branch('zero-compare')
    labels['end'] = base + len(halfwords) * 2
    if outside_store_address is not None:
        emit(0x2601)                     # MOVS r6,#1
        literal(7, outside_store_address)
        emit(0x603E)                     # STR r6,[r7]
    if stack_temporary:
        emit(0xBC80)                     # POP {r7}
    if saved_lr_call:
        emit(0x2000 if overwrite_saved_lr else 0x2001)  # MOVS r0,#0/1
        if overwrite_saved_lr:
            emit(0x9001)                 # STR r0,[sp,#4], overwrite saved LR
        index = len(halfwords)
        emit(0)
        emit(0)
        fixups.append(('call', index, 'saved-helper', None))
        emit(0xBC80)                     # POP {r7}
        emit(0xBC08)                     # POP {r3}
        emit(0x4718)                     # BX r3, restoring entry LR
        labels['saved-helper'] = base + len(halfwords) * 2
        emit(0x4770)                     # BX lr
    elif outside_call:
        emit(0xF000)                     # BL to following instruction
        emit(0xF800)
        emit(0x4770)                     # BX lr (clobbered LR loops here)
    else:
        emit(0x4770)                     # BX lr
    if bypass_row:
        labels['early-return'] = base + len(halfwords) * 2
        emit(0x4770)                     # BX lr

    for kind, index, value, slot in fixups:
        pc = base + index * 2
        if kind == 'literal':
            displacement = pool + slot * 4 - ((pc + 4) & ~3)
            halfwords[index] = 0x4800 | (value << 8) | (displacement // 4)
        elif kind == 'call':
            displacement = (labels[value] - (pc + 4)) // 2
            halfwords[index] = 0xF000 | ((displacement >> 11) & 0x7ff)
            halfwords[index + 1] = 0xF800 | (displacement & 0x7ff)
        else:
            displacement = (labels[value] - (pc + 4)) // 2
            halfwords[index] = (
                0xD000 | (slot << 8) | (displacement & 0xFF)
                if slot is not None
                else 0xE000 | (displacement & 0x7FF)
            )

    code = struct.pack('<' + 'H' * len(halfwords), *halfwords)
    image = bytearray(table + 0x80)
    image[base:base + len(code)] = code
    for index, value in enumerate(literal_values):
        struct.pack_into('<I', image, pool + 4 * index, value)
    if separate_zero:
        struct.pack_into('<3I', image, table, 0x220, 0x1000, 0x40)
        struct.pack_into('<2I', image, zero_table, 0x1040, 0x20)
        row = StartupCopyRow(table, 0x220, 0x1000, 0x40,
                             zero_table, 0x1040, 0x20)
    else:
        struct.pack_into('<5I', image, table, 0x220, 0x1000, 0x40, 0x1040, 0x20)
        row = ScatterCandidate(table, 0x220, 0x1000, 0x40, 0x1040, 0x20)
    return bytes(image), row


def ordered_copy_fixture(*, wrong_stride=False, source_gap=False,
                         unused_row_fields=False, reverse_second=False,
                         bypass_second_compare=False, clobber_bound=False,
                         duplicate_update=False,
                         conditional_duplicate_update=False,
                         unmodelled_multiple_transfer=False,
                         nested_cycle=False,
                         outside_store_address=None):
    base, table, source, target = 0x100, 0x400, 0x600, 0x1000
    size, trailing = 0x20, 0x20
    halfwords, labels, fixups, literal_values = [], {}, [], []

    def emit(value):
        halfwords.append(value)

    def literal(register, address):
        slot = len(literal_values)
        literal_values.append(address)
        index = len(halfwords)
        emit(0)
        fixups.append(('literal', index, register, slot))

    def branch(label, condition=None):
        index = len(halfwords)
        emit(0)
        fixups.append(('branch', index, label, condition))

    def loop(name, *, zero, split, first=False):
        if zero:
            literal(0, trailing if unused_row_fields else table + 16)
            if not unused_row_fields:
                emit(0x6800)
            if split:
                emit(0x0840)
            literal(1, target + size if unused_row_fields else table + 12)
            if not unused_row_fields:
                emit(0x6809)
            emit(0x1846)
            if first:
                if unused_row_fields:
                    literal(4, target + size)
                else:
                    literal(0, table + 12)
                    emit(0x6804)
        elif first:
            literal(0, size if unused_row_fields else table + 8)
            if not unused_row_fields:
                emit(0x6800)
            emit(0x0840)
            literal(1, target if unused_row_fields else table + 4)
            if not unused_row_fields:
                emit(0x6809)
            emit(0x1846)
            if unused_row_fields:
                literal(5, source)
                literal(4, target)
            else:
                literal(0, table)
                emit(0x6805)
                literal(0, table + 4)
                emit(0x6804)
        else:
            if name == 'copy-rest' and source_gap:
                emit(0x3504)  # ADD r5,#4 breaks source-span adjacency
            literal(0, target if unused_row_fields else table + 4)
            if not unused_row_fields:
                emit(0x6800)
            literal(1, size if unused_row_fields else table + 8)
            if not unused_row_fields:
                emit(0x6809)
            emit(0x1846)
        labels[name + '-compare'] = base + len(halfwords) * 2
        if name == 'copy-rest' and bypass_second_compare:
            emit(0x42B7)  # CMP r7,r6; unknown condition reaches BLO directly
            branch(name + '-test', 1)
        emit(0x42B4)  # CMP r4,r6
        if name == 'copy-rest' and bypass_second_compare:
            labels[name + '-test'] = base + len(halfwords) * 2
        if name == 'copy-rest' and reverse_second:
            branch(name + '-body', 2)  # BHS must not be interpreted as BLO
        else:
            branch(name + '-body', 3)
        branch(name + '-exit')
        labels[name + '-body'] = base + len(halfwords) * 2
        if name == 'copy-rest' and clobber_bound:
            emit(0x2610)  # MOVS r6,#0: destroys the loop bound each iteration
        if zero:
            emit(0x2000)  # MOVS r0,#0
            emit(0x6020)  # STR r0,[r4]
            emit(0x3404)
        else:
            if name == 'copy-rest' and nested_cycle:
                labels[name + '-load'] = base + len(halfwords) * 2
            emit(0x6828)  # LDR r0,[r5]
            if name == 'copy-rest' and nested_cycle:
                emit(0x2F00)  # CMP r7,#0, producing an unknown condition
                branch(name + '-load', 1)  # BNE repeats the inner load
            emit(0x6020)  # STR r0,[r4]
            if name == 'copy-rest' and unmodelled_multiple_transfer:
                emit(0xCD01)  # LDMIA r5!,{r0}
            emit(0x3408 if wrong_stride and first else 0x3404)
            if name == 'copy-rest' and duplicate_update:
                emit(0x3404)  # second cursor increment in one loop iteration
            if name == 'copy-rest' and conditional_duplicate_update:
                emit(0xBF08)  # IT EQ
                emit(0x3404)  # predicated second cursor increment
            emit(0x3504)
        branch(name + '-compare')
        labels[name + '-exit'] = base + len(halfwords) * 2

    loop('copy-half', zero=False, split=True, first=True)
    loop('copy-rest', zero=False, split=False)
    loop('clear-half', zero=True, split=True, first=True)
    loop('clear-rest', zero=True, split=False)
    if outside_store_address is not None:
        literal(0, outside_store_address)
        emit(0x2101)  # MOVS r1,#1
        emit(0x6001)  # STR r1,[r0]
    if unused_row_fields:
        for field in (table, table + 4, table + 8, table + 12, table + 16):
            literal(0, field)
            emit(0x6800)
    emit(0x4770)  # BX lr

    pool = (base + len(halfwords) * 2 + 3) & ~3
    for kind, index, first, second in fixups:
        pc = base + index * 2
        if kind == 'literal':
            literal_address = pool + 4 * second
            displacement = literal_address - ((pc + 4) & ~3)
            halfwords[index] = 0x4800 | (first << 8) | (displacement // 4)
        else:
            displacement = (labels[first] - (pc + 4)) // 2
            halfwords[index] = (
                0xD000 | (second << 8) | (displacement & 0xFF)
                if second is not None
                else 0xE000 | (displacement & 0x7FF)
            )
    code = struct.pack('<' + 'H' * len(halfwords), *halfwords)
    image = bytearray(0x700)
    image[base:base + len(code)] = code
    for index, value in enumerate(literal_values):
        struct.pack_into('<I', image, pool + 4 * index, value)
    struct.pack_into('<5I', image, table, source, target, size,
                     target + size, trailing)
    image[source:source + size] = bytes(range(size))
    return bytes(image), VectorCopyRow(table, source, target, size,
                                       target + size, base)


def reset_handoff_fixture(*, bypass=False, alternate_call=False,
                          disconnected=False):
    image = bytearray(0xB0)
    transfer_entry, completion = 0x44, 0x46
    words = []
    if bypass or alternate_call:
        words.extend((0x2900, 0xD015 if bypass else 0xD00D))
    else:
        words.extend((0x46C0, 0x46C0))
        transfer_entry, completion = 0x40, 0x42
    if disconnected:
        words = [0x4770]
    else:
        words.extend((0x4802, 0x4700))
    struct.pack_into('<' + 'H' * len(words), image, 0x40, *words)
    struct.pack_into('<I', image, 0x50, 0x80)
    if bypass:
        struct.pack_into('<H', image, 0x70, 0x4770)
    if alternate_call:
        # The branch at 0x42 reaches this unrelated call path. The computed
        # cross-ISA handoff remains the only callable reset continuation.
        struct.pack_into('<HHH', image, 0x60, 0xF000, 0xF816, 0x4770)
        struct.pack_into('<H', image, 0x90, 0x4770)
    struct.pack_into('<II', image, 0x80, 0xE92D4000, 0xE12FFF1E)
    facts = FirmwareFacts(bytes(image))
    transfer = OrderedCopyTransfer(
        CodeAddress(transfer_entry, 'thumb'), (), (), (), (), (), (), (),
        CodeAddress(completion, 'thumb'))
    return facts, transfer
