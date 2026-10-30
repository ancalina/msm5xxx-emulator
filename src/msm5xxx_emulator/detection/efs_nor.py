"""RAM-selected inline EFS descriptor with bank-relative AMD x16 callbacks.

Fingerprints cover instructions (including command arithmetic and DQ6/DQ2
polling), with only BL displacements and PC-literal displacements normalized.
All normalized edges are resolved and checked separately. No part-name string,
file name, absolute code address or fixed bank geometry is an admission key.
"""
from __future__ import annotations

import hashlib
import struct

from .arm import arm_b_target, thumb_bl_target, thumb_literal_value
from .memory_layout import find_linker_layout
from .signatures import find_all

# (instruction span, relocation-normalized instruction SHA256).
_GRAMMAR = {
    'efs_init': (140, '44aec14afc8a3c8259e69d4eff75abfdb2a7562409e77780e6bf516be09f5267'),
    'efs_wrapper': (78, '7e9b201f45877c4c044de89da1b172c361c4fd35657f09e0ec50d81c0db46232'),
    'copy': (204, '1b53f8a93c4b70daa5933a89f6f51021942212309382e207b2da6f36bc9c0731'),
    'init': (20, '0d1aeef03426ad7a5ab261c49d96436367fe2f3fd5b98c15a243f96f0c025b8e'),
    'read': (88, '57582d5c991207cb5597a51a0b74c65224e43407c58718a1e04ddac96b8bb41b'),
    'program': (458, '5fc1638f0ab597fe81d778feb43d8170cec77738293d272fc455a386a15adb67'),
    'erase': (110, '20fd92f346be333325b506af367fd8fc8d2e1163e8b7a48fa1b6dea63d296306'),
    'poll_result': (22, '57f93fbe43b320fc360f9154696d606b4858a13cb47be5e2cf13ff24ac7936aa'),
    'suspend': (54, '54f1b6aa180a48147ad7f6a7c6504e69ae2dbb7697275d44a4bd3e0d65b2fce1'),
    'resume': (48, '2e01e926da1838e23359e7d5574667dad31d4afdcba935860dc34cd7c325b2a6'),
    'erase_command': (172, '00ee6417b1cf228c84187a15d685a0a38e7a040bd86fc3122d09a68da85ca867'),
    'suspend_command': (136, 'c95d9f567f15bdbfb6006b8a597596e9a6031671114a6564c59b8c41d3f04e1f'),
    'resume_command': (136, '4a292c6b9195b8e1c66dc924f504b92c6aef7772bb8c21258023494a26be9aac'),
    'poll': (112, 'bb412afad81a1f68ff290d743e46ad242fa7e9e5c02aba289724b913c342bb55'),
}
_ROOT_HASH = '181a7be7a562772b6e10c7f594033fc3c6f4888eee66ab8d5611dbcfaa1f59ea'


class _Unclosed(ValueError):
    pass


def _need(value, reason):
    if not value:
        raise _Unclosed(reason)


def _word(image, at, size=4):
    _need(type(at) is int and 0 <= at <= len(image) - size, 'source-bounds')
    return int.from_bytes(image[at:at + size], 'little')


def _thumb_body(image, at, size):
    """Normalize only relocations; return resolved edges and their source pools."""
    _need(type(at) is int and not at & 1 and 0 <= at <= len(image) - size, 'code-bounds')
    body = bytearray(image[at:at + size])
    calls, literals, pools = {}, {}, []
    offset = 0
    while offset < size:
        op = _word(image, at + offset, 2)
        if op & 0xf800 == 0xf000 and offset + 4 <= size:
            target = thumb_bl_target(image, at + offset)
            _need(target is not None and not target & 1 and 0 <= target < len(image) - 1, 'call-target')
            calls[offset] = target
            body[offset:offset + 4] = bytes(4)
            offset += 4
            continue
        if op & 0xf800 == 0x4800:
            value = thumb_literal_value(image, at + offset, op >> 8 & 7)
            _need(value is not None, 'literal-source')
            literals[offset] = value
            pool = ((at + offset + 4) & ~3) + (op & 255) * 4
            pools.append((pool, pool + 4))
            struct.pack_into('<H', body, offset, op & 0xff00)
        offset += 2
    return hashlib.sha256(body).hexdigest(), calls, literals, pools


def _body(image, at, role, guards):
    size, digest = _GRAMMAR[role]
    actual, calls, literals, pools = _thumb_body(image, at, size)
    _need(actual == digest, role + '-grammar')
    guards.extend([(at, at + size), *pools])
    return calls, literals


def _reset_copy(image, ram_base, ram_size, guards):
    root = arm_b_target(image, 0)
    _need(root is not None and not root & 3 and 0 <= root <= len(image) - 0xb4, 'reset-owner')
    body = bytearray(image[root:root + 0xb4])
    literals = {}
    for off in range(0, len(body), 4):
        op = _word(image, root + off)
        if op & 0x0f7f0000 == 0x051f0000:
            pool = root + off + 8 + (op & 4095)
            literals[off] = _word(image, pool)
            guards.append((pool, pool + 4))
            struct.pack_into('<I', body, off, op & 0xfffff000)
    _need(hashlib.sha256(body).hexdigest() == _ROOT_HASH, 'reset-grammar')
    guards.extend([(0, 4), (root, root + len(body))])
    for off in (0, 0x18, 0x30, 0x60, 0x78, 0x9c):
        _need(literals[off] & 1 and literals[off] < len(image)
              and literals[off + 8] == root + off + 21
              and literals[off + 12] == root + off + (25 if off == 0x9c else 24), 'reset-call-return')
    for off in (0x4c, 0x54, 0x5c):
        _need(ram_base < literals[off] <= ram_base + ram_size and not literals[off] & 3, 'reset-stack')
    copy = literals[0x60] - 1
    _, values = _body(image, copy, 'copy', guards)
    _need(values[0] == 0x03000700, 'copy-watchdog')
    copies, zeros = [], []
    for source_off, target_off, size_off, zero_offs in (
            (0x16, 0xc, 0xe, (0x38, 0x3a)),
            (0x60, 0x56, 0x58, (0x7c, 0x7e)),
            (0xac, 0xa2, 0xa4, None)):
        table = values[source_off]
        _need(not table & 3 and values[target_off] == table + 4
              and values[size_off] == table + 8, 'copy-tuple')
        source, target, size = (_word(image, table + off) for off in (0, 4, 8))
        _need(size > 0 and not (source | target | size) & 3 and source + size <= len(image)
              and (ram_base <= target < target + size <= ram_base + ram_size
                   or 0x03800000 <= target < target + size <= 0x03a00000), 'copy-span')
        copies.append((source, target, size))
        guards.extend([(table, table + (20 if zero_offs else 12)), (source, source + size)])
        if zero_offs:
            _need(values[zero_offs[0]] == table + 12 and values[zero_offs[1]] == table + 16, 'zero-tuple')
            begin, length = _word(image, table + 12), _word(image, table + 16)
            _need(target + size == begin and length > 0 and not (begin | length) & 3
                  and ram_base <= begin < begin + length <= ram_base + ram_size, 'zero-span')
            zeros.append((begin, begin + length))
    destinations = [(target, target + size) for _, target, size in copies] + zeros
    _need(all(not (a < d and c < b) for i, (a, b) in enumerate(destinations)
              for c, d in destinations[i + 1:]), 'copy-zero-conflict')
    return copies


def _profile(image, init, load, flash, ram, ram_size):
    guards = []
    _, init_literals = _body(image, init, 'init', guards)
    state, cell = init_literals[0], init_literals[4]
    _need(not (state | cell) & 3 and ram <= state <= ram + ram_size - 12
          and ram <= cell <= ram + ram_size - 4, 'runtime-globals')
    # The active EFS service initializes this selection directly, without probe IDs.
    wrappers = [at for at in find_all(image, struct.pack('<H', 0xb580))
                if not at & 1 and thumb_bl_target(image, at + 2) == init]
    _need(len(wrappers) == 1, 'efs-init-wrapper-owner')
    _, wrapper_values = _body(image, wrappers[0], 'efs_wrapper', guards)
    owners = [at for at in find_all(image, struct.pack('<2H', 0xb590, 0x2000))
              if not at & 1 and thumb_bl_target(image, at + 0x6c) == wrappers[0]]
    _need(len(owners) == 1, 'efs-service-owner')
    _, owner_values = _body(image, owners[0], 'efs_init', guards)
    copies = _reset_copy(image, ram, ram_size, guards)
    live = cell + 4
    linked = find_linker_layout(image, required_span=(cell, 8))
    _need(linked is not None, 'descriptor-copy-provenance')
    sources = [(source + live - target, target, size) for source, target, size in copies
               if target <= cell and live + 0x150 <= target + size]
    _need(len(sources) == 1 and sources[0] == (linked.data_source + live - linked.data_target, linked.data_target, linked.data_size), 'descriptor-copy-owner')
    _need(not (state < live + 0x150 and cell < state + 12), 'runtime-global-overlap')
    _need(wrapper_values[0x1a] == wrapper_values[0x2c]
          and owner_values[4] == owner_values[0x34], 'efs-initializer-globals')
    init_writes = ((wrapper_values[8], 0x410), (wrapper_values[0x1a], 0x52),
                   (owner_values[4] - 0x34, 0x674), (owner_values[0x16], 0x1e0))
    critical = ((cell, live + 0x150), (state, state + 12))
    _need(all(ram <= address < address + size <= ram + ram_size
              and not address & 3
              and all(not (address < end and start < address + size)
                      for start, end in critical)
              for address, size in init_writes), 'efs-initializer-write-overlap')
    guards.append((linked.table_offset, linked.table_offset + 20))
    descriptor = sources[0][0]
    _need(_word(image, descriptor - 4) == 0, 'initial-selection')
    name, count = _word(image, descriptor), _word(image, descriptor + 4)
    _need(0 < count <= 71 and descriptor + 0x150 <= flash, 'geometry-count')
    # Callbacks in this grammar access metadata at +0x130 and +0x134.
    # Compare those accesses with the parsed array end rather than trusting count.
    metadata = descriptor + 0x124
    _need(not any(image[descriptor + 8 + count * 4:metadata]), 'geometry-padding')
    sectors = [_word(image, descriptor + 8 + i * 4) for i in range(count)]
    sector = sectors[0]
    _need(sector >= 0x1000 and not sector & (sector - 1)
          and all(size == sector for size in sectors), 'geometry-uniform')
    id0, id1, reserved, banks = struct.unpack_from('<HHII', image, metadata)
    _need(reserved == 0 and banks == 1, 'descriptor-mode')
    base, size = _word(image, metadata + 0xc), _word(image, metadata + 0x10)
    _need(size == sum(sectors) and base > 0 and not base % sector
          and base + size <= min(flash, ram), 'geometry-span')
    _need(0 <= name < flash and image.find(b'\0', name, min(flash, name + 64)) > name, 'descriptor-label')
    label_end = image.find(b'\0', name, min(flash, name + 64))
    guards.append((name, label_end + 1))
    methods, calls, values = {}, {}, {}
    for i, role in enumerate(('read', 'program', 'erase', 'poll_result', 'suspend', 'resume')):
        pointer = _word(image, metadata + 0x14 + i * 4)
        _need(pointer & 1, 'callback-isa')
        methods[role] = pointer - 1
        calls[role], values[role] = _body(image, pointer - 1, role, guards)
    for role, offset, expected in (
            ('read', 8, cell), ('read', 0x1c, state), ('read', 0x32, cell), ('read', 0x34, state),
            ('program', 8, cell), ('program', 0x18, state), ('erase', 2, state),
            ('erase', 0x26, cell), ('poll_result', 0, state),
            ('suspend', 4, state), ('resume', 4, state)):
        _need(values[role][offset] == expected, 'callback-globals')
    flag = values['poll_result'][6] + 0x1c
    _need(values['erase'][0x4e] + 0x1c == flag
          and ram <= flag < ram + ram_size
          and all(not (start <= flag < end) for start, end in critical), 'result-flag-overlap')
    command = calls['erase'][0x4a]
    command_calls, command_values = _body(image, command, 'erase_command', guards)
    _need(command_values[0x2c] == values['program'][0x72] == values['program'][0x134] == 0x5555
          and command_values[0x36] == values['program'][0x7c] == values['program'][0x13e] == 0x2aaa, 'unlock-literals')
    bus = command_values[0xe]
    _need(all(values['program'][off] == bus for off in
              (0x54, 0xae, 0xcc, 0x116, 0x174, 0x192))
          and ram <= bus <= ram + ram_size - 16 and not bus & 3
          and all(not (bus < end and start < bus + 16) for start, end in critical), 'bus-global-overlap')
    bus_sources = [source + bus - target for source, target, extent in copies
                   if target <= bus <= target + extent - 16]
    _need(len(bus_sources) == 1 and 0x03000000 <= _word(image, bus_sources[0]) < 0x03001000
          and not _word(image, bus_sources[0]) & 1, 'bus-mmio-provenance')
    _need(all(not (bus < address + extent and address < bus + 16)
              for address, extent in init_writes), 'bus-initializer-overlap')
    critical += ((bus, bus + 16), (flag, flag + 1))
    poll = command_calls[0x58]
    _need(calls['program'][0x9a] == poll and calls['program'][0x15e] == poll, 'program-erase-poll-link')
    _, poll_values = _body(image, poll, 'poll', guards)
    _need(poll_values[0x1e] == poll_values[0x2c]
          and ram <= poll_values[0x1e] <= ram + ram_size - 12, 'poll-buffer')
    scratch = poll_values[0x1e]
    _need(all(not (scratch < end and start < scratch + 12)
              for start, end in critical)
          and all(not (scratch < address + size and address < scratch + 12)
                  for address, size in init_writes), 'poll-buffer-overlap')
    for role, off in (('suspend', 0x1a), ('resume', 0x1e)):
        inner_calls, inner_values = _body(image, calls[role][off], role + '_command', guards)
        _need(inner_calls[0x36] == poll and inner_values[0xe] == command_values[0xe], 'suspend-resume-link')
    # IRQ ownership and restoration are shared by both actual command paths.
    save, restore = command_calls[4], command_calls[0x22]
    _need(all(calls['program'][off] == save for off in
              (0x4a, 0x50, 0xaa, 0xc8, 0x10c, 0x112, 0x170, 0x18e)), 'irq-save-link')
    _need(all(calls['program'][off] == restore for off in
              (0x68, 0x92, 0xc2, 0xe0, 0x12a, 0x156, 0x188, 0x1a6)), 'irq-restore-link')
    guards.append((descriptor - 4, metadata + 0x2c))
    _need(all(0 <= start < end <= flash and not (start < base + size and base < end)
              for start, end in guards), 'source-overlaps-array')
    return dict(signature='inline-copy-selected-efs-amd-x16-v1', admission='temporary-evidence-gated',
                base=base, size=size, sector_size=sector, backing_size=1 << (size - 1).bit_length(),
                id0=id0, id1=id1, descriptor=descriptor, initializer=init,
                selection_cell=cell, state_global=state,
                guard_intervals=[list(span) for span in sorted(set(guards))])


def find_inline_efs_nor_profile(image: bytes, load_address: int, flash_size: int,
                                ram_base: int, ram_size: int) -> tuple[dict | None, str | None]:
    """Admit one complete source graph, rejecting all ambiguous init candidates."""
    # str r0,[r1]; str r0,[r2]; adds r0,r2,#4; str r0,[r2].
    anchor = struct.pack('<4H', 0x6008, 0x6010, 0x1d10, 0x6010)
    view = image[:flash_size] if type(flash_size) is int and flash_size > 0 else image
    # The selection initializer is shared with older fixed-unlock drivers.
    # Classify this bank-relative compiler before emitting candidate notes:
    # lsls r1,#16; adds r0,r1,r0; lsls r0,#1 forms a bank-relative
    # halfword command address. The complete linked callbacks are checked below.
    if struct.pack('<3H', 0x0409, 0x1808, 0x0040) not in view:
        return None, None
    candidates = [hit - 6 for hit in find_all(view, anchor)
                  if hit >= 6 and not hit & 1 and hit + 14 <= len(view)
                  and _word(view, hit - 6, 2) & 0xff00 == 0x4900
                  and _word(view, hit - 4, 2) == 0x2000
                  and _word(view, hit - 2, 2) & 0xff00 == 0x4a00
                  and view[hit + 8:hit + 14] == struct.pack('<3H', 0x2000, 0x7108, 0x4770)]
    if not candidates:
        return None, None
    if load_address != 0 or not 0 < flash_size <= len(image) or ram_size <= 0:
        return None, 'inline-efs-layout-unverified'
    if len(candidates) != 1:
        return None, 'inline-efs-initializers-ambiguous'
    try:
        return _profile(image[:flash_size], candidates[0], load_address, flash_size, ram_base, ram_size), None
    except (_Unclosed, KeyError, struct.error) as error:
        return None, 'inline-efs-' + str(error)
