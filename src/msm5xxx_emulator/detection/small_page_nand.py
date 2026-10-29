"""Temporary reset-linked x16 main/OOB software class, not physical NAND identity."""
from __future__ import annotations

import hashlib
import struct

from .bootstrap_sdram import (
    _READ_HEAD, _READ_SIZE, _Reject, _external_bus_ports, _require,
    _reset_copy_profile, _word, reset_copy_ram_profile,
)


_THUMB = {
    'program': (0xda, bytes.fromhex('ffb5151c041c1f1c500884b0'),
                '536dcc6f40040768a48ca41c58462d5d2ebe463fec9438199df8eda55dbcb61d',
                (0x12, 0x2a, 0x4a, 0x50, 0x82, 0xc0, 0xc4), (0xe, 0x10, 0x24, 0x26),
                ((0x54, 2, 20), (0x6e, 1, 19), (0x8a, 0, 22))),
    'erase': (0x48, bytes.fromhex('90b5010a0c06240e07063f0e'),
              '79b5142afe69f872b80aaf9a9e1d0057db628ffe87aa09b68a3fcf2308c92c11',
              (0xc, 0x12, 0x2e, 0x32, 0x36), (), ((0x18, 2, 20), (0x1e, 1, 19))),
    'status': (0x2c, bytes.fromhex('0020072189051d22120580b4'),
               'a3e98a9d31cdd7524902e74f6e98a4d5ed008dd95022afa62afc89290aef6d86',
               (), (0x1a,), ((2, 0, 22), (6, 2, 20))),
    'transfer': (0xbc, bytes.fromhex('f0b5151c00274200ffb083b0'),
                 '37563f454d4cc8f22c29b51b450e0d4f7a9680c4967921aca30e18249d030597',
                 (0x1e, 0x32, 0x40, 0x7e, 0x8a, 0x96),
                 (0xc, 0x30, 0x3e, 0x6c, 0x94, 0x9e, 0xa8, 0xac), ()),
}


def _unique(image: bytes, head: bytes, alignment: int, start=0, end=None) -> int:
    positions = []
    end = len(image) if end is None else end
    at = start
    while True:
        at = image.find(head, at, end)
        if at < 0:
            break
        if at % alignment == 0:
            positions.append(at)
        at += 1
    _require(len(positions) == 1)
    return positions[0]


def _thumb_body(image, entry, name, ports, resolve):
    size, _head, digest, calls, literals, operands = _THUMB[name]
    raw, _ = resolve(entry, size)
    _require(entry % 2 == 0)
    code = bytearray(image[raw:raw + size])
    targets, values = {}, {}
    for offset in calls:
        first, second = struct.unpack_from('<HH', code, offset)
        _require(first & 0xf800 == 0xf000 and second & 0xf800 == 0xf800)
        delta = (first & 0x7ff) << 12 | (second & 0x7ff) << 1
        if delta & 0x400000:
            delta -= 0x800000
        target = entry + offset + 4 + delta
        resolve(target, 2)
        targets[offset] = target
        struct.pack_into('<HH', code, offset, 0xf000, 0xf800)
    for offset in literals:
        instruction = struct.unpack_from('<H', code, offset)[0]
        _require(instruction & 0xf800 == 0x4800)
        address = ((entry + offset + 4) & ~3) + (instruction & 255) * 4
        literal, _ = resolve(address, 4)
        values[offset] = _word(image, literal)
        struct.pack_into('<H', code, offset, instruction & 0xff00)
    for offset, index, shift in operands:
        instruction = struct.unpack_from('<H', code, offset)[0]
        _require(instruction & 0xf800 == 0x2000
                 and (instruction & 255) << shift == ports[index])
        struct.pack_into('<H', code, offset, instruction & 0xff00)
    _require(hashlib.sha256(code).hexdigest() == digest)
    return targets, values


def _read_copy_chain(image, read, resolve):
    def veneer(entry):
        raw, owner = resolve(entry, 8)
        opcode, target = struct.unpack_from('<II', image, raw)
        _require(entry % 4 == 0 and opcode == 0xe51ff004 and target % 4 == 0)
        resolve(target, 4)
        return target, owner

    def body(entry, size, spans, digest, external=None):
        raw, owner = resolve(entry, size)
        _require(entry % 4 == 0 and raw % 4 == 0)
        code = bytearray(image[raw:raw + size])
        offsets = {i for start, end in spans for i in range(start, end, 4)}
        outgoing = None
        for offset in sorted(offsets):
            word = _word(code, offset)
            if word & 0x0e000000 != 0x0a000000:
                continue
            _require(not word & 0x01000000)
            delta = word & 0xffffff
            if delta & 0x800000:
                delta -= 0x1000000
            target = entry + offset + 8 + delta * 4
            if offset == external:
                _require(word >> 24 == 0x2a)
                resolve(target, 8)
                outgoing = target
                struct.pack_into('<I', code, offset, word & 0xff000000)
            else:
                _require(target - entry in offsets)
        _require(hashlib.sha256(b''.join(code[a:b] for a, b in spans)).hexdigest() == digest)
        _require(external is None or outgoing is not None)
        return outgoing, owner

    move, owner = veneer(read['copy'])
    _require(owner == 'iram')
    # Alternate Thumb-entry gaps are unreachable from the verified ARM entries.
    forward, _ = body(move, 0xa0, ((0, 0x40), (0x50, 0xa0)),
                      'a32ef98f812d769bdd6efaf68b90943427a909aec93852925d07e2144ae64bc2', 8)
    forward, _ = veneer(forward)
    _, owner = body(forward, 0x124, ((0, 0xb4), (0xb8, 0x124)),
                    'bd0a995de1c6807828d91b312d648e042d618df6582a3dfcfdbb361c43c4982d')
    _require(owner == 'iram')


def small_page_nand_profile(image: bytes) -> dict | None:
    """Close software528-byte/32-page transfers;65536 virtual rows are not capacity.

    Unsupported or ambiguous shapes retain native fallback.
    """
    if not isinstance(image, bytes):
        return None
    try:
        ram = reset_copy_ram_profile(image)
        reset = _reset_copy_profile(image)
        _require(ram is not None and reset is not None)
        rows = reset['descriptors']
        ports = _external_bus_ports(image, rows)
        _require(0x01000000 <= ports[0] <= 0x01e00000 and ports[0] % 0x200000 == 0
                 and ports[0] + 0x200000 <= ram['reserved_base'] + ram['reserved_size'])

        def resolve(address, size):
            _require(size > 0 and 0 <= address < address + size <= 0x100000000)
            matches = []
            if address < len(image):
                _require(address + size <= len(image))
                matches.append((address, 'nor'))
            for row in rows:
                start, end = row['target'], row['target'] + row['size']
                if address < end and start < address + size:
                    _require(start <= address and address + size <= end)
                    raw = row['source'] + address - start
                    _require(0 <= raw <= len(image) - size)
                    matches.append((raw, row['role']))
            _require(len(matches) == 1)
            return matches[0]

        iram, = [row for row in rows if row['role'] == 'iram']
        raw = _unique(image, _READ_HEAD, 4, iram['source'], iram['source'] + iram['size'])
        entry = iram['target'] + raw - iram['source']
        _require(resolve(entry, _READ_SIZE)[0] == raw)
        calls = {}
        for offset in (0x6c, 0x74, 0xac, 0xb0, 0x1d8):
            word = _word(image, raw + offset)
            delta = word & 0xffffff
            if delta & 0x800000:
                delta -= 0x1000000
            calls[offset] = entry + offset + 8 + delta * 4

        def thumb_veneer(target):
            location, _ = resolve(target, 12)
            _require(_word(image, location) == 0xe59fc000
                     and _word(image, location + 4) == 0xe12fff1c)
            pointer = _word(image, location + 8)
            _require(pointer & 1)
            resolve(pointer - 1, 2)
            return pointer - 1

        read = {'disable': thumb_veneer(calls[0x6c]), 'reset': thumb_veneer(calls[0x74]),
                'enable': thumb_veneer(calls[0xac]), 'ready': thumb_veneer(calls[0xb0]),
                'copy': calls[0x1d8]}
        _require(read['disable'] % 4 == read['enable'] % 4 == 0)
        _read_copy_chain(image, read, resolve)
        ready_raw, _ = resolve(read['ready'], 14)
        literal = ((read['ready'] + 4) & ~3) + image[ready_raw] * 4
        literal_raw, _ = resolve(literal, 4)
        descriptor_raw, _ = resolve(_word(image, literal_raw), 32)
        ready_address = _word(image, descriptor_raw + 20)
        _require(0x03000700 <= ready_address <= 0x0300077e)

        entries, bodies = {}, {}
        for name in ('program', 'erase'):
            entries[name] = _unique(image, _THUMB[name][1], 2)
            bodies[name], _ = _thumb_body(image, entries[name], name, ports, resolve)
        for name, links in (
                ('program', {0x4a: 'disable', 0x50: 'reset', 0x82: 'enable', 0xc0: 'ready'}),
                ('erase', {0xc: 'disable', 0x12: 'reset', 0x2e: 'enable', 0x32: 'ready'})):
            _require(all(bodies[name][offset] == read[field] for offset, field in links.items()))
        _require(bodies['program'][0x12] == bodies['program'][0x2a])
        # The diagnostic callee stays native guest code; no trap or bypass is installed.
        status = bodies['program'][0xc4]
        _require(status == bodies['erase'][0x36])
        _, status_values = _thumb_body(image, status, 'status', ports, resolve)
        _require(0 < status_values[0x1a] <= 0x100000)

        transfer = _unique(image, _THUMB['transfer'][1], 2)
        links, literals = _thumb_body(image, transfer, 'transfer', ports, resolve)
        _require(links[0x1e] == entries['erase']
                 and links[0x40] == links[0x7e] == entries['program']
                 and links[0x32] == links[0x8a])
        wrapper, _ = resolve(links[0x32], 12)
        _require(links[0x32] % 4 == wrapper % 4 == 0
                 and image[wrapper:wrapper + 8] == bytes.fromhex('7847c04604f01fe5')
                 and _word(image, wrapper + 8) == entry)
        _require(literals[0xc] == literals[0xac]
                 and literals[0x30] == literals[0x3e] == literals[0x9e]
                 and literals[0x6c] == 0xfff8)
        for address, size in ((literals[0xc], 0x800), (literals[0x30] - 0x40, 592),
                              (literals[0x94], 0x40), (literals[0xa8], 4)):
            _require(ram['ram_base'] <= address <= ram['ram_base'] + ram['ram_size'] - size
                     and address % 4 == 0
                     and (address + size <= ram['reserved_base']
                          or address >= ram['reserved_base'] + ram['reserved_size']))
        # shortcut: Single-witness200ns idle FF and virtual rows; refine with independent timing/capacity evidence, never forced READY.
        return {'profile': 'reset-copy-x16-main-oob-v1', 'experimental': True,
                'data_address': ports[0], 'address_address': ports[1],
                'command_address': ports[2], 'ready_address': ready_address, 'ready_mask': 0x80,
                'page_size': 512, 'spare_size': 16, 'pages_per_block': 32,
                'pages': 65536, 'idle_reset_ns': 200}
    except (_Reject, KeyError, TypeError, ValueError, struct.error, OverflowError):
        return None
