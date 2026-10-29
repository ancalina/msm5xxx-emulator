"""Temporary single-witness reset/copy class with a separate external-bus gap.

The rounded initialized/zero extent is a logical allocation requirement, not
physical SDRAM capacity. This pure helper enables no device or runtime mapping.
"""
from __future__ import annotations
import hashlib
import struct


FIRST = bytes.fromhex(
    "00409fe5010014e300e09f1500e09f0514ff2fe17847000000409fe5010014e300e09f1500e09f0514ff2fe178470000"
    "00409fe5010014e300e09f1500e09f0514ff2fe17847000000409fe5010014e300e09f1500e09f0514ff2fe178470000"
    "d7f021e300d09fe5dbf021e300d09fe5d3f021e300d09fe500409fe5010014e300e09f1500e09f0514ff2fe178470000"
    "00409fe5010014e300e09f1500e09f0514ff2fe17847000000409fe5010014e300e09f1500e09f0514ff2fe178470000"
    "000050e30000001a000000ea"
)
FIRST_LITERALS = (0, 8, 12, 24, 32, 36, 48, 56, 60, 72, 80, 84, 100, 108, 116, 120, 128, 132, 144, 152, 156, 168, 176, 180)

SECOND = bytes.fromhex(
    "00409fe5010014e300e09f1500e09f0514ff2fe17847000000409fe5010014e300e09f1500e09f0514ff2fe178470000"
    "00409fe5010014e300e09f1500e09f0514ff2fe178470000d7f021e300d09fe5dbf021e300d09fe5d3f021e300d09fe5"
    "00409fe5010014e300e09f1500e09f0514ff2fe178470000"
)
SECOND_LITERALS = (0, 8, 12, 24, 32, 36, 48, 56, 60, 76, 84, 92, 96, 104, 108)

COPIER = bytes.fromhex(
    "004980b40120087000230b700048004f02683f68d619004a15680468012043e02a6822606a686260aa68a260ea68e260"
    "2a6922616a696261aa69a261ea69e2612a6a22626a6a6262aa6aa262ea6ae2622a6b22636a6b6263aa6ba263ea6be263"
    "2a6c22646a6c6264aa6ca264ea6ce2642a6d22656a6d6265aa6da265ea6de2652a6e22666a6e6266aa6ea266ea6ee266"
    "2a6f22676a6f6267aa6fa267ea6fe26708700b7080358034b442b9d30a1c0870191c1370004b004c1f6824683e193c1c"
    "22e021606160a160e16021616161a161e16121626162a162e16221636163a163e16321646164a164e16421656165a165"
    "e16521666166a166e16621676167a167e167107011708034b442dad310701170004b004c1f6824683e19004f3d681c68"
    "43e02b6823606b686360ab68a360eb68e3602b6923616b696361ab69a361eb69e3612b6a23626b6a6362ab6aa362eb6a"
    "e3622b6b23636b6b6363ab6ba363eb6be3632b6c23646b6c6364ab6ca364eb6ce3642b6d23656b6d6365ab6da365eb6d"
    "e3652b6e23666b6e6366ab6ea366eb6ee3662b6f23676b6f6367ab6fa367eb6fe3671070117080358034b442b9d31070"
    "1170004b004c1f6824683e193c1c22e021606160a160e16021616161a161e16121626162a162e16221636163a163e163"
    "21646164a164e16421656165a165e16521666166a166e16621676167a167e167107011708034b442dad310701170004b"
    "004c1f6824683e19004f3d681c6805e02b6823601070117004350434b442f7d310701170004b004c1f6824683e19004f"
    "3d681c6843e02b6823606b686360ab68a360eb68e3602b6923616b696361ab69a361eb69e3612b6a23626b6a6362ab6a"
    "a362eb6ae3622b6b23636b6b6363ab6ba363eb6be3632b6c23646b6c6364ab6ca364eb6ce3642b6d23656b6d6365ab6d"
    "a365eb6de3652b6e23666b6e6366ab6ea366eb6ee3662b6f23676b6f6367ab6fa367eb6fe3671070117080358034b442"
    "b9d310701170004b004c1f6824683e193c1c22e021606160a160e16021616161a161e16121626162a162e16221636163"
    "a163e16321646164a164e16421656165a165e16521666166a166e16621676167a167e167107011708034b442dad31070"
    "117080bc7047"
)
COPIER_LITERALS = (0, 12, 14, 22, 180, 182, 272, 274, 282, 434, 436, 526, 528, 536, 564, 566, 574, 726, 728)

class _Reject(Exception):
    pass


def _require(condition: bool) -> None:
    if not condition:
        raise _Reject


def _word(image: bytes, address: int) -> int:
    _require(address & 3 == 0 and 0 <= address <= len(image) - 4)
    return struct.unpack_from('<I', image, address)[0]


def _branch(image: bytes, pc: int, opcode: int) -> int:
    word = _word(image, pc)
    _require(word >> 24 == opcode)
    delta = word & 0xFFFFFF
    if delta & 0x800000:
        delta -= 0x1000000
    target = pc + 8 + delta * 4
    _require(0 <= target <= len(image) - 4)
    return target


def _stage(image: bytes, entry: int, expected: bytes, literal_offsets: tuple,
           calls: tuple, deps: list, branches: tuple = ()) -> dict:
    _require(entry & 3 == 0 and 0 <= entry <= len(image) - len(expected))
    code = bytearray(image[entry:entry + len(expected)])
    deps.append([entry, len(expected)])
    values = {}
    for offset in literal_offsets:
        instruction = _word(image, entry + offset)
        _require(instruction & 0x0F7F0000 == 0x051F0000)
        address = entry + offset + 8 + (instruction & 4095) * (1 if instruction & 0x800000 else -1)
        values[offset] = _word(image, address)
        deps.append([address, 4])
        struct.pack_into('<I', code, offset, instruction & ~4095)
    for offset in branches:
        instruction = _word(image, entry + offset)
        struct.pack_into('<I', code, offset, instruction & 0xFF000000)
    _require(code == expected)
    for offset in calls:
        pc = entry + offset
        target = values[offset]
        _require(values[offset + 8] == ((pc + 20) | 1)
                 and values[offset + 12] == pc + 24)
        _require(struct.unpack_from('<H', image, pc + 20)[0] == 0x4778)
        _require(0 <= (target & ~1) <= len(image) - 2
                 and (target & 1 or target & 3 == 0))
        deps.append([target & ~1, 2])
    # Stack literal operands are bounded logical addresses, never capacity inputs.
    for offset in set(literal_offsets) - {o + n for o in calls for n in (0, 8, 12)}:
        _require(0x01000000 <= values[offset] < 0x02000000 and values[offset] & 3 == 0)
    return values


def _copier(image: bytes, entry: int, deps: list) -> dict:
    _require(entry & 1 == 0 and 0 <= entry <= len(image) - len(COPIER))
    code = bytearray(image[entry:entry + len(COPIER)])
    deps.append([entry, len(COPIER)])
    values = {}
    for offset in COPIER_LITERALS:
        instruction = struct.unpack_from('<H', code, offset)[0]
        _require(instruction & 0xF800 == 0x4800)
        address = ((entry + offset + 4) & ~3) + (instruction & 255) * 4
        values[offset] = _word(image, address)
        deps.append([address, 4])
        code[offset] = 0
    _require(code == COPIER and values[0] == 0x03000700)
    descriptors = []
    # The complete leaf body proves this exact copy/zero/IRAM/high ordering.
    for destination, length, source, zero, zero_size, role, alignment in (
            (0xC, 0xE, 0x16, 0xB4, 0xB6, 'bootstrap', 128),
            (0x110, 0x112, 0x11A, 0x1B2, 0x1B4, 'low', 128),
            (0x20E, 0x210, 0x218, None, None, 'iram', 4),
            (0x234, 0x236, 0x23E, 0x2D6, 0x2D8, 'high', 128)):
        table = values[source]
        _require(values[destination] == table + 4 and values[length] == table + 8)
        size = 12 if zero is None else 20
        _require(table & 3 == 0 and 0 <= table <= len(image) - size)
        deps.append([table, size])
        fields = struct.unpack_from('<' + 'I' * (size // 4), image, table)
        start, target, count = fields[:3]
        _require(not (start | target | count) & 3 and count > 0)
        rounded = (count + alignment - 1) // alignment * alignment
        _require(start + rounded <= min(len(image), 0x100000000)
                 and target + rounded <= 0x100000000)
        row = {'role': role, 'descriptor': table, 'source': start, 'target': target,
               'size': count, 'copy_end': target + rounded,
               'source_extent': [start, rounded], 'copy_quantum': alignment}
        if zero is not None:
            _require(values[zero] == table + 12 and values[zero_size] == table + 16)
            bss, bss_size = fields[3:]
            end = bss + (bss_size + 127) // 128 * 128
            _require(bss == target + count and bss & 3 == 0
                     and bss_size > 0 and bss_size & 3 == 0
                     and end <= 0x100000000)
            row.update(bss=bss, bss_size=bss_size, zero_end=end)
            _require(0x01000000 <= target < row['copy_end'] <= 0x02000000
                     and 0x01000000 <= bss < end <= 0x02000000)
        else:
            _require(target == 0x03800000 and rounded <= 0x20000)
        descriptors.append(row)
    _require(len({row['descriptor'] for row in descriptors}) == 4)
    bootstrap, low, _, high = descriptors
    _require(low['target'] == 0x01000000
             and max(bootstrap['copy_end'], bootstrap['zero_end'], low['copy_end'], low['zero_end']) <= 0x01800000
             and 0x01800000 <= high['target'])
    return {'entry': entry, 'descriptors': descriptors}


def _reset_copy_profile(image: bytes) -> dict | None:
    """Return only a reset-linked experimental logical extent, never a RAM map.

    A conditional first-reset continuation is structurally reachable, not proved
    taken at runtime. Initial helper bodies remain unverified. NAND aperture
    ownership and physical alias/capacity are separate obligations.
    """
    if not isinstance(image, bytes):
        return None
    try:
        deps = [[0, 4]]
        first = _branch(image, 0, 0xEA)
        _require(first < 0x10000)
        first_calls = _stage(image, first, FIRST, FIRST_LITERALS,
               (0, 0x18, 0x30, 0x48, 0x78, 0x90, 0xA8), deps, (0xC4, 0xC8))
        alternative = _branch(image, first + 0xC4, 0x1A)
        _require(first + len(FIRST) <= alternative < first + 0x400)
        vector = _branch(image, first + 0xC8, 0xEA)
        _require(vector >= first + len(FIRST))
        deps.append([vector, 4])
        second = _branch(image, vector, 0xEA)
        _require(vector + 4 <= second < vector + 0x4000)
        calls = _stage(image, second, SECOND, SECOND_LITERALS, (0, 0x18, 0x30, 0x60), deps)
        leaf = calls[0x60]
        _require(leaf & 1 == 1)
        copier = _copier(image, leaf - 1, deps)
        # Inspect only actual dispatch targets for a second known leaf class.
        # A conflicting reachable descriptor must not be hidden by final-call selection.
        linked = {first_calls[o] for o in (0, 0x18, 0x30, 0x48, 0x78, 0x90, 0xA8)}
        linked.update(calls[o] for o in (0, 0x18, 0x30, 0x60))
        for pointer in linked - {leaf}:
            entry = pointer & ~1
            if pointer & 1 and 0 <= entry <= len(image) - len(COPIER):
                normalized = bytearray(image[entry:entry + len(COPIER)])
                for offset in COPIER_LITERALS:
                    normalized[offset] = 0
                if normalized == COPIER:
                    other = _copier(image, entry, deps)
                    _require(other['descriptors'] == copier['descriptors'])
        rows = copier['descriptors']
        end = max(max(row['copy_end'], row['zero_end']) for row in rows if row['role'] != 'iram')
        end = (end + 0xFFF) & ~0xFFF
        _require(0x01800000 < end <= 0x02000000)
        return {
            'profile': 'reset-linked-unrolled128-logical-extent-v1',
            'experimental': True, 'runtime_admitted': False,
            'logical_base': 0x01000000, 'logical_size': end - 0x01000000,
            'logical_end': end, 'first_reset': first, 'second_vector': vector,
            'second_reset': second, 'copier': copier['entry'], 'descriptors': rows,
            'stack_pointers': tuple(first_calls[o] for o in (100, 108, 116))
                              + tuple(calls[o] for o in (76, 84, 92)),
            'nor_dependencies': sorted(map(list, set(map(tuple, deps)))),
            'root_path': 'conditional-reset-continuation; auxiliary-callees-unverified',
            'separate_obligations': ['physical-capacity-and-alias', 'NAND-aperture-ownership',
                                     'runtime-reset-path'],
        }
    except (_Reject, struct.error, OverflowError):
        return None

_READ_SIZE = 0x1ec
_READ_HEAD = bytes.fromhex('f04f2de90360a0e10040a0e101a012e2')
_READ_SHA = '4cc9920d0aa18b446678b6619c8ec353d2419d9cb28b1c4fe4f98e3b9260f96d'


def _external_bus_ports(image: bytes, rows: list[dict]) -> tuple[int, int, int]:
    def resolve(address: int, size: int) -> int:
        _require(size > 0 and 0 <= address < address + size <= 0x100000000)
        matches = []
        if address < len(image):
            _require(address + size <= len(image))
            matches.append(address)
        for row in rows:
            start, end = row['target'], row['copy_end']
            if address < end and start < address + size:
                _require(start <= address and address + size <= end)
                raw = row['source'] + address - start
                _require(0 <= raw <= len(image) - size)
                matches.append(raw)
        _require(len(matches) == 1)
        return matches[0]

    iram, = [row for row in rows if row['role'] == 'iram']
    start, end = iram['source'], iram['source'] + iram['size']
    candidates = []
    position = start
    while True:
        position = image.find(_READ_HEAD, position, end)
        if position < 0:
            break
        if position % 4 == 0:
            candidates.append(position)
        position += 1
    _require(len(candidates) == 1)
    raw, = candidates
    _require(raw + _READ_SIZE <= end)
    entry = iram['target'] + raw - start
    _require(resolve(entry, _READ_SIZE) == raw)
    body = bytearray(image[raw:raw + _READ_SIZE])
    targets = {}
    for offset in (0x6c, 0x74, 0xac, 0xb0, 0x1d8):
        instruction = _word(body, offset)
        _require(instruction & 0x0f000000 == 0x0b000000)
        delta = instruction & 0xffffff
        if delta & 0x800000:
            delta -= 0x1000000
        target = entry + offset + 8 + delta * 4
        _require(target % 4 == 0)
        resolve(target, 4)
        targets[offset] = target
        struct.pack_into('<I', body, offset, instruction & 0xff000000)
    ports = []
    for offset in (0x78, 0x90, 0xb8):
        instruction = _word(body, offset)
        _require(instruction & 0x0ff00000 == 0x03a00000)
        value, rotate = instruction & 255, ((instruction >> 8) & 15) * 2
        if rotate:
            value = ((value >> rotate) | (value << (32 - rotate))) & 0xffffffff
        ports.append(value)
        struct.pack_into('<I', body, offset, instruction & ~4095)
    _require(hashlib.sha256(body).hexdigest() == _READ_SHA)
    command, address, data = ports
    _require(data >= len(image) and data + 0x80000 == address
             and data + 0x100000 == command and command < 0x03000000)

    def veneer(target: int) -> tuple[int, int]:
        location = resolve(target, 12)
        _require(_word(image, location) == 0xe59fc000
                 and _word(image, location + 4) == 0xe12fff1c)
        pointer = _word(image, location + 8)
        _require(pointer & 1)
        entry = pointer & ~1
        return entry, resolve(entry, 2)

    reset, raw_reset = veneer(targets[0x74])
    raw_reset = resolve(reset, 10)
    code = image[raw_reset:raw_reset + 10]
    _require(code[:2] == bytes.fromhex('ff20')
             and code[3:] == bytes.fromhex('21090508707047')
             and code[2] << 20 == command)
    ready, _ = veneer(targets[0xb0])
    raw_ready = resolve(ready, 14)
    code = image[raw_ready:raw_ready + 14]
    _require(code[1:] == bytes.fromhex('4840690188090afcd370470000'))
    literal = ((ready + 4) & ~3) + code[0] * 4
    descriptor = _word(image, resolve(literal, 4))
    values = struct.unpack_from('<8I', image, resolve(descriptor, 32))
    _require(values[4] == values[5] and values[5] % 2 == 0
             and 0x03000000 <= values[5] < 0x03001000)
    for offset, expected in (
            (0x6c, '7847000000000fe1c01080e301f021e1c00000e21eff2fe1'),
            (0xac, '7847000000000fe1c010c0e301f021e1c00000e21eff2fe1')):
        helper, _ = veneer(targets[offset])
        location = resolve(helper, 24)
        _require(image[location:location + 24] == bytes.fromhex(expected))
    return data, address, command


def reset_copy_ram_profile(image: bytes) -> dict | None:
    """Recognize one temporary reset/copy/external-bus class.

    The linked firmware shapes prove a logical RAM envelope and a disjoint bus
    window. Physical capacity, aliasing, device identity and timing remain
    unknown; callers must preserve their own configuration and runtime gates.
    """
    try:
        reset = _reset_copy_profile(image)
        _require(reset is not None)
        rows = reset['descriptors']
        ports = _external_bus_ports(image, rows)
        high, = [row for row in rows if row['role'] == 'high']
        bootstrap, = [row for row in rows if row['role'] == 'bootstrap']
        ram_base = reset['logical_base']
        ram_end = ram_base + reset['logical_size']
        gap_base, gap_end = ports[0], high['target']
        _require(ram_base < gap_base < gap_end < ram_end
                 and gap_base % 0x1000 == gap_end % 0x1000 == 0)
        _require(all(gap_base <= port and port + 2 <= gap_end for port in ports))
        for stack in reset['stack_pointers']:
            _require(ram_base + 4 <= stack <= ram_end - 4
                     and (stack + 4 <= gap_base or stack - 4 >= gap_end))
        for row in rows:
            if row['role'] == 'iram':
                continue
            for start, end in ((row['target'], row['copy_end']),
                               (row['bss'], row['zero_end'])):
                _require(end <= gap_base or start >= gap_end)
        return {
            'profile': 'reset-copy-external-bus-gap-v1', 'experimental': True,
            'ram_base': ram_base, 'ram_size': reset['logical_size'],
            'reserved_base': gap_base, 'reserved_size': gap_end - gap_base,
            'bootstrap_linker': {
                'table_offset': bootstrap['descriptor'],
                'data_source': bootstrap['source'], 'data_target': bootstrap['target'],
                'data_size': bootstrap['size'], 'bss_target': bootstrap['bss'],
                'bss_size': bootstrap['bss_size'],
            },
        }
    except (_Reject, KeyError, TypeError, ValueError, struct.error, OverflowError):
        return None
