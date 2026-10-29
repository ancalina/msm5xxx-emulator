"""Static MA5 GPIO/parent route discovery; runtime admission stays off."""
from __future__ import annotations

import re
import struct

from .arm import thumb_bl_target, thumb_literal_value
from .audio import find_ma5_readback_candidate

# shortcut: closed instruction-shape classes; widen only after independent linkage proof.
_SPANS = {
    'install_direct': (('00b50000000000494023ca8b9a43ca83ca8b004bda8389690a80002801d100000000002100200000000000210020004a0000000008bc1847', (2, 30, 38, 48), (6, 18, 46), (36, 44)),),
    'boot_copy': (('0120004908700020087000480068004909684018061c00480068051c00480068041cb44208d204e0281d051c201d041cf7e728682060f7e70120004908700020087000480068004909684018061c00480068051c00480068041cb44208d204e0281d051c201d041cf7e728682060f7e70120004908700020087000480068004909684018061c00480068051c00480068041cb44208d204e0281d051c201d041cf7e728682060f7e7012000490870002008707047', (), (2, 10, 14, 22, 28, 58, 66, 70, 78, 84, 114, 122, 126, 134, 140, 170), ()),),
    'gpio_dispatch': (
        ('b0b5004c208900490a8a0240201c80890b8d0340201c008a403109880840051c00200127002a004914d03b1c1f1c87403f043f0c151c3d4004d101300004000c1028f3db80000858000000002781b0bc08bc1847002b13d03a1c171c87403f043f0c1d1c3d4004d101300004000c1028f3db80004018006c00000000a781e6e7002d14d03a1c131c83401f043f0c2b1c3b4004d101300004000c1028f3db8000401880300068000000002782cfe70049488901304881cae7', (72, 120, 166), (2, 6, 38, 174), ()),
    ),
    'gpio_register': (
        ('f0b5071c0d1c141c002801db2f2f03dd0020f0bc08bc184700000000ba003b071b0f012199403f0918235f43004b004edb19002c06d1004fc943b7501a8a1140198211e0b4501a8a004c0a431a82012d02d15a8a0a4301e05a8a8a435a825a8a9d682a80e2591180198a5a681180002801d1000000000120cbe7', (24, 114), (44, 46, 54, 72), ()),
    ),
    'gpio_init': (
        ('f0b5002700000000051c0000000000211923004a9b01d418004e6182b180002801d100000000000000000021a1823181002801d100000000000000000021e182b181002801d100000000004900482039088188810882004a508a91680880508d116a0880d01d39304188936b1980918ad3681980918d536a19808088d16b0880004a0048b90001373f043f0c302f5050f8db002d01d10000000000491d2000000000f0bc08bc1847', (4, 10, 34, 38, 52, 56, 70, 150, 158), (18, 24, 74, 76, 86, 128, 130, 154), ()),
    ),
    'parent_register': (
        ('f8b5041c0f1c00000000051c002f004e00d1371c002c01db1f2c09db00000000002200920023221c00a10048000000001c20004960434018002c02d100490f6300e04761b74204d1c1680a8803899a430ae0c1680a8801890a4006d102681180c1680a8803891a430a80c168026909881288406811400180002d01d100000000f8bc08bc1847', (6, 28, 44, 124), (14, 42, 50, 60), (40,)),
        ('f0b5041c0f1c00000000051c002f004e00d1371c002c01db1f2c06db00000000232000010049000000001c20004960434018002c02d100490f6300e04761b74204d1c1680a8803899a430ae0c1680a8801890a4006d102681180c1680a8803891a430a80c168026909881288406811400180002d01d100000000f0bc08bc1847', (6, 28, 38, 118), (14, 36, 44, 54), ()),
        ('f0b5041c0f1c00000000051c002f004e00d1371c002c01db1f2c03db00490048000000001c20004960434018002c02d100490f6300e04761b74204d1c1680a8803899a430ae0c1680a8801890a4006d102681180c1680a8803891a430a80c168026909881288406811400180002d01d100000000f0bc08bc1847', (6, 32, 112), (14, 28, 30, 38, 48), ()),
    ),
    'soc_dispatch': (
        ('f0b586b000000000004ad188029111890191004f3888004a13880299194001400491b888538801991940084004990390084307d10000000000480088012800d08ae085e00120059005980a230049584340180090008804990840051c0098408803990840041c281c204300d165e00098004a8088004fc0430004000cd0800099c988c943118111880840b8821089518808403883000000000098067a45e01c20004970434718004b7868143398420fd1388928400cd0786900000000388b0130388338898543291c0d0400492d0c0880004b78681833984224d13889011c214020d0082803d001239b0398420dd100498880786900000000388b013038833889c04320400404240c0ce0786900000000388b0130388338898443211c0c040049240c888001363604360c0098407ab04203db002db3d1002cb1d1059801300004000c0590042800da7ee70000000060e7000000000028fbd1004f0299f9800199398100000000f888398808400049888238897a8810400883004908880130088006b0f0bc08bc1847', (4, 52, 148, 184, 244, 268, 330, 336, 354), (8, 18, 22, 56, 76, 112, 116, 160, 166, 202, 208, 238, 286, 344, 364, 376), ()),
        ('f0b587b000000000004f1b20f9884001029139890191004940180690004f3888004b1a880299114001400491b8885a8801991140084004990390084307d10000000000480088012800d09ce097e00120059005980a230049584340180090008804990840051c0098408803990840041c281c204300d177e00098004a8088004fc0430004000cd0800099c988c943118111880840b8821089518808403883000000000098067a45e01c20004970434718004b7868143398420fd1388928400cd0786900000000388b0130388338898543291c0d0400492d0c0880004b78681833984224d13889011c214020d0082803d001239b0398420dd100498880786900000000388b013038833889c04320400404240c0ce0786900000000388b0130388338898443211c0c040049240c888001363604360c0098407ab04203db002db3d1002cb1d10698004a0088d1690b041b0c984201dc002807d101310048d161c08b002801d000000000059801300004000c0590042800da6ce7000000004ee7000000000028fbd1004f0299f9800199398100000000f888398808400049888238897a8810400883004908880130088007b0f0bc08bc1847', (4, 62, 158, 194, 254, 278, 356, 376, 382, 400), (8, 22, 28, 32, 66, 86, 122, 126, 170, 176, 212, 218, 248, 296, 326, 346, 390, 410, 422), ()),
        ('f0b586b000000000004ad188029111890191004f3888004a13880299194001400491b888538801991940084004990390084307d10000000000480088012800d099e094e00120059005980a230049584340180090008804990840041c0098408803990840051c201c284300d174e00098004a8088004fc0430004000cd0800099c988c943118111880840b8821089518808403883000000000098067a54e01c20004970430c314718004b7868143398421dd13889011c214019d0a10b0ad30049097b1f2906d18443211c0c040049240c088036e0786900000000388b0130388338898443211c0c040049240c0880004b78681833984224d13889011c294020d0082803d001239b0398420dd100498880786900000000388b013038833889c043284005042d0c0ce0786900000000388b0130388338898543291c0d0400492d0c888001363604360c0098407ab04203db002ca4d1002da2d1059801300004000c0590042800da6fe70000000051e7000000000028fbd1004f0299f9800199398100000000f888398808400049888238897a8810400883004908880130088006b0f0bc08bc1847', (4, 52, 148, 214, 274, 298, 360, 366, 384), (8, 18, 22, 56, 76, 112, 116, 160, 168, 190, 204, 232, 238, 268, 316, 374, 394, 406), ()),
    ),
    'chip_isr': (
        ('f0b500000000004d09262868f6018019817801318170002000000000071c00000000041c102000000000000000000002204306d02a68012192195170391c0000000028688019817801398170381c00000000f0bc08bc1847', (2, 24, 30, 38, 42, 62, 78), (6,), ()),
        ('f0b5004d09262868f6018019817801318170002000000000071c00000000041c102000000000000000000002204306d02a68012192195170391c0000000028688019817801398170381c00000000f0bc08bc1847', (20, 26, 34, 38, 58, 74), (2,), ()),
    ),
    'chip_wrapper': (
        ('00b50000000008bc1847', (2,), (), ()),
    ),
    'install_conditional': (
        ('90b5004f012815d13978002912d138701037787b002803d000480078002801d0004a00e0004a002100200000000090bc08bc18470028fad13878002401280ad100220021002000000000012149050048000000003c700048004904701720c00108184471b92000010818c47184710d2040020818c461dae7', (42, 70, 80), (2, 24, 32, 36, 78, 86, 88), (40, 68)),
    ),
    'install_sense': (
        ('80b50021002000000000004f002138750020004a00000000387580bc08bc1847', (6, 20), (10, 18), (4, 16)),
    ),
    'sense': (
        ('90b5071c0c1c002801db302f03db002090bc08bc1847000000003a07120f012191403a0918235a43004b9a18012c02d1938a194302e0938ac94319409182918ad2681180002801d1000000000120dfe7', (22, 72), (40,), ()),
    ),
    'deferred': (
        ('00b50020000000000121490500480000000008bc1847', (4, 14), (12,), ()),
    ),
    'parent_init': (
        ('f0b500000000071c0000000000211923004a9b01d418004d6181a982002801d100000000000000000026a6812e83002801d100000000ae8300482880a880002f01d10000000000490020000000000049012000000000002000000000004800000000f0bc08bc1847', (2, 8, 32, 36, 50, 66, 74, 82, 88, 94), (16, 22, 56, 70, 78, 92), ()),
    ),
    'exception_register': (
        ('004a002801d1d161704711627047', (), (0,), ()),
        ('004a002801d15160704791607047', (), (0,), ()),
    ),
}


class _Reject(Exception):
    pass


def _span(image: bytes, entry: int, role: str) -> dict:
    for encoded, calls, literals, pins in _SPANS[role]:
        expected = bytes.fromhex(encoded)
        if entry & 1 or not 0 <= entry <= len(image) - len(expected):
            continue
        code = bytearray(image[entry:entry + len(expected)])
        targets, values, pin_values = {}, {}, {}
        dependencies = [[entry, len(expected)]]
        valid = True
        for offset in calls:
            target = thumb_bl_target(image, entry + offset)
            if target is None or target & 1 or not 0 <= target <= len(image) - 2:
                valid = False
                break
            targets[offset] = target
            dependencies.append([target, 2])
            code[offset:offset + 4] = b'\0' * 4
        if not valid:
            continue
        for offset in literals:
            word = struct.unpack_from('<H', code, offset)[0]
            if word & 0xF800 != 0x4800:
                valid = False
                break
            value = thumb_literal_value(image, entry + offset, word >> 8 & 7)
            if value is None:
                valid = False
                break
            values[offset] = value
            dependencies.append([((entry + offset + 4) & ~3) + (word & 255) * 4, 4])
            code[offset] = 0
        for offset in pins:
            if role == 'parent_register':
                word = struct.unpack_from('<H', code, offset)[0]
                if word & 0xFF00 != 0xA100:
                    valid = False
                    break
                address = ((entry + offset + 4) & ~3) + (word & 255) * 4
                end = image.find(b'\0', address, min(address + 128, len(image)))
                if not 0 <= address < len(image) or end < address:
                    valid = False
                    break
                values[offset] = address
                dependencies.append([address, end - address + 1])
            pin_values[offset] = code[offset]
            code[offset] = 0
        if valid and code == expected:
            return {'entry': entry, 'size': len(expected), 'calls': targets,
                    'literals': values, 'pins': pin_values, 'dependencies': dependencies}
    raise _Reject(role + '-shape-unmatched')


def _scan(image: bytes, role: str) -> list[dict]:
    entries = set()
    for encoded, calls, literals, pins in _SPANS[role]:
        code = bytes.fromhex(encoded)
        erased = set(literals) | set(pins)
        erased.update(position for offset in calls for position in range(offset, offset + 4))
        pattern = b''.join(b'.' if i in erased else re.escape(bytes([byte]))
                           for i, byte in enumerate(code))
        for match in re.finditer(b'(?=(' + pattern + b'))', image, re.DOTALL):
            if not match.start() & 1:
                entries.add(match.start())
            if len(entries) > 64:
                raise _Reject(role + '-search-limit')
    return [_span(image, entry, role) for entry in sorted(entries)]


def _boot_copy(image: bytes) -> tuple[list[tuple], list[list[int]]]:
    # Finite ARM reset/word-copy class. The copy consumes only three descriptor words.
    if len(image) < 4:
        return [], []
    branch = struct.unpack_from('<I', image)[0]
    if branch >> 24 != 0xEA:
        return [], []
    delta = branch & 0xFFFFFF
    reset = 8 + ((delta - 0x1000000 if delta & 0x800000 else delta) << 2)
    expected = bytes.fromhex('00409fe5010014e300e09f1500e09f0514ff2fe17847000000409fe5010014e300e09f1500e09f0514ff2fe17847000000409fe5010014e300e09f1500e09f0514ff2fe178470000000050e35b00001ad7f021e300d09fe5dbf021e300d09fe5d3f021e300d09fe500409fe5010014e300e09f1500e09f0514ff2fe17847000000b09fe500c09be500b09fe500409be54057a0e308b0a0e30070a0e30080a0e30090a0e300a0a0e34069a0e3206046e28007a5e88007a5e8206056e2fbffff2a0120a0e300309fe5003093e50020c3e50020a0e30020c3e501b04be200005be3f0ffff1a00b09fe500c08be500b09fe500408be500409fe5010014e300e09f1500e09f0514ff2fe178470000')
    if not 0 <= reset <= len(image) - len(expected):
        return [], []
    code = bytearray(image[reset:reset + len(expected)])
    values, deps = {}, [[0, 4], [reset, len(expected)]]
    for offset in (0, 8, 12, 24, 32, 36, 48, 56, 60, 84, 92, 100, 104, 112, 116, 128, 136, 196, 228, 236, 244, 252, 256):
        word = struct.unpack_from('<I', code, offset)[0]
        if word & 0x0F7F0000 != 0x051F0000:
            return [], []
        address = reset + offset + 8 + (word & 4095) * (1 if word & 0x800000 else -1)
        if address & 3 or not 0 <= address <= len(image) - 4:
            return [], []
        values[offset] = struct.unpack_from('<I', image, address)[0]
        deps.append([address, 4])
        struct.pack_into('<I', code, offset, word & ~4095)
    if code != expected:
        return [], []
    for first in (0, 0x18, 0x30, 0x68, 0xF4):
        callee = values[first]
        if not 0 <= (callee & ~1) <= len(image) - 2 or (not callee & 1 and callee & 3):
            return [], []
        deps.append([callee & ~1, 2])
        if (values[first + 8] != ((reset + first + 20) | 1)
                or values[first + 12] != reset + first + 24):
            return [], []
    pointer = values[0xF4]
    if not pointer & 1:
        return [], []
    try:
        copier = _span(image, pointer - 1, 'boot_copy')
    except _Reject:
        return [], []
    deps.extend(copier['dependencies'])
    literals = copier['literals']
    # Middle copy loads source/target/size through a single adjacent three-word row.
    source_pointer, target_pointer, size_pointer = literals[0x4E], literals[0x42], literals[0x46]
    if (target_pointer != source_pointer + 4 or size_pointer != source_pointer + 8
            or literals[0x54] != target_pointer):
        return [], []
    if any(literals[o] != 0x03000700 for o in (2, 0x3A, 0x72, 0xAA)):
        return [], []
    for address in {v for o, v in literals.items() if o not in (2, 0x3A, 0x72, 0xAA)}:
        if address & 3 or not 0 <= address <= len(image) - 4:
            return [], []
        deps.append([address, 4])
    source, target, size = struct.unpack_from('<3I', image, source_pointer)
    # Reset's literal-free clear loop proves 01000000..01800000 independently.
    if (source & 3 or target != 0x01000000 or not size or size & 3
            or size > 0x800000 or source > len(image) - size):
        return [], []
    # The first copy precedes this initialized span; the final copy must not
    # overwrite any of the independently cleared SDRAM after the middle copy.
    for source_offset, target_offset, size_offset, repeat_offset, final in (
            (0x16, 0xA, 0xE, 0x1C, False), (0x86, 0x7A, 0x7E, 0x8C, True)):
        pointer = literals[source_offset]
        if (literals[target_offset] != pointer + 4
                or literals[size_offset] != pointer + 8
                or literals[repeat_offset] != pointer + 4
                or not 0 <= pointer <= len(image) - 12):
            return [], []
        other_source, other_target, other_size = struct.unpack_from('<3I', image, pointer)
        if (not other_size or (other_source | other_target | other_size) & 3
                or other_source > len(image) - other_size
                or other_target + other_size > 0x100000000):
            return [], []
        end = 0x01800000 if final else target + size
        if max(other_target, target) < min(other_target + other_size, end):
            return [], []
        deps.append([pointer, 12])
    deps.append([source_pointer, 12])
    return [(source_pointer, source, target, size, 0x01800000)], deps


def _layouts(image: bytes) -> list[tuple]:
    result = []
    for offset in range(0, min(len(image) - 20, 0x40000) + 1, 4):
        source, target, size, bss, zero = struct.unpack_from('<5I', image, offset)
        if (0 < size <= 0x800000 and source <= len(image) - size
                and 0x01000000 <= target < 0x02000000
                and target + size == bss and 0 <= zero <= 0x2000000
                and bss + zero <= 0x02000000):
            result.append((offset, source, target, size, bss + zero))
    boot, _ = _boot_copy(image)
    if boot:
        row = boot[0]
        if any(max(old[2], row[2]) < min(old[2] + old[3], row[2] + row[3]) for old in result):
            raise _Reject('bootstrap-initialized-overlap')
        # Preserve higher independently initialized rows; discard the uncovered tail.
        higher = [old[2] for old in result if row[2] + row[3] <= old[2] < row[4]]
        end = min(higher, default=row[4])
        if any(max(old[2], row[2]) < min(old[4], end) for old in result):
            raise _Reject('bootstrap-scatter-overlap')
        boot = [(*row[:4], end)]
    return result + boot


def _mapping(layouts: list[tuple], address: int, size: int, data: bool = False) -> tuple:
    matches = [row for row in layouts if row[2] <= address
               <= (row[2] + row[3] if data else row[4]) - size]
    if len(matches) != 1:
        raise _Reject('scatter-none-or-ambiguous')
    return matches[0]


def _check(condition: bool, reason: str) -> None:
    if not condition:
        raise _Reject(reason)


def _one(spans: list[dict], reason: str) -> dict:
    _check(len(spans) == 1, reason)
    return spans[0]


def _pointer(image: bytes, pointer: int) -> int:
    _check(pointer & 1 and 0 <= pointer - 1 <= len(image) - 2, 'function-pointer-unmapped')
    return pointer - 1


def _indirect_call_chain(image: bytes, entry: int) -> dict:
    _check(not entry & 1 and 0 <= entry <= len(image) - 2,
           'gpio-indirect-call-unmatched')
    if image[entry:entry + 2] == b'\x00\x47':
        return {'profile': 'thumb-bx-r0-v1', 'entry': entry, 'leaf': entry,
                'nor_dependencies': [[entry, 2]]}
    # Preserve R0/LR through one closed Thumb-to-ARM literal veneer.
    if (entry & 3 or entry > len(image) - 16
            or image[entry:entry + 12] != bytes.fromhex('7847c04600c09fe51cff2fe1')):
        raise _Reject('gpio-indirect-call-unmatched')
    pointer = struct.unpack_from('<I', image, entry + 12)[0]
    leaf = _pointer(image, pointer)
    _check(image[leaf:leaf + 2] == b'\x00\x47', 'gpio-indirect-call-unmatched')
    return {'profile': 'thumb-arm-literal-bx-r0-v1', 'entry': entry, 'leaf': leaf,
            'literal': entry + 12, 'nor_dependencies': [[entry, 16], [leaf, 2]]}


def _direct_accessor(image: bytes, literal_load: int, value: int) -> dict | None:
    register = struct.unpack_from('<H', image, literal_load)[0] >> 8 & 7
    word = struct.unpack_from('<H', image, literal_load + 2)[0]
    opcode = word & 0xF800
    widths = {0x6000: 4, 0x6800: 4, 0x7000: 1, 0x7800: 1, 0x8000: 2, 0x8800: 2}
    if opcode not in widths or word >> 3 & 7 != register:
        return None
    width = widths[opcode]
    return {'address': value + ((word >> 6 & 31) * width), 'width': width,
            'accessor': literal_load + 2, 'access': 'read' if word & 0x800 else 'write'}


def _route(image: bytes, audio: dict, init: dict, scanned: dict, layouts: list[tuple]) -> dict:
    spans = [init]
    boot_layouts, boot_dependencies = _boot_copy(image)
    nor, ram = list(boot_dependencies), []
    if boot_layouts:
        boot_row = boot_layouts[0]
        higher = [row for row in layouts if boot_row[2] + boot_row[3] <= row[2] < boot_row[4]]
        if higher:
            boundary = min(row[2] for row in higher)
            nor.extend([[row[0], 20] for row in higher if row[2] == boundary])
    table = init['literals'][0x56]
    callbacks = init['literals'][0x80]
    gpio_entry = _pointer(image, init['literals'][0x9A])
    gpio = _span(image, gpio_entry, 'gpio_dispatch')
    spans.append(gpio)
    gl = gpio['literals']
    _check(gl == {2: 0x03000C80, 6: table, 0x26: callbacks, 0xAE: table + 0x40},
           'gpio-dispatch-table-linkage')
    thunk = gpio['calls'][0x48]
    _check(set(gpio['calls'].values()) == {thunk}, 'gpio-indirect-call-unmatched')
    indirect = _indirect_call_chain(image, thunk)
    nor.extend(indirect['nor_dependencies'])
    default = _pointer(image, init['literals'][0x82])
    _check(image[default:default + 2] == b'\x70\x47', 'gpio-default-unmatched')
    registrar = _one([span for span in scanned['gpio_register']
                      if span['literals'] == {0x2C: table, 0x2E: callbacks,
                                              0x36: default | 1, 0x48: table}],
                     'gpio-registrar-none-or-ambiguous')
    spans.append(registrar)
    lock, unlock = registrar['calls'][0x18], registrar['calls'][0x72]
    _check(all(init['calls'][offset] == lock for offset in (4, 10, 0x26, 0x38))
           and all(init['calls'][offset] == unlock for offset in (0x22, 0x34, 0x46, 0x96)),
           'gpio-init-lock-linkage')
    _check(init['literals'][0x18] == init['literals'][0x4A] == 0x03000CA0
           and init['literals'][0x4C] == 0xFFFF, 'gpio-init-mmio-unmatched')
    parent_reg = _span(image, init['calls'][0x9E], 'parent_register')
    spans.append(parent_reg)
    table_offset, unlock_offset, error_offset = {
        122: (0x26, 0x70, 0x1C), 128: (0x2C, 0x76, 0x24),
        134: (0x32, 0x7C, 0x28),
    }[parent_reg['size']]
    parent_table = parent_reg['literals'][table_offset]
    _check(parent_reg['calls'][6] == lock
           and parent_reg['calls'][unlock_offset] == unlock,
           'parent-registrar-lock-linkage')
    _check(not (table | callbacks | parent_table) & 3, 'route-table-unaligned')
    parent_state = parent_table - 12
    socs = []
    for soc in scanned['soc_dispatch']:
        literals = soc['literals']
        if soc['size'] == 392:
            coherent = (all(literals[o] == 0x03000C80 for o in
                            (0x12, 0x74, 0xA6, 0xCA, 0xD0, 0xEE, 0x11E, 0x16C))
                        and all(literals[o] == parent_state for o in (8, 0x16, 0x70, 0x158))
                        and literals[0xA0] == parent_table
                        and literals[0x4C] == parent_table + 31 * 28 + 4
                        and all(soc['calls'][o] == thunk for o in (0xB8, 0xF4, 0x10C))
                        and all(soc['calls'][o] == lock for o in (0x14A, 0x162))
                        and all(soc['calls'][o] == unlock for o in (0x34, 0x94)))
        elif soc['size'] == 438:
            coherent = (all(literals[o] == 0x03000C80 for o in
                            (0x1C, 0x7E, 0xB0, 0xD4, 0xDA, 0xF8, 0x128, 0x19A))
                        and all(literals[o] == parent_state for o in (8, 0x20, 0x7A, 0x186))
                        and literals[0x16] == literals[0xAA] == parent_table
                        and literals[0x56] == parent_table + 31 * 28 + 4
                        and all(soc['calls'][o] == thunk for o in (0xC2, 0xFE, 0x116))
                        and all(soc['calls'][o] == lock for o in (0x178, 0x190))
                        and all(soc['calls'][o] == unlock for o in (0x3E, 0x9E)))
        else:
            coherent = (all(literals[o] == 0x03000C80 for o in
                            (0x12, 0x74, 0xA8, 0xCC, 0xE8, 0xEE, 0x10C, 0x13C, 0x18A))
                        and literals[0xBE] == 0x03000720
                        and all(literals[o] == parent_state for o in (8, 0x16, 0x70, 0xA0, 0x176))
                        and literals[0x4C] == parent_table + 31 * 28 + 4
                        and all(soc['calls'][o] == thunk for o in (0xD6, 0x112, 0x12A))
                        and all(soc['calls'][o] == lock for o in (0x168, 0x180))
                        and all(soc['calls'][o] == unlock for o in (0x34, 0x94)))
        if coherent:
            socs.append(soc)
    soc = _one(socs, 'soc-dispatcher-none-or-ambiguous')
    spans.append(soc)
    # Parent init registers this actual SoC dispatcher into the exception callback table.
    parent_init = _one([span for span in scanned['parent_init']
                       if span['literals'][0x46] == soc['entry'] | 1],
                      'parent-init-none-or-ambiguous')
    spans.append(parent_init)
    _check(parent_init['literals'][0x16] == 0x03000C80
           and parent_init['literals'][0x38] == 0xFFFF
           and all(parent_init['calls'][o] == lock for o in (2, 8, 0x24))
           and all(parent_init['calls'][o] == unlock for o in (0x20, 0x32, 0x42))
           and parent_init['calls'][0x4A] == parent_init['calls'][0x52],
           'parent-init-registration-linkage')
    exception = _span(image, parent_init['calls'][0x4A], 'exception_register')
    spans.append(exception)
    _check(not exception['literals'][0] & 3, 'exception-array-unaligned')
    exception_offset = ((struct.unpack_from('<H', image, exception['entry'] + 6)[0] >> 6) & 31) * 4
    other_exception = _pointer(image, parent_init['literals'][0x4E])
    error_pointer = parent_reg['literals'][error_offset]
    _check(0 <= error_pointer < len(image), 'parent-error-literal-unmapped')
    nor.extend([[other_exception, 2], [error_pointer, 1]])
    boot_calls = []
    for match in re.finditer(rb'(?=.[\xf0-\xf7].[\xf8-\xff])', image, re.DOTALL):
        call = match.start()
        if (call >= 4 and not call & 1 and thumb_bl_target(image, call) == init['entry']
                and thumb_bl_target(image, call - 4) == parent_init['entry']):
            boot_calls.append(call - 4)
    _check(len(boot_calls) == 1, 'init-caller-none-or-ambiguous')
    nor.append([boot_calls[0], 8])
    index = struct.unpack_from('<H', image, init['entry'] + 0x9C)[0] & 255
    _check(0 < index < 31, 'parent-index-unmatched')
    descriptor = parent_table + index * 28
    desc_layout = _mapping(layouts, descriptor, 28, data=True)
    desc_rom = desc_layout[1] + descriptor - desc_layout[2]
    words = list(struct.unpack_from('<7I', image, desc_rom))
    status, enable, mask, shadow, priority, initial, reserved = words
    _check(status == 0x03000C84 and enable == 0x03000C98
           and 0 < mask <= 0x8000 and not mask & (mask - 1)
           and shadow == parent_state + 2 and priority == parent_state + 8
           and initial == parent_reg['literals'][0xE] and not reserved,
           'parent-descriptor-linkage')
    if soc['size'] == 392:
        priorities = soc['literals'][0x4C]
        priority_layout = _mapping(layouts, priorities, 40, data=True)
        priority_rom = priority_layout[1] + priorities - priority_layout[2]
        eligible = []
        for row_index in range(1, 4):
            low, high, disable_low, disable_high, first, last = struct.unpack_from(
                '<4H2B', image, priority_rom + row_index * 10)
            _check(0 < first <= last < 31, 'parent-priority-range-unmatched')
            if first <= index <= last and (high if enable == 0x03000C98 else low) & mask:
                eligible.append(row_index)
        _check(len(eligible) == 1, 'parent-priority-owner-unmatched')
        nor.append([priority_rom, 40])
    _pointer(image, initial)
    nor.extend([[desc_layout[0], 12 if any(row[0] == desc_layout[0] for row in boot_layouts) else 20], [desc_rom, 28], [initial - 1, 2]])
    gpio_layout = _mapping(layouts, table, 72, data=True)
    gpio_rom = gpio_layout[1] + table - gpio_layout[2]
    rows = []
    for bank in range(3):
        row = struct.unpack_from('<4I4H', image, gpio_rom + bank * 24)
        expected = (0x03000C88 + 4 * bank, 0x03000CA4 + 4 * bank,
                    0x03000CB0 + 4 * bank, 0x0300074C + 4 * bank, 0, 0xFFFF, 0, 0)
        _check(row == expected, 'gpio-row-unmatched')
        rows.append({'pending_ack': row[0], 'enable': row[1], 'polarity': row[2],
                     'trigger': row[3], 'cache_ram': table + bank * 24 + 16,
                     'initial_cache': list(row[4:])})
    nor.extend([[gpio_layout[0], 12 if any(row[0] == gpio_layout[0] for row in boot_layouts) else 20], [gpio_rom, 72], [default, 2]])
    context = audio['structural_evidence']['context_pointer']
    ctx_layout = _mapping(layouts, context, 4, data=True)
    ctx_rom = ctx_layout[1] + context - ctx_layout[2]
    context_initial = struct.unpack_from('<I', image, ctx_rom)[0]
    nor.extend([[ctx_layout[0], 12 if any(row[0] == ctx_layout[0] for row in boot_layouts) else 20], [ctx_rom, 4]])
    isrs = []
    entries = audio['structural_evidence']['entries']
    for isr in scanned['chip_isr']:
        calls = isr['calls']
        shift = 4 if isr['size'] == 88 else 0
        if (isr['literals'][2 + shift] == context
                and all(calls[o + shift] == entries['select'] for o in (0x14, 0x22, 0x4A))
                and all(calls[o + shift] == entries['dataread'] for o in (0x1A, 0x26))):
            isrs.append(isr)
    isr = _one(isrs, 'chip-isr-none-or-ambiguous')
    isr_shift = 4 if isr['size'] == 88 else 0
    wrapper = _span(image, isr['calls'][0x3A + isr_shift], 'chip_wrapper')
    spans.extend([isr, wrapper])
    installers = []
    for install in scanned['install_conditional']:
        if (install['calls'][0x2A] != registrar['entry']
                or install['calls'][0x46] != registrar['entry']
                or install['literals'][0x20] != isr['entry'] | 1):
            continue
        pin = install['pins'][0x28]
        if not 0 <= pin < 48 or install['pins'][0x44] != pin:
            continue
        deferred = _span(image, _pointer(image, install['literals'][0x24]), 'deferred')
        _check(deferred['calls'][4] == entries['index']
               and deferred['literals'][0xC] == install['literals'][0x4E],
               'deferred-gate-linkage')
        active, other = install['literals'][2], install['literals'][0x18]
        installers.append((install, {
            'profile': 'conditional-install-direct-or-task-v1', 'entry': install['entry'],
            'pin': pin, 'polarity_argument': 0, 'installed_flag': active,
            'installed_value': 1, 'direct_callback': isr['entry'] | 1,
            'deferred_callback': deferred['entry'] | 1,
            'direct_gate': {'any': [{'address': active + 0x1D, 'op': 'eq', 'value': 0},
                                    {'address': other, 'op': 'ne', 'value': 0}]},
            'deferred_gate': {'all': [{'address': active + 0x1D, 'op': 'ne', 'value': 0},
                                      {'address': other, 'op': 'eq', 'value': 0}]},
            'deferred_signal_tcb': deferred['literals'][0xC],
            'deferred_signal_mask': 0x200000, 'deferred_task_path_verified': False,
        }, [deferred], [[active, 1], [active + 0x1D, 1], [other, 1]]))
    for install in scanned['install_direct']:
        if (install['calls'][0x30] != registrar['entry']
                or install['literals'][0x2E] != isr['entry'] | 1):
            continue
        pin = install['pins'][0x24]
        if not 0 <= pin < 48 or install['pins'][0x2C] != pin:
            continue
        sense = _span(image, install['calls'][0x26], 'sense')
        _check(sense['literals'][0x28] == table
               and sense['calls'][0x16] == lock and sense['calls'][0x48] == unlock
               and install['calls'][2] == lock and install['calls'][0x1E] == unlock,
               'direct-install-lock-sense-linkage')
        cache, mirror = install['literals'][6], install['literals'][0x12]
        cache_layout = _mapping(layouts, cache, 32, data=True)
        cache_rom = cache_layout[1] + cache - cache_layout[2]
        _check(struct.unpack_from('<I', image, cache_rom + 0x18)[0] == 0x03000730,
               'direct-install-cache-pointer-unmatched')
        _mapping(layouts, mirror, 32, data=True)
        nor.extend([[cache_rom, 32]])
        installers.append((install, {
            'profile': 'direct-install-no-flag-v1', 'entry': install['entry'],
            'pin': pin, 'polarity_argument': 0, 'trigger_argument': 0, 'installed_flag': None,
            'installed_value': None, 'direct_callback': isr['entry'] | 1,
            'deferred_callback': None, 'direct_gate': None, 'deferred_gate': None,
            'deferred_signal_tcb': None, 'deferred_signal_mask': None,
        }, [sense], [[cache, 32], [mirror, 32]]))
    for install in scanned['install_sense']:
        if (install['calls'][0x14] != registrar['entry']
                or install['literals'][0x12] != isr['entry'] | 1):
            continue
        pin = install['pins'][4]
        if not 0 <= pin < 48 or install['pins'][0x10] != pin:
            continue
        sense = _span(image, install['calls'][6], 'sense')
        _check(sense['literals'][0x28] == table
               and sense['calls'][0x16] == lock and sense['calls'][0x48] == unlock,
               'sense-table-linkage')
        _check(install['literals'][0xA] == context_initial + 0x480, 'install-context-linkage')
        active = install['literals'][0xA] + 0x14
        installers.append((install, {
            'profile': 'explicit-sense-direct-install-v1', 'entry': install['entry'],
            'pin': pin, 'polarity_argument': 0, 'trigger_argument': 0,
            'installed_flag': active, 'installed_value': 1,
            'direct_callback': isr['entry'] | 1, 'deferred_callback': None,
            'direct_gate': None, 'deferred_gate': None,
        }, [sense], [[active, 1]]))
    _check(len(installers) == 1, 'audio-install-none-or-ambiguous')
    install, installation, extra, gate_ram = installers[0]
    spans.extend([install, *extra])
    pin = installation['pin']
    ram.extend([[table, 72], [callbacks, 48 * 4], [parent_table, 31 * 28],
                [descriptor, 28], [parent_state, 12], [shadow, 2], [priority, 2],
                [exception['literals'][0] + exception_offset, 8], [context, 4],
                [context_initial + 0x480, 3], *gate_ram])
    _check(context_initial & 3 == 0, 'initial-context-unaligned')
    _check(init['literals'][0x12] == parent_init['literals'][0x10], 'init-state-linkage')
    init_state = init['literals'][0x12]
    ram.extend([[init_state + 0x64A, 4], [init_state + 0x652, 6]])
    auxiliaries = [{
        'address': table + 0x4A, 'width': 2,
        'literal_load': gpio['entry'] + 0xAE, 'accessor': gpio['entry'] + 0xB0,
        'path': 'no-enabled-gpio-pending', 'purpose': 'miss-counter',
    }]
    # These non-route literals have no invented callee-pointee extent.
    exact_route_addresses = {table, callbacks, context, parent_table, parent_state,
                             shadow, priority, descriptor, context_initial,
                             init_state, init_state + 0x640}
    for span in spans:
        nor.extend(span['dependencies'])
        for offset, value in span['literals'].items():
            if 0x01000000 <= value < 0x02000000:
                _mapping(layouts, value, 1)
                if span is gpio and offset == 0xAE:
                    continue
                if value not in exact_route_addresses:
                    accessor = _direct_accessor(image, span['entry'] + offset, value)
                    if accessor is not None:
                        _check(not accessor['address'] % accessor['width'],
                               'auxiliary-accessor-unaligned')
                        ram.append([accessor['address'], accessor['width']])
                    auxiliaries.append({'address': value, 'width': None,
                                        'direct_accessor': accessor,
                                        'literal_load': span['entry'] + offset,
                                        'path': ('parent-registrar-index-zero' if span is parent_reg and offset in (0x30, 0x36) else
                                                 'uninstall-path' if span is install and offset >= 0x4E else
                                                 'initialization-or-installation' if span in
                                                 (init, parent_init, install, *extra) else
                                                 'unclassified-other-irq-or-tracing'),
                                        'purpose': 'callee-or-auxiliary-path-unverified'})
            elif value >= 0x03000000:
                _check(value in {0x03000C80, 0x03000CA0, 0x03000720},
                       'auxiliary-mmio-literal-unmatched')
            elif value > 0xFFFF:
                _check(value < len(image), 'auxiliary-rom-literal-unmapped')
                nor.append([value & ~1, 2])
    for address, size in ram:
        layout = _mapping(layouts, address, size)
        nor.append([layout[0], 12 if any(row[0] == layout[0] for row in boot_layouts) else 20])
    _mapping(layouts, auxiliaries[0]['address'], 2)
    ram.append([auxiliaries[0]['address'], 2])
    auxiliary_calls = []
    bound_calls = {
        init['entry']: set(init['calls']), registrar['entry']: {0x18, 0x72},
        parent_reg['entry']: {6, unlock_offset},
        gpio['entry']: set(gpio['calls']), isr['entry']: set(isr['calls']) - ({2} if isr_shift else set()),
        parent_init['entry']: {2, 8, 0x20, 0x24, 0x32, 0x42, 0x4A, 0x52},
        exception['entry']: set(),
    }
    bound_calls[install['entry']] = ({0x2A, 0x46} if installation['deferred_callback']
                                      is not None else {6, 0x14})
    if installation['profile'] == 'direct-install-no-flag-v1':
        bound_calls[install['entry']] = {2, 0x1E, 0x26, 0x30}
    for companion in extra:
        bound_calls[companion['entry']] = ({4} if companion['size'] == 22 else
                                           set(companion['calls']))
    bound_calls[soc['entry']] = ({0x34, 0x94, 0xB8, 0xF4, 0x10C, 0x14A, 0x162}
                                 if soc['size'] == 392 else
                                  ({0x3E, 0x9E, 0xC2, 0xFE, 0x116, 0x178, 0x190}
                                 if soc['size'] == 438 else
                                 {0x34, 0x94, 0xD6, 0x112, 0x12A, 0x168, 0x180}))
    for span in spans:
        for offset, target in span['calls'].items():
            if offset not in bound_calls.get(span['entry'], set()):
                path = ('gpio-chip-source-dispatch' if span is wrapper else
                        'invalid-parent-index' if span is parent_reg else
                        'initialization-or-installation' if span in (parent_init, install, *extra)
                        else 'unclassified-other-irq-or-tracing')
                auxiliary_calls.append({'callsite': span['entry'] + offset,
                                        'target': target, 'path': path,
                                        'callee_body_verified': False})
    return {
        'family': 'ma5', 'grammar': 'ma5-gpio-parent-irq-v1', 'status': 'candidate',
        'static_status': 'candidate', 'reject_reason': None, 'runtime_admitted': False,
        'source_profile': 'three-bank-gpio-parent-descriptor-v1',
        'admission_note': 'auxiliary-paths-unverified; live callback/exception proof required',
        'gpio': {'table_ram': table, 'table_rom': gpio_rom, 'rows': rows,
                 'callbacks_ram': callbacks, 'pin': pin, 'bank': pin >> 4,
                 'mask': 1 << (pin & 15), 'callback_slot': callbacks + pin * 4,
                 'registrar': registrar['entry'], 'dispatcher': gpio_entry,
                 'default_callback': default | 1, 'indirect_call_chain': indirect},
        'parent': {'table_ram': parent_table, 'index': index,
                   'descriptor_ram': descriptor, 'descriptor_rom': desc_rom, 'words': words,
                   'status_ack': status, 'enable': enable, 'mask': mask,
                   'enable_shadow': shadow, 'priority_shadow': priority,
                   'callback_slot': descriptor + 20, 'handler_counter': descriptor + 24,
                   'installed_gpio_dispatcher': gpio_entry | 1,
                   'dispatcher': soc['entry'], 'registrar': parent_reg['entry'],
                   'initializer': parent_init['entry'], 'gpio_initializer': init['entry'],
                   'adjacent_boot_registration': boot_calls[0],
                   'exception_registrar': exception['entry'],
                   'exception_callback_slot': exception['literals'][0] + exception_offset,
                   'installed_soc_dispatcher': soc['entry'] | 1},
        'chip': {'isr': isr['entry'], 'selector': entries['select'],
                 'data_reader': entries['dataread'],
                 'data_read_sites': audio['sites'][f"read_{audio['data_offset']}"],
                 'priority_wrapper': wrapper['entry'], 'priority_dispatcher': wrapper['calls'][2],
                 'context_holder': context, 'initial_context': context_initial},
        'installation': installation, 'aux_addresses': auxiliaries,
        'aux_calls': auxiliary_calls,
        'nor_dependencies': [list(span) for span in sorted({tuple(span) for span in nor})],
        'ram_dependencies': [list(span) for span in sorted({tuple(span) for span in ram})],
    }


def find_ma5_gpio_irq_candidate(image: bytes, audio_candidate: object) -> dict:
    """Find one same-image static route; this never enables native IRQ admission."""
    rejected = {'family': 'ma5', 'grammar': 'ma5-gpio-parent-irq-v1',
                'status': 'rejected', 'static_status': 'rejected',
                'runtime_admitted': False, 'reject_reason': 'route-none'}
    if (not isinstance(audio_candidate, dict)
            or audio_candidate.get('family') != 'ma5'
            or audio_candidate.get('grammar') != 'ma5-readback-v1'
            or audio_candidate.get('static_status') != 'candidate'
            or find_ma5_readback_candidate(image) != audio_candidate):
        return {**rejected, 'reject_reason': 'audio-same-image-unmatched'}
    try:
        scanned = {role: _scan(image, role) for role in
                   ('gpio_init', 'gpio_register', 'soc_dispatch', 'parent_init', 'chip_isr',
                    'install_conditional', 'install_sense', 'install_direct')}
        layouts = _layouts(image)
        candidates, reasons = [], []
        for init in scanned['gpio_init']:
            try:
                candidates.append(_route(image, audio_candidate, init, scanned, layouts))
            except _Reject as error:
                reasons.append(str(error))
            if len(candidates) > 1:
                return {**rejected, 'reject_reason': 'route-ambiguous'}
        return candidates[0] if candidates else {
            **rejected, 'reject_reason': reasons[0] if len(set(reasons)) == 1 else 'route-none'}
    except _Reject as error:
        return {**rejected, 'reject_reason': str(error)}


__all__ = ('find_ma5_gpio_irq_candidate',)
