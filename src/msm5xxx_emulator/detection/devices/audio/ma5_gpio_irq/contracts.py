from __future__ import annotations
from msm5xxx_emulator.detection.fact_bodies import thumb_body
from msm5xxx_emulator.detection.startup_layouts import (StartupLayoutError as _Reject, boot_copy as _boot_copy, layouts as _layouts,)

_SPANS = {'install_direct': (('00b50000000000494023ca8b9a43ca83ca8b004bda8389690a80002801d100000000002100200000000000210020004a0000000008bc1847', (2, 30, 38, 48),
    (6, 18, 46), (36, 44)),), 'gpio_dispatch': (('b0b5004c208900490a8a0240201c80890b8d0340201c008a403109880840051c00200127002a004914d03b1c1f1c87403f043f0c151c3d4004d101300004000c1028f3db80000858000000002781b0bc08bc1847002b13d03a1c171c87403f043f0c1d1c3d4004d101300004000c1028f3db80004018006c00000000a781e6e7002d14d03a1c131c83401f043f0c2b1c3b4004d101300004000c1028f3db8000401880300068000000002782cfe70049488901304881cae7',
    (72, 120, 166), (2, 6, 38, 174), ()),), 'gpio_register': (('f0b5071c0d1c141c002801db2f2f03dd0020f0bc08bc184700000000ba003b071b0f012199403f0918235f43004b004edb19002c06d1004fc943b7501a8a1140198211e0b4501a8a004c0a431a82012d02d15a8a0a4301e05a8a8a435a825a8a9d682a80e2591180198a5a681180002801d1000000000120cbe7',
    (24, 114), (44, 46, 54, 72), ()),), 'gpio_init': (('f0b5002700000000051c0000000000211923004a9b01d418004e6182b180002801d100000000000000000021a1823181002801d100000000000000000021e182b181002801d100000000004900482039088188810882004a508a91680880508d116a0880d01d39304188936b1980918ad3681980918d536a19808088d16b0880004a0048b90001373f043f0c302f5050f8db002d01d10000000000491d2000000000f0bc08bc1847',
    (4, 10, 34, 38, 52, 56, 70, 150, 158), (18, 24, 74, 76, 86, 128, 130, 154), ()),), 'parent_register': (('f8b5041c0f1c00000000051c002f004e00d1371c002c01db1f2c09db00000000002200920023221c00a10048000000001c20004960434018002c02d100490f6300e04761b74204d1c1680a8803899a430ae0c1680a8801890a4006d102681180c1680a8803891a430a80c168026909881288406811400180002d01d100000000f8bc08bc1847',
    (6, 28, 44, 124), (14, 42, 50, 60), (40,)), ('f0b5041c0f1c00000000051c002f004e00d1371c002c01db1f2c06db00000000232000010049000000001c20004960434018002c02d100490f6300e04761b74204d1c1680a8803899a430ae0c1680a8801890a4006d102681180c1680a8803891a430a80c168026909881288406811400180002d01d100000000f0bc08bc1847',
    (6, 28, 38, 118), (14, 36, 44, 54), ()), ('f0b5041c0f1c00000000051c002f004e00d1371c002c01db1f2c03db00490048000000001c20004960434018002c02d100490f6300e04761b74204d1c1680a8803899a430ae0c1680a8801890a4006d102681180c1680a8803891a430a80c168026909881288406811400180002d01d100000000f0bc08bc1847',
    (6, 32, 112), (14, 28, 30, 38, 48), ())), 'soc_dispatch': (('f0b586b000000000004ad188029111890191004f3888004a13880299194001400491b888538801991940084004990390084307d10000000000480088012800d08ae085e00120059005980a230049584340180090008804990840051c0098408803990840041c281c204300d165e00098004a8088004fc0430004000cd0800099c988c943118111880840b8821089518808403883000000000098067a45e01c20004970434718004b7868143398420fd1388928400cd0786900000000388b0130388338898543291c0d0400492d0c0880004b78681833984224d13889011c214020d0082803d001239b0398420dd100498880786900000000388b013038833889c04320400404240c0ce0786900000000388b0130388338898443211c0c040049240c888001363604360c0098407ab04203db002db3d1002cb1d1059801300004000c0590042800da7ee70000000060e7000000000028fbd1004f0299f9800199398100000000f888398808400049888238897a8810400883004908880130088006b0f0bc08bc1847',
    (4, 52, 148, 184, 244, 268, 330, 336, 354), (8, 18, 22, 56, 76, 112, 116, 160, 166, 202, 208, 238, 286, 344, 364, 376), ()), ('f0b587b000000000004f1b20f9884001029139890191004940180690004f3888004b1a880299114001400491b8885a8801991140084004990390084307d10000000000480088012800d09ce097e00120059005980a230049584340180090008804990840051c0098408803990840041c281c204300d177e00098004a8088004fc0430004000cd0800099c988c943118111880840b8821089518808403883000000000098067a45e01c20004970434718004b7868143398420fd1388928400cd0786900000000388b0130388338898543291c0d0400492d0c0880004b78681833984224d13889011c214020d0082803d001239b0398420dd100498880786900000000388b013038833889c04320400404240c0ce0786900000000388b0130388338898443211c0c040049240c888001363604360c0098407ab04203db002db3d1002cb1d10698004a0088d1690b041b0c984201dc002807d101310048d161c08b002801d000000000059801300004000c0590042800da6ce7000000004ee7000000000028fbd1004f0299f9800199398100000000f888398808400049888238897a8810400883004908880130088007b0f0bc08bc1847',
    (4, 62, 158, 194, 254, 278, 356, 376, 382, 400), (8, 22, 28, 32, 66, 86, 122, 126, 170, 176, 212, 218, 248, 296, 326, 346, 390, 410, 422), ()), ('f0b586b000000000004ad188029111890191004f3888004a13880299194001400491b888538801991940084004990390084307d10000000000480088012800d099e094e00120059005980a230049584340180090008804990840041c0098408803990840051c201c284300d174e00098004a8088004fc0430004000cd0800099c988c943118111880840b8821089518808403883000000000098067a54e01c20004970430c314718004b7868143398421dd13889011c214019d0a10b0ad30049097b1f2906d18443211c0c040049240c088036e0786900000000388b0130388338898443211c0c040049240c0880004b78681833984224d13889011c294020d0082803d001239b0398420dd100498880786900000000388b013038833889c043284005042d0c0ce0786900000000388b0130388338898543291c0d0400492d0c888001363604360c0098407ab04203db002ca4d1002da2d1059801300004000c0590042800da6fe70000000051e7000000000028fbd1004f0299f9800199398100000000f888398808400049888238897a8810400883004908880130088006b0f0bc08bc1847',
    (4, 52, 148, 214, 274, 298, 360, 366, 384), (8, 18, 22, 56, 76, 112, 116, 160, 168, 190, 204, 232, 238, 268, 316, 374, 394, 406), ())), 'chip_isr': (('f0b500000000004d09262868f6018019817801318170002000000000071c00000000041c102000000000000000000002204306d02a68012192195170391c0000000028688019817801398170381c00000000f0bc08bc1847',
    (2, 24, 30, 38, 42, 62, 78), (6,), ()), ('f0b5004d09262868f6018019817801318170002000000000071c00000000041c102000000000000000000002204306d02a68012192195170391c0000000028688019817801398170381c00000000f0bc08bc1847',
    (20, 26, 34, 38, 58, 74), (2,), ())), 'chip_wrapper': (('00b50000000008bc1847', (2,), (), ()),), 'install_conditional': (('90b5004f012815d13978002912d138701037787b002803d000480078002801d0004a00e0004a002100200000000090bc08bc18470028fad13878002401280ad100220021002000000000012149050048000000003c700048004904701720c00108184471b92000010818c47184710d2040020818c461dae7',
    (42, 70, 80), (2, 24, 32, 36, 78, 86, 88), (40, 68)),), 'install_sense': (('80b50021002000000000004f002138750020004a00000000387580bc08bc1847', (6, 20), (10,
    18), (4, 16)),), 'sense': (('90b5071c0c1c002801db302f03db002090bc08bc1847000000003a07120f012191403a0918235a43004b9a18012c02d1938a194302e0938ac94319409182918ad2681180002801d1000000000120dfe7',
    (22, 72), (40,), ()),), 'deferred': (('00b50020000000000121490500480000000008bc1847', (4, 14), (12,), ()),), 'parent_init': (('f0b500000000071c0000000000211923004a9b01d418004d6181a982002801d100000000000000000026a6812e83002801d100000000ae8300482880a880002f01d10000000000490020000000000049012000000000002000000000004800000000f0bc08bc1847',
    (2, 8, 32, 36, 50, 66, 74, 82, 88, 94), (16, 22, 56, 70, 78, 92), ()),), 'exception_register': (('004a002801d1d161704711627047', (), (0,), ()), ('004a002801d15160704791607047',
    (), (0,), ()))}
_HASH_SPANS = { 'parent_register': (124, '71cd61ee48d207e5de457801189461b1d48837bc58097089aff5b020572269d8', 0, bytes.fromhex('f0b5041c0f1c'), (6, 34, 114), (14,
    32, 40, 50), ()), 'soc_dispatch': (394, '8adcb3d8d461ad4f94d665e98678c5afa3513029af352321fecec86233131959', 0, bytes.fromhex('f0b586b0'), (4, 52, 148, 186,
    246, 270, 332, 338, 356), (8, 18, 22, 56, 76, 112, 116, 160, 168, 204, 210, 240, 288, 346, 366, 378), ()), 'chip_isr': (84,
    'e5366b0fa510ddf3958c1aa3e0f9238c8ee2133269fb4c10d37906103f6975c0', 4, bytes.fromhex('09266868f60180198178'), (20, 26, 34, 38, 58, 74), (2,), ()), }
_SPANS['install_inline'] = _SPANS.get('install_inline', ()) + (('012000000000071c00210020004a00000000002f03d0', (2, 14), (12,), (10,)),)

def _span(image: bytes, entry: int, role: str) -> dict:
    from . import _HASH_SPANS, _Reject, _SPANS, facts_for, hashlib, struct
    variants = [(bytes.fromhex(encoded), None, len(bytes.fromhex(encoded)), calls, literals, pins) for encoded, calls, literals, pins in _SPANS[role]]
    if role in _HASH_SPANS:
        size, digest, _, _, calls, literals, pins = _HASH_SPANS[role]
        variants.append((None, digest, size, calls, literals, pins))
    for expected, digest, size, calls, literals, pins in variants:
        if entry & 1 or not 0 <= entry <= len(image) - size:
            continue
        body = thumb_body(facts_for(image), entry, size, call_offsets=calls, literal_offsets=literals)
        if body is None or any(target & 1 or not 0 <= target <= len(image)-2 for _, target in body.calls):
            continue
        code = bytearray(body.normalized)
        targets = dict(body.calls)
        values = {offset: value for offset, _, value, _ in body.literals}
        pin_values = {}
        dependencies = [[entry, size]] + [[target, 2] for _, target in body.calls]
        dependencies += [[pool, 4] for _, _, _, pool in body.literals]
        valid = True
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
        # The final state-object store has two observed word offsets.  They
        # differ in one Thumb STR immediate bit; all other operands and the
        # linked callback/registrar checks remain fixed.
        if valid and role == 'install_conditional':
            code[0x74] |= 1 << 7
        if valid and (code == expected if expected is not None else hashlib.sha256(code).hexdigest() == digest):
            return {'entry': entry, 'size': size, 'calls': targets, 'literals': values, 'pins': pin_values, 'dependencies': dependencies}
    raise _Reject(role + '-shape-unmatched')

def _scan(image: bytes, role: str) -> list[dict]:
    from . import _HASH_SPANS, _Reject, _SPANS, _span, re
    entries = set()
    for encoded, calls, literals, pins in _SPANS[role]:
        code = bytes.fromhex(encoded)
        erased = set(literals) | set(pins)
        if role == 'install_conditional':
            erased.add(0x74)
        erased.update(position for offset in calls for position in range(offset, offset + 4))
        pattern = b''.join(b'.' if i in erased else re.escape(bytes([byte])) for i, byte in enumerate(code))
        for match in re.finditer(b'(?=(' + pattern + b'))', image, re.DOTALL):
            if not match.start() & 1:
                entries.add(match.start())
            if len(entries) > 64:
                raise _Reject(role + '-search-limit')
    if role in _HASH_SPANS:
        _, _, anchor_offset, anchor, _, _, _ = _HASH_SPANS[role]
        position = 0
        while (position := image.find(anchor, position)) >= 0:
            entry = position - anchor_offset
            position += 1
            if entry < 0 or entry & 1:
                continue
            try:
                _span(image, entry, role)
            except _Reject:
                continue
            entries.add(entry)
            if len(entries) > 64:
                raise _Reject(role + '-search-limit')
    return [_span(image, entry, role) for entry in sorted(entries)]

def _mapping(layouts: list[tuple], address: int, size: int, data: bool = False) -> tuple:
    from . import _Reject
    matches = [row for row in layouts if row[2] <= address <= (row[2] + row[3] if data else row[4]) - size]
    if len(matches) != 1:
        raise _Reject('scatter-none-or-ambiguous')
    return matches[0]

def _check(condition: bool, reason: str) -> None:
    from . import _Reject
    if not condition:
        raise _Reject(reason)

def _one(spans: list[dict], reason: str) -> dict:
    from . import _check
    _check(len(spans) == 1, reason)
    return spans[0]

def _pointer(image: bytes, pointer: int) -> int:
    from . import _check
    _check(pointer & 1 and 0 <= pointer - 1 <= len(image) - 2, 'function-pointer-unmapped')
    return pointer - 1

def _indirect_call_chain(image: bytes, entry: int) -> dict:
    from . import _Reject, _check, _pointer, struct
    _check(not entry & 1 and 0 <= entry <= len(image) - 2, 'gpio-indirect-call-unmatched')
    if image[entry:entry + 2] == b'\x00\x47':
        return {'profile': 'thumb-bx-r0-v1', 'entry': entry, 'leaf': entry, 'nor_dependencies':[[entry, 2]]}
    # Preserve R0/LR through one closed Thumb-to-ARM literal veneer.
    if (entry & 3 or entry > len(image) - 16 or image[entry:entry + 12] != bytes.fromhex('7847c04600c09fe51cff2fe1')):
        raise _Reject('gpio-indirect-call-unmatched')
    pointer = struct.unpack_from('<I', image, entry + 12)[0]
    leaf = _pointer(image, pointer)
    _check(image[leaf:leaf + 2] == b'\x00\x47', 'gpio-indirect-call-unmatched')
    return {'profile': 'thumb-arm-literal-bx-r0-v1', 'entry': entry, 'leaf': leaf, 'literal': entry + 12, 'nor_dependencies':[[entry, 16],[leaf, 2]]}

def _direct_accessor(image: bytes, literal_load: int, value: int) -> dict | None:
    from . import struct
    register = struct.unpack_from('<H', image, literal_load)[0] >> 8 & 7
    word = struct.unpack_from('<H', image, literal_load + 2)[0]
    opcode = word & 0xF800
    widths = {0x6000: 4, 0x6800: 4, 0x7000: 1, 0x7800: 1, 0x8000: 2, 0x8800: 2}
    if opcode not in widths or word >> 3 & 7 != register:
        return None
    width = widths[opcode]
    return {'address': value + ((word >> 6 & 31) * width), 'width': width, 'accessor': literal_load + 2, 'access': 'read' if word & 0x800 else 'write'}
