"""Source-owned byte-command/halfword-data secondary with an ARM initializer.

Full compiler bodies retain branches, register choices, geometry and stores.
Only literal-load offsets and direct BL displacements are normalized. Runtime
scanout still requires two complete adjacent 96-byte page rows.
"""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.fact_bodies import normalized_body
from msm5xxx_emulator.detection.values import CodeAddress
import hashlib
import re
import struct
from msm5xxx_emulator.detection.arm import arm_b_target
from msm5xxx_emulator.detection.layout_queries import find_overlays

_PROFILES = {'reset': (92, '7b4b4e97534e6b56323e2634e0966523ea83fdd83f451dc810b3716e8b155e72', (), ((0, 4), (8, 14), (12, 14), (24, 4), (32, 14), (36, 14), (52,
    13), (60, 13), (68, 13), (72, 4), (80, 14), (84, 14))), 'copy': (312, 'fa991f3b097e415dfeaae16a82f4e4b42a0daa50ad2c06a79ea0548d5b503f92', (), ((2, 1), (10,
    0), (14, 1), (22, 0), (28, 0), (56, 1), (68, 1), (76, 0), (80, 1), (88, 0), (112, 1), (124, 1), (132, 0), (136, 1), (144, 0), (150, 0), (178, 1), (190, 1),
    (198, 0), (202, 1), (210, 0), (234, 1), (246, 1), (254, 0), (258, 1), (266, 0), (272, 0), (302, 1))), 'setup': (108,
    '453879efd5031db7f0a5b0bfa8e445b5062829265266d08e894ad5c3a9936b17', (48, 58, 68, 98), ((84, 1),)), 'consumer': (162,
    'd0d15e51aa8d9d91d11a993c201092a748c8d07cbda34006979ad1787c4e8a8f', (108,), ((2, 5), (46, 4))), 'binding': (24,
    '059ca30e671f281c8939526cd9fac9a9a694b5ca666756de389125a46b606035', (8, 20), ((0, 3), (2, 1), (12, 3), (14, 1))), 'initializer': (236,
    '19947a342731e5ae1edef36a0337089965fb17ae1098303080742869a2199639', (76, 164), ((20, 2), (32, 2), (44, 2), (60, 1), (80, 0), (88, 0), (104, 2), (116, 2), (128,
    2), (140, 0), (148, 0), (156, 0), (168, 2), (196, 2), (220, 1)))}

def _word(b, p):
    if not 0 <= p <= len(b) - 4:
        raise ValueError()
    return struct.unpack_from('<I', b, p)[0]

def _body(b, p, role):
    n, sha, calls, lits = _PROFILES[role]
    arm = role in ('initializer', 'reset')
    if p < 0 or p % (4 if arm else 2) or p + n > len(b):
        return None
    body = normalized_body(facts_for(b), CodeAddress(p, 'arm' if arm else 'thumb'), n, limit=len(b), thumb_calls=() if arm else calls, thumb_literals=() if arm
        else tuple(offset for offset, _ in lits), arm_literals=tuple(offset for offset, _ in lits) if arm else (), arm_branches=calls if arm else (), call_fill=b'\0\0\0\xeb'
        if arm else struct.pack('<HH', 0xf000, 0xf800))
    if body is None or body.sha256 != sha:
        return None
    edges = dict(body.branches if arm else body.calls)
    if any(target & 1 or not 0 <= target < len(b) for target in edges.values()):
        return None
    lv = {offset: value for offset, _, _, value in body.literals}
    if arm:
        for offset in calls:
            if _word(b, p + offset) >> 0x18 != 0xeb:
                return None
        pools = {offset: pool for offset, _, pool, _ in body.literals}
        for offset, register in lits:
            if _word(b, p + offset) & 0xf7ff000 != 0x51f0000 | register << 0xc:
                return None
            pool = pools[offset]
            if pool & 3 or not 0 <= pool <= len(b) - 4:
                return None
    return edges, lv

def _ram(p, n):
    return 0x1000000 <= p and p + n <= 0x1800000

def find_mixed_page_secondary(b):
    """Require paired bindings, reset-owned relocation, geometry and full consumer."""
    candidates = set()
    for m in re.finditer(re.escape(struct.pack('<HH', 0x1f1a, 0x2000)), b):
        bind = m.start() - 4
        binding = _body(b, bind, 'binding')
        if binding is None:
            continue
        bc, bv = binding
        if (bc[0x8] != bc[0x14] or bv[0] != 0x02800004 or bv[0xc] != 0x02000004 or not _ram(bv[2], 0x4b00) or not _ram(bv[0xe], 0x300)):
            continue
        veneer = bc[0x8]
        if veneer & 3 or b[veneer:veneer + 0x8] != struct.pack('<HHI', 0x4778, 0x46c0, 0xe51ff004):
            continue
        try:
            runtime = _word(b, veneer + 0x8)
        except ValueError:
            continue
        rows = [r for r in find_overlays(b) if r.target <= runtime and runtime + 0xec <= r.target + r.size]
        if len(rows) != 1:
            continue
        row = rows[0]
        if (row.source | row.target | row.size | runtime) & 3:
            continue
        if not _reset_owns_copy(b, row):
            continue
        init = row.source + runtime - row.target
        initial = _body(b, init, 'initializer')
        if initial is None:
            continue
        ic, iv = initial
        g = iv[0x14] - 0x18
        if g & 3 or not _ram(g, 0x2b8):
            continue
        spans = ((bv[2], bv[2] + 0x4b00), (bv[0xe], bv[0xe] + 0x300), (g, g + 0x2b8))
        if any(a < d and c < z for i, (a, z) in enumerate(spans) for c, d in spans[i + 1:]):
            continue
        if not _memset(b, ic[0x4c]):
            continue
        fields = {0x14: 0x18, 0x20: 0x1a, 0x2c: 0x20, 0x3c: 0x2c, 0x50: 8, 0x58: 0xc, 0x68: 0x1c, 0x74: 0x1e, 0x80: 0x82, 0x8c: 0x84, 0x94: 0x10, 0x9c: 0x14,
            0xc4: 0xb5, 0xdc: 0xb6}
        if any((iv[o] != g + d for o, d in fields.items())) or not _ram(iv[0xa8], 0x9ea):
            continue
        thunk = ic[0xa4]
        if thunk & 3 or b[thunk:thunk + 0x8] != struct.pack('<II', 0xe59fc000, 0xe12fff1c):
            continue
        try:
            target = _word(b, thunk + 0x8)
        except ValueError:
            continue
        if not target & 1:
            continue
        setup = target & ~1
        sp = _body(b, setup, 'setup')
        if sp is None:
            continue
        sc, sv = sp
        if (len({sc[o] for o in (0x30, 0x3a, 0x44)}) != 1 or sv[0x54] != g + 0x80 or not callee_at(b, sc[0x30], 'power_delay')):
            continue
        cp = _body(b, sc[0x62], 'consumer')
        if cp is None:
            continue
        cc, cv = cp
        if cv[2] != g + 0x80 or cv[0x2e] != g + 0x80:
            continue
        if b[cc[0x6c]:cc[0x6c] + 0x8] != struct.pack('<4H', 0x2101, 0x649, 0x8088, 0x4770):
            continue
        candidates.add((bind, setup, sc[0x62]))
    return 0x2000000 if len(candidates) == 1 else None

def _reset_owns_copy(b, row):
    """Bind the final scatter-copy stage to the ARM reset call and overlay table."""
    reset = arm_b_target(b, 0)
    if reset is None:
        return False
    rp = _body(b, reset, 'reset')
    if rp is None:
        return False
    _, rv = rp
    returns = ((8, 0x15), (0xc, 0x18), (0x20, 0x2d), (0x24, 0x30), (0x50, 0x5d), (0x54, 0x60))
    if any(rv[o] != reset + d for o, d in returns):
        return False
    if any((not _ram(rv[o] - 0x100, 0x100) for o in (0x34, 0x3c, 0x44))):
        return False
    if any((not rv[o] & 1 or not 0 <= rv[o] - 1 < len(b) for o in (0, 0x18, 0x48))):
        return False
    first, second = rv[0] & ~1, rv[0x18] & ~1
    if b[first:first + 2] != struct.pack('<H', 0x4770) or not _early_init(b, second):
        return False
    cp = _body(b, rv[0x48] & ~1, 'copy')
    if cp is None:
        return False
    _, cv = cp
    gpio_loads = (2, 0x38, 0x44, 0x70, 0x7c, 0xb2, 0xbe, 0xea, 0xf6, 0x12e)
    if any(cv[o] != 0x03000600 for o in gpio_loads):
        return False
    table = cv[0x10a]
    if table != row.table_offset:
        return False
    if (cv[0xfe], cv[0x102], cv[0x110]) != (table + 4, table + 0x8, table + 4):
        return False
    try:
        values = tuple(_word(b, table + o) for o in (0, 4, 8))
        return not table & 3 and values == (row.source, row.target, row.size)
    except ValueError:
        return False

def _memset(b, entry):
    # ARM memset prefix and its external tail branch, through a copied LDR-PC
    # veneer to the complete bulk writer. No guest memory is seeded here.
    if entry & 3 or entry < 0 or entry + 0x4c > len(b):
        return False
    if hashlib.sha256(b[entry:entry + 0x4c]).hexdigest() != ('f842a43850eddef4efe734593ea6d1bbc648babaffa650f1eea91f166801ddf4'):
        return False
    thunk = arm_b_target(b, entry + 0x34)
    if thunk is None or thunk & 3:
        return False
    try:
        if _word(b, thunk) != 0xe51ff004:
            return False
        bulk = _word(b, thunk + 4)
    except ValueError:
        return False
    return (not bulk & 3 and 0 <= bulk <= len(b) - 0x58 and hashlib.sha256(b[bulk:bulk + 0x58]).hexdigest() ==
        'dd4952f77f161aa5da5c77195458577840c427dd09e23131d4716fa8af936e0b')

def _early_init(b, entry):
    # Complete returning GPIO/EBI initialization body before the scatter copier.
    if entry < 0 or entry & 1 or entry + 0x252> len(b):
        return False
    code = bytearray(b[entry:entry + 0x252])
    for offset, register in ((4, 1), (8, 1), (14, 1), (20, 1), (28, 1), (60, 3), (78, 3), (88, 3), (100, 3), (106, 3), (112, 3), (120, 3), (152, 3), (170, 3), (180,
        3), (192, 3), (198, 3), (204, 3), (212, 3), (244, 3), (262, 3), (272, 3), (284, 3), (292, 3), (298, 3), (308, 3), (320, 2), (322, 3), (328, 2), (344, 2),
        (348, 2), (356, 3), (364, 3), (370, 3), (378, 3), (390, 3), (412, 3), (420, 2), (424, 2), (430, 3), (440, 2), (448, 2), (452, 3), (456, 2), (466, 3), (474,
        3), (478, 3), (482, 3), (488, 3), (494, 3), (498, 3), (504, 3), (508, 3), (514, 3), (522, 3), (530, 3), (538, 3), (546, 2), (554, 3), (560, 3), (566, 3),
        (572, 3), (578, 3), (584, 3)):
        value = facts_for(b).thumb_literal_value(entry + offset, register)
        if value is None:
            return False
        code.extend(struct.pack("<I", value))
    return hashlib.sha256(code).hexdigest() == '3643e4a8678090d75aae81934f38d58b0f167861852a28dcb08df3f703e61599'

# Required evidence providers are bound by registry discovery.
REQUIRES = {'callee_at': ('input.scanner_callees', 'callee_at')}
