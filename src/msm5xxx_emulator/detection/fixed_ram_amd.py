"""Uniform AMD EFS bank selected by a copied fixed descriptor constructor."""

import struct, hashlib, re
from .arm import thumb_literal_value, thumb_bl_target
from .watchdog import _shape
from .memory_layout import find_linker_layout

_CONTRACTS = {
    "init": [
        20,
        "ebb86ee8cd33b26543f96d90a37f53d4abcd222dcce6367a355bfc6a1648ec54",
        [[0, 1], [4, 2]],
    ],
    "read": [
        88,
        "29285ca067a051a194d541a3c0a64258063b587f9b8dd0e4e930bf2abcb348a6",
        [[8, 1], [28, 1], [50, 0], [52, 1]],
    ],
    "program": [
        458,
        "c10b104a56301fb560b77d31476627bc0d3014774c2f84e819b7b9185c3ddcd3",
        [
            [8, 2],
            [24, 3],
            [84, 3],
            [114, 0],
            [124, 3],
            [162, 1],
            [164, 0],
            [174, 1],
            [204, 2],
            [278, 2],
            [308, 0],
            [318, 3],
            [358, 0],
            [360, 1],
            [372, 1],
            [402, 2],
            [444, 1],
            [446, 0],
        ],
    ],
    "erase": [
        110,
        "35b9bc7853f24f18970eb748ba97f3c2c368d81b818d3ec8d3ad0d1cfcd46843",
        [[2, 4], [8, 5], [32, 0], [38, 0], [62, 1], [64, 0], [78, 1], [90, 0]],
    ],
    "poll": [
        22,
        "9042b847a06781d2e34f7479c5864090b94736bb94bc828cd07dfed5c8b1b356",
        [[0, 1], [6, 0]],
    ],
    "suspend": [
        54,
        "a1d556167677ed384925a41d907018e45191bc3b04b42fd2f2055406580e3af4",
        [[4, 5], [16, 1], [18, 0]],
    ],
    "resume": [
        48,
        "dbaa881face7f608f190048d0f74500544af9b85b3071eb0ab9a629b13046b26",
        [[4, 5], [16, 1], [18, 0]],
    ],
    "poll_leaf": [
        110,
        "9edfa9ea40c321a99e553ef0b3cde3fd7872fb15cd3d00581a6d81ee90c8d0c2",
        [[14, 1], [16, 0], [30, 2], [44, 2]],
    ],
    "erase_leaf": [
        170,
        "70bd365ae14ab0d6c57cf8eba9088ad91fff2617486727e384336d44ab2a619b",
        [[14, 5], [44, 0], [54, 6], [100, 1]],
    ],
}


def _match_body(image, entry, role, bound):
    size, digest, literals = _CONTRACTS[role]
    if entry is None or entry & 1 or not 0 <= entry <= bound - size:
        return False
    payload = bytearray(image[entry : entry + size])
    for offset, register in literals:
        pc = entry + offset
        pool = ((pc + 4) & ~3) + image[pc] * 4
        value = thumb_literal_value(image, pc, register)
        if value is None or not 0 <= pool <= bound - 4:
            return False
        payload.extend(struct.pack("<I", value))
    return hashlib.sha256(payload).hexdigest() == digest


def find_fixed_ram_amd_profile(
    image: bytes, flash_size: int, ram_base: int, ram_size: int
) -> dict | None:
    if not 0 < flash_size <= ram_base < ram_base + ram_size <= 0x02000000:
        return None
    bound = min(len(image), 0xC00000)
    candidates = []
    for m in re.finditer(re.escape(struct.pack("<2H", 0x6008, 0x6010)), image[:bound]):
        init = m.start() - 6
        shape = _shape(
            image,
            init,
            20,
            {
                2: 0x2000,
                6: 0x6008,
                8: 0x6010,
                10: 0x1D10,
                12: 0x6010,
                14: 0x2000,
                16: 0x7108,
                18: 0x4770,
            },
            {0: 1, 4: 2},
            (),
        )
        if shape is None or not _match_body(image, init, "init", bound):
            continue
        global_base, active = shape[0][0], shape[0][4]
        if not (
            ram_base <= global_base <= ram_base + ram_size - 8
            and ram_base <= active <= ram_base + ram_size - 0x154
        ):
            continue
        layout = find_linker_layout(image, required_span=(active + 4, 0x150))
        if layout is None:
            continue
        descriptor = layout.data_source + active + 4 - layout.data_target
        if not 0 <= descriptor <= bound - 0x150:
            continue
        name, count = struct.unpack_from("<2I", image, descriptor)
        sectors = struct.unpack_from("<71I", image, descriptor + 8)
        ident, reserved, banks, base, size, *methods = struct.unpack_from(
            "<11I", image, descriptor + 0x124
        )
        if (
            count != 63
            or sectors[:count] != (0x10000,) * count
            or any(sectors[count:])
            or ident != 0x009C0098
            or reserved
            or banks != 1
            or base != 0xC00000
            or size != 0x3F0000
            or base + size > flash_size
            or not 0 < name < bound - 64
            or image.find(b"\0", name, name + 64) < name + 4
            or len(set(methods)) != 6
            or any(not x & 1 for x in methods)
        ):
            continue
        # This descriptor uses byte base/size, unlike the related39-slot word map.
        addresses = dict(
            zip(
                ("read", "program", "erase", "poll", "suspend", "resume"),
                (x - 1 for x in methods),
            )
        )
        addresses.update(
            init=init,
            erase_leaf=thumb_bl_target(image, addresses["erase"] + 0x4A),
            poll_leaf=thumb_bl_target(image, addresses["program"] + 0x9A),
        )
        if any(not _match_body(image, a, role, bound) for role, a in addresses.items()):
            continue
        if (
            thumb_literal_value(image, addresses["read"] + 8, 1) != active
            or thumb_literal_value(image, addresses["read"] + 0x1C, 1) != global_base
        ):
            continue
        callers = []
        at = 0
        while (at := image.find(struct.pack("<H", 0xB580), at, bound)) >= 0:
            caller = at
            at += 1
            if not caller & 1 and thumb_bl_target(image, caller + 2) == init:
                callers.append(caller)
        if len(callers) != 1:
            continue
        candidates.append(
            dict(
                signature="fixed-ram71-amd-efs-v1",
                base=base,
                size=size,
                sector_size=0x10000,
                id0=0x98,
                id1=0x9C,
                constructor=init,
                descriptor=descriptor,
                active=active,
                base_global=global_base,
                boot_initializer=callers[0],
                methods=tuple(methods),
            )
        )
    return candidates[0] if len(candidates) == 1 else None
