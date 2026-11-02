"""Selected Intel-command EFS partitions with explicit Sharp PCR setup.

Compiler contracts cover each complete selected driver body. Geometry comes
from the selected descriptor and its relocated singleton table, rather than a
model name or an assumed whole-chip capacity. Captured EFS bytes stay intact.
"""

from __future__ import annotations

import re
import struct
import hashlib

from .arm import thumb_bl_target, thumb_literal_value
from .memory_layout import find_linker_layout
from .source_body import match_thumb_contract as _body

def _irq_veneer(image: bytes, entry: int, restore: bool, depth: int = 0) -> bool:
    if depth > 1 or entry & 3 or not 0 <= entry <= len(image) - 24:
        return False
    prefix, padding, *arm = struct.unpack_from('<HH5I', image, entry)
    if (prefix == 0x4778 and padding == 0x46C0
            and arm[:2] == [0xE59FC000, 0xE12FFF1C] and arm[2] & 1):
        return _irq_veneer(image, arm[2] & ~1, restore, depth + 1)
    return (prefix == 0x4778 and padding == 0 and arm == [
        0xE10F0000, 0xE3C010C0 if restore else 0xE38010C0,
        0xE121F001, 0xE20000C0, 0xE12FFF1E,
    ])



# Two compiler/control-flow classes; only BL and declared literal displacements
# are normalized. Every decoded target and global is checked below.
_FAMILIES = (
    {
        "initializer": {
            "size": 0x2E,
            "sha256": "ccf4c743ec00e6254aa9aff115f12be65fdac945940532dfec978b5da760f70f",
            "calls": (12, 22, 32),
            "literals": {2: 7, 4: 4, 30: 1},
        },
        "probe": {
            "size": 0xA6,
            "sha256": "bcbb5e23e233b924c84fbf1724d51267975010171d3ffde020f9f7fb67947645",
            "calls": (100, 126, 130, 154),
            "literals": {12: 7, 104: 4, 40: 5, 42: 1},
        },
        "read": {
            "size": 0x36,
            "sha256": "67df9b082f0a11372cb45cd65cbd54d8d88bfafd17f75b289685d0b9e69c861a",
            "calls": (46,),
            "literals": {0: 3, 20: 7},
        },
        "program": {
            "size": 0x120,
            "sha256": "88df1bb16897b949232bee073a3e8fcaf8d69932c4d658548fed0cd364f7bf74",
            "calls": (40, 66, 254, 280),
            "literals": {2: 6, 26: 0, 44: 2, 72: 1, 258: 2},
        },
        "erase": {
            "size": 0x76,
            "sha256": "40955fa2433093b2a10a55972b196150d0fe2ce8492d4860a22adfdb165878a3",
            "calls": (28, 38, 42, 68),
            "literals": {2: 4, 46: 2, 72: 0, 84: 1, 88: 1, 36: 1},
        },
        "poll": {
            "size": 0x5A,
            "sha256": "22799d334bdf02d967fac573421e66cd34170d10c5d6af982ae55370f090bb0d",
            "calls": (52, 78),
            "literals": {2: 0, 4: 1, 56: 1, 46: 1},
        },
        "suspend": {
            "size": 0x4E,
            "sha256": "448576bf6b767bc64723fcb7895a598356e4fe1862594eb8107064354271bcd8",
            "calls": (),
            "literals": {0: 0, 4: 1, 38: 7},
        },
        "resume": {
            "size": 0x1A,
            "sha256": "56b31ec84bf1662652609be60ce55283e777078f07e9bd77a7ebb00e9a258337",
            "calls": (),
            "literals": {0: 0, 2: 1, 16: 1},
        },
    },
    {
        "initializer": {
            "size": 0x2E,
            "sha256": "ccf4c743ec00e6254aa9aff115f12be65fdac945940532dfec978b5da760f70f",
            "calls": (12, 22, 32),
            "literals": {2: 7, 4: 4, 30: 1},
        },
        "probe": {
            "size": 0xA6,
            "sha256": "40a00cf125650581baa3e1219f7e110570bb081fa784657dc9aa2e9196565df6",
            "calls": (100, 126, 130, 154),
            "literals": {12: 7, 104: 4, 40: 6, 42: 1},
        },
        "read": {
            "size": 0x36,
            "sha256": "67df9b082f0a11372cb45cd65cbd54d8d88bfafd17f75b289685d0b9e69c861a",
            "calls": (46,),
            "literals": {0: 3, 20: 7},
        },
        "program": {
            "size": 0x124,
            "sha256": "7b3f87f18135e1aafef43a320a19af74d3c41093bc96ac4bda47ddf7086dbe60",
            "calls": (40, 66, 258, 284),
            "literals": {2: 6, 26: 0, 44: 2, 72: 1, 262: 2},
        },
        "erase": {
            "size": 0x76,
            "sha256": "d16f6f7480fd53b39fc74c01a18ce7b677d3fdd4f1ba53b3a742796a5feda4df",
            "calls": (28, 38, 42, 68),
            "literals": {2: 4, 46: 2, 72: 0, 84: 1, 88: 1, 36: 1},
        },
        "poll": {
            "size": 0x5A,
            "sha256": "93d31dbc6372b972a561ae02fe67a07c057ed66537913a417afdab73abfe3582",
            "calls": (52, 78),
            "literals": {2: 0, 4: 1, 56: 1, 46: 1},
        },
        "suspend": {
            "size": 0x50,
            "sha256": "04b53a14308778472fc88673a91c6d963f6ad62779d18466e50dd2553b4e40ef",
            "calls": (),
            "literals": {0: 0, 4: 1, 40: 7},
        },
        "resume": {
            "size": 0x1A,
            "sha256": "56b31ec84bf1662652609be60ce55283e777078f07e9bd77a7ebb00e9a258337",
            "calls": (),
            "literals": {0: 0, 2: 1, 16: 1},
        },
    },
)


def _memcpy(image, p, bound):
    if p & 3 or not 0 <= p <= min(len(image), bound) - 0xA4:
        return False
    a, b, c, branch = struct.unpack_from("<4I", image, p)
    if (a, b, c) != (
        0x4778,
        0xE0403001,
        0xE1530002,
    ) or branch & 0xFF000000 != 0x2A000000:
        return False
    immediate = branch & 0xFFFFFF
    if immediate & 0x800000:
        immediate -= 1 << 24
    target = p + 0x14 + (immediate << 2)
    if target is None or not 0 <= target <= min(len(image), bound) - 0x124:
        return False
    # Full active reverse-copy CFG; the gap54.. is a separate alignment path.
    data = bytearray(0xA4)
    data[:0x44] = image[p : p + 0x44]
    data[0x54:] = image[p + 0x54 : p + 0xA4]
    struct.pack_into("<I", data, 0xC, branch & 0xFF000000)
    return (
        hashlib.sha256(data).hexdigest()
        == "600640f7089445ba119797686b8fbc8d31419342c1ae7d936ac82dec92c12437"
        and target <= min(len(image), bound) - 0x124
        and hashlib.sha256(image[target : target + 0x124]).hexdigest()
        == "d23861ffa04d410138ac1c45b3b52de6bd924bc490cd783ed4e90f1362f14ad8"
    )


_ERROR_HASHES = {
    "31ccde460b0bb143b51f4c3887a08d7c35d8da4c877e932781693bc6bdc0deeb",
    "5884e25bc3ff16cd4298fdfd820934a76f7e37962b827b1e069ed87e13eaf0b8",
    "e2fd4ef1aaaa7580c7388e118c9f198e67475a43298fcf21753c4f4572d7236a",
}


def _error_sink(image, p, bound):
    if p & 1 or not 0 <= p <= min(len(image), bound) - 156:
        return False
    values = []
    for off, reg in ((14, 1), (20, 1), (26, 0), (48, 5), (122, 4), (130, 0)):
        word = struct.unpack_from("<H", image, p + off)[0]
        pool = ((p + off + 4) & ~3) + (word & 255) * 4
        value = thumb_literal_value(image, p + off, reg)
        if value is None or not 0 <= pool <= bound - 4:
            return False
        values.append(value)
    if any(
        (target := thumb_bl_target(image, p + off)) is None
        or not 0 <= target < min(len(image), bound) - 2
        for off in (6, 10, 40, 84, 118, 132, 146)
    ):
        return False
    return (
        hashlib.sha256(image[p : p + 156] + struct.pack("<6I", *values)).hexdigest()
        in _ERROR_HASHES
    )


def find_sharp_intel_profile(
    image: bytes, flash_size: int, ram_base: int, ram_size: int
) -> dict | None:
    if not 0 < len(image) <= flash_size <= ram_base < ram_base + ram_size <= 0x2000000:
        return None
    ram_end = ram_base + ram_size

    def ram(p, n):
        return type(p) is int and ram_base <= p <= ram_end - n

    out = []
    for m in re.finditer(re.escape(struct.pack("<H", 0xB590)), image):
        init = m.start()
        root = _body(image, init, _FAMILIES[0]["initializer"], flash_size)
        if root is None:
            continue
        base_global, active = root["literals"][2], root["literals"][4]
        if (
            not ram(base_global, 12)
            or base_global & 3
            or not ram(active, 4)
            or active & 3
        ):
            continue
        probe = root["calls"][0xC]
        for family in _FAMILIES:
            pc = _body(image, probe, family["probe"], flash_size)
            if pc is None:
                continue
            pv = pc["literals"]
            table, view = pv[0xC], pv[0x2A]
            desc = view - 0x80
            if (
                pv[0x28] != base_global
                or not ram(table, 8)
                or table & 3
                or desc & 3
                or not 0 <= desc <= min(len(image), flash_size) - 0xD4
            ):
                continue
            name, count = struct.unpack_from("<2I", image, desc)
            sectors = struct.unpack_from("<39I", image, desc + 8)
            ident, reserved, banks, words, size_words, *methods = struct.unpack_from(
                "<11I", image, desc + 0xA4
            )
            base, size = words * 2, size_words * 2
            if (
                count != 32
                or sectors[:32] != (0x10000,) * 32
                or any(sectors[32:])
                or reserved
                or banks != 1
                or ident != 0x00B100B0
                or sum(sectors) != size
                or not 0 < base < base + size == flash_size
                or name != desc + 0xD0
                or image.find(b"\0", name, min(name + 64, len(image))) < name + 4
                or any(not p & 1 for p in methods)
            ):
                continue
            layout = find_linker_layout(image, required_span=(table, 8))
            if (
                layout is None
                or layout.data_source + layout.data_size > base
                or not ram(layout.data_target, layout.data_size)
                or not ram(layout.bss_target, layout.bss_size)
                or not layout.data_target
                <= active
                <= layout.bss_target + layout.bss_size - 4
                or not layout.bss_target
                <= base_global
                <= layout.bss_target + layout.bss_size - 12
            ):
                continue
            t = layout.data_source + table - layout.data_target
            if struct.unpack_from("<2I", image, t) != (desc, 0):
                continue
            bodies = {"initializer": root, "probe": pc}
            bad = False
            for role, p in zip(
                ("read", "program", "erase", "poll", "suspend", "resume"), methods
            ):
                bc = _body(image, p & ~1, family[role], base)
                if bc is None:
                    bad = True
                    break
                bodies[role] = bc
            if (
                bad
                or any(p[1] > base for p in (root["code"], pc["code"]))
                or any(
                    end > base for end in [p[1] for p in (*root["pools"], *pc["pools"])]
                )
                or desc + 0x110 > base
            ):
                continue
            irq_save, irq_restore = pc["calls"][0x64], pc["calls"][0x7E]
            if (
                pc["calls"][0x82] != irq_save
                or pc["calls"][0x9A] != irq_restore
                or any(
                    p & 3
                    or not 0 <= p <= base - 24
                    or struct.unpack_from("<I", image, p)[0] != 0x4778
                    for p in (irq_save, irq_restore)
                )
                or not _irq_veneer(image, irq_save, False)
                or not _irq_veneer(image, irq_restore, True)
            ):
                continue
            shadow = pv[0x68]
            if not ram(shadow, 0x22) or shadow & 1:
                continue
            state = (
                (base_global, base_global + 12),
                (active, active + 4),
                (table, table + 8),
                (shadow, shadow + 0x22),
            )
            if any(
                a < d and c < b
                for i, (a, b) in enumerate(state)
                for c, d in state[i + 1 :]
            ):
                continue
            expected = {
                "read": {0: active, 0x14: base_global},
                "program": {
                    2: active,
                    0x1A: base_global + 4,
                    0x2C: shadow,
                    0x48: base_global,
                },
                "erase": {
                    2: base_global + 4,
                    0x2E: shadow,
                    0x48: active,
                    0x54: base_global + 8,
                    0x58: base_global,
                },
                "poll": {
                    2: base_global + 8,
                    4: base_global,
                    0x38: shadow,
                    0x2E: base_global + 4,
                },
                "suspend": {0: base_global + 8, 4: base_global},
                "resume": {0: base_global + 8, 2: base_global, 0x10: base_global + 4},
            }
            for role, values in expected.items():
                if any(bodies[role]["literals"].get(k) != v for k, v in values.items()):
                    bad = True
            program_end = 0x102 if family["program"]["size"] == 0x120 else 0x106
            suspend_state = 0x26 if family["suspend"]["size"] == 0x4E else 0x28
            if (
                bodies["program"]["literals"][program_end] != shadow
                or bodies["suspend"]["literals"][suspend_state] != base_global + 4
            ):
                continue
            for role, lockoffs, restoreoffs in [
                ("program", (0x28, program_end - 4), (0x42, program_end + 0x16)),
                ("erase", (0x2A,), (0x44,)),
                ("poll", (0x34,), (0x4E,)),
            ]:
                c = bodies[role]["calls"]
                if any(c[k] != irq_save for k in lockoffs) or any(
                    c[k] != irq_restore for k in restoreoffs
                ):
                    bad = True
            if (
                bad
                or bodies["erase"]["calls"][0x1C] != root["calls"][0x16]
                or bodies["erase"]["calls"][0x26] != root["calls"][0x20]
                or not _memcpy(image, bodies["read"]["calls"][0x2E], base)
                or not _error_sink(image, root["calls"][0x20], base)
            ):
                continue
            prep = root["calls"][0x16]
            if (
                prep & 3
                or not 0 <= prep <= base - 12
                or image[prep : prep + 12]
                != struct.pack("<3I", 0x4778, 0xE02AA00A, 0xE12FFF1E)
            ):
                continue
            if any(
                not 0 <= p < base - 4 or image.find(b"\0", p, min(p + 80, base)) < p + 4
                for p in (root["literals"][0x1E], bodies["erase"]["literals"][0x24])
            ):
                continue
            # Executable bodies, pools and descriptors have disjoint storage owners.
            code = [v["code"] for v in bodies.values()]
            pools = {span for v in bodies.values() for span in v["pools"]}
            if any(
                a < d and c < b
                for i, (a, b) in enumerate(code)
                for c, d in code[i + 1 :]
            ):
                continue
            if any(
                a < d and c < b
                for a, b in code
                for c, d in [*pools, (desc, name + 64), (t, t + 8)]
            ):
                continue
            out.append(
                dict(
                    signature="sharp-pcr-selected-efs-partition-v1",
                    geometry=(base, size, 0x10000, 0xB0, 0xB1),
                    initializer=init,
                    probe=probe,
                    descriptor=desc,
                    table_source=t,
                    table_runtime=table,
                    base_global=base_global,
                    active_global=active,
                    shadow=shadow,
                    methods=tuple(methods),
                    pcr_setup_word=0x400,
                    memcpy_address=bodies["read"]["calls"][0x2E],
                    error_sink_address=root["calls"][0x20],
                    irq_save=irq_save,
                    irq_restore=irq_restore,
                )
            )
    return out[0] if len(out) == 1 else None
