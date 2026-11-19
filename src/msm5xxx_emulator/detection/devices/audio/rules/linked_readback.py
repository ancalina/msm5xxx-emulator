"""MA3 register verification linked to leaf byte-port accessors."""
from __future__ import annotations

import struct
from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, SymbolicValue, facts_for


SOURCE_CLASS = "linked-byte-port-readback-v1"


def _leaf(image, entry):
    if entry is None or entry & 1 or not 0 <= entry <= len(image) - 2:
        return None
    facts = facts_for(image)
    argument = SymbolicValue.arg(0)
    region = facts.function(CodeAddress(entry), budget=64, stop_at_initial_return=True,
        symbolic_registers={a.ARM_REG_R0: argument})
    if not region.complete or region.calls or region.back_edges or not region.instructions:
        return None
    for pc in region.instructions:
        ins = facts.decode(pc)
        if (ins is None or ins.size != 2 or ins.writeback
                or ins.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)):
            return None
    ports = [access for access in region.accesses if 0x02000000 <= access.address < 0x03000000]
    if len(ports) != 1 or ports[0].width != 1:
        return None
    port = ports[0]
    symbolic = [access for access in region.symbolic_accesses if access.instruction == port.instruction]
    if len(symbolic) != 1:
        return None
    if port.operation == "write":
        if symbolic[0].value != argument:
            return None
    else:
        value = facts.register_value(region, region.instructions[-1], a.ARM_REG_R0)
        if (value is None or value.kind != "load" or value.site != port.instruction
                or value.width != 1 or value.signed):
            return None
    dependencies = {(pc.address, facts.decode(pc).size) for pc in region.instructions}
    dependencies.update((literal.pool, 4) for literal in region.literals)
    pools = {literal.pool for literal in region.literals}
    ram = set()
    for access in region.accesses:
        if access is port or access.address in pools:
            continue
        if not 0x01000000 <= access.address <= 0x02000000 - access.width or access.width != 1:
            return None
        ram.add((access.address, access.width))
    return {"entry": entry, "address": port.address, "kind": port.operation,
        "site": port.instruction.address, "nor": dependencies, "ram": ram}


def find_linked_ma3_readback(image):
    from .ma3 import _thumb_readback_verifiers
    from .ma5 import _thumb_bl_targets
    facts = facts_for(image)
    found = []
    for verifier, reader in _thumb_readback_verifiers(image):
        if not 0 <= reader <= len(image) - 0xc8:
            continue
        word = lambda off: struct.unpack_from("<H", image, reader + off)[0]
        if tuple(word(off) for off in (0, 2, 4, 6, 0xc, 0x14, 0x16, 0x18)) != (
                0xb5f8, 0x1c07, 0x1c0d, 0x2003, 0x2f80, 0x2301, 0x039b, 0x429f):
            continue
        entries = {"write_0": facts.thumb_call_target(reader + 8),
                   "write_2": facts.thumb_call_target(reader + 0x84),
                   "read_2": facts.thumb_call_target(reader + 0xc4)}
        leaves = {name: _leaf(image, entry) for name, entry in entries.items()}
        if any(leaf is None for leaf in leaves.values()):
            continue
        base = leaves["write_0"]["address"]
        if (not 0x02001000 <= base <= 0x02ffff00
                or leaves["write_0"]["kind"] != "write"
                or leaves["write_2"]["kind"] != "write"
                or leaves["read_2"]["kind"] != "read"
                or any(leaves[name]["address"] != base + 2 for name in ("write_2", "read_2"))):
            continue
        calls = set(_thumb_bl_targets(image, reader, 0xc8))
        if not set(entries.values()) <= calls:
            continue
        pollers = calls - set(entries.values())
        if len(pollers) != 2 or any(target is None or not 0 <= target <= len(image) - 0x90 for target in pollers):
            continue
        statuses = []
        for poller in sorted(pollers):
            candidates = [_leaf(image, target) for target in set(_thumb_bl_targets(image, poller, 0x50))]
            candidates = [leaf for leaf in candidates if leaf is not None and leaf["kind"] == "read" and leaf["address"] == base]
            if len(candidates) != 1:
                break
            statuses.append(candidates[0])
        if len(statuses) != 2 or statuses[0]["entry"] != statuses[1]["entry"]:
            continue
        leaves["read_0"] = statuses[0]
        if len({leaf["entry"] for leaf in leaves.values()}) != 4:
            continue
        nor = {(verifier, 90), (reader, 0xc8), *((poller, 0x90) for poller in pollers)}
        ram = set()
        for leaf in leaves.values():
            nor.update(leaf["nor"]); ram.update(leaf["ram"])
        found.append({"family": "ma3", "grammar": "ma3-readback-v1",
            "static_status": "accepted", "reject_reason": None,
            "source_class": SOURCE_CLASS, "base": base, "data_offset": 2,
            "verifier_entry": verifier, "register_reader": reader,
            "status_pollers": sorted(pollers),
            "sites": {name: [leaf["site"]] for name, leaf in leaves.items()},
            "block_write_offsets": [], "nor_dependencies": sorted(nor), "ram_dependencies": sorted(ram),
            "register_readback": [[0x90, 0xa0, 0x60], [0xa0, 0xb0, 0x3c], [0x14a, 0x152, 0x40]]})
    return found[0] if len(found) == 1 else None
