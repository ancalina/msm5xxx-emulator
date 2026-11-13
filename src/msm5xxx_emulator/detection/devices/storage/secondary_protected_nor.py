"""Source evidence for table-described secondary x16 NOR windows."""
from __future__ import annotations

import struct

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.values import SymbolicValue

from . import secondary_protected_protocol
from .secondary_protected_prefix import prefix_consumers as _prefix_consumers

_ID_WIDTH_OFFSET = 0xAC
_BEGIN_OFFSET = 0xB0
_BOUND_OFFSET = 0xB4
_CALLBACK_OFFSETS = (0xB8, 0xBC, 0xC0, 0xC4, 0xC8, 0xCC)
_OBJECT_SIZE = 0xD0
_TABLE_LIMIT = 0xB0
_MIN_BEGIN = 0x01000000


def _u32(image: bytes, at: int) -> int:
    return struct.unpack_from("<I", image, at)[0]


def _object_geometry(image: bytes, at: int) -> dict | None:
    """Read and validate the fixed descriptor fields without trusting names."""
    if at < 0 or at & 3 or at + _OBJECT_SIZE > len(image):
        return None
    count = _u32(image, at + 4)
    if not 1 <= count <= 64 or 8 + count * 4 > _TABLE_LIMIT:
        return None
    sectors = tuple(_u32(image, at + 8 + index * 4) for index in range(count))
    if any(size == 0 or size & 1 for size in sectors):
        return None
    if _u32(image, at + _ID_WIDTH_OFFSET) != 2:
        return None
    begin = _u32(image, at + _BEGIN_OFFSET) * 2
    bound = _u32(image, at + _BOUND_OFFSET) * 2
    extent = sum(sectors)
    if begin < _MIN_BEGIN or bound < extent or begin + extent > 0x100000000:
        return None
    callbacks = tuple(_u32(image, at + off) for off in _CALLBACK_OFFSETS)
    if any(not (pointer & 1) or (pointer & ~1) >= len(image) for pointer in callbacks):
        return None
    if len(set(callbacks)) != len(callbacks):
        return None
    return {
        "object": at,
        "sector_count": count,
        "sector_sizes": sectors,
        "begin": begin,
        "max_bound": bound,
        "extent": extent,
        "callbacks": callbacks,
    }


def _sector_count_callers(facts, prefix_entry: int) -> tuple[dict, ...]:
    """Find complete callers that invoke a sector-count getter and loop."""
    prefix_calls = {site for site, target in facts.call_candidates(isa="thumb")
                    if target == prefix_entry}
    found = []
    for site in sorted(prefix_calls):
        # Function discovery is bounded to the conventional nearby Thumb
        # prologue, but ownership is confirmed by the shared function query.
        for delta in range(2, 0x81, 2):
            entry = site - delta
            ins = facts.decode(CodeAddress(entry, "thumb"))
            if ins is None or ins.mnemonic != "push" or "lr" not in ins.op_str:
                continue
            fn = facts.function(CodeAddress(entry, "thumb"), budget=512,
                                symbolic_registers={})
            if not fn.complete or not fn.back_edges or site not in {i.address for i in fn.instructions}:
                continue
            calls = [(call_site.address, target.address) for call_site, target in fn.calls]
            if not any(call_site == site and target == prefix_entry for call_site, target in calls):
                continue
            getters = [target for call_site, target in calls if call_site < site]
            if not getters:
                continue
            found.append({"entry": entry, "count_getter": getters[-1],
                          "prefix_call": site, "loop_end": fn.instructions[-1].address + 2,
                          "function_interval": (fn.entry.address,
                                            fn.instructions[-1].address + 2)})
            break
    return tuple(found)


def _callback_protocols(facts, callbacks: tuple[int, ...]) -> dict | None:
    """Require bounded shared-function evidence for x16 command sequences."""
    bodies = {}
    for pointer in callbacks:
        entry = pointer & ~1
        body = facts.function(CodeAddress(entry, "thumb"), budget=2048,
                              symbolic_registers={})
        if not body.complete:
            return None
        bodies[pointer] = body

    def decoded(body):
        return [facts.decode(CodeAddress(item.address, "thumb"))
                for item in body.instructions]

    def immediates(instructions):
        values = set()
        for ins in instructions:
            for operand in ins.operands:
                if operand.type == 2:
                    values.add(operand.imm & 0xFFFFFFFF)
        return values

    program_body, erase_body, poll_body = (bodies[callbacks[index]] for index in (1, 2, 3))
    program, erase, poll = map(decoded, (program_body, erase_body, poll_body))
    if not ({0x40, 0x41, 0x80} <= immediates(program) and
            any(ins.mnemonic == "strh" for ins in program)):
        return None
    if not ({0x20, 0xD0} <= immediates(erase) and
            any(ins.mnemonic == "strh" for ins in erase)):
        return None
    if not ({0x70, 0x50, 0xFF} <= immediates(poll) and
            any(ins.mnemonic == "ldrh" for ins in poll)):
        return None
    program_targets = {target.address & ~1 for _, target in program_body.calls}
    erase_targets = {target.address & ~1 for _, target in erase_body.calls}
    shared = program_targets & erase_targets
    helpers = []
    for target in shared:
        helper = facts.function(CodeAddress(target, "thumb"), budget=512,
                                symbolic_registers={})
        if not helper.complete:
            continue
        ins = decoded(helper)
        vals = immediates(ins)
        sector_masks = vals & {0x3F, 0x7F}
        if ({0x60, 0xAC, 0x7B} <= vals and sector_masks and
                any(item.mnemonic == "ands" for item in ins) and
                any(item.mnemonic == "bics" for item in ins) and
                sum(item.mnemonic == "strh" for item in ins) >= 4):
            ordered = []
            for value in (0x60, 0xAC, 0x7B):
                sites = [item.address for item in ins if any(
                    operand.type == 2 and operand.imm & 0xFFFFFFFF == value
                    for operand in item.operands)]
                if not sites:
                    break
                ordered.append(min(sites))
            if len(ordered) == 3 and ordered == sorted(ordered):
                helpers.append((helper, sector_masks))
    if len(helpers) != 1:
        return None
    helper, sector_masks = helpers[0]
    return {"command_helper": (helper.entry.address, helper.instructions[-1].address + 2),
            "program": (program_body.entry.address, program_body.instructions[-1].address + 2),
            "erase": (erase_body.entry.address, erase_body.instructions[-1].address + 2),
            "poll": (poll_body.entry.address, poll_body.instructions[-1].address + 2),
            "_sector_masks": sector_masks}


def _owners_for_literals(facts, values: tuple[int, ...]) -> tuple:
    """Resolve literal references to complete containing Thumb functions."""
    entries = {}
    for value in values:
        for literal in facts.literal_references(value):
            site = literal.instruction.address
            owners = []
            for delta in range(0, 0x82, 2):
                entry = site - delta
                ins = facts.decode(CodeAddress(entry, "thumb"))
                if ins is None or ins.mnemonic != "push" or "lr" not in ins.op_str:
                    continue
                body = facts.function(CodeAddress(entry, "thumb"), budget=1024,
                                      symbolic_registers={})
                if body.complete and any(item.address == site for item in body.instructions):
                    owners.append(body)
                    break
            if owners:
                entries[owners[0].entry.address] = owners[0]
            else:
                direct = facts.function(CodeAddress(site, "thumb"), budget=1024,
                                        symbolic_registers={})
                if direct.complete and any(item.address == site for item in direct.instructions):
                    entries[site] = direct
    return tuple(entries.values())


def _owners_for_sites(facts, sites):
    entries = {}
    for site in sites:
        for delta in range(0, 0x82, 2):
            entry = site - delta
            ins = facts.decode(CodeAddress(entry, "thumb"))
            if ins is None or ins.mnemonic != "push" or "lr" not in ins.op_str:
                continue
            body = facts.function(CodeAddress(entry, "thumb"), budget=1024,
                                  symbolic_registers={})
            if body.complete and any(item.address == site for item in body.instructions):
                entries[entry] = body
                break
    return tuple(entries.values())


def _constant(value):
    return value.value if isinstance(value, SymbolicValue) and value.kind == "const" else None


def _linked_lifecycle(facts, geometry, global_address, count_caller):
    """Close descriptor selection and the sector-count publication chain."""
    object_address = geometry["object"]
    all_refs = _owners_for_literals(facts, (global_address, object_address + 0x80))
    selectors = []
    for body in all_refs:
        literals = {item.value for item in body.literals}
        if not {global_address, object_address + 0x80} <= literals:
            continue
        has_template = any(0x14000000 <= value < 0x15000000 for value in literals)
        has_bus_write = any(access.operation == "write" and access.width == 2 and
                            _constant(access.value) == 0xFF and
                            isinstance(access.address, SymbolicValue) and
                            access.address.kind == "op" and
                            any(child.kind == "load" and child.operands and
                                _constant(child.operands[0]) == global_address + 8
                                for child in access.address.operands)
                            for access in body.symbolic_accesses)
        if has_template and has_bus_write:
            selectors.append(body)
    if not selectors:
        return None
    # A literal can be the first instruction of a function whose entry is a
    # couple of bytes earlier; merge overlapping complete views of that body.
    selectors.sort(key=lambda body: body.entry.address)
    selector = selectors[0]
    if any(body.entry.address - selector.entry.address > 0x10 for body in selectors[1:]):
        return None
    selector_target = selector.entry.address

    constructors = []
    for body in _owners_for_literals(facts, (global_address,)):
        writes = {(access.address.value, access.width, _constant(access.value))
                  for access in body.symbolic_accesses
                  if access.operation == "write" and isinstance(access.address, SymbolicValue)
                  and access.address.kind == "const"}
        targets = [target.address for _, target in body.calls]
        if ({(global_address + 8, 4, 0), (global_address + 4, 4, 0),
             (global_address, 1, 0)} <= writes and selector_target in targets):
            constructors.append(body)
    if len(constructors) != 1:
        return None
    constructor = constructors[0]

    getters = []
    for body in _owners_for_literals(facts, (global_address,)):
        if (not body.calls and len(body.instructions) <= 8 and
                body.instructions and facts.decode(body.instructions[0]).mnemonic == "ldr" and
                any(access.operation == "read" and access.width == 4 and
                    isinstance(access.address, SymbolicValue) and
                    _constant(access.address) == global_address + 4
                    for access in body.symbolic_accesses)):
            getters.append(body)
    if len(getters) != 1:
        return None
    active_getter = getters[0]

    count_global = None
    count_init = None
    for body in _owners_for_sites(facts, (site for site, target in facts.call_candidates(isa="thumb")
                                       if target == active_getter.entry.address)):
        if not any(target.address == active_getter.entry.address for _, target in body.calls):
            continue
        writes = [access for access in body.symbolic_accesses
                  if access.operation == "write" and access.width == 2 and
                  isinstance(access.address, SymbolicValue) and
                  access.address.kind == "const" and
                  0x14000000 <= access.address.value < 0x15000000]
        for access in writes:
            address = access.address.value
            if any(literal.value == address for literal in body.literals):
                count_global, count_init = address, body
                break
        if count_init is not None:
            break
    if count_init is None or count_caller["count_getter"] is None:
        return None
    count_getter = facts.function(CodeAddress(count_caller["count_getter"], "thumb"),
                                  budget=64, symbolic_registers={})
    if (not count_getter.complete or len(count_getter.instructions) > 4 or count_getter.calls or
            not any(access.operation == "read" and access.width == 2 and
                    isinstance(access.address, SymbolicValue) and
                    _constant(access.address) == count_global
                    for access in count_getter.symbolic_accesses)):
        return None

    reset_callers = []
    for site, target in facts.call_candidates(isa="thumb"):
        if target not in (constructor.entry.address, count_init.entry.address):
            continue
        for body in _owners_for_sites(facts, (site,)):
            sequence = [(call_site.address, call_target.address)
                        for call_site, call_target in body.calls
                        if call_target.address in (constructor.entry.address,
                                                   count_init.entry.address)]
            if (len(sequence) == 2 and
                    sequence[0][1] == constructor.entry.address and
                    sequence[1][1] == count_init.entry.address and
                    sequence[0][0] < sequence[1][0]):
                reset_callers.append(body)
    unique_callers = {body.entry.address: body for body in reset_callers}
    if len(unique_callers) != 1:
        return None
    reset_caller = next(iter(unique_callers.values()))

    return {
        "selector": selector_target,
        "constructor": constructor.entry.address,
        "active_object_getter": active_getter.entry.address,
        "count_initializer": count_init.entry.address,
        "count_getter": count_getter.entry.address,
        "reset_caller": reset_caller.entry.address,
        "count_global": count_global,
    }


def _select_candidate(facts, candidates, global_address, count_caller):
    """Resolve descriptor duplicates through the linked active-object path."""
    if len(candidates) == 1:
        geometry, protocol = candidates[0]
        return geometry, dict(protocol), _linked_lifecycle(
            facts, geometry, global_address, count_caller)
    linked = []
    for geometry, protocol in candidates:
        lifecycle = _linked_lifecycle(facts, geometry, global_address, count_caller)
        if lifecycle is not None:
            linked.append((geometry, dict(protocol), lifecycle))
    return linked[0] if len(linked) == 1 else None


def find_secondary_protected_nor(image: bytes, ram_base: int, ram_size: int) -> dict | None:
    """Return a linked table-geometry candidate or ``None`` when it is open.

    Descriptor selection and sector-count publication are linked through
    source queries. Reset-copy provenance still has to be closed before the
    candidate can select a runtime model.
    """
    if (not isinstance(image, (bytes, bytearray)) or type(ram_base) is not int or
            type(ram_size) is not int or ram_base < 0 or ram_size <= 0 or
            ram_base + ram_size > 0x100000000):
        return None
    image = bytes(image)
    facts = facts_for(image)
    candidates = []
    # Descriptor fields are aligned data words; candidate discovery does not
    # inspect or pattern-match instruction bytes.
    for width_site in range(0, len(image) - _ID_WIDTH_OFFSET - _OBJECT_SIZE + 1, 4):
        if _u32(image, width_site + _ID_WIDTH_OFFSET) != 2:
            continue
        geometry = _object_geometry(image, width_site)
        if geometry is not None:
            protocols = _callback_protocols(facts, geometry["callbacks"])
            if protocols is not None:
                candidates.append((geometry, protocols))
    if not candidates:
        return None
    # Resolve table aliases through actual lifecycle linkage, not raw offset
    # ordering. A lone candidate remains useful as a diagnostic even if its
    # object publication path is still open.
    consumers = _prefix_consumers(facts)
    if len(consumers) != 1:
        return None
    count_callers = _sector_count_callers(facts, consumers[0]["entry"])
    if len(count_callers) != 1:
        return None
    selected = _select_candidate(facts, candidates,
        consumers[0]["global_address"], count_callers[0])
    if selected is None:
        return None
    geometry, protocols, lifecycle = selected
    sector_masks = protocols.pop("_sector_masks")
    if 0x7F in sector_masks:
        identify = secondary_protected_protocol.identify_base_path(facts)
        if identify is not None:
            protocols["identify_base"] = (identify[0], identify[1])
            protocols["identify_caller"] = (identify[3], identify[4])
    # Open lifecycle queries keep the descriptor diagnostic-only.
    return {
        "signature": "table-summed-secondary-protected-nor-x16-v1",
        "admission": "candidate-awaiting-reset-copy",
        "bus_width": 2,
        "address": geometry["begin"],
        "size": geometry["extent"],
        "max_bound": geometry["max_bound"],
        "sector_sizes": list(geometry["sector_sizes"]),
        "selected_object": geometry["object"],
        "methods": {"read": geometry["callbacks"][0] & ~1,
                    "program": geometry["callbacks"][1] & ~1,
                    "erase": geometry["callbacks"][2] & ~1,
                    "poll": geometry["callbacks"][3] & ~1,
                    "suspend": geometry["callbacks"][4] & ~1,
                    "resume": geometry["callbacks"][5] & ~1},
        "protocol_intervals": {key: list(value) for key, value in protocols.items()},
        "sector_prefix_consumer": consumers[0],
        "sector_count_caller": count_callers[0],
        "lifecycle": lifecycle,
        "unclosed": ["reset-copy-provenance"] if lifecycle is not None else
                    ["publication-or-count-linkage", "reset-copy-provenance"],
    }
