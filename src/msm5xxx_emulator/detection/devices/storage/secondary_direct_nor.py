"""Source proof for direct, command-selected secondary x16 NOR apertures."""
from __future__ import annotations

import struct

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.values import SymbolicValue

from .secondary_protected_protocol import (
    _source_sector_masks,
    identify_base_path,
)


_SECTOR = 0x10000
_SECTOR_MASK = 0x7F
_TABLE_ROW = 0x1C
_BANK_SIZE = (_SECTOR_MASK + 1) * _SECTOR


def _constant(value):
    if isinstance(value, SymbolicValue) and value.kind == "const":
        return value.value
    return value if type(value) is int else None


def _body(facts, entry, budget=1024):
    result = facts.function(CodeAddress(entry, "thumb"), budget=budget,
                            symbolic_registers={})
    return (result if result.complete and not result.unresolved and
            not result.truncated and result.instructions else None)


def _call_targets(body):
    return {target.address for _, target in body.calls
            if target.isa == "thumb"}


def _writes(body):
    return {_constant(access.value) for access in body.symbolic_accesses
            if access.operation == "write" and access.width == 2}


def _command_leaf(facts, entry):
    body = facts.function(CodeAddress(entry, "thumb"), budget=128,
                          symbolic_registers={a.ARM_REG_R0: SymbolicValue.arg(0)})
    if (not body.complete or body.unresolved or body.truncated or
            not body.instructions):
        return None
    if body is None or body.calls:
        return None
    writes = [access for access in body.symbolic_accesses
              if access.operation == "write" and access.width == 2]
    values = [_constant(access.value) for access in writes]
    if not {0x60, 0xAC, 0x7B} <= set(values) or len(writes) < 4:
        return None
    if any(not isinstance(access.address, SymbolicValue) or
           access.address.kind != "arg" or access.address.value != 0
           for access in writes):
        return None
    if not values.index(0x60) < values.index(0xAC) < values.index(0x7B):
        return None
    instructions = [facts.decode(pc) for pc in body.instructions]
    bic_stores = [store for pc, ins in zip(body.instructions, instructions)
                  if ins is not None and ins.id == a.ARM_INS_BIC and
                  ins.operands and ins.operands[0].type == a.ARM_OP_REG
                  if (store := _result_store(facts, body, pc, ins.operands[0].reg)) is not None]
    if not bic_stores:
        return None
    mask_sites = {site for site, _, _ in _source_sector_masks(facts, body)}
    if not mask_sites:
        return None
    mask_stores = []
    for pc in body.instructions:
        ins = facts.decode(pc)
        if ins is None or ins.id != a.ARM_INS_AND or len(ins.operands) != 2:
            continue
        left, right = ins.operands
        if left.type != a.ARM_OP_REG or right.type != a.ARM_OP_REG:
            continue
        if pc.address not in mask_sites:
            continue
        mask = _constant(facts.register_value(body, pc, right.reg))
        store = _result_store(facts, body, pc, left.reg)
        if mask == _SECTOR_MASK and store is not None:
            mask_stores.append(store)
    if not mask_stores:
        return None
    command_stores = {value: min(access.instruction.address for access in writes
                                 if _constant(access.value) == value)
                      for value in (0x60, 0xAC, 0x7B)}
    if not any(command_stores[0x60] < mask_store < command_stores[0xAC] < bic_store <
               command_stores[0x7B] for mask_store in mask_stores
               for bic_store in bic_stores):
        return None
    return body


def _result_store(facts, body, producer, result_reg):
    """Require a computed command value to reach a halfword bus write."""
    started = False
    for pc in body.instructions:
        if pc.address == producer.address:
            started = True
            continue
        if not started:
            continue
        ins = facts.decode(pc)
        if ins is None:
            return False
        if (ins.id == a.ARM_INS_STRH and len(ins.operands) == 2 and
                ins.operands[0].type == a.ARM_OP_REG and
                ins.operands[0].reg == result_reg):
            return pc.address
        try:
            _, written = ins.regs_access()
        except Exception:
            return None
        if result_reg in written:
            return None
    return None


def _is_page_reader(body, facts, command_entry):
    values = _writes(body)
    if not {0x40, 0x41} <= values or command_entry not in _call_targets(body):
        return False
    for pc in body.instructions:
        ins = facts.decode(pc)
        if (ins is None or ins.id != a.ARM_INS_CMP or len(ins.operands) != 2
                or ins.operands[1].type != a.ARM_OP_IMM
                or ins.operands[1].imm != 0x80):
            continue
        for branch, target in body.back_edges:
            if branch < pc.address or target > pc.address:
                continue
            if any(target <= item.address <= branch and
                   facts.decode(item) is not None and
                   facts.decode(item).id == a.ARM_INS_STRH
                   for item in body.instructions):
                return True
    return False


def _is_erase(body, facts, command_entry):
    return ({0x20, 0xD0} <= _writes(body) and
            command_entry in _call_targets(body))


def _is_status_poll(body, facts):
    if not {0x70, 0x50, 0xFF} <= _writes(body):
        return False
    return any(facts.decode(item) is not None and
               facts.decode(item).id == a.ARM_INS_LDRH and
               any(target <= item.address <= branch
                   for branch, target in body.back_edges)
               for item in body.instructions)


def _owned_functions(facts, sites):
    found = {}
    for site in sites:
        site = site.address if isinstance(site, CodeAddress) else site
        for delta in range(0, 0x82, 2):
            entry = site - delta
            ins = facts.decode(CodeAddress(entry, "thumb"))
            if ins is None or ins.id != a.ARM_INS_PUSH or "lr" not in ins.op_str:
                continue
            body = _body(facts, entry)
            if body is not None and any(pc.address == site for pc in body.instructions):
                found[entry] = body
                break
    return tuple(found.values())


def _range_rows(image, table, base):
    """Read adjacent source range records bounded by the decoded aperture."""
    rows = []
    cursor = table
    while cursor + _TABLE_ROW <= len(image):
        start, delta, _source_size, end, unit = struct.unpack_from("<5I", image, cursor)
        extent = end - (start + delta)
        # The linked range consumer bounds against +0xc explicitly. The
        # adjacent +8/+0x10 fields are operation metadata, not byte extents.
        if (delta > end - start or extent <= 0 or
                start < base or end > base + _BANK_SIZE):
            break
        rows.append((start + delta, end))
        cursor += _TABLE_ROW
    if len(rows) < 3:
        return None
    ordered = sorted(rows)
    if any(ordered[i + 1][0] < ordered[i][1]
           for i in range(len(ordered) - 1)):
        return None
    return rows, cursor


def _table_index_consumer(facts, body, table):
    """Close index*row-size, literal table base, and a row-end field load."""
    symbolic = {a.ARM_REG_R0: SymbolicValue.arg(0),
                a.ARM_REG_R1: SymbolicValue.arg(1),
                a.ARM_REG_R2: SymbolicValue.arg(2),
                a.ARM_REG_R3: SymbolicValue.arg(3)}
    entry = body.entry.address
    body = facts.function(CodeAddress(entry, "thumb"), budget=2048,
                          symbolic_registers=symbolic)
    if not body.complete or body.unresolved or body.truncated:
        return None
    table_loads = {literal.instruction.address: literal.register
                   for literal in body.literals if literal.value == table}
    if not table_loads:
        return None
    scaled = set()
    for pc in body.instructions:
        ins = facts.decode(pc)
        if ins is None or ins.id != a.ARM_INS_MUL or len(ins.operands) != 3:
            continue
        dest, left, right = ins.operands
        if dest.type != a.ARM_OP_REG or left.type != a.ARM_OP_REG or right.type != a.ARM_OP_REG:
            continue
        pairs = ((left.reg, right.reg), (right.reg, left.reg))
        for constant_reg, index_reg in pairs:
            factor = _constant(facts.register_value(body, pc, constant_reg))
            index = facts.register_value(body, pc, index_reg)
            if (factor == _TABLE_ROW and isinstance(index, SymbolicValue)
                    and index.kind == "arg" and index.value == 3):
                scaled.add((pc.address, dest.reg))
    if not scaled:
        return None
    consumers = []
    for pc in body.instructions:
        ins = facts.decode(pc)
        if (ins is None or ins.id != a.ARM_INS_LDR or len(ins.operands) != 2
                or ins.operands[0].type != a.ARM_OP_REG
                or ins.operands[1].type != a.ARM_OP_MEM
                or ins.operands[1].mem.disp != 0x0C):
            continue
        row_reg = ins.operands[1].mem.base
        origins = facts.register_origins(body, pc, row_reg)
        if not origins:
            continue
        for mul_pc, product_reg in scaled:
            if not _origin_uses_table_and_product(
                    facts, body, pc, row_reg, mul_pc, product_reg,
                    set(table_loads.items())):
                continue
            consumers.append((pc.address, body))
    return consumers or None


def _origin_uses_table_and_product(facts, body, use, register, mul_pc,
                                   product_reg, table_loads):
    """Walk reaching definitions and require both source components."""
    seen = set()
    marks = set()
    def visit(at, reg, depth=0):
        if depth > 16 or (at.address, reg) in seen:
            return
        seen.add((at.address, reg))
        for definition, defined_reg in facts.register_origins(body, at, reg) or ():
            if definition.address == mul_pc and defined_reg == product_reg:
                marks.add("index")
                continue
            if (definition.address, defined_reg) in table_loads:
                marks.add("table")
                continue
            ins = facts.decode(definition)
            if ins is None:
                continue
            try:
                read, _ = ins.regs_access()
            except Exception:
                continue
            for source_reg in read:
                visit(definition, source_reg, depth + 1)
    visit(use, register)
    return marks == {"table", "index"}


def _range_table(facts, image, base):
    candidates = {}
    # Literal targets first bound table candidates; a whole-image bytewise
    # scan would treat unrelated metadata as possible descriptors.
    refs = facts.literal_references_in(((0, len(image)),))
    grouped = {}
    for literal in refs:
        table = literal.value
        if type(table) is int and table % 4 == 0 and table + _TABLE_ROW <= len(image):
            grouped.setdefault(table, []).append(literal)
    for table, references in grouped.items():
        parsed = _range_rows(image, table, base)
        if parsed is None:
            continue
        rows, end = parsed
        owners = _owned_functions(facts, (ref.instruction.address for ref in references))
        for owner in owners:
            uses = _table_index_consumer(facts, owner, table)
            if uses:
                key = (table, end, tuple(rows))
                candidates.setdefault(key, {})[owner.entry.address] = owner
    if len(candidates) != 1:
        return None
    (table, end, rows), consumers = next(iter(candidates.items()))
    return table, end, rows, tuple(consumers.values())


def _evidence(facts, body):
    spans = set()
    for pc in body.instructions:
        instruction = facts.decode(pc)
        size = instruction.size if instruction is not None else 2
        spans.add((pc.address, pc.address + size))
    spans.update((item.pool, item.pool + 4) for item in body.literals)
    return spans


def find_secondary_direct_nor(image: bytes):
    """Find a direct 8MiB x16 NOR protocol and source-linked range table."""
    if not isinstance(image, bytes) or len(image) < 0x10000:
        return None
    facts = facts_for(image)
    base_path = identify_base_path(facts)
    if base_path is None:
        return None
    identify_entry, identify_end, bank_base, owner_entry, owner_end = base_path
    owner = _body(facts, owner_entry)
    identify_body = _body(facts, identify_entry, 32)
    if (owner is None or identify_body is None or owner_end > len(image) or
            identify_end > len(image)):
        return None
    owner_targets = _call_targets(owner)
    if identify_entry not in owner_targets:
        return None

    profiles = []
    for manager_entry in owner_targets - {identify_entry}:
        manager = _body(facts, manager_entry)
        if manager is None:
            continue
        children = []
        for target in _call_targets(manager):
            child = _body(facts, target)
            if child is not None:
                children.append((target, child))
        readers = [(entry, body) for entry, body in children
                   if any(_is_page_reader(body, facts, helper_entry)
                          for helper_entry in _call_targets(body))]
        erasers = [(entry, body) for entry, body in children
                   if any(_is_erase(body, facts, helper_entry)
                          for helper_entry in _call_targets(body))]
        pollers = [(entry, body) for entry, body in children
                   if _is_status_poll(body, facts)]
        if len(readers) != 1 or len(erasers) != 1 or len(pollers) != 1:
            continue
        shared = _call_targets(readers[0][1]) & _call_targets(erasers[0][1])
        helpers = [(_command_leaf(facts, target), target) for target in shared]
        helpers = [(body, target) for body, target in helpers if body is not None]
        if len(helpers) != 1:
            continue
        command, command_entry = helpers[0]
        if command_entry not in _call_targets(erasers[0][1]):
            continue
        tables = _range_table(facts, image, bank_base)
        if tables is None:
            continue
        table, table_end, rows, consumers = tables
        spans = (_evidence(facts, owner) | _evidence(facts, identify_body) |
                 _evidence(facts, manager) | _evidence(facts, command))
        for _, body in (readers[0], erasers[0], pollers[0]):
            spans |= _evidence(facts, body)
        for consumer in consumers:
            spans |= _evidence(facts, consumer)
        spans.add((table, table_end))
        profiles.append({
            "signature": "direct-secondary-protected-nor-x16-v1",
            "bank_base": bank_base,
            "bank_size": _BANK_SIZE,
            "sector_size": _SECTOR,
            "identity_queried": False,
            "ranges": rows,
            "range_table": table,
            "protocol": {"initialize": manager_entry,
                         "command": command_entry,
                         "read_program": readers[0][0],
                         "erase": erasers[0][0],
                         "poll": pollers[0][0]},
            "evidence_spans": tuple(sorted(spans)),
        })
    return profiles[0] if len(profiles) == 1 else None
