"""Source-closed event spill and callback proof for encoded keypad paths."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, SymbolicValue
from .encoded_paths import _is


def _producer_callback(image, facts, producer):
    """Prove byte argument flow through the producer frame into its callback."""
    if type(producer) is not int or not 0 <= producer < len(image) - 0x30:
        return None
    entry = CodeAddress(producer, "thumb")
    region = facts.function(entry, budget=128,
        initial_registers={a.ARM_REG_R0: SymbolicValue.arg(0)})
    frame = facts.stack_frame(region) if region.complete else None
    if (not region.complete or region.truncated or region.unresolved or frame is None
            or not frame.complete or not frame.balanced):
        return None

    def at(offset):
        return facts.decode(CodeAddress(producer + offset, "thumb"))

    def memory(ins, ident, register, base, displacement):
        return bool(_is(ins, ident) and len(ins.operands) == 2
            and ins.operands[0].type == a.ARM_OP_REG
            and ins.operands[0].reg == register
            and ins.operands[1].type == a.ARM_OP_MEM
            and ins.operands[1].mem.base == base
            and ins.operands[1].mem.disp == displacement
            and not ins.operands[1].mem.index and not ins.writeback)

    push, copy, enable_ptr, control_ptr = (at(0), at(2), at(4), at(6))
    enable_read, enable_cmp, enable_branch = at(8), at(10), at(12)
    control_read, control_cmp, control_branch = at(14), at(16), at(18)
    stack_base, event_store, event_reload, call = at(20), at(22), at(24), at(26)
    saved = {a.ARM_REG_R3, a.ARM_REG_R4, a.ARM_REG_R5,
             a.ARM_REG_R7, a.ARM_REG_LR}
    if (not _is(push, a.ARM_INS_PUSH) or push.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
            or {op.reg for op in push.operands if op.type == a.ARM_OP_REG} != saved
            or len(push.operands) != len(saved)
            or not _is(copy, a.ARM_INS_ADD) or len(copy.operands) != 3
            or tuple(op.reg if op.type == a.ARM_OP_REG else op.imm
                     for op in copy.operands) != (a.ARM_REG_R7, a.ARM_REG_R0, 0)
            or not memory(enable_read, a.ARM_INS_LDRB, a.ARM_REG_R0, a.ARM_REG_R0, 0)
            or not _is(enable_cmp, a.ARM_INS_CMP) or len(enable_cmp.operands) != 2
            or (enable_cmp.operands[0].reg, enable_cmp.operands[1].imm) !=
               (a.ARM_REG_R0, 0)
            or not _is(enable_branch, a.ARM_INS_B) or enable_branch.cc != a.ARM_CC_EQ
            or len(enable_branch.operands) != 1
            or enable_branch.operands[0].imm != producer + 0x24
            or not memory(control_read, a.ARM_INS_LDR, a.ARM_REG_R1,
                          a.ARM_REG_R5, 0x30)
            or not _is(control_cmp, a.ARM_INS_CMP) or len(control_cmp.operands) != 2
            or (control_cmp.operands[0].reg, control_cmp.operands[1].imm) !=
               (a.ARM_REG_R1, 0)
            or not _is(control_branch, a.ARM_INS_B) or control_branch.cc != a.ARM_CC_EQ
            or len(control_branch.operands) != 1
            or control_branch.operands[0].imm != producer + 0x24
            or not _is(stack_base, a.ARM_INS_ADD) or len(stack_base.operands) != 3
            or tuple(op.reg if op.type == a.ARM_OP_REG else op.imm
                     for op in stack_base.operands) !=
               (a.ARM_REG_R3, a.ARM_REG_SP, 0)
            or not memory(event_store, a.ARM_INS_STRB, a.ARM_REG_R7,
                          a.ARM_REG_R3, 0)
            or not memory(event_reload, a.ARM_INS_LDR, a.ARM_REG_R0,
                          a.ARM_REG_SP, 0)
            or not _is(call, a.ARM_INS_BL)):
        return None

    literals = (facts.literal(CodeAddress(producer + 4, "thumb")),
                facts.literal(CodeAddress(producer + 6, "thumb")))
    if (any(item is None or type(item.value) is not int for item in literals)
            or not _is(enable_ptr, a.ARM_INS_LDR) or len(enable_ptr.operands) != 2
            or enable_ptr.operands[0].reg != a.ARM_REG_R0
            or not _is(control_ptr, a.ARM_INS_LDR) or len(control_ptr.operands) != 2
            or control_ptr.operands[0].reg != a.ARM_REG_R5
            or any(ins.operands[1].type != a.ARM_OP_MEM
                   or ins.operands[1].mem.base != a.ARM_REG_PC
                   or item.register != ins.operands[0].reg
                   for ins, item in zip((enable_ptr, control_ptr), literals))
            or facts.reaching_definitions(region, CodeAddress(producer + 8, "thumb"),
                                          a.ARM_REG_R0) !=
               (CodeAddress(producer + 4, "thumb"),)
            or facts.reaching_definitions(region, CodeAddress(producer + 14, "thumb"),
                                          a.ARM_REG_R5) !=
               (CodeAddress(producer + 6, "thumb"),)):
        return None
    enable_address, control_address = (item.value for item in literals)
    store_site, reload_site, call_site = (CodeAddress(producer + off, "thumb")
                                          for off in (22, 24, 26))
    base_site = CodeAddress(producer + 20, "thumb")
    enable_fallthrough = CodeAddress(producer + 14, "thumb")
    control_fallthrough = CodeAddress(producer + 20, "thumb")
    slot = frame.offset_at(base_site)
    reload_accesses = [access for access in frame.accesses
        if access.site == reload_site and access.operation == "read"]
    saved_r3 = any(access.site == entry and access.operation == "write"
        and (access.offset, access.width, access.register) ==
            (slot, 4, a.ARM_REG_R3) for access in frame.accesses)
    edges = {}
    for source, target in region.control_edges:
        edges.setdefault(source.address, set()).add(target.address)
    if (slot != -4 * len(saved) or not saved_r3
            or len(reload_accesses) != 1
            or (reload_accesses[0].offset, reload_accesses[0].width,
                reload_accesses[0].register) != (slot, 4, a.ARM_REG_R0)
            or frame.offset_at(store_site) != frame.offset_at(reload_site)
            or frame.offset_at(call_site) != frame.offset_at(reload_site)
            or facts.register_value(region, store_site, a.ARM_REG_R7) !=
               SymbolicValue.arg(0)
            or facts.reaching_definitions(region, store_site, a.ARM_REG_R7) !=
               (CodeAddress(producer + 2, "thumb"),)
            or facts.reaching_definitions(region, store_site, a.ARM_REG_R3) !=
               (base_site,)
            or facts.reaching_definitions(region, call_site, a.ARM_REG_R0) !=
               (reload_site,)
            or facts.reaching_definitions(region, call_site, a.ARM_REG_R1) !=
               (CodeAddress(producer + 14, "thumb"),)
            or edges.get(enable_branch.address) !=
               {enable_fallthrough.address, producer + 0x24}
            or edges.get(control_branch.address) !=
               {control_fallthrough.address, producer + 0x24}
            or not region.dominates(enable_fallthrough, store_site)
            or not region.dominates(control_fallthrough, store_site)
            or not region.dominates(base_site, store_site)
            or not region.dominates(store_site, reload_site)
            or not region.dominates(reload_site, call_site)):
        return None

    state_ranges = ((enable_address, 1), (control_address + 0x30, 4))
    if any(address < 0 or address + size > 0x100000000
           for address, size in state_ranges):
        return None
    target = facts.thumb_call_target(producer + 0x1A)
    if target is None or target >= len(image) - 2:
        return None
    callback = facts.decode(CodeAddress(target, "thumb"))
    if not _is(callback, a.ARM_INS_BX,
            ((a.ARM_OP_REG, a.ARM_REG_R1, None, None, None),)):
        return None
    dependencies = {(producer, 0x1E), (target, 2)}
    dependencies.update((literal.pool, 4) for literal in literals)
    return {"stub": target, "dependencies": dependencies,
        "state_addresses": sorted({enable_address, control_address}),
        "state_ranges": state_ranges}
