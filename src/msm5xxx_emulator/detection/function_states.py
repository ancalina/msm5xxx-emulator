"""Conservative joins of incoming register and memory states."""
from __future__ import annotations

def join(old, incoming):
    old_regs, old_memory, old_pending, old_version, old_sources = old
    new_regs, new_memory, new_pending, new_version, new_sources = incoming
    merged = {reg: value for reg, value in old_regs.items() if new_regs.get(reg) == value}
    merged_memory = old_memory and new_memory
    merged_pending = {key: value for key, value in old_pending.items() if new_pending.get(key) == value}
    merged_version = old_version if old_version == new_version else None
    merged_sources = {register: source for register, source in old_sources.items() if new_sources.get(register) == source}
    state = (merged, merged_memory, merged_pending, merged_version, merged_sources)
    changed = (merged != old_regs or merged_memory != old_memory or merged_pending != old_pending or merged_version != old_version or merged_sources !=
        old_sources)
    return state, changed
