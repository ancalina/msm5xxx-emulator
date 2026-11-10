"""Shared bounded matching for relocation-normalized Thumb bodies."""
from __future__ import annotations
import hashlib
import struct
from dataclasses import dataclass
from typing import Mapping
from .facts import FirmwareFacts, facts_for
from .values import CodeAddress
from capstone import arm as a

@dataclass(frozen=True, slots=True)
class NormalizedBody:
    """Cached bytes and decoded operands for one explicitly described body."""

    normalized: bytes
    sha256: str
    calls: tuple[tuple[int, int], ...]
    branches: tuple[tuple[int, int], ...]
    literals: tuple[tuple[int, int, int, int], ...]
    pools: tuple[tuple[int, int], ...]

@dataclass(frozen=True, slots=True)
class ThumbBodyFacts:
    """Cached raw and normalized Thumb bytes with selected decoded operands."""

    normalized: bytes
    sha256: str
    call_prefixes: tuple[int, ...]
    calls: tuple[tuple[int, int], ...]
    literal_sites: tuple[tuple[int, int], ...]
    literals: tuple[tuple[int, int, int, int], ...]
    pools: tuple[tuple[int, int], ...]

def thumb_body(facts: FirmwareFacts, entry: int, size: int, *, limit: int | None = None, runtime_base: int | None = None, phase: str = 'reset', bank: str =
    'primary', call_offsets=None, literal_offsets=None, call_fill: bytes = b'\0\0\0\0', literal_keep_mask: int = 0xFF00,) -> ThumbBodyFacts | None:
    """Observe relocation operands in a bounded Thumb body and cache the result.

    ``None`` offsets discover every valid Thumb BL pair or literal load;
    sequences select explicit sites. Call targets and literal pools are returned
    relative to ``runtime_base`` and are deliberately not range-checked. The
    literal mask contains bits retained in each 16-bit load instruction.
    """
    if (type(entry) is not int or type(size) is not int or size < 0 or not isinstance(call_fill, bytes) or len(call_fill) != 4 or type(literal_keep_mask) is not
        int or not 0 <= literal_keep_mask <= 0xFFFF):
        return None
    max_size = len(facts.image) if limit is None else limit
    if type(max_size) is not int or entry < 0 or entry + size > max_size:
        return None
    base = facts.base if runtime_base is None else runtime_base
    calls_arg = None if call_offsets is None else tuple(call_offsets)
    literals_arg = None if literal_offsets is None else tuple(literal_offsets)
    if (calls_arg is not None and (any(type(off) is not int for off in calls_arg) or len(set(calls_arg)) != len(calls_arg)) or literals_arg is not None and (any(type(off)
        is not int for off in literals_arg) or len(set(literals_arg)) != len(literals_arg))):
        return None
    def extract():
        start = base + entry
        raw = (facts.view.read(start, size, phase=phase, bank=bank) if size else b'')
        if raw is None:
            return None
        prefixes, auto_calls, literal_sites = [],[],[]
        for offset in range(0, size - 1, 2):
            word = struct.unpack_from('<H', raw, offset)[0]
            if word & 0xF800 == 0xF000:
                prefixes.append(offset)
                if (offset + 4 <= size and struct.unpack_from('<H', raw, offset + 2)[0] & 0xF800 == 0xF800):
                    auto_calls.append(offset)
            elif word & 0xF800 == 0x4800:
                literal_sites.append((offset, word >> 8 & 7))
        selected_calls = tuple(auto_calls) if calls_arg is None else calls_arg
        selected_literals = (tuple(offset for offset, _ in literal_sites) if literals_arg is None else literals_arg)
        literal_registers = dict(literal_sites)
        normalized = bytearray(raw)
        calls, literals, pools = [],[],[]
        for offset in selected_calls:
            if (offset not in auto_calls or not 0 <= offset <= size - 4):
                return None
            if runtime_base is None:
                target = facts.thumb_call_target(entry + offset, phase=phase, bank=bank)
            else:
                ins = facts.decode(CodeAddress(start + offset, 'thumb', phase, bank))
                target = (ins.operands[0].imm - base if ins is not None and ins.id == a.ARM_INS_BL and ins.operands and ins.operands[0].type == a.ARM_OP_IMM
                    else None)
            if target is None:
                return None
            calls.append((offset, target))
            normalized[offset:offset + 4] = call_fill
        for offset in selected_literals:
            register = literal_registers.get(offset)
            if (register is None or not 0 <= offset <= size - 2):
                return None
            site = CodeAddress(start + offset, 'thumb', phase, bank)
            literal = facts.literal(site)
            if literal is None or literal.register != a.ARM_REG_R0 + register:
                return None
            pool = literal.pool - base
            literals.append((offset, register, literal.value, pool))
            pools.append((pool, pool + 4))
            word = struct.unpack_from('<H', normalized, offset)[0]
            struct.pack_into('<H', normalized, offset, word & literal_keep_mask)
        return ThumbBodyFacts(bytes(normalized), hashlib.sha256(normalized).hexdigest(), tuple(prefixes), tuple(calls), tuple(literal_sites), tuple(literals),
            tuple(pools),)
    return facts.memo('thumb-body', (entry, size, max_size, base, phase, bank, calls_arg, literals_arg, call_fill, literal_keep_mask), extract,)

def match_thumb_shape(image: bytes, entry: int, shape: tuple, *, facts: FirmwareFacts | None = None):
    """Match a hashed body with its complete set of calls and literal loads.

    ``shape`` is ``(size, digest, call_offsets, literal_offsets)``. Only call
    immediates and literal-load displacement bytes are normalized. The result
    maps each declared site to its decoded value and lists literal-pool spans.
    """
    size, digest, call_offsets, literal_offsets = shape
    if (type(entry) is not int or type(size) is not int or size < 0 or entry < 0 or entry & 1 or entry + size > len(image)):
        return None
    context = facts if facts is not None else facts_for(image)
    body = thumb_body(context, entry, size, limit=len(image))
    if body is None:
        return None
    calls = dict(body.calls)
    literals = {offset: value for offset, _, value, _ in body.literals}
    pools = list(body.pools)
    if (any(target & 1 or not 0 <= target <= len(image) - 2 for target in calls.values()) or any(not 0 <= start <= len(image) - 4 for start, _ in pools) or
        tuple(calls) != tuple(call_offsets) or tuple(literals) != tuple(literal_offsets) or body.sha256 != digest):
        return None
    return calls, literals, pools

def normalized_body(facts: FirmwareFacts, entry: CodeAddress | int, size: int, *, limit: int | None = None, runtime_base: int | None = None, thumb_calls=(),
    thumb_literals=(), arm_literals=(), arm_branches=(), call_fill: bytes | None = b'\0\0\0\0', preserve_internal_branches: bool = False, literal_masks: Mapping[int,
    int] | None = None,) -> NormalizedBody | None:
    """Return a cached normalized body and its explicitly selected operands."""
    if (type(size) is not int or call_fill is not None and (not isinstance(call_fill, bytes) or len(call_fill) != 4) or literal_masks is not None and not
        isinstance(literal_masks, Mapping)):
        return None
    try:
        sites = (tuple(thumb_calls), tuple(thumb_literals), None if arm_literals is None else tuple(arm_literals), None if arm_branches is None else tuple(arm_branches))
        masks = tuple(sorted((literal_masks or {}).items()))
    except (TypeError, ValueError):
        return None
    return facts.memo('normalized-body', (entry, size, limit, runtime_base, *sites, call_fill, preserve_internal_branches, masks), lambda: _normalized_body(facts,
        entry, size, limit=limit, runtime_base=runtime_base, thumb_calls=sites[0], thumb_literals=sites[1], arm_literals=sites[2], arm_branches=sites[3],
        call_fill=call_fill, preserve_internal_branches=preserve_internal_branches, literal_masks=dict(masks),),)

def _normalized_body(facts: FirmwareFacts, entry: CodeAddress | int, size: int, *, limit: int | None, runtime_base: int | None, thumb_calls, thumb_literals,
    arm_literals, arm_branches, call_fill: bytes | None, preserve_internal_branches: bool, literal_masks: Mapping[int, int] | None,) -> NormalizedBody | None:
    """Observe a bounded body after normalizing only caller-named operands.

    ``entry`` is an execution address. An integer is relative to ``facts.base``;
    ``runtime_base`` may supply its execution base for a materialized body. The
    exclusive ``limit`` applies to body bytes, branch targets and literal pools.
    Thumb BLs and ARM B/BLs in the explicit call/branch lists receive
    ``call_fill``. Explicit literal sites use a per-site *keep mask* (16 bits
    for Thumb, 32 bits for ARM); all other instruction and data bytes stay
    unchanged. Result addresses are execution addresses and literal records
    contain ``(offset, register, pool, value)``.

    This is a structural observation only. It does not decide whether any
    decoded instruction sequence describes a device.
    """
    if (size < 0 or call_fill is not None and len(call_fill) != 4 or type(facts) is not FirmwareFacts):
        return None
    if isinstance(entry, CodeAddress):
        pc = entry
        if runtime_base is not None:
            pc = CodeAddress(runtime_base, entry.isa, entry.phase, entry.bank)
    elif type(entry) is int:
        pc = CodeAddress((facts.base if runtime_base is None else runtime_base) + entry)
    else:
        return None
    masks = dict(literal_masks or {})
    calls_in = tuple(thumb_calls)
    literals_in = tuple(thumb_literals)
    arm_literals_in = None if arm_literals is None else tuple(arm_literals)
    branches_in = None if arm_branches is None else tuple(arm_branches)
    if (pc.isa not in ('arm', 'thumb') or pc.address < 0 or size == 0 or pc.address % (4 if pc.isa == 'arm' else 2) or any(type(offset) is not int or offset < 0
        for offset in (*calls_in, *literals_in, *(arm_literals_in if arm_literals_in is not None else ()), *(branches_in if branches_in is not None else ())))):
        return None
    end = pc.address + size
    bound = (1 << 32) if limit is None else limit
    if type(bound) is not int or not pc.address < end <= bound:
        return None
    if (len(set(calls_in)) != len(calls_in) or len(set(literals_in)) != len(literals_in) or arm_literals_in is not None and len(set(arm_literals_in)) != len(arm_literals_in)
        or branches_in is not None and len(set(branches_in)) != len(branches_in)):
        return None
    raw = facts.view.read(pc.address, size, phase=pc.phase, bank=pc.bank)
    if raw is None:
        return None
    normalized = bytearray(raw)
    calls, branches, literals, pools = [],[],[],[]
    if pc.isa == 'arm' and (arm_literals_in is None or branches_in is None):
        words = tuple(struct.unpack_from('<I', raw, offset)[0] for offset in range(0, size - size % 4, 4))
        if arm_literals_in is None:
            arm_literals_in = tuple(offset for offset, word in zip(range(0, len(words) * 4, 4), words) if word & 0x0F7F0000 == 0x051F0000)
        if branches_in is None:
            branches_in = tuple(offset for offset, word in zip(range(0, len(words) * 4, 4), words) if word & 0x0E000000 == 0x0A000000)
    if arm_literals_in is None or branches_in is None:
        return None
    def target_at(offset, isa, allowed):
        site = CodeAddress(pc.address + offset, isa, pc.phase, pc.bank)
        ins = facts.decode(site)
        if (ins is None or ins.id not in allowed or not ins.operands or ins.operands[0].type != a.ARM_OP_IMM):
            return None
        target = ins.operands[0].imm
        return target if type(target) is int and 0 <= target < bound - 1 else None
    for offset in calls_in:
        if pc.isa != 'thumb' or offset + 4 > size:
            return None
        target = target_at(offset, 'thumb', (a.ARM_INS_BL,))
        if target is None:
            return None
        calls.append((offset, target))
        fill = call_fill
        if fill is None:
            fill = bytes(4) if pc.isa == 'thumb' else bytes((normalized[offset + 3], 0, 0, 0))
        normalized[offset:offset + 4] = fill
    for offset in branches_in:
        if pc.isa != 'arm' or offset + 4 > size:
            return None
        target = target_at(offset, 'arm', (a.ARM_INS_B, a.ARM_INS_BL))
        if target is None:
            return None
        branches.append((offset, target))
        if not (preserve_internal_branches and pc.address <= target < end):
            fill = call_fill
            if fill is None:
                fill = bytes((0, 0, 0, normalized[offset + 3]))
            normalized[offset:offset + 4] = fill
    for isa, offsets in (('thumb', literals_in), ('arm', arm_literals_in)):
        for offset in offsets:
            width = 2 if isa == 'thumb' else 4
            if pc.isa != isa or offset + width > size:
                return None
            site = CodeAddress(pc.address + offset, isa, pc.phase, pc.bank)
            literal = facts.literal(site)
            if literal is None or not 0 <= literal.pool < bound - 3:
                return None
            raw_pool = facts.view.read(literal.pool, 4, phase=pc.phase, bank=pc.bank)
            if raw_pool is None:
                return None
            mask = masks.get(offset, 0xFF00 if isa == 'thumb' else 0xFFFFF000)
            if type(mask) is not int or not 0 <= mask < 1 << (8 * width):
                return None
            word = int.from_bytes(normalized[offset:offset + width], 'little')
            normalized[offset:offset + width] = (word & mask).to_bytes(width, 'little')
            literals.append((offset, literal.register, literal.pool, literal.value))
            pools.append((literal.pool, literal.pool + 4))
    expected_masks = set(literals_in) | set(arm_literals_in)
    if set(masks) - expected_masks:
        return None
    return NormalizedBody(bytes(normalized), hashlib.sha256(normalized).hexdigest(), tuple(calls), tuple(branches), tuple(literals), tuple(sorted(set(pools))),)

def match_thumb_contract(image: bytes, entry: int, contract: dict, immutable_limit: int, *, facts: FirmwareFacts | None = None) -> dict | None:
    """Match a complete bounded body with declared call/literal operands.

    Unlike :func:`match_thumb_shape`, this contract names literal registers
    and bounds both target code and pools by ``immutable_limit``. Its hash
    normalizes declared call instructions to four zero bytes and declared
    literal instructions by clearing their low displacement byte.
    """
    bound = min(len(image), immutable_limit)
    size = contract['size']
    if (type(entry) is not int or type(size) is not int or size < 0 or entry & 1 or not 0 <= entry <= bound - size):
        return None
    context = facts if facts is not None else facts_for(image)
    call_sites = tuple(contract['calls'])
    literal_roles = contract['literals']
    body = thumb_body(context, entry, size, limit=bound, call_offsets=call_sites, literal_offsets=tuple(literal_roles), call_fill=bytes(4), literal_keep_mask=0xFF00,)
    if body is None:
        return None
    calls = dict(body.calls)
    literals = {offset: value for offset, _, value, _ in body.literals}
    pools = list(body.pools)
    if (set(body.call_prefixes) != set(call_sites) or dict(body.literal_sites) != literal_roles or any(not 0 <= target < bound - 2 for target in calls.values())
        or any(not 0 <= pool <= bound - 4 for pool, _ in pools) or set(calls) != set(call_sites) or set(literals) != set(literal_roles) or body.sha256 !=
        contract['sha256']):
        return None
    return dict(calls=calls, literals=literals, pools=pools, code=(entry, entry + size))
