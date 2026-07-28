"""Read-only structural evidence for an auxiliary completion builder.

This does not model a modem, result values, IRQs, timing, or service state.
The caller supplies a previously proven Thumb entry point; ambiguity stays a
native fallback.
"""
from __future__ import annotations

from dataclasses import dataclass
import struct

from .arm import (
    _thumb_path_preserves_register,
    _thumb_reachable,
    _thumb_writes_register,
)


_MAX_FUNCTION_BYTES = 0x300
_SEMANTIC_LIMIT = (
    "static call/dataflow shape only; completion values and device semantics unknown"
)


@dataclass(frozen=True)
class AuxSelector:
    pc: int
    base: int
    offset: int

    def as_dict(self) -> dict[str, int]:
        return {"pc": self.pc, "base": self.base, "offset": self.offset}


@dataclass(frozen=True)
class AuxLoad:
    pc: int
    use_pc: int
    base: int
    width: str
    offset: int
    value_register: int

    def as_dict(self) -> dict[str, int | str]:
        return {"pc": self.pc, "use_pc": self.use_pc, "base": self.base,
                "width": self.width, "offset": self.offset,
                "value_register": self.value_register}


@dataclass(frozen=True)
class AuxCompletionEvidence:
    """Immutable, static-only result for an already-bound auxiliary function."""

    entry_file_offset: int | None
    return_file_offset: int | None
    work_stride: int | None
    saved_work_register: int | None = None
    saved_count_register: int | None = None
    index_register: int | None = None
    selector: AuxSelector | None = None
    loads: tuple[tuple[str, AuxLoad], ...] = ()
    record_u16_offsets: tuple[int, ...] = ()
    record_u32_offset: int | None = None
    confidence: str = "rejected"
    reject_reason: str | None = None
    semantic_limit: str = _SEMANTIC_LIMIT

    def as_dict(self) -> dict[str, object]:
        return {
            "entry_file_offset": self.entry_file_offset,
            "return_file_offset": self.return_file_offset,
            "work_stride": self.work_stride,
            "saved_work_register": self.saved_work_register,
            "saved_count_register": self.saved_count_register,
            "index_register": self.index_register,
            "selector": self.selector.as_dict() if self.selector else None,
            "loads": {name: load.as_dict() for name, load in self.loads},
            "record_u16_offsets": self.record_u16_offsets,
            "record_u32_offset": self.record_u32_offset,
            "confidence": self.confidence,
            "reject_reason": self.reject_reason,
            "semantic_limit": self.semantic_limit,
        }


def _reject(reason: str) -> AuxCompletionEvidence:
    return AuxCompletionEvidence(None, None, None, reject_reason=reason)


def _u16(image: bytes, at: int) -> int | None:
    return struct.unpack_from("<H", image, at)[0] if 0 <= at <= len(image) - 2 else None


def _add_imm3(word: int | None) -> tuple[int, int, int] | None:
    if word is None or word & 0xFE00 != 0x1C00:
        return None
    return word & 7, word >> 3 & 7, word >> 6 & 7


def _add_reg(word: int | None) -> tuple[int, int, int] | None:
    if word is None or word & 0xFE00 != 0x1800:
        return None
    return word & 7, word >> 3 & 7, word >> 6 & 7


def _add_imm8(word: int | None) -> tuple[int, int] | None:
    if word is None or word & 0xF800 != 0x3000:
        return None
    return word >> 8 & 7, word & 0xFF


def _mov_imm(word: int | None) -> tuple[int, int] | None:
    if word is None or word & 0xF800 != 0x2000:
        return None
    return word >> 8 & 7, word & 0xFF


def _mul(word: int | None) -> tuple[int, int] | None:
    if word is None or word & 0xFFC0 != 0x4340:
        return None
    return word & 7, word >> 3 & 7


def _cmp_reg(word: int | None) -> tuple[int, int] | None:
    if word is None or word & 0xFFC0 != 0x4280:
        return None
    return word & 7, word >> 3 & 7


def _shift_lsl_reg(word: int | None) -> tuple[int, int] | None:
    if word is None or word & 0xFFC0 != 0x4080:
        return None
    return word & 7, word >> 3 & 7


def _literal(image: bytes, at: int, register: int, image_offset: int) -> int | None:
    word = _u16(image, at)
    if word is None or word & 0xF800 != 0x4800 or word >> 8 & 7 != register:
        return None
    local = ((image_offset + at + 4) & ~3) + (word & 0xFF) * 4 - image_offset
    return struct.unpack_from("<I", image, local)[0] if 0 <= local <= len(image) - 4 else None


def _is_bl(image: bytes, at: int) -> bool:
    return ((_u16(image, at) or 0) & 0xF800 == 0xF000
            and (_u16(image, at + 2) or 0) & 0xF800 == 0xF800)


def _conditional_target(at: int, word: int | None) -> int | None:
    if word is None or word & 0xF000 != 0xD000 or word & 0x0F00 >= 0x0E00:
        return None
    delta = (word & 0xFF) << 1
    return at + 4 + (delta - 0x200 if delta & 0x100 else delta)


def _load_store(word: int | None) -> tuple[str, int, int, int] | None:
    if word is None:
        return None
    value, base, unit = word & 7, word >> 3 & 7, word >> 6 & 0x1F
    kinds = ((0x7000, "strb", 1), (0x7800, "ldrb", 1),
             (0x8000, "strh", 2), (0x8800, "ldrh", 2),
             (0x6000, "str", 4), (0x6800, "ldr", 4))
    for mask, kind, scale in kinds:
        if word & 0xF800 == mask:
            return kind, value, base, unit * scale
    return None


def _function(image: bytes, entry: int) -> tuple[set[int], int] | None:
    reached = _thumb_reachable(image, entry, min(len(image), entry + _MAX_FUNCTION_BYTES))
    returns = [at for at in reached if (_u16(image, at) or 0) & 0xFF00 == 0xBD00]
    return (reached, returns[0]) if len(returns) == 1 else None


def detect_aux_completion_shape(
        image: bytes, entry_file_offset: int, image_offset: int = 0,
) -> AuxCompletionEvidence:
    """Validate one pre-bound Thumb builder; never reads or changes runtime state."""
    entry = entry_file_offset - image_offset
    if entry & 1 or not 0 <= entry < len(image):
        return _reject("aux-entry-outside-primary")
    function = _function(image, entry)
    if function is None:
        return _reject("aux-return-cardinality")
    reached, returned = function
    ordered = sorted(reached)
    first_call = next((at for at in ordered if _is_bl(image, at)), entry + 0x20)
    saved: dict[int, int] = {}
    for at in ordered:
        if not entry <= at < min(first_call, entry + 0x30):
            continue
        add = _add_imm3(_u16(image, at))
        if add is not None and add[2] == 0 and add[1] in (0, 1):
            saved[add[1]] = add[0]
    if set(saved) != {0, 1} or saved[0] == saved[1]:
        return _reject("aux-r0-r1-save-missing")
    work, count = saved[0], saved[1]

    candidates: list[tuple[int, int, int, int]] = []
    for at in ordered:
        multiply = _mul(_u16(image, at))
        if multiply is None:
            continue
        record, index = multiply
        stride = next((mov[1] for probe in range(at - 2, max(entry - 2, at - 0x12), -2)
                       if (mov := _mov_imm(_u16(image, probe))) is not None and mov[0] == record), None)
        if stride is not None and stride > 0 and not stride & 1 and _add_reg(_u16(image, at + 2)) == (record, record, work):
            candidates.append((at, record, index, stride))
    if len(candidates) != 1:
        return _reject(f"aux-record-base-cardinality:{len(candidates)}")
    multiply_at, record, index, stride = candidates[0]
    if not any(_mov_imm(_u16(image, at)) == (index, 0)
               for at in ordered if entry <= at < multiply_at):
        return _reject("aux-saved-r0-r1-loop-unclosed")
    if not any(_cmp_reg(_u16(image, at)) == (index, count)
               and (target := _conditional_target(at + 2, _u16(image, at + 2))) is not None
               and target <= multiply_at for at in ordered):
        return _reject("aux-saved-r0-r1-loop-unclosed")

    selector: AuxSelector | None = None
    for at in ordered:
        if not entry <= at < multiply_at:
            continue
        decoded = _load_store(_u16(image, at))
        if decoded is None or decoded[0] != "strb":
            continue
        _, value, base, offset = decoded
        for probe in range(at - 2, max(entry - 2, at - 0x12), -2):
            if (_shift_lsl_reg(_u16(image, probe)) == (value, index)
                    and _mov_imm(_u16(image, probe - 2)) == (value, 1)
                    and probe - 2 in reached
                    and probe in reached
                    and probe + 2 in reached
                    and _thumb_path_preserves_register(
                        image, probe + 2, at, at + 2, value
                    )
                    and _thumb_path_preserves_register(
                        image, probe + 4, at, at + 2, base
                    )
                    and (literal := _literal(
                        image, probe + 2, base, image_offset
                    )) is not None):
                selector = AuxSelector(image_offset + probe + 2, literal, offset)
                break
    if selector is None:
        return _reject("aux-selector-onehot-missing")

    loads: list[AuxLoad] = []
    for at in ordered:
        word = _u16(image, at)
        if word is None or word & 0xF800 != 0x4800:
            continue
        register = word >> 8 & 7
        literal = _literal(image, at, register, image_offset)
        if literal is None:
            continue
        for probe in range(at + 2, min(at + 0x12, len(image) - 1), 2):
            if probe not in reached:
                continue
            if not _thumb_path_preserves_register(
                    image, at + 2, probe, probe + 2, register):
                continue
            decoded = _load_store(_u16(image, probe))
            if decoded is None or decoded[2] != register:
                continue
            if decoded[0] in {"ldrb", "ldrh"}:
                loads.append(AuxLoad(
                    image_offset + at, image_offset + probe, literal,
                    "u8" if decoded[0] == "ldrb" else "u16", decoded[3], decoded[1],
                ))
            break
    e = [item for item in loads if item.width == "u8" and item.use_pc < selector.pc]
    m = [item for item in loads if item.width == "u16" and item.use_pc > selector.pc]
    if not e or not m:
        return _reject("aux-e-m-l-s-width-shape-missing")
    middle = m[0]
    l = next((item for item in loads if item.width == "u8" and item.use_pc > middle.use_pc), None)
    s = next((item for item in loads if item.width == "u16" and l is not None and item.use_pc > l.use_pc), None)
    if l is None or s is None:
        return _reject("aux-e-m-l-s-width-shape-missing")
    if len({e[-1].base, middle.base, l.base, s.base, selector.base}) != 5:
        return _reject("aux-e-m-l-s-literal-distinctness-missing")

    aliases = {record: 0}
    stores: list[tuple[int, int]] = []
    for at in ordered:
        if not multiply_at <= at < returned:
            continue
        word = _u16(image, at)
        previous = dict(aliases)
        preserved: set[int] = set()
        if at == multiply_at:
            preserved.add(record)
        elif (add := _add_imm3(word)) is not None and add[1] in previous:
            aliases[add[0]] = previous[add[1]] + add[2]
            preserved.add(add[0])
        elif (add8 := _add_imm8(word)) is not None and add8[0] in previous:
            aliases[add8[0]] = previous[add8[0]] + add8[1]
            preserved.add(add8[0])
        elif (addreg := _add_reg(word)) == (record, record, work) and at == multiply_at + 2:
            aliases[record] = previous[record]
            preserved.add(record)
        elif (decoded := _load_store(word)) is not None:
            kind, _, base, offset = decoded
            if base in previous and kind in {"strh", "str"}:
                stores.append((2 if kind == "strh" else 4, previous[base] + offset))
        for register in tuple(previous):
            if word is not None and _thumb_writes_register(word, register) and register not in preserved:
                aliases.pop(register, None)
    half = {offset for width, offset in stores if width == 2}
    words = {offset for width, offset in stores if width == 4}
    field = next((offset for offset in sorted(half)
                  if {offset, offset + 2, offset + 4} <= half and offset + 8 in words), None)
    if field is None:
        return _reject("aux-w-3xu16-u32-store-shape-missing")
    return AuxCompletionEvidence(
        entry_file_offset=entry_file_offset,
        return_file_offset=image_offset + returned,
        work_stride=stride,
        saved_work_register=work,
        saved_count_register=count,
        index_register=index,
        selector=selector,
        loads=(("E", e[-1]), ("M", middle), ("L", l), ("S", s)),
        record_u16_offsets=(field, field + 2, field + 4),
        record_u32_offset=field + 8,
        confidence="static-shape",
    )
