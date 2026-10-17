"""Read-only structural evidence for auxiliary builders and search result consumers.

This does not model a modem, result values, IRQs, timing, or service state.
The caller supplies a previously proven Thumb entry point; ambiguity stays a
native fallback.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import struct

from .arm import (
    _thumb_path_preserves_register,
    _thumb_reachable,
    _thumb_writes_register,
    _thumb_function_start,
    thumb_bl_target,
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


def detect_search2_result_shape(
        image: bytes, entry_file_offset: int, image_offset: int = 0,
) -> dict[str, object]:
    """Bind a preselected FIFO consumer; do not infer RF values or enable a device."""
    result: dict[str, object] = {
        "confidence": "rejected",
        "semantic_limit": "static word-to-record order only; RF values, timing and IRQ unknown",
    }
    entry = entry_file_offset - image_offset
    if (entry & 1 or not 0 <= entry <= len(image) - 4
            or (_u16(image, entry) or 0) & 0xFF00 != 0xB500):
        return {**result, "reject_reason": "search2-entry-prologue"}
    end = min(len(image), entry + _MAX_FUNCTION_BYTES)
    reached = _thumb_reachable(image, entry, end)
    literal_word = _u16(image, entry + 2) or 0
    port = literal_word >> 8 & 7
    aperture = _literal(image, entry + 2, port, image_offset)
    if aperture is None or port < 4 or not 0x03000000 <= aperture < 0x04000000:
        return {**result, "reject_reason": "search2-port-literal"}
    candidates = []
    for at in sorted(reached):
        if not all(at + delta in reached for delta in range(0, 22, 2)):
            continue
        first = _load_store(_u16(image, at))
        second = _load_store(_u16(image, at + 8))
        if (first is None or second is None
                or first[0] != "ldrh" or first[2] != port
                or second[0] != "ldrh" or second[2] != port
                or first[3] != 12 or second[3] != 12):
            continue
        shift = _u16(image, at + 2) or 0
        pointer, index = shift & 7, shift >> 3 & 7
        addition = _add_reg(_u16(image, at + 4))
        if shift & 0xFFC0 != 0x0040 or addition is None:
            continue
        record = addition[2]
        if (addition[:2] != (pointer, pointer)
                or len({port, pointer, index, record}) != 4
                or first[1] in {port, pointer, index, record}
                or second[1] in {port, pointer, index, record}):
            continue
        a = _load_store(_u16(image, at + 6))
        b = _load_store(_u16(image, at + 18))
        if (a is None or b is None
                or a[:3] != ("strh", first[1], pointer)
                or b[:3] != ("strh", second[1], pointer)
                or a[3] == b[3]):
            continue
        if (_mov_imm(_u16(image, at - 2)) != (index, 0)
                or at - 2 not in reached
                or _add_imm8(_u16(image, at + 10)) != (index, 1)
                or _u16(image, at + 12) != (0x0600 | index << 3 | index)
                or _u16(image, at + 14) != (0x1600 | index << 3 | index)
                or _u16(image, at + 16) != (0x2804 | index << 8)
                or (_u16(image, at + 20) or 0) & 0xFF00 != 0xDB00
                or _conditional_target(at + 20, _u16(image, at + 20)) != at):
            continue
        # A retained literal on just one branch is insufficient port provenance.
        if any(_thumb_writes_register(_u16(image, pc) or 0, port)
               and (_u16(image, pc) or 0) & 0xFF00 != 0xBD00
               for pc in reached if entry + 4 <= pc < at):
            continue
        candidates.append({
            "loop_file_offset": image_offset + at,
            "aperture": aperture, "fifo_offset": 12, "access_width": 2,
            "peak_count": 4, "words_per_record": 8,
            "word_pair_record_offsets": (a[3], b[3]),
        })
    if len(candidates) != 1:
        return {**result, "reject_reason": f"search2-result-loop-cardinality:{len(candidates)}"}
    return {**result, **candidates[0], "confidence": "static-shape",
            "entry_file_offset": entry_file_offset, "reject_reason": None}


def _search2_worker_tail(image, worker, base):
    matches = []
    for load, body, branch, returned in ((0x74,0x76,0x7c,0x7e),(0x72,0x74,0x7a,0x7c)):
        matches.append(_literal(image,worker+load,0,0)==base
            and image[worker+body:worker+body+6]==bytes.fromhex('007a8407a40f')
            and _conditional_target(worker+branch,_u16(image,worker+branch))==worker+0x1a
            and _u16(image,worker+returned)==0xbdf0)
    return sum(matches)==1


def find_search2_transport_profile(
        image: bytes, tick_position: int,
) -> dict[str, object]:
    """Bind an experimental primary-NOR transport; never invent RF samples."""
    from .rex import find_rex_5ms_irq_route, _rex_5ms_registration_targets

    result: dict[str, object] = {
        "signature": "thumb-search2-six-word-four-pair-v1",
        "accepted": False, "active": False,
        "semantic_limit": "transport topology only; RF samples and timing require an explicit backend",
    }

    def reject(reason: str) -> dict[str, object]:
        return {**result, "reject_reason": reason}

    packed = bytes.fromhex(
        "8e80049a8a80039a8a808c80c2088a803a7a400392021043"
        "ba7a120210437a7a10438880"
    )
    writers = []
    at = 0
    while (at := image.find(packed, at)) >= 0:
        if not at & 1 and at >= 20:
            base = _literal(image, at - 2, 1, 0)
            tables = [_literal(image, at - delta, 1, 0) for delta in (20, 16)]
            entry = _thumb_function_start(image, at)
            if (base == 0x03000800 and entry < at
                    and at in _thumb_reachable(image, entry, min(len(image), entry + _MAX_FUNCTION_BYTES))
                    and _u16(image, at - 18) == 0x5A0A
                    and _u16(image, at - 12) == 0x5A0A
                    and all(t is not None and 0 <= t <= len(image) - 1024
                            for t in tables)):
                values = [struct.unpack_from("<512H", image, t) for t in tables]
                if (all(0 < v < 0x8000 for table in values for v in table)
                        and len(set(zip(*values))) == 512):
                    writers.append((at, entry, base, tables))
        at += 2
    if len(writers) != 1:
        return reject(f"search2-writer-cardinality:{len(writers)}")
    writer, entry, base, tables = writers[0]
    consumers = []
    for match in re.finditer(rb"[\x00-\xff]\xb5[\x00-\xff][\x4c-\x4f]", image):
        if match.start() & 1 or _literal(image, match.start() + 2,
                                        image[match.start() + 3] & 7, 0) != base:
            continue
        consumer = detect_search2_result_shape(image, match.start())
        if (consumer["confidence"] == "static-shape"
                and consumer["word_pair_record_offsets"] == (44, 36)):
            consumers.append(consumer)
    if len(consumers) != 1:
        return reject(f"search2-consumer-cardinality:{len(consumers)}")
    consumer = consumers[0]
    calls: dict[int, list[int]] = {}
    for match in re.finditer(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", image):
        pc = match.start()
        if not pc & 1 and (target := thumb_bl_target(image, pc)) is not None:
            calls.setdefault(target, []).append(pc)
    workers = []
    for call in calls.get(consumer["entry_file_offset"], []):
        worker = _thumb_function_start(image, call)
        info = _literal(image, worker + 4, 1, 0)
        if (call != worker + 0x4A or _u16(image, worker) != 0xB5F0
                or not _search2_worker_tail(image, worker, base)
                or info is None
                or _literal(image, consumer["entry_file_offset"] + 0x12, 4, 0) != info
                or _literal(image, worker + 0x42, 1, 0) != info
                or image[worker + 0x3E:worker + 0x42] != bytes.fromhex("a00805d3")
                or image[worker + 0x44:worker + 0x4A] != bytes.fromhex("0878002801d0")):
            continue
        workers.append(worker)
    if len(set(workers)) != 1:
        return reject(f"search2-worker-cardinality:{len(set(workers))}")
    worker = workers[0]
    loop = consumer["loop_file_offset"]
    pending = _literal(image, writer + 44, 0, 0)
    queue_put = thumb_bl_target(image, writer + 46)
    queue_get = thumb_bl_target(image, loop - 12)
    if (pending is None or not 0x01000000 <= pending < 0x02000000
            or _literal(image, loop - 14, 0, 0) != pending
            or _u16(image, writer + 42) != 0x1C39
            or _u16(image, loop - 4) != 0x6A03
            or queue_put is None or not 0 <= queue_put < len(image)
            or queue_get is None or not 0 <= queue_get < len(image)):
        return reject("search2-pending-queue-unclosed")
    if tick_position & 1 or not 0 <= tick_position < len(image):
        return reject("search2-timer-entry-invalid")
    route = find_rex_5ms_irq_route(image, tick_position)
    registrations = _rex_5ms_registration_targets(image, tick_position)
    if route is None or len(registrations) != 3 or len(set(registrations)) != 1:
        return reject("search2-controller-route-unclosed")
    registrar = registrations[0]
    callbacks = []
    for call in calls.get(worker, []):
        callback = _thumb_function_start(image, call)
        if (call == callback + 0x16 and _u16(image, callback) == 0xB580
                and image[callback + 4:callback + 8] == bytes.fromhex("00780028")
                and _literal(image, callback + 0xA, 0, 0) == base
                and image[callback + 0xC:callback + 0x16]
                == bytes.fromhex("007a8707bf0fb80801d3")
                and _literal(image, callback + 0x1E, 1, 0) == worker | 1
                and _u16(image, callback + 0x20) == 0x2006
                and thumb_bl_target(image, callback + 0x22) == registrar
                and thumb_bl_target(image, callback + 0x2C) == worker):
            callbacks.append(callback)
    if len(set(callbacks)) != 1:
        return reject(f"search2-callback-cardinality:{len(set(callbacks))}")
    callback = callbacks[0]
    initial = []
    for call in calls.get(registrar, []):
        if (_u16(image, call - 2) == 0x2006
                and _literal(image, call - 4, 1, 0) == callback | 1):
            initial.append(call)
    if len(initial) != 1:
        return reject(f"search2-registration-cardinality:{len(initial)}")
    wrapper, handler, handler_slot, timer_slot, status, enable, mask = route
    descriptor_table = struct.unpack_from("<I", image, handler + 0x168)[0]
    if descriptor_table + 28 * 28 + 20 != timer_slot:
        return reject("search2-descriptor-table-mismatch")
    prefix = struct.pack("<3I", status, enable, mask)
    if image.count(prefix) != 1:
        return reject("search2-descriptor-template-ambiguous")
    timer_template = image.find(prefix)
    search_template = timer_template - (28 - 6) * 28
    if search_template < 0:
        return reject("search2-descriptor-template-outside-primary")
    timer_row = struct.unpack_from("<7I", image, timer_template)
    row = struct.unpack_from("<7I", image, search_template)
    if (row[:2] != (status, enable) or row[3:] != timer_row[3:]
            or row[2] != 0x80 or row[2] == mask):
        return reject("search2-interrupt-descriptor-mismatch")
    return {**result, "accepted": True, "reject_reason": None,
            "aperture": base, "writer_entry": entry,
            "write_sites": tuple(writer + delta for delta in (0, 4, 8, 10, 14, 34)),
            "mask_tables": tuple(tables), "consumer": consumer,
            "worker": worker, "callback": callback, "registration": initial[0],
            "pending_queue": pending, "queue_put": queue_put, "queue_get": queue_get,
            "irq_wrapper": wrapper, "irq_handler": handler,
            "irq_handler_slot": handler_slot, "irq_status": status,
            "irq_enable": enable, "irq_mask": row[2],
            "irq_callback_slot": descriptor_table + 6 * 28 + 20}


def _search1_result_at(image: bytes, at: int) -> dict[str, object] | None:
    if at < 64 or at & 1 or at + 24 > len(image):
        return None
    w = struct.unpack_from("<12H", image, at)
    first, energy = _load_store(w[0]), _load_store(w[1])
    if not first or first[0] != "strb" or first[3] != 8:
        return None
    _, index, base, _ = first
    if not energy or energy[0] != "ldrh" or energy[2:] != (base, 4):
        return None
    value, address = energy[1], w[2] & 7
    add = _add_reg(w[3])
    if (w[2] & 0xFFC0 != 0x0040 or (w[2] >> 3) & 7 != index
            or not add or add[:2] != (address, address)):
        return None
    record = add[2]
    if (len({index, base, value, address, record}) != 5
            or _load_store(w[4]) != ("strh", value, address, 44)
            or _load_store(w[5]) != ("ldrh", value, base, 12)
            or w[6] != (0x3001 | index << 8)
            or w[7] != (0x0400 | index << 3 | index)
            or w[8] != (0x1400 | index << 3 | index)
            or w[9] != (0x2804 | index << 8)
            or _load_store(w[10]) != ("strh", value, address, 36)
            or w[11] != 0xDBF3 or _u16(image, at - 2) != (0x2000 | index << 8)):
        return None
    bindings = []
    for load in range(at - 64, at - 2, 2):
        if _literal(image, load, base, 0) != 0x03000040:
            continue
        valid = True
        for pc in range(load + 2, at, 2):
            op = _u16(image, pc)
            access = _load_store(op)
            if access:
                valid &= not (access[0].startswith("ldr") and access[1] == base)
            elif op & 0xF800 in (0x4800, 0x2000):
                valid &= (op >> 8) & 7 != base
            else:
                valid = False
        if valid:
            bindings.append(load)
    if len(bindings) != 1:
        return None
    return {"loop_file_offset": at, "base_literal_load": bindings[0],
            "aperture": 0x03000040, "selector_offset": 8,
            "energy_offset": 4, "index_offset": 12, "peak_count": 4,
            "record_offsets": [44, 36], "access_width": 2,
            "registers": {"index": index, "base": base, "value": value,
                          "address": address, "record": record}}


def _find_search1_result(image: bytes) -> dict[str, object] | None:
    matches = [shape for m in re.finditer(b"\xf3\xdb", image)
               if (shape := _search1_result_at(image, m.start() - 22))]
    return matches[0] if len(matches) == 1 else None


def _find_search1_writer(image: bytes, profile: dict) -> dict[str, object] | None:
    consumer = _find_search1_result(image)
    if not consumer or not profile["accepted"]:
        return None
    entry = _thumb_function_start(image, consumer["loop_file_offset"])
    pending = _literal(image, entry + 2, 0, 0)
    if (pending is None or not 0x01000000 <= pending < 0x02000000
            or thumb_bl_target(image, entry + 4) != profile["queue_get"]):
        return None
    stores = ((0, 0x40), (4, 0x44), (10, 0x10), (16, 0x3C), (42, 4),
              (46, 8), (52, 12), (56, 0x14), (118, 0x18), (122, 0x1C),
              (138, 0x20), (142, 0x24), (144, 0x28), (148, 0x2C),
              (166, 0x30), (170, 0x34), (174, 0x38))
    opcodes = (0x700A, 0x7108, 0x7010, 0x7308, 0x7101, 0x7201,
               0x7301, 0x7110, 0x7211, 0x7310, 0x7003, 0x7102,
               0x7201, 0x7301, 0x7008, 0x7108, 0x7208)
    matches = []
    for match in re.finditer(bytes.fromhex("0a7000120871787a"), image):
        first = match.start()
        if first & 1 or first < 4 or first + 176 > len(image):
            continue
        if any(_u16(image, first + delta) != op
               for (delta, _), op in zip(stores, opcodes)):
            continue
        if any(_literal(image, first + delta, reg, 0) != address
               for delta, reg, address in (
                   (-4, 1, 0x03000040), (8, 2, 0x03000010), (14, 1, 0x03000030),
                   (112, 2, 0x03000010), (134, 0, 0x03000020), (152, 1, 0x03000030))):
            continue
        if (image[first + 38:first + 42] != bytes.fromhex("03200006")
                or [_literal(image, first + d, 1, 0) for d in (124, 130)]
                != list(profile["mask_tables"])):
            continue
        writer = _thumb_function_start(image, first)
        body = _function(image, writer)
        if not body:
            continue
        puts = [pc for pc in body[0]
                if thumb_bl_target(image, pc) == profile["queue_put"]
                and _literal(image, pc - 4, 0, 0) == pending
                and _u16(image, pc - 2) == 0x1C39]
        if len(puts) != 1:
            continue
        matches.append({"writer_entry": writer, "first_store": first,
                        "last_store": first + 174,
                        "stores": [{"pc": first + delta,
                                    "address": 0x03000000 + offset, "width": 1}
                                   for delta, offset in stores],
                        "pending_queue": pending, "consumer_entry": entry,
                        "consumer": consumer})
    return matches[0] if len(matches) == 1 else None


_S1_SITES = (0, 4, 10, 16, 78, 82, 88, 94, 170, 174, 190, 194, 196, 200, 212, 216, 220)

_S1_OFFSETS = (64, 68, 16, 60, 4, 8, 12, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56)

_S1_OPS = (28682, 28936, 28688, 29448, 28931, 29187, 29443, 28952, 29201, 29456, 28675, 28930, 29185, 29441, 28680, 28936, 29192)

_S1_BLOCKS = {22: 'cb8d107883420bd1032809d03b79032b06d0088e032803d0052b01d0052814d1', 56: 'fc2345882b40bd7aad07ad0f2b4343804388', 74: '03200006', 80: 'bb8a', 84: 'bb8a1b0a', 90: 'f88a', 96: '10780623c88538790886'}

def _find_conditional_search1_writer(image, shared):
    if shared.get('accepted') is not True:
        return None
    consumer = _find_search1_result(image)
    if consumer is None:
        return None
    entry = _thumb_function_start(image, consumer['loop_file_offset'])
    pending = _literal(image, entry + 2, 0, 0)
    if pending is None or not 16777216 <= pending <= 33554420 or thumb_bl_target(image, entry + 4) != shared['queue_get']:
        return None
    matches = []
    for match in re.finditer(bytes.fromhex('0a7000120871787a'), image):
        first = match.start()
        if first & 1 or first < 4 or first + 222 > len(image):
            continue
        if any((_u16(image, first + d) != op for d, op in zip(_S1_SITES, _S1_OPS))):
            continue
        if any((image[first + d:first + d + len(bytes.fromhex(raw))] != bytes.fromhex(raw) for d, raw in _S1_BLOCKS.items())):
            continue
        if any((_literal(image, first + d, reg, 0) != value for d, reg, value in ((-4, 1, 50331712), (8, 2, 50331664), (14, 1, 50331696), (92, 3, 50331664), (168, 2, 50331664), (186, 0, 50331680), (204, 1, 50331696)))):
            continue
        if [_literal(image, first + d, 1, 0) for d in (176, 182)] != list(shared['mask_tables']):
            continue
        cache = _literal(image, first + 18, 1, 0)
        current = _literal(image, first + 20, 2, 0)
        shadow = _literal(image, first + 54, 0, 0)
        if any((v is None or not 16777216 <= v <= 33554432 - span for v, span in ((cache, 50), (current, 1), (shadow, 4)))):
            continue
        ranges = ((cache, cache + 50), (current, current + 1), (shadow, shadow + 4))
        if any((a < d and c < z for i, (a, z) in enumerate(ranges) for c, d in ranges[i + 1:])):
            continue
        writer = _thumb_function_start(image, first)
        body = _function(image, writer)
        if writer != first - 84 or body is None or body[1] != writer + 388 or (_u16(image, writer) != 46584) or (_u16(image, writer + 388) != 48632) or (thumb_bl_target(image, writer + 4) != shared['queue_get']) or (not set((first + d for d in _S1_SITES)).issubset(body[0])):
            continue
        owner = _literal(image, entry + 12, 5, 0)
        if owner is None or not 16777216 <= owner <= 33554412 or _literal(image, writer + 12, 6, 0) != owner:
            continue
        puts = [pc for pc in body[0] if thumb_bl_target(image, pc) == shared['queue_put'] and _literal(image, pc - 4, 0, 0) == pending and (_u16(image, pc - 2) == 7225)]
        if len(puts) != 1:
            continue
        matches.append({'writer_entry': writer, 'first_store': first, 'last_store': first + 220, 'grammar': 'conditional-config-cache-v1', 'optional_config_lanes': [4, 5, 6, 7], 'stores': [{'pc': first + d, 'address': 50331648 + off, 'width': 1} for d, off in zip(_S1_SITES, _S1_OFFSETS)], 'pending_queue': pending, 'consumer_entry': entry, 'consumer': consumer, 'cache_address': cache, 'current_address': current, 'shadow_address': shadow, 'evidence_status': 'temporary-one-witness-class, runtime activation requires native gate'})
    return matches[0] if len(matches) == 1 else None

def find_search1_transport_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind the byte-program/selected-result class; leave native activation off."""
    result = {"signature": "thumb-search1-byte-program-selected-four-pair-v1",
              "accepted": False, "active": False,
              "semantic_limit": "static command/queue/result class; RF and timing need a backend"}
    shared = find_search2_transport_profile(image, tick_position)
    if not shared["accepted"]:
        return {**result, "reject_reason": "search1-shared-route:" + shared["reject_reason"]}
    writer = _find_search1_writer(image, shared)
    if writer is None:
        writer = _find_conditional_search1_writer(image, shared)
    if writer is None:
        return {**result, "reject_reason": "search1-command-result-link-unclosed"}
    return {**result, **writer, "accepted": True, "reject_reason": None,
            "shared_search2_profile": shared}


def _finger_quality_at(image: bytes, read: int) -> dict[str, object] | None:
    if read<64 or read&1 or read+68>len(image):return None
    prefix={-56:0x2101,-54:0x4081,-50:0x7219,-46:0x8a0d,-44:0x2148,
            -42:0x4341,-40:0x1909,-38:0x1dcb,-36:0x3339,-34:0x801d,-30:0x7a2d,-28:0x709d}
    tail={0:0x899b,2:0x9301,6:0xae01,8:0x7836,10:0x78ab,12:0x401e,
          14:0xab01,16:0x701e,18:0x785b,20:0x878b,22:0x786d,24:0x9e01,
          26:0x40ae,30:0x1c33,32:0x42ab,34:0x9601,36:0xd800,38:0x9d01,
          40:0x9501,42:0xab01,44:0x785b,46:0x2508,48:0x4085,50:0x874b,
          52:0x1c2b,54:0x4013,56:0x3001,58:0x0400,60:0x0c00,62:0x870b,
          64:0x42b8,66:0xdbc1}
    if any(_u16(image,read+d)!=op for d,op in (prefix|tail).items()):return None
    if any(_literal(image,read+d,r,0)!=value for d,r,value in
           [(-52,3,0x3000070),(-48,1,0x30000a0),(-32,5,0x30000b0),
            (-2,3,0x3000080),(28,5,0xffff)]):return None
    if any(_thumb_writes_register(_u16(image,pc),1) for pc in range(read-32,read-2,2)):return None
    scale=_literal(image,read+4,5,0)
    if scale is None or not 0x1000000<=scale<=0x1fffffc:return None
    entry=_thumb_function_start(image,read);body=_function(image,entry)
    if not body or read not in body[0] or _u16(image,entry+2)!=0x1c04:return None
    if _literal(image,entry+28,0,0)!=0x30000e0 or _u16(image,entry+30)!=0x7902:return None
    return {'signature':'thumb-selected-finger-rssi-u16-scale-u8-v1','active':False,
            'entry':entry,'loop':read-56,'selector_store':read-50,'rss_word_read':read,
            'rss_address':0x300008c,'rss_width':2,'quality_store':read+50,'stride':72,
            'quality_offset':58,'raw_upper_offset':60,'lock_flags_offset':56,
            'position_low_address':0x30000b0,'position_high_address':0x30000b8,
            'scale_shift_address':scale+1,'low_mask_address':scale+2,
            'semantic_limit':'static selected-bank/read/scale/record dataflow only; physical energy, lock and RF timing unclosed'}

def _find_finger_quality(image: bytes) -> dict[str, object] | None:
    shapes=[s for m in re.finditer(bytes.fromhex('9b890193'),image) if (s:=_finger_quality_at(image,m.start()))]
    return shapes[0] if len(shapes)==1 else None


def find_finger_transport_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Find a selected-bank receiver class; keep activation explicit."""
    result = {"signature": "thumb-selected-finger-rssi-u16-scale-u8-v1",
              "accepted": False, "active": False,
              "semantic_limit": "static RSSI/position dataflow; physical energy and timing need a backend"}
    shared = find_search2_transport_profile(image, tick_position)
    if not shared["accepted"]:
        return {**result, "reject_reason": "finger-shared-route:" + shared["reject_reason"]}
    reader = _find_finger_quality(image)
    if reader is None:
        return {**result, "reject_reason": "finger-selected-reader-unclosed"}
    return {**result, **reader, "accepted": True, "reject_reason": None,
            "mask_tables": shared["mask_tables"], "bank_count": 4,
            "shared_search2_profile": shared}


def find_decoder_init_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind a bounded initialization-IRQ probe, not a decoded radio channel."""
    from .rex import find_rex_5ms_irq_route

    result = {"signature": "thumb-decoder-six-halfword-init-v1", "accepted": False,
              "active": False, "semantic_limit": "one initialization IRQ only; no decoded samples, clock calibration or service"}

    def reject(reason):
        return {**result, "reject_reason": reason}

    reader_pattern = re.compile(
        rb"\x00\xb5.\x4a\x00\x21\x11\x83\x06\x22\x01\x1c.\x48....\x00\xbd", re.S)
    copy_code = bytes.fromhex("90b5002304e004881f1c7f00cc5301339342f8db90bd")
    readers = []
    for match in reader_pattern.finditer(image):
        at = match.start()
        helper = thumb_bl_target(image, at + 14)
        if (not at & 1 and helper is not None
                and image[helper:helper + len(copy_code)] == copy_code
                and _literal(image, at + 2, 2, 0) == 0x03000a40
                and _literal(image, at + 12, 0, 0) == 0x03000a70):
            readers.append((at, helper))
    if len(readers) != 1:
        return reject(f"decoder-reader-cardinality:{len(readers)}")
    reader, helper = readers[0]
    transport = find_search2_transport_profile(image, tick_position)
    route = find_rex_5ms_irq_route(image, tick_position)
    if not transport["accepted"] or route is None:
        return reject("decoder-controller-route-unclosed")
    calls = {}
    for match in re.finditer(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", image):
        pc = match.start()
        if not pc & 1 and (target := thumb_bl_target(image, pc)) is not None:
            calls.setdefault(target, []).append(pc)
    reader_calls = calls.get(reader, [])
    if len(reader_calls) != 1:
        return reject(f"decoder-isr-cardinality:{len(reader_calls)}")
    isr = _thumb_function_start(image, reader_calls[0])
    if _u16(image, isr) != 0xb5b0 or reader_calls[0] != isr + 0x56:
        return reject("decoder-isr-shape")
    registrar = thumb_bl_target(image, transport["registration"])
    registrations = [pc for pc in calls.get(registrar, [])
                     if _u16(image, pc - 2) == 0x2005
                     and _literal(image, pc - 4, 1, 0) == (isr | 1)]
    if len(registrations) != 1:
        return reject(f"decoder-registration-cardinality:{len(registrations)}")
    registration = registrations[0]
    initializer = thumb_bl_target(image, registration + 10)
    if initializer is None:
        return reject("decoder-initializer-call")
    write = initializer + 0x34
    if (image[write - 10:write - 8] != bytes.fromhex("b988")
            or image[write - 6:write + 2] != bytes.fromhex("1940b980b9882181")
            or not _literal(image, write - 8, 3, 0) == 0xfff8
            or not _literal(image, write - 0x24, 4, 0) == 0x03000a00
            or image[initializer + 0x12:initializer + 0x1e]
            != bytes.fromhex("194040231943b980b9882181")):
        return reject("decoder-sync-init-shape")
    prefix = struct.pack("<3I", transport["irq_status"], transport["irq_enable"], route[-1])
    if image.count(prefix) != 1:
        return reject("decoder-descriptor-template-ambiguous")
    timer_at = image.find(prefix)
    row_at = timer_at - (28 - 5) * 28
    if row_at < 0:
        return reject("decoder-descriptor-outside-primary")
    row = struct.unpack_from("<7I", image, row_at)
    timer = struct.unpack_from("<7I", image, timer_at)
    mask = row[2]
    if (row[:2] != timer[:2] or row[3:] != timer[3:] or not mask
            or mask > 0xffff or mask & (mask - 1)
            or mask in (route[-1], transport["irq_mask"])):
        return reject("decoder-descriptor-mismatch")
    return {**result, "accepted": True, "reject_reason": None,
            "reader": reader, "copy_helper": helper, "data_words": 6,
            "descriptor_template": row_at,
            "initializer": initializer, "init_write": write, "isr": isr,
            "registration": registration,
            "irq_callback_slot": transport["irq_callback_slot"] - 28,
            "irq_status": row[0], "irq_enable": row[1], "irq_mask": mask}


def find_combiner_clock_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Couple the latched phase getter and roll ISR to the decoder controller."""
    result = {"signature": "thumb-combiner-latched-phase-v1", "accepted": False,
              "active": False, "semantic_limit": "static clock topology; epoch/SLAM and fractional physical calibration unverified"}

    def reject(reason):
        return {**result, "reject_reason": reason}

    def fixed(value):
        return re.escape(bytes.fromhex(value))

    pattern = re.compile(fixed("08b5") + b"...." + fixed("0104090c") + b"."
                         + fixed("4800220271027a00ab1a70007b5870002901d1")
                         + b"...." + fixed("00a8008808bd"), re.S)
    getters = [m.start() for m in pattern.finditer(image)
               if not m.start() & 1 and _literal(image, m.start() + 10, 0, 0) == 0x030000f0]
    if len(getters) != 1:
        return reject(f"combiner-position-getter-cardinality:{len(getters)}")
    getter = getters[0]
    decoder = find_decoder_init_profile(image, tick_position)
    if not decoder["accepted"]:
        return reject("combiner-decoder-controller-unclosed")
    registrar = thumb_bl_target(image, decoder["registration"])
    candidates = {}
    for m in re.finditer(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", image):
        pc = m.start()
        if pc & 1 or _u16(image, pc - 2) != 0x2001 or thumb_bl_target(image, pc) != registrar:
            continue
        pointer = _literal(image, pc - 4, 1, 0)
        if pointer is None or not pointer & 1:
            continue
        callback = pointer - 1
        if (thumb_bl_target(image, callback + 0x1aa) == getter
                and thumb_bl_target(image, callback + 0x2a4) == getter):
            candidates.setdefault(callback, []).append(pc)
    if len(candidates) != 1:
        return reject(f"combiner-roll-isr-cardinality:{len(candidates)}")
    callback = next(iter(candidates))
    row_at = decoder["descriptor_template"] - 4 * 28
    if row_at < 0:
        return reject("combiner-roll-descriptor-outside-primary")
    row = struct.unpack_from("<7I", image, row_at)
    other = struct.unpack_from("<7I", image, decoder["descriptor_template"])
    mask = row[2]
    if (row[:2] != other[:2] or row[3:] != other[3:] or not mask
            or mask > 0xffff or mask & (mask - 1) or mask == other[2]):
        return reject("combiner-roll-descriptor-mismatch")
    first_shape = bytes.fromhex("48220092f81d01302a1c18230021061c")
    second_shape = bytes.fromhex("1822009200234821301c2a1c")
    consumers = []
    at = 0
    queue = _literal(image, decoder["isr"] + 0x5e, 0, 0)
    queue_get = thumb_bl_target(image, decoder["isr"] + 0xc)
    while (at := image.find(first_shape, at)) >= 0:
        entry = _thumb_function_start(image, at)
        if (at == entry + 0x16
                and image[entry + 0x42:entry + 0x4e] == second_shape
                and thumb_bl_target(image, entry + 0x26) is not None
                and thumb_bl_target(image, entry + 0x26) == thumb_bl_target(image, entry + 0x4e)
                and queue is not None and _literal(image, entry + 0x64, 0, 0) == queue
                and queue_get is not None and thumb_bl_target(image, entry + 0x66) == queue_get):
            consumers.append(entry)
        at += 2
    if len(consumers) != 1:
        return reject(f"decoder-pipeline-consumer-cardinality:{len(consumers)}")
    return {**result, "accepted": True, "reject_reason": None,
            "sync_consumer": consumers[0], "decoder_pipeline_bits": 24,
            "position_getter": getter, "roll_isr": callback,
            "registrations": candidates[callback], "irq_mask": mask,
            "descriptor_template": row_at,
            "irq_callback_slot": decoder["irq_callback_slot"] - 4 * 28}


def find_paging_decoder_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind the paging IRQ/read/carry class; decoded source activation stays explicit."""
    result = {"signature": "thumb-paging-two-subframe-head72-v1", "accepted": False,
              "active": False, "semantic_limit": "static paging transport; ideal metrics and physical timing remain provisional"}

    def reject(reason):
        return {**result, "reject_reason": reason}

    def code(at, value):
        expected = bytes.fromhex(value)
        return at >= 0 and image[at:at + len(expected)] == expected

    decoder = find_decoder_init_profile(image, tick_position)
    clock = find_combiner_clock_profile(image, tick_position)
    if not decoder["accepted"] or not clock["accepted"]:
        return reject("paging-shared-decoder-clock-unclosed")
    readers = []
    pattern = rb"\x00\xb5.\x4a\x00\x21\x11\x83.\x49\x0a\x88\x01\x1c.\x48....\x00\xbd"
    for match in re.finditer(pattern, image, re.S):
        at = match.start()
        count = _literal(image, at + 8, 1, 0)
        if (not at & 1 and _literal(image, at + 2, 2, 0) == 0x03000a40
                and _literal(image, at + 14, 0, 0) == 0x03000a70
                and thumb_bl_target(image, at + 16) == decoder["copy_helper"]
                and count is not None and 0x01000000 <= count <= 0x01fffffe
                and not count & 1):
            readers.append((at, count))
    if len(readers) != 1:
        return reject(f"paging-reader-cardinality:{len(readers)}")
    reader, count = readers[0]
    calls = {}
    for match in re.finditer(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", image):
        pc = match.start()
        if not pc & 1 and (target := thumb_bl_target(image, pc)) is not None:
            calls.setdefault(target, []).append(pc)
    if len(calls.get(reader, [])) != 1:
        return reject("paging-isr-cardinality")
    isr = _thumb_function_start(image, calls[reader][0])
    shift = 0
    if (calls[reader][0] == isr + 0x160 and _u16(image,isr)==0xb5fc
            and code(isr+0x15a,"f81d0130061c") and code(isr+0x1ba,"0220b880")
            and code(isr+0x140,"fcbd") and code(isr+0x1ec,"a8e7")):
        returned = thumb_bl_target(image,isr+0x1e8)
        if returned is None or not code(returned,"f746"):
            return reject("paging-return-helper-unclosed")
        shift = 2
    elif (calls[reader][0] != isr + 0x162 or _u16(image, isr) != 0xb5fc
            or not code(isr + 0x15c, "f81d0130061c")
            or not code(isr + 0x1bc, "0220b880")):
        return reject("paging-isr-reader-shape")
    status = thumb_bl_target(image, isr + 0xda - shift)
    initializer = thumb_bl_target(image, isr + 0x1e2 - shift)
    if status is None or initializer is None:
        return reject("paging-isr-callees")
    if (not code(status + 4, "09881183")
            or not code(status + 10, "118a417009120170118a4180f746")
            or _literal(image, status, 1, 0) != count
            or _literal(image, status + 2, 2, 0) != 0x03000a40
            or _literal(image, status + 8, 2, 0) != 0x03000a60):
        return reject("paging-status-wordcount-shape")
    if (not code(initializer, "b0b5071c")
            or not code(initializer + 0x14, "194020231943a180a1882981")
            or not code(initializer + 0x2c, "a188")
            or not code(initializer + 0x30, "1940a180a1882981")
            or _literal(image, initializer + 0x12, 5, 0) != 0x03000a00
            or _literal(image, initializer + 0xe, 3, 0) != 0xff9f
            or _literal(image, initializer + 0x2e, 3, 0) != 0xfff8):
        return reject("paging-20ms-initializer-shape")
    mode = thumb_bl_target(image, initializer + 4)
    if (mode is None or not code(mode, "00b5")
            or _literal(image, mode + 2, 1, 0) != count
            or not code(mode + 4, "002803d0012804d1062000e00c20088004e0")):
        return reject("paging-rate-wordcount-shape")
    registrar = thumb_bl_target(image, decoder["registration"])
    registrations = [pc for pc in calls.get(registrar, [])
                     if _u16(image, pc - 2) == 0x2005
                     and _literal(image, pc - 4, 1, 0) == (isr | 1)]
    if len(registrations) != 1:
        return reject("paging-slot5-registration-cardinality")
    sync = clock["sync_consumer"]
    bitcopy = thumb_bl_target(image, sync + 0x26)
    queue_get = thumb_bl_target(image, decoder["isr"] + 0xc)
    queue = _literal(image, isr + 0x1c0 - shift, 0, 0)
    if queue is None or not 0x01000000 <= queue <= 0x01fffff4:
        return reject("paging-consumer-queue-unclosed")
    consumers = []
    for match in re.finditer(re.escape(bytes.fromhex("a2880021281c00926388321c")), image):
        entry = match.start() - 0x46
        cache = _literal(image, entry + 0x1a, 0, 0)
        if (entry < 0 or entry & 1 or _u16(image, entry) != 0xb5f8 or cache is None
                or not 0x01000000 <= cache <= 0x01ffff00
                or _literal(image, entry + 0xc, 6, 0) != cache + 0x22
                or any(_literal(image, entry + delta, reg, 0) != cache
                       for delta, reg in ((0x28, 1), (0x30, 0), (0x3e, 0),
                                          (0x52, 7), (0x96, 7)))
                or not code(entry + 0xe, "f51f113dec1d2f34")
                or not code(entry + 0x18, "f91d") or not code(entry + 0x1c, "01311822281c")
                or not code(entry + 0x7a, "62880023281c0092a188321c")
                or thumb_bl_target(image, entry + 0x54) != bitcopy
                or thumb_bl_target(image, entry + 0x86) != bitcopy
                or thumb_bl_target(image, entry + 0xc6) != queue_get
                or _literal(image, entry + 0xc4, 0, 0) != queue):
            continue
        layouts = []
        for layout in re.finditer(re.escape(bytes.fromhex("c02000e060204887")), image):
            at = layout.start()
            if (not at & 1 and _literal(image, at - 6, 1, 0) == cache
                    and _literal(image, at + 8, 5, 0) == cache + 0x40
                    and _literal(image, at + 12, 1, 0) == cache
                    and code(at + 10, "4820")
                    and code(at + 14, "a880488f483868804e8f70080004000c8887")):
                layouts.append(at)
        if len(layouts) == 1:
            consumers.append((entry, cache, layouts[0]))
    if len(consumers) != 1:
        return reject(f"paging-head72-consumer-cardinality:{len(consumers)}")
    consumer, cache, layout = consumers[0]
    return {**result, "accepted": True, "reject_reason": None,
            "isr": isr, "reader": reader, "status_reader": status,
            "initializer": initializer, "init_write": initializer + 0x36,
            "wordcount_address": count, "consumer": consumer,
            "registration": registrations[0], "copy_helper": decoder["copy_helper"],
            "bitcopy_helper": bitcopy, "mode_initializer": mode,
            "pipeline_cache": cache, "pipeline_layout": layout, "head_bits": 72,
            "frame_bits": [192, 96], "data_words": [12, 6],
            "descriptor_template": decoder["descriptor_template"],
            "irq_callback_slot": decoder["irq_callback_slot"],
            "irq_status": decoder["irq_status"], "irq_enable": decoder["irq_enable"],
            "irq_mask": decoder["irq_mask"]}


def find_search1_abort_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind the original shared-owner teardown; leave cancellation activation explicit."""
    result = {"signature": "thumb-search1-shared-owner-zero-abort-v1",
              "accepted": False, "active": False,
              "semantic_limit": "static original teardown only; cancellation needs a backend"}
    transport = find_search1_transport_profile(image, tick_position)
    if not transport["accepted"]:
        return {**result, "reject_reason": "search1-abort-transport-unclosed"}
    shared = transport["shared_search2_profile"]
    owner = _literal(image, transport["consumer_entry"] + 0xc, 5, 0)
    control = _literal(image, shared["worker"] + 4, 1, 0)
    if (owner is None or not 0x01000000 <= owner <= 0x01ffffec
            or control is None or not 0x01000000 <= control <= 0x01fffffe):
        return {**result, "reject_reason": "search1-abort-owner-unclosed"}
    fixed = {
        0: 0xb5f0, 4: 0x2700, 6: 0x7920, 0xc: 0x2800, 0xe: 0xd102,
        0x10: 0x7828, 0x12: 0x2800, 0x14: 0xd01e, 0x16: 0x706f,
        0x1c: 0x7829, 0x1e: 0x0400, 0x20: 0x0c00, 0x22: 0x2900,
        0x24: 0xd007, 0x28: 0x2302, 0x2a: 0x880a, 0x2c: 0x431a,
        0x2e: 0x7032, 0x30: 0x8809, 0x32: 0x4319, 0x34: 0x7031,
        0x36: 0x7921, 0x38: 0x2900, 0x3a: 0xd002,
        0x3e: 0x700f, 0x40: 0x710f, 0x42: 0x2800, 0x44: 0xd101,
        0x4c: 0x2009, 0x4e: 0x8008, 0x50: 0x7127, 0x52: 0x702f,
        0x54: 0x7a30, 0x5a: 0x2001, 0x5c: 0x7068,
        0x60: 0x2101, 0x62: 0x1c28, 0x6e: 0x2101,
        0x70: 0x02c9, 0x72: 0x1c28, 0x78: 0x6027, 0x7a: 0xbdf0,
    }
    matches = []
    pattern = rb"\xf0\xb5.\x4c\x00\x27\x20\x79"
    for match in re.finditer(pattern, image, re.S):
        at = match.start()
        if (at & 1 or at + 0x7c > len(image)
                or any(_u16(image, at + delta) != op for delta, op in fixed.items())
                or _literal(image, at + 2, 4, 0) != owner
                or _literal(image, at + 0xa, 5, 0) != control
                or _literal(image, at + 8, 6, 0) != 0x03000800
                or _literal(image, at + 0x3c, 1, 0) != 0x03000040
                or _literal(image, at + 0x4a, 1, 0) != 0x04800020):
            continue
        shadow = _literal(image, at + 0x26, 1, 0)
        timer = _literal(image, at + 0x68, 0, 0)
        tcb = _literal(image, at + 0x5e, 5, 0)
        clear_signal = thumb_bl_target(image, at + 0x64)
        calls = [thumb_bl_target(image, at + delta)
                 for delta in (0x18, 0x46, 0x56, 0x64, 0x6a, 0x74)]
        if (shadow is None or not 0x01000000 <= shadow <= 0x01fffffe
                or timer is None or not 0x01000000 <= timer <= 0x01ffffec
                or tcb is None or not 0x01000000 <= tcb <= 0x01fffffc
                or thumb_bl_target(image, at + 0x74) != clear_signal
                or any(target is None or not 0 <= target < len(image)
                       for target in calls)):
            continue
        matches.append(at)
    if len(matches) != 1:
        return {**result, "reject_reason": f"search1-abort-cardinality:{len(matches)}"}
    entry = matches[0]
    return {**result, "accepted": True, "reject_reason": None,
            "entry": entry, "first_store": entry + 0x3e,
            "second_store": entry + 0x40, "owner_address": owner,
            "control_address": control}


# Complete local callback variants differ only in their diagnostic block.
_TX_INIT_CALLBACK_SHAPES = (
    (bytes.fromhex("f0b5004c0121208801302080201d071c00000000004e0125307800282ed0002000000000707800280ad001281ad1381c000000000121381c00000000657516e00420000000000048007800000000301d00000000004906200870004904200000000004e0f52080000049000000000025357010210048000000003de0004f6575f81d19300079002833d0012000000000f87a00000000f87a012200217873f81d1e30000000003878032825d13e1c4037787a002820d00025004c7d72207863781b02184318d00048a070030ae370201d00000000387a0130607300000000a073f07ae073201c0000000025702b0a637002e00020000000000048042100000000f0bd"), (16, 32, 48, 56, 66, 74, 80, 94, 106, 118, 140, 146, 162, 208, 218, 230, 244, 252), (2, 20, 70, 84, 90, 104, 116, 124, 184, 198, 248)),
    (bytes.fromhex("f0b5004c0121208801302080201d071c00000000004e0125307800282dd0002000000000707800280ad001281ad1381c000000000121381c00000000657515e00420000000000048007800000000301d00000000004906200870004904200000000003e000490048000000000025357010210048000000003de0004f6575f81d19300079002833d0012000000000f87a00000000f87a012200217873f81d1e30000000003878032825d13e1c4037787a002820d00025004c7d72207863781b02184318d00048a070030ae370201d00000000387a0130607300000000a073f07ae073201c0000000025702b0a637002e00020000000000048042100000000f0bd"), (16, 32, 48, 56, 66, 74, 80, 94, 104, 116, 138, 144, 160, 206, 216, 228, 242, 250), (2, 20, 70, 84, 90, 100, 102, 114, 122, 182, 196, 246)),
)
_TX_INIT_CONTROL_SHAPE = (bytes.fromhex("f0b50049004ecc1dcf1dff37ff343a345a370028004d18d1000000003988004b1940398039882980002801d10000000000000000e18a004b194001231943e182e18ab18100282ad127e000000000004910230a781a430a700978004a1173002801d10000000000000000e18a004b194001231943e182e18ab181002801d100000000000000003988004b194004231943398039882980002801d100000000f0bd"), (24, 44, 48, 74, 98, 102, 126, 130, 154), (2, 4, 20, 30, 54, 78, 90, 108, 136))


def _tx_init_code_matches(image: bytes, entry: int, shape: tuple) -> bool:
    expected, calls, literals = shape
    if entry & 1 or not 0 <= entry <= len(image) - len(expected):
        return False
    actual = bytearray(image[entry:entry + len(expected)])
    for offset in calls:
        target = thumb_bl_target(image, entry + offset)
        if target is None or not 0 <= target < len(image):
            return False
        actual[offset:offset + 4] = b"\0" * 4
    for offset in literals:
        actual[offset] = 0
    return actual == expected


def find_tx_init_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind a local encoder initialization IRQ class; never activate or time it."""
    result = {"signature": "thumb-tx-init-slot4-armed-control-v1",
              "accepted": False, "active": False,
              "semantic_limit": "static local initialization only; timing, RF and device completion unproven"}
    decoder = find_decoder_init_profile(image, tick_position)
    if not decoder["accepted"]:
        return {**result, "reject_reason": "tx-init-controller-unclosed"}
    registrar = thumb_bl_target(image, decoder["registration"])
    descriptor = decoder["descriptor_template"] - 28
    slot = decoder["irq_callback_slot"] - 28
    if descriptor < 0 or slot < 0x01000000 + 20:
        return {**result, "reject_reason": "tx-init-descriptor-outside-primary"}
    row = struct.unpack_from("<7I", image, descriptor)
    other = struct.unpack_from("<7I", image, decoder["descriptor_template"])
    if row[:2] != other[:2] or row[3:] != other[3:] or row[2] != 8:
        return {**result, "reject_reason": "tx-init-descriptor-mismatch"}

    def ram(value, size):
        return value is not None and 0x01000000 <= value <= 0x02000000 - size

    matches = []
    for match in re.finditer(rb"\xf0\xb5.\x4c\x01\x21\x20\x88\x01\x30\x20\x80", image, re.S):
        entry = match.start()
        for shape in _TX_INIT_CALLBACK_SHAPES:
            if not _tx_init_code_matches(image, entry, shape):
                continue
            short = len(shape[0]) == 0x100
            # The shorter diagnostic block moves all following code by two bytes.
            after = lambda offset: entry + offset - (2 if short else 0)
            counter = _literal(image, entry + 2, 4, 0)
            armed = _literal(image, entry + 0x14, 6, 0)
            tcb = _literal(image, after(0x74), 0, 0)
            control = thumb_bl_target(image, entry + 0x20)
            signal = thumb_bl_target(image, after(0x76))
            if (not ram(counter, 0x140) or not ram(armed, 2)
                    or not ram(counter - 0xa4, 0x1e4) or armed != counter - 12
                    or not ram(tcb, 0x18)
                    or _literal(image, entry + 0x46, 0, 0) != counter + 0x13c
                    or not ram(_literal(image, entry + 0x54, 1, 0), 1)
                    or _literal(image, after(0x7c), 7, 0) != counter - 0xa4
                    or _literal(image, after(0xb8), 4, 0) != counter - 0x58
                    or _literal(image, after(0xc6), 0, 0) != 0x1013
                    or _literal(image, after(0xf8), 0, 0) != tcb
                    or thumb_bl_target(image, entry + 0x38) != thumb_bl_target(image, entry + 0x10)
                    or thumb_bl_target(image, entry + 0x5e) != registrar
                    or thumb_bl_target(image, after(0x8c)) != control
                    or thumb_bl_target(image, after(0xf4)) != control
                    or thumb_bl_target(image, after(0xfc)) != signal
                    or not _tx_init_code_matches(image, control, _TX_INIT_CONTROL_SHAPE)):
                continue
            alternate = _literal(image, entry + 0x5a, 1, 0)
            if (alternate is None or not alternate & 1 or alternate >= len(image)
                    or (short and _literal(image, entry + 0x66, 0, 0) != 0x3da)):
                continue
            # Bind the signal OR/store and its lock to the control helper's lock.
            if (image[signal:signal + 6] != bytes.fromhex("f0b50e1c071c")
                    or image[signal + 10:signal + 20] != bytes.fromhex("fc68051c201c3043f860")
                    or thumb_bl_target(image, signal + 6) != thumb_bl_target(image, control + 0x18)):
                continue
            shadow = _literal(image, control + 2, 1, 0)
            input_shadow = _literal(image, control + 0x4e, 1, 0)
            if (not ram(shadow, 0x180) or not ram(input_shadow, 1)
                    or _literal(image, control + 4, 6, 0) != 0x030002a0
                    or _literal(image, control + 0x14, 5, 0) != 0x030002c0
                    or _literal(image, control + 0x1e, 3, 0) != 0xfff3
                    or _literal(image, control + 0x36, 3, 0) != 0xfffc
                    or _literal(image, control + 0x5a, 2, 0) != 0x03000670
                    or _literal(image, control + 0x6c, 3, 0) != 0xfffc
                    or _literal(image, control + 0x88, 3, 0) != 0xfff3):
                continue
            registrations = []
            for call in re.finditer(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", image):
                pc = call.start()
                if (pc & 1 or _u16(image, pc - 2) != 0x2004
                        or _literal(image, pc - 4, 1, 0) != entry | 1
                        or thumb_bl_target(image, pc) != registrar):
                    continue
                start = _thumb_function_start(image, pc)
                if pc in _thumb_reachable(image, start, min(len(image), start + _MAX_FUNCTION_BYTES)):
                    registrations.append(pc)
            if len(registrations) != 1:
                continue
            pc = registrations[0]
            if (image[pc + 4:pc + 6] != bytes.fromhex("0124")
                    or _literal(image, pc + 6, 7, 0) != armed
                    or _literal(image, pc + 8, 6, 0) != tcb
                    or image[pc + 10:pc + 16] != bytes.fromhex("1021301c7c70")
                    or image[pc + 20:pc + 24] != bytes.fromhex("3c701020")):
                continue
            code_dependencies = ((entry, len(shape[0])),
                                 (control, len(_TX_INIT_CONTROL_SHAPE[0])),
                                 (registrar, 0x6e), (signal, 20),
                                 *((call - 4, 28) for call in registrations))
            ram_dependencies = ((slot - 20, 24), (armed, 16), (tcb, 0x18),
                                (counter, 0x140), (shadow, 0x180), (input_shadow, 1))
            if (any(not 0 <= address <= len(image) - size
                    for address, size in code_dependencies)
                    or any(not ram(address, size) for address, size in ram_dependencies)):
                continue
            matches.append({"callback": entry, "callback_size": len(shape[0]),
                            "callback_slot": slot, "armed_flag": armed,
                            "tx_tcb": tcb, "counter_address": counter,
                            "descriptor_template": descriptor,
                            "irq_status": row[0], "irq_enable": row[1], "irq_mask": row[2],
                            "registrations": tuple(registrations), "registrar": registrar,
                            "control_helper": control, "control_shadow": shadow,
                            "input_shadow": input_shadow, "signal_setter": signal,
                            "alternate_callback": alternate & ~1,
                            "first_flag_load": entry + 0x18,
                            "flag_clear_store": after(0x70),
                            "signal10_call": after(0x76),
                            "signal4_call": after(0xfc),
                            "code_dependencies": code_dependencies,
                            "ram_dependencies": ram_dependencies})
    if len(matches) != 1:
        return {**result, "reject_reason": f"tx-init-class-cardinality:{len(matches)}"}
    return {**result, **matches[0], "accepted": True, "reject_reason": None}


_TX_FRAME_DATA_SHAPE = (bytes.fromhex('f0b5004e051c307b0c1c171c0138032803d90049004800000000042f03d90049004800000000004e0049327b9000401840380121b940c06b401801380004000cf8400604360c0048032180181038c91b002cc07b0cd0004b1201d2188b00d318da1f093a203b5b8a1278004f3b8000e00022004f004c3b7b004fdb00df194b00ff18203f3f8ba781004f004c3f7bff003f19fb18203b1b8b004c2382004f004b3f7bdb19103bdb7b8900000108435901084311020843071c000000000049004bca891a40004b3b401a43ca81c989004a9183002801d1000000000048007b022804dd012000000000012009e0002000000000002000000000002000000000002000000000291c321c004800000000f0bd'), (22, 34, 184, 214, 228, 238, 244, 250, 256, 266), (2, 18, 20, 30, 32, 38, 40, 70, 86, 106, 114, 116, 120, 136, 138, 152, 156, 158, 188, 190, 196, 206, 218, 264))
_TX_FRAME_TABLE = bytes.fromhex('1800000024000000180000002400000000000000000000000800b0090c00130f0600c0010800b0090a00640f0c00130f0600c0090600c0090800b0090c00130f0600c0090800b0090a00640f0c00130f0600009c0600009c0800009b0c0030f1100067c8100067c8100067c8100067c8000000000000000000000000000000000000000000000000001500150015001500000000000000000000000000000000000880000000000045144514451445140100020200010001')
_TX_FRAME_FIXED_WRITER = bytes.fromhex('b0b5002357087c0006e0cf5c5d1c6b1c4d5d2d022f4307809c42f6dc520801d3c95c0180b0bd')


def find_tx_frame_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind an explicit local frame IRQ/FIFO class without selecting timing."""
    init = find_tx_init_profile(image, tick_position)
    result = {**init, "signature": "thumb-tx-frame-slot4-fixed-fifo-v1",
              "accepted": False, "active": False,
              "semantic_limit": "temporary explicit local frame IRQ/FIFO input class only; period and phase provisional; auxiliary callees, codec, RF and output completion unproven"}
    if not init["accepted"]:
        return result
    callback = init["callback"]
    data_call = callback + (0xa2 if init["callback_size"] == 0x102 else 0xa0)
    data = thumb_bl_target(image, data_call)
    if data is None or not _tx_init_code_matches(image, data, _TX_FRAME_DATA_SHAPE):
        return {**result, "reject_reason": "tx-frame-data-shape-unclosed"}
    writer = thumb_bl_target(image, data + 0x10a)
    if (writer is None or image[writer:writer + 38] != _TX_FRAME_FIXED_WRITER
            or _literal(image, data + 0x108, 0, 0) != 0x03000298):
        return {**result, "reject_reason": "tx-frame-fixed-writer-unclosed"}
    mode = _literal(image, data + 2, 6, 0)
    shadow = _literal(image, data + 0xbc, 1, 0)
    working = init["counter_address"] - 0xa4
    if (mode is None or mode & 3 or not 0x01000000 <= mode <= 0x02000000 - 16
            or shadow != init["control_shadow"] + 0x140
            or any(_literal(image, data + at, register, 0) != mode
                   for at, register in ((0x26, 6), (0x72, 7), (0x88, 7), (0x9c, 7), (0xda, 0)))
            or _literal(image, callback + (0x7c if init["callback_size"] == 0x102 else 0x7a), 7, 0) != working):
        return {**result, "reject_reason": "tx-frame-state-alias-unclosed"}
    table = _literal(image, data + 0x28, 1, 0)
    if (table is None or table & 3 or table < 8 or image[table:table + len(_TX_FRAME_TABLE)] != _TX_FRAME_TABLE
            or any(_literal(image, data + at, register, 0) != table + offset
                   for at, register, offset in ((0x46, 0, 0xb4), (0x56, 3, 0x10),
                       (0x78, 7, 0x70), (0x8a, 4, 0x90), (0x9e, 3, 0xb0)))
            or _literal(image, data + 0x12, 1, 0) != table - 8
            or _literal(image, data + 0x1e, 1, 0) != table - 8):
        return {**result, "reject_reason": "tx-frame-table-unclosed"}
    diagnostic = _literal(image, data + 0x14, 0, 0)
    # Diagnostic record IDs vary independently of the device protocol.
    if (diagnostic is None or not 0 <= diagnostic < 0xffff
            or _literal(image, data + 0x20, 0, 0) != diagnostic + 1
            or any(_literal(image, data + at, register, 0) != value
                   for at, register, value in ((0x6a, 7, 0x030002a0),
                       (0x74, 4, 0x03000220), (0x98, 4, 0x03000220),
                       (0xbe, 3, 0xf083), (0xc4, 3, 0xf7c), (0xce, 2, 0x03000280)))
            or thumb_bl_target(image, data + 0x16) != thumb_bl_target(image, data + 0x22)
            or thumb_bl_target(image, data + 0xe4) != thumb_bl_target(image, data + 0xee)
            or thumb_bl_target(image, data + 0xb8) != thumb_bl_target(image, init["control_helper"] + 0x18)
            or thumb_bl_target(image, data + 0xd6) != thumb_bl_target(image, init["control_helper"] + 0x2c)):
        return {**result, "reject_reason": "tx-frame-call-literal-alias-unclosed"}
    targets = tuple(dict.fromkeys(thumb_bl_target(image, data + at)
                                 for at in _TX_FRAME_DATA_SHAPE[1]))
    pools = tuple((((data + at + 4) & ~3) + (image[data + at] * 4), 4)
                  for at in _TX_FRAME_DATA_SHAPE[2])
    # Two-byte target spans express map bounds only, not auxiliary semantics.
    code = init["code_dependencies"] + ((data, 0x110), (writer, 38),
            (table - 8, len(_TX_FRAME_TABLE) + 8)) + pools + tuple((target, 2) for target in targets)
    ram = init["ram_dependencies"] + ((working, 0xa4), (mode, 16), (shadow, 16))
    if (any(not 0 <= address <= len(image) - size for address, size in code)
            or any(not 0x01000000 <= address <= 0x02000000 - size for address, size in ram)):
        return {**result, "reject_reason": "tx-frame-dependency-unmapped"}
    return {**result, "accepted": True, "reject_reason": None,
            "data_helper": data, "data_call": data_call, "fixed_writer": writer,
            "fifo_port": 0x03000298, "mode_base": mode, "mode_address": mode + 12,
            "mode_literal_load": data + 2, "mode_byte_load": data + 6,
            "mode_range": (1, 4), "working_base": working, "working_buffer": working + 0x25,
            "table": table, "table_size": len(_TX_FRAME_TABLE),
            "maximum_buffer_bytes": 18,
            "unclosed_auxiliary_calls": tuple(thumb_bl_target(image, data + at)
                                               for at in (0x16, 0xe4, 0xf4, 0xfa, 0x100)),
            "code_dependencies": code, "ram_dependencies": ram}


# Coupled traffic mode1 instruction classes; literal addresses and BLs bind below.
_TRAFFIC_READER_SHAPE = (bytes.fromhex("f0b5041c171c0048c9000818c51f093d002a004e01d0012f0cd1287a40083083287b40080204120c211c004800000000002f01d0022f0dd1687a40083083687b40080204120ce11d1d31004800000000002f01d0032f0dd1a87a40083083a87b40080204120ce11d2f31004800000000002f01d0042f0bd1e87a40083083e87b40080204120ce11d3931004800000000f0bd"), (44, 76, 108, 140), (6, 18, 42, 74, 106, 138))
_TRAFFIC_METRICS_SHAPE = (bytes.fromhex("b0b5004ac0008018c21f093a507a004b4008023818830048078a0f713f120f70078a0f81977a7f08023f1f83078a4f713f124f70078a4f81d77a7f08023f1f83078a8f713f128f70078a8f81d77ad27b7f085208ba181a83028aca711212ca70008ac881487940004871887980008871c879c000c871b0bd"), (), (2, 14, 22))
_TRAFFIC_INIT_SHAPE = (bytes.fromhex("b0b5071c0000000000000000004c004ba188004d194020231943a180a1882981002801d10000000000000000a188004b1940a180a1882981002801d100000000004d004c032f0cdb00000000218a004b1940022319432182218a298000280cd109e000000000218a004b19402182218a2980002801d100000000004800000000002807d1381c000000000121381c00000000b0bd00210172004a0773011c101c00000000b0bd"), (4, 8, 36, 40, 60, 72, 98, 118, 124, 134, 142, 160), (12, 14, 18, 46, 64, 66, 78, 104, 122, 152))
_TRAFFIC_REGISTRATION_SHAPE = (bytes.fromhex("00484078000000000048012100000000004905200000000004e0"), (4, 12, 20), (0, 8, 16))
_TRAFFIC_CALLBACK_SHAPE = (bytes.fromhex("f0b586b0004800888406a40e032c004d1bd12878002818d00048004940780000000000000000004a0028908104d1022701200000000003e000200000000000270021381c00000000d3e200490878002822dd01380870087800281dd1004f381c000000001022381c391c0000000000480021027802a800000000381c391c02aa000000000422381c391c000000000121381c0000000003e00048012100000000004800000000071c04d1004900480000000096e2"), (30, 34, 50, 58, 68, 96, 106, 118, 128, 138, 146, 156, 162, 174), (4, 14, 24, 26, 38, 74, 92, 110, 152, 160, 170, 172))
_TRAFFIC_DATA_CALL_SHAPE = (bytes.fromhex("f888002806d0004800224178f81d013000000000"), (16,), (6,))
_TRAFFIC_EMIT_SHAPE = (bytes.fromhex("0420b8800598004900000000391c0048000000000048082100000000"), (8, 16, 24), (6, 14, 20))
_TRAFFIC_QUALITY_SHAPE = (bytes.fromhex("00b500484178062917d202a35b5c5b009f44001c13030c0f0f0f4088032802d10000000000bd0000000000bd"), (32, 38), (2,))
_TRAFFIC_ORDINARY_SHAPE = (bytes.fromhex("b0b500480078c1070048c90f427807794079d407e40f002909d0002c03d00f3087421fdc01e04d2f37dc0420b0bd004a02239178d57819401d40d3799279002c12d03c2810dc002901d1002d0ad0002d04d0d91d033188421ddc03e0d11d0331884212dc0320b0bd00290ad0002d08d0934201da402b0edd9a420eda3c2a0cdc03e0002903d03c2a01dc0220b0bd002d03d0402b01dc0120b0bd0020b0bd"), (), (2, 8, 46))
_TRAFFIC_VARIANT_SHAPE = (bytes.fromhex("f0b5004d0223a8789843a870c820a8712878c6070048f60f417807794279cc07c178e40fc0791940002e14d0002c09d0d31d08339f420cdd00291ad00c30904228db16e04d2f27dc002902d01730b84220db0420f0bd002c0dd03c2a0bdcaf78bb0801d2002904d0002902d00a30824210dc0320f0bdaa7802231a4006d0002904d0c82808da402806dc03e0002903d0402801dc0120f0bd0020f0bd"), (), (2, 20))
_TRAFFIC_COEFFICIENTS_SHAPE = (bytes.fromhex("0022052801dd101cf74600490a83004a80018218d01f393803888b8343888b8383888b83c3888b8303898b8343898b8383898b83c3898b83038a8b83438a8b83838a8b83c38a8b83038b8b83438b8b83838b8b83c08b8883d01f193802888a8342888a8382888a83c2888a8302898a8342898a8382898a83c2898a83028a8a83428a8a83828a8a83c28a8a83028b8a83428b8a83828b8a83c08b88830120f746"), (), (10, 14))
_TRAFFIC_SELECTORS_SHAPE = (bytes.fromhex("80b5004a0023138041277f029780004fc000c0191038077a7f089780004f9780477a7f089780004f9780877a7f089780002901d0004900e000499180c07a400890809380938020201080938093804020108093809380602010809380938080bd"), (), (2, 14, 28, 38, 52, 56))


def find_traffic_decoder_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind mode1 erasure output only; no timing, qualification or RF is inferred."""
    from .memory_layout import find_linker_layout

    result = {"signature": "thumb-traffic-mode1-erasure-row5-v1", "accepted": False,
              "active": False,
              "semantic_limit": "static mode1 erasure-only output and matched callback intervals; auxiliary status ports, other modes, cadence, qualified frames, RF and calls unproven"}

    def reject(reason):
        return {**result, "reject_reason": reason}

    def matches(at, shape):
        return at is not None and _tx_init_code_matches(image, at, shape)

    readers = []
    for match in re.finditer(re.escape(bytes.fromhex("f0b5041c171c")), image):
        at = match.start()
        if matches(at, _TRAFFIC_READER_SHAPE):
            readers.append(at)
    if len(readers) != 1:
        return reject(f"traffic-reader-cardinality:{len(readers)}")
    reader = readers[0]
    decoder = find_decoder_init_profile(image, tick_position)
    if not decoder["accepted"]:
        return reject("traffic-shared-decoder-unclosed")
    helper = decoder["copy_helper"]
    if (any(thumb_bl_target(image, reader + off) != helper for off in (0x2c, 0x4c, 0x6c, 0x8c))
            or _literal(image, reader + 0x12, 6, 0) != 0x03000a40
            or any(_literal(image, reader + off, 0, 0) != 0x03000a70
                   for off in (0x2a, 0x4a, 0x6a, 0x8a))):
        return reject("traffic-reader-port-copy-unclosed")
    layout_pointer = _literal(image, reader + 6, 0, 0)
    if layout_pointer is None or layout_pointer & 3 or not 0x01000008 <= layout_pointer <= 0x01ffffd8:
        return reject("traffic-layout-address-invalid")
    layout_address = layout_pointer - 8
    registrar = thumb_bl_target(image, decoder["registration"])
    registrations = []
    for match in re.finditer(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", image):
        pc = match.start()
        if (not pc & 1 and thumb_bl_target(image, pc) == registrar
                and matches(pc - 20, _TRAFFIC_REGISTRATION_SHAPE)):
            registrations.append(pc)
    if len(registrations) != 1:
        return reject(f"traffic-registration-cardinality:{len(registrations)}")
    registration = registrations[0]
    mode_base = _literal(image, registration - 20, 0, 0)
    callback = _literal(image, registration - 4, 1, 0)
    initializer = thumb_bl_target(image, registration - 16)
    if (callback is None or not callback & 1 or mode_base is None
            or mode_base & 3 or not 0x01000000 <= mode_base <= 0x01ffffec):
        return reject("traffic-mode-callback-address-invalid")
    isr = callback - 1
    data_call, emission = isr + 0x17c, isr + 0x5c6
    if (not matches(isr, _TRAFFIC_CALLBACK_SHAPE)
            or not matches(data_call, _TRAFFIC_DATA_CALL_SHAPE)
            or not matches(emission, _TRAFFIC_EMIT_SHAPE)
            or thumb_bl_target(image, data_call + 16) != reader
            or _literal(image, data_call + 6, 0, 0) != mode_base
            or _literal(image, isr + 4, 0, 0) != 0x03000a60
            or _literal(image, isr + 0x18, 0, 0) != mode_base
            or _literal(image, isr + 0xe, 5, 0) != mode_base + 0x10):
        return reject("traffic-callback-reader-shape-unclosed")
    metrics = thumb_bl_target(image, isr + 0x1e)
    quality = thumb_bl_target(image, isr + 0x22)
    if (not matches(metrics, _TRAFFIC_METRICS_SHAPE)
            or _literal(image, metrics + 2, 2, 0) != layout_pointer
            or _literal(image, metrics + 0xe, 3, 0) != 0x03000a40
            or _literal(image, metrics + 0x16, 0, 0) != 0x03000a60
            or not matches(quality, _TRAFFIC_QUALITY_SHAPE)
            or _literal(image, quality + 2, 0, 0) != mode_base):
        return reject("traffic-metrics-quality-dispatch-unclosed")
    variant = thumb_bl_target(image, quality + 0x20)
    ordinary = thumb_bl_target(image, quality + 0x26)
    metric_record = _literal(image, isr + 0x1a, 1, 0)
    if (not matches(ordinary, _TRAFFIC_ORDINARY_SHAPE)
            or not matches(variant, _TRAFFIC_VARIANT_SHAPE)
            or metric_record is None
            or any(_literal(image, ordinary + off, reg, 0) != metric_record
                   for off, reg in ((2, 0), (8, 0), (0x2e, 2)))
            or any(_literal(image, variant + off, reg, 0) != metric_record
                   for off, reg in ((2, 5), (0x14, 0)))):
        return reject("traffic-mode1-quality-leaves-unclosed")
    if not matches(initializer, _TRAFFIC_INIT_SHAPE):
        return reject("traffic-initializer-shape-unclosed")
    clock = thumb_bl_target(image, initializer + 4)
    clock_shape = (bytes.fromhex("00490320087000490020087000490870f746"), (), (0, 6, 12))
    lock = thumb_bl_target(image, initializer + 8)
    unlock = thumb_bl_target(image, initializer + 0x24)
    coefficients = thumb_bl_target(image, initializer + 0x86)
    selectors = thumb_bl_target(image, initializer + 0x8e)
    shadow = _literal(image, initializer + 0xc, 4, 0)
    if (not matches(clock, clock_shape)
            or any(_literal(image, clock + off, 1, 0) != value for off, value in
                   ((0, 0x03000300), (6, 0x030002e0), (12, 0x03000900)))
            or lock == unlock
            or any(thumb_bl_target(image, initializer + off) != lock for off in (0x28, 0x48, 0x62))
            or any(thumb_bl_target(image, initializer + off) != unlock for off in (0x3c, 0x76))
            or shadow is None or _literal(image, initializer + 0x42, 4, 0) != shadow + 0x20
            or any(_literal(image, initializer + off, reg, 0) != value for off, reg, value in
                   ((0xe, 3, 0xffdf), (0x12, 5, 0x03000a00), (0x2e, 3, 0xfff8),
                    (0x40, 5, 0x03000a60), (0x4e, 3, 0xfffd), (0x68, 3, 0xfffd)))
            or not matches(coefficients, _TRAFFIC_COEFFICIENTS_SHAPE)
            or _literal(image, coefficients + 0xa, 1, 0) != 0x03000a20
            or _literal(image, coefficients + 0xe, 2, 0) != layout_address + 0x60
            or not matches(selectors, _TRAFFIC_SELECTORS_SHAPE)
            or any(_literal(image, selectors + off, reg, 0) != value for off, reg, value in
                   ((2, 2, 0x03000a40), (0xe, 7, layout_pointer), (0x1c, 7, 0x8210),
                    (0x26, 7, 0x8220), (0x34, 1, 0x9230), (0x38, 1, 0x8230)))):
        return reject("traffic-initializer-ports-aliases-unclosed")
    decoder_isr = decoder["isr"]
    queue_get = thumb_bl_target(image, initializer + 0x7c)
    queue_put = thumb_bl_target(image, initializer + 0xa0)
    free_queue = _literal(image, isr + 0xa0, 0, 0)
    if (free_queue is None or queue_get != thumb_bl_target(image, decoder_isr + 0xc)
            or queue_put != thumb_bl_target(image, decoder_isr + 0x62)
            or image[decoder_isr + 0x66:decoder_isr + 0x6a] != bytes.fromhex("0821281c")
            or thumb_bl_target(image, emission + 24) != thumb_bl_target(image, decoder_isr + 0x6a)
            or _literal(image, emission + 20, 0, 0) != _literal(image, decoder_isr + 0x10, 5, 0)
            or free_queue != _literal(image, decoder_isr + 0x3e, 0, 0)
            or thumb_bl_target(image, isr + 0xa2) != queue_get
            or thumb_bl_target(image, emission + 16) != queue_put
            or _literal(image, emission + 6, 1, 0) != _literal(image, isr + 0x5c, 7, 0)
            or _literal(image, emission + 0xe, 0, 0) != free_queue - 12):
        return reject("traffic-frame-queue-aliases-unclosed")
    layout = find_linker_layout(image, required_span=(layout_address, 48))
    if layout is None:
        return reject("traffic-layout-linker-unclosed")
    layout_source = layout.data_source + layout_address - layout.data_target
    rows = image[layout_source:layout_source + 48]
    if len(rows) != 48 or rows[:8] != bytes(8):
        return reject("traffic-layout-rows-invalid")
    maxima = [0, 0, 0, 0]
    for row in range(1, 6):
        descriptor = rows[row * 8:(row + 1) * 8]
        end = 0
        for rate, capacity in enumerate((36, 18, 10, 6)):
            start, count = descriptor[rate], descriptor[rate + 4]
            if start != end or start & 1 or count & 1 or not 0 < count <= capacity:
                return reject("traffic-layout-descriptor-invalid")
            end = start + count + 4
            maxima[rate] = max(maxima[rate], count)
        if end > 86:
            return reject("traffic-layout-descriptor-overflow")
    if maxima != [36, 18, 10, 6]:
        return reject("traffic-layout-capacity-class-unclosed")
    shapes = ((reader, _TRAFFIC_READER_SHAPE), (metrics, _TRAFFIC_METRICS_SHAPE),
              (initializer, _TRAFFIC_INIT_SHAPE), (clock, clock_shape),
              (registration - 20, _TRAFFIC_REGISTRATION_SHAPE),
              (isr, _TRAFFIC_CALLBACK_SHAPE), (data_call, _TRAFFIC_DATA_CALL_SHAPE),
              (emission, _TRAFFIC_EMIT_SHAPE), (quality, _TRAFFIC_QUALITY_SHAPE),
              (ordinary, _TRAFFIC_ORDINARY_SHAPE), (variant, _TRAFFIC_VARIANT_SHAPE),
              (coefficients, _TRAFFIC_COEFFICIENTS_SHAPE), (selectors, _TRAFFIC_SELECTORS_SHAPE))
    code_dependencies = [(layout.table_offset, 20), (layout_source, 48),
                         (decoder["descriptor_template"], 28), (decoder_isr, 0x74), (helper, 22)]
    ram_dependencies = [(mode_base, 0x14), (layout_address, 48), (metric_record, 16),
                        (shadow, 0x32), (decoder["irq_callback_slot"], 4),
                        (free_queue - 12, 24),
                        (_literal(image, isr + 0x26, 2, 0), 0x12)]
    for at, shape in shapes:
        code_dependencies.append((at, len(shape[0])))
        code_dependencies.extend((thumb_bl_target(image, at + off), 2) for off in shape[1])
        for off in shape[2]:
            pc = at + off
            pool = ((pc + 4) & ~3) + (_u16(image, pc) & 255) * 4
            code_dependencies.append((pool, 4))
            value = _literal(image, pc, _u16(image, pc) >> 8 & 7, 0)
            if value is not None and 0x01000000 <= value < 0x02000000:
                ram_dependencies.append((value, 4))
    if any(at is None or at < 0 or size <= 0 or at + size > len(image)
           for at, size in code_dependencies):
        return reject("traffic-code-dependency-outside-image")
    if any(at is None or at < 0x01000000 or at + size > 0x02000000
           for at, size in ram_dependencies):
        return reject("traffic-RAM-dependency-outside-class")
    return {**result, "accepted": True, "reject_reason": None,
            "isr": isr, "reader": reader, "status_reader": metrics,
            "initializer": initializer, "mode_base": mode_base,
            "layout_address": layout_address, "layout_source": layout_source,
            "linker_table_offset": layout.table_offset, "copy_helper": helper,
            "registration": registration, "quality_dispatcher": quality,
            "quality_ordinary": ordinary, "quality_variant3": variant,
            **{key: decoder[key] for key in ("descriptor_template", "irq_callback_slot",
                                            "irq_status", "irq_enable", "irq_mask")},
            "code_dependencies": sorted(set(code_dependencies)),
            "ram_dependencies": sorted(set(ram_dependencies))}
