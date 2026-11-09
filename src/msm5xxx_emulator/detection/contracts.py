"""Declarative instruction, literal and call evidence shared by driver rules."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

from .facts import CodeAddress, FirmwareFacts, facts_for, thumb_call_target
from .arm import thumb_bl_target
from capstone import arm as a


@dataclass(frozen=True, slots=True)
class BodyFacts:
    entry: int
    size: int
    literals: tuple[tuple[int, int], ...]
    calls: tuple[tuple[int, int], ...]
    pools: tuple[int, ...]
    phase: str = 'reset'
    bank: str = 'primary'

    @property
    def values(self):
        return dict(self.literals)

    @property
    def targets(self):
        return dict(self.calls)

    @property
    def dependencies(self):
        return ((self.entry, self.size),) + tuple((pool, 4) for pool in self.pools)


@dataclass(frozen=True, slots=True)
class BodySpec:
    """Closed compiler evidence with relocatable operands decoded separately.

    ``words`` contains (offset, expected, mask) triples. Literal registers and
    call sites are declared independently; no digest can authorize a match.
    Constraints between captures belong to the device's capability rule.
    """

    size: int
    words: tuple[tuple[int, int, int], ...] = ()
    literals: tuple[tuple[int, int], ...] = ()
    calls: tuple[int, ...] = ()
    isa: str = 'thumb'

    def __post_init__(self):
        unit = 2 if self.isa == 'thumb' else 4
        if self.isa not in ('arm', 'thumb') or self.size <= 0 or self.size % unit:
            raise ValueError('invalid instruction contract size or instruction set')
        fields = [off for off, _, _ in self.words] + [off for off, _ in self.literals] + list(self.calls)
        if any(off < 0 or off % unit or off + unit > self.size for off in fields):
            raise ValueError('instruction field outside contract')
        if len(set(fields)) != len(fields):
            raise ValueError('overlapping instruction contract fields')
        if self.isa == 'thumb' and any(off + 4 > self.size for off in self.calls):
            raise ValueError('truncated Thumb call field')

    @classmethod
    def thumb(cls, size, fixed, literals=(), calls=()):
        return cls(size, tuple((off, word, 0xFFFF) for off, word in sorted(fixed.items())),
                   tuple(sorted(dict(literals).items())), tuple(calls))

    @classmethod
    def thumb_body(cls, pattern: bytes, calls=(), literals=()):
        """Describe a supplied compiler template with separately decoded fields."""
        omitted = set(calls) | {off + 2 for off in calls} | dict(literals).keys()
        fixed = {off: struct.unpack_from('<H', pattern, off)[0]
                 for off in range(0, len(pattern), 2) if off not in omitted}
        return cls.thumb(len(pattern), fixed, literals, calls)

    def match(self, facts: FirmwareFacts, entry: int | CodeAddress,
              limit: int | None = None) -> BodyFacts | None:
        explicit_view = isinstance(entry, CodeAddress)
        pc = entry if explicit_view else CodeAddress(entry, self.isa)
        start = pc.address
        unit = 2 if self.isa == 'thumb' else 4
        bound = min(len(facts.image), limit if limit is not None else len(facts.image))
        if pc.isa != self.isa or start % unit:
            return None
        if not explicit_view and not 0 <= start - facts.base <= bound - self.size:
            return None
        read = lambda address, size: facts.view.read(address, size, phase=pc.phase, bank=pc.bank)

        def extract():
            code = read(start, self.size)
            if code is None:
                return None
            fmt = '<H' if unit == 2 else '<I'
            if any(struct.unpack_from(fmt, code, off)[0] & mask != expected
                   for off, expected, mask in self.words):
                return None
            values, targets, pools = [], [], []
            for off, register in self.literals:
                site = CodeAddress(start + off, self.isa, pc.phase, pc.bank)
                if self.isa == 'thumb':
                    word = struct.unpack_from('<H', code, off)[0]
                    if word & 0xF800 != 0x4800 or word >> 8 & 7 != register:
                        return None
                    pool = ((site.address + 4) & ~3) + (word & 255) * 4
                    raw = read(pool, 4)
                    value = int.from_bytes(raw, 'little') if raw is not None else None
                else:
                    literal = facts.literal(site)
                    registers = (a.ARM_REG_R0, a.ARM_REG_R1, a.ARM_REG_R2, a.ARM_REG_R3,
                                 a.ARM_REG_R4, a.ARM_REG_R5, a.ARM_REG_R6, a.ARM_REG_R7,
                                 a.ARM_REG_R8, a.ARM_REG_R9, a.ARM_REG_R10, a.ARM_REG_R11,
                                 a.ARM_REG_R12, a.ARM_REG_SP, a.ARM_REG_LR, a.ARM_REG_PC)
                    if literal is None or literal.register != registers[register]:
                        return None
                    pool, value = literal.pool, literal.value
                if value is None or (not explicit_view and not facts.base <= pool <= facts.base + bound - 4):
                    return None
                values.append((off, value))
                pools.append(pool)
            for off in self.calls:
                if self.isa == 'thumb':
                    relative = thumb_call_target(code, off)
                    target = None if relative is None else relative + start
                else:
                    ins = facts.decode(CodeAddress(start + off, 'arm', pc.phase, pc.bank))
                    target = (ins.operands[0].imm if ins is not None and ins.id == a.ARM_INS_BL
                              and ins.operands and ins.operands[0].type == a.ARM_OP_IMM else None)
                if target is None or target % unit or read(target, 2) is None:
                    return None
                if not explicit_view and not facts.base <= target <= facts.base + bound - 2:
                    return None
                targets.append((off, target))
            return BodyFacts(start, self.size, tuple(values), tuple(targets),
                             tuple(sorted(set(pools))), pc.phase, pc.bank)
        return facts.memo('body', (self, pc, bound, explicit_view), extract)

    def find(self, facts: FirmwareFacts, limit: int | None = None, *,
             phase: str = 'reset', bank: str = 'primary'):
        unit = 2 if self.isa == 'thumb' else 4
        full = (1 << (unit * 8)) - 1
        fixed = {off: expected for off, expected, mask in self.words if mask == full}
        if not fixed:
            raise ValueError('discovery requires a fixed instruction anchor')
        runs = []
        for off in sorted(fixed):
            if not runs or runs[-1][0] + len(runs[-1][1]) != off:
                runs.append((off, bytearray()))
            runs[-1][1].extend(fixed[off].to_bytes(unit, 'little'))
        anchor_offset, anchor = max(runs, key=lambda item: len(item[1]))
        for address in facts.string_candidates(bytes(anchor), phase=phase, bank=bank):
            entry = address - anchor_offset
            if phase != 'reset' or bank != 'primary':
                entry = CodeAddress(entry, self.isa, phase, bank)
            match = self.match(facts, entry, limit)
            if match is not None:
                yield match


def match_thumb_shape(image, entry, size, fixed, literals, calls):
    """Compatibility adapter while callers move to persistent BodySpec rules."""
    match = BodySpec.thumb(size, fixed, literals, calls).match(facts_for(image), entry)
    return (match.values, match.targets) if match is not None else None


def _normalized_thumb_sha256(
        image: bytes, position: int, length: int,
) -> tuple[str, tuple[int, ...]] | None:
    """Hash one exact Thumb body while ignoring relocated BL immediates."""
    if position < 0 or position + length > len(image):
        return None
    normalized = bytearray(image[position:position + length])
    calls: list[int] = []
    for offset in range(0, length - 3, 2):
        if thumb_bl_target(image, position + offset) is None:
            continue
        calls.append(offset)
        normalized[offset:offset + 4] = b"\0" * 4
    return hashlib.sha256(normalized).hexdigest(), tuple(calls)


def loaded_source_matches(profile: dict, original: bytes, loaded: bytes) -> bool:
    """Check that every declared source interval is present and unchanged."""
    if not isinstance(profile, dict) or not profile.get("code_intervals"):
        return False
    for role in ("code_intervals", "literal_intervals", "data_intervals",
                 "boot_guard_intervals"):
        intervals = profile.get(role, [])
        if not isinstance(intervals, (tuple, list)):
            return False
        for span in intervals:
            if (not isinstance(span, (tuple, list)) or len(span) != 2
                    or any(type(value) is not int for value in span)):
                return False
            start, end = span
            if not 0 <= start < end <= min(len(original), len(loaded)):
                return False
            if original[start:end] != loaded[start:end]:
                return False
    return True


def source_class_limit(image: bytes, config: object) -> int | None:
    """Return the supplied firmware prefix covered by the loader contract."""
    flash = getattr(config, "flash_size", None)
    load, entry = getattr(config, "load_address", None), getattr(config, "entry", None)
    if (not isinstance(image, bytes) or getattr(config, "image_kind", None) != "firmware"
            or type(load) is not int or type(entry) is not int or load != 0 or entry != 0
            or type(flash) is not int or not 0 < flash <= 0xffffffff):
        return None
    return min(len(image), flash)
