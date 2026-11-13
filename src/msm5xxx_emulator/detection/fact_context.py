"""Lazy analysis context for one immutable image and address view."""
from __future__ import annotations
from .arm import thumb_bl_target as thumb_call_target
from .fact_indexes import FactIndexes
from .fact_models import Literal
from .fact_queries import FactQueries
from .fact_references import FactReferences
from .function_analysis import analyze_function
from .image_view import ImageView
from .values import CodeAddress
from capstone import arm as a
from threading import RLock
import capstone as cs

class FirmwareFacts(FactIndexes, FactQueries, FactReferences):
    'One analysis context per immutable image and address view.\n\nDecode is lazy and cached by phase, address and ISA. Unknown instructions,\nopaque calls and conflicting incoming values cannot establish constants.'

    def __init__(self, image: bytes, base: int = 0, view: ImageView | None = None):
        self.image = bytes(image)
        self.base = base
        self.view = view if view is not None else ImageView.raw(self.image, base=base)
        self._engines = {}
        self._decoded = {}
        self._functions = {}
        self._function_ids = set()
        self._queries = {}
        self._lock = RLock()

    def memo(self, name, parameters, extract):
        key = (name, parameters)
        with self._lock:
            if key not in self._queries:
                self._queries[key] = extract()
            return self._queries[key]

    def after_loads(self, operations, *, source_phase='reset', phase='post-copy', bank='primary'):
        """Analyse an ordered copy/zero sequence proved by a startup predicate.

        Tuple-shaped data alone must never be passed here as proof of execution.
        The derived context keeps its own phase-aware decode and query caches.
        """
        operations = tuple(operations)
        return self.memo('after-loads', (operations, source_phase, phase, bank), lambda: FirmwareFacts(self.image, self.base, self.view.materialize(operations,
            source_phase=source_phase, phase=phase, bank= bank)))

    def decode(self, pc: CodeAddress, *, cache: bool = True):
        """Decode supplied code, optionally without retaining a candidate probe."""
        if pc.isa not in ('arm', 'thumb'):
            raise ValueError('unsupported instruction set')
        with self._lock:
            if pc not in self._decoded:
                alignment = 4 if pc.isa == 'arm' else 2
                raw = self.view.read(pc.address, 4, phase=pc.phase, bank=pc.bank)
                if raw is None and pc.isa == 'thumb':
                    raw = self.view.read(pc.address, 2, phase=pc.phase, bank=pc.bank)
                if pc.address % alignment or raw is None:
                    decoded = None
                else:
                    if pc.isa not in self._engines:
                        engine = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM if pc.isa == 'arm' else cs.CS_MODE_THUMB)
                        engine.detail = True
                        self._engines[pc.isa] = engine
                    decoded = next(self._engines[pc.isa].disasm(raw, pc.address, count=1), None)
                if cache:
                    self._decoded[pc] = decoded
                return decoded
            return self._decoded[pc]

    def literal(self, pc: CodeAddress) -> Literal | None:
        ins = self.decode(pc)
        if ins is None or ins.id != a.ARM_INS_LDR or len(ins.operands) != 2:
            return None
        dst, src = ins.operands
        if (dst.type != a.ARM_OP_REG or src.type != a.ARM_OP_MEM or src.mem.base != a.ARM_REG_PC or src.mem.index):
            return None
        bias = (pc.address + 4) & ~3 if pc.isa == 'thumb' else pc.address + 8
        pool = bias + src.mem.disp
        raw = self.view.read(pool, 4, phase=pc.phase, bank=pc.bank)
        return Literal(pc, pool, dst.reg, int.from_bytes(raw, 'little')) if raw is not None else None

    def thumb_literal_value(self, position: int, register: int, *, phase='reset', bank='primary') -> int | None:
        """Return one supplied Thumb literal value by legacy image offset."""
        if not 0 <= register <= 7:
            return None
        raw = self.view.read(self.base + position, 2, phase=phase, bank=bank)
        if raw is None or int.from_bytes(raw, 'little') & 0xff00 != 0x4800 | register << 8:
            return None
        item = self.literal(CodeAddress(self.base + position, 'thumb', phase, bank))
        return (item.value if item is not None and item.register == a.ARM_REG_R0 + register else None)

    def thumb_call_target(self, position: int, *, phase='reset', bank='primary'):
        """Return a supplied Thumb BL target as a legacy image-relative offset."""
        address = self.base + position
        raw = self.view.read(address, 4, phase=phase, bank=bank)
        target = thumb_call_target(raw, 0) if raw is not None else None
        return position + target if target is not None else None

    function = analyze_function
