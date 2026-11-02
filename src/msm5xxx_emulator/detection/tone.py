"""Static evidence for the MSM5000 two-channel tone generator."""
from __future__ import annotations

import struct
import re

from .arm import thumb_bl_target
from .audio import find_audio_transport

# Both independently disassembled converters use this exact table. Matching all
# four literal-pool constants plus the writer's ten ordered byte stores is the
# signature; MMIO addresses alone are not sufficient evidence.
_DIVIDERS = (307500, 2152500, 4305000, 8610000)
_WRITES = (
    0x030006C8, 0x030006DC, 0x030006BC, 0x030006B8,
    0x030006C4, 0x030006C0, 0x030006D0, 0x030006CC,
    0x030006D8, 0x030006D4,
)


def _literal_values(image: bytes) -> set[int]:
    return {value for value in _DIVIDERS
            if image.find(struct.pack("<I", value)) >= 0}


def _tone_converter_entries(image: bytes) -> set[int]:
    """Return call targets whose code loads all four divider constants."""
    needed = set(_DIVIDERS)
    if _literal_values(image) != needed:
        return set()
    n = len(image)
    refs: list[tuple[int, int]] = []
    for match in re.finditer(rb'(?=([\x00-\xff][\x48-\x4f]))', image):
        pc = match.start()
        if pc & 1:
            continue
        insn = image[pc] | image[pc + 1] << 8
        literal = ((pc + 4) & ~3) + ((insn & 0xFF) << 2)
        if literal + 4 <= n:
            value = struct.unpack_from("<I", image, literal)[0]
            if value in needed:
                refs.append((pc, value))
    entries: set[int] = set()
    for pc, _ in refs:
        used = {value for target_pc, value in refs
                if pc <= target_pc < pc + 0x80}
        if used == needed:
            # Use the nearest Thumb function prologue preceding these literal
            # loads. The recovered converter starts 0x36 bytes before its
            # first table reference in both independently analyzed builds.
            for target in range(pc & ~1, max(-1, pc - 0x50), -2):
                if target + 2 <= n:
                    push = struct.unpack_from("<H", image, target)[0]
                    if push & 0xFE00 == 0xB400 and push & 0x100:
                        entries.add(target)
                        break
    return entries


def _thumb_tone_writer(image: bytes) -> list[int]:
    """Find a contiguous Thumb STRB sequence targeting the ten tone bytes.

    The firmware's writer loads the three MMIO base literals, then emits the
    ten stores in this order. Resolve only PC-relative LDR literals and
    immediate STRB instructions, and require all ten stores within 0x80 bytes.
    """
    n = len(image)
    converter_entries = _tone_converter_entries(image)
    if not converter_entries:
        return []
    literals: set[int] = set()
    for value in (0x030006B0, 0x030006C0, 0x030006D0):
        needle = struct.pack("<I", value)
        offset = image.find(needle)
        while offset >= 0:
            literals.add(offset)
            offset = image.find(needle, offset + 1)
    if not literals:
        return []

    # Find only PC-relative LDRs that refer to one of the three tone bases.
    # The regular expression scans in optimized C; the short Thumb decoder
    # then runs only around those references.
    windows: set[tuple[int, int]] = set()
    for match in re.finditer(rb'(?=([\x00-\xff][\x48-\x4f]))', image):
        pc = match.start()
        if pc & 1:
            continue
        insn = image[pc] | image[pc + 1] << 8
        literal = ((pc + 4) & ~3) + ((insn & 0xFF) << 2)
        if literal in literals:
            windows.add((max(0, pc - 0x100) & ~1,
                         min(n - 1, pc + 0x100) & ~1))

    hits: list[int] = []
    for start, stop in sorted(windows):
        regs: dict[int, int] = {}
        stores: list[tuple[int, int]] = []
        for pc in range(start, stop, 2):
            insn = image[pc] | image[pc + 1] << 8
            if insn & 0xF800 == 0x4800:
                reg = insn >> 8 & 7
                literal = ((pc + 4) & ~3) + ((insn & 0xFF) << 2)
                if literal + 4 <= n:
                    regs[reg] = struct.unpack_from("<I", image, literal)[0]
                else:
                    regs.pop(reg, None)
            elif insn & 0xF800 == 0x7000:
                base = insn >> 3 & 7
                if base in regs:
                    addr = regs[base] + (insn >> 6 & 0x1F)
                    if addr in _WRITES:
                        stores.append((pc, addr))
                        stores = stores[-len(_WRITES):]
                        if (len(stores) == len(_WRITES)
                                and tuple(a for _, a in stores) == _WRITES
                                and pc - stores[0][0] < 0x80):
                            writer_store_start = stores[0][0]
                            calls_converter = False
                            for call in range(max(0, writer_store_start - 0x200),
                                              writer_store_start - 2, 2):
                                target = thumb_bl_target(image, call)
                                if target in converter_entries:
                                    calls_converter = True
                                    break
                            if calls_converter:
                                hits.append(writer_store_start)
                    else:
                        stores.clear()
            else:
                op = insn & 0xF800
                if op in (0x2000, 0x2800, 0x3000, 0x3800, 0x4000,
                          0x5000, 0x6000, 0x6800, 0x8000, 0x8800,
                          0x9000, 0x9800, 0xA000, 0xA800, 0xC000, 0xC800):
                    regs.pop(insn >> 8 & 7, None)
    return sorted(set(hits))


def find_tone_generator(image: bytes) -> dict[str, object]:
    """Return evidence for the known two-channel MSM5000 tone block."""
    values = _literal_values(image)
    missing = [value for value in _DIVIDERS if value not in values]
    writers = _thumb_tone_writer(image)
    result: dict[str, object] = {
        "family": "msm5000-two-channel-tone",
        "grammar": "divider-table-plus-ten-strb-v1",
        "static_status": "rejected",
        "reject_reason": None,
        "converter_constants": list(_DIVIDERS),
        "writer_offsets": writers,
    }
    if missing:
        result["reject_reason"] = "converter-constant-set-incomplete"
    elif len(writers) != 1:
        result["reject_reason"] = (
            "tone-writer-none" if not writers else "tone-writer-ambiguous"
        )
    else:
        result["static_status"] = "accepted"
        result["writer_offset"] = writers[0]
    return result


def tone_admission(
        image: bytes,
        audio_transport: dict[str, object] | None = None,
) -> dict[str, object]:
    """Fail closed when an admitted Yamaha or opaque transport owns audio."""
    tone = find_tone_generator(image)
    transport = (audio_transport if audio_transport is not None
                 else find_audio_transport(image))
    if (tone["static_status"] == "accepted"
            and transport.get("static_status") == "accepted"):
        return {
            **tone,
            "static_status": "rejected",
            "reject_reason": "admitted-audio-transport-present",
            "audio_transport": transport,
        }
    return tone


__all__ = ("find_tone_generator", "tone_admission")
