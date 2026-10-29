"""Closed source shape for the 244-byte paired DMD download/readback driver."""
from __future__ import annotations

import re
import struct

from .arm import thumb_bl_target, thumb_literal_value
from .boot import DMD_DOWNLOAD_SIGNATURE

_DRIVER_SIZE = 0xF4
_PROFILE_SIGNATURE = "dmd5100-paired-program-readback-v1"
_HOLES = ((0x0E, 0x12), (0x26, 0x2A), (0x4E, 0x52), (0x56, 0x5A),
          (0xD0, 0xD4), (0xD6, 0xD7), (0xD8, 0xDC),
          (0xE0, 0xE4), (0xE8, 0xEC),
          (0xF0, 0xF4))
# Relocatable BLs, three address literals, and only the failure-line imm8 vary.
_DRIVER = bytes.fromhex(
    'f0b5002701250024354901200870000000000604360c334900200873324b3149'
    '988810398881000000002e482e4b103809e02d4b79001a685218528802821a68'
    '515a01820237284bd988b942f1dc00000000002e01d100000000244e0e203072'
    '00203073307a204f0020f9883a684b0809e061001d4e515a3689b14201d00025'
    '03e0023401308342f3dc184a00201073107afb88002100203c685f0809e04b00'
    'e3185b889689b34201d0002503e0023101308742f3dc00201072002d08d00849'
    '02200870074901200873f0bc08bc1847000000000649002005f0b2fef5e70000'
    '000000005000000300000000e007000300000000'
)
_MASK = bytearray(b"\xff" * _DRIVER_SIZE)
for _start, _end in _HOLES:
    _MASK[_start:_end] = bytes(_end - _start)
_MASK = bytes(_MASK)
_BL_PATTERN = re.compile(rb"(?=[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff])")


def _driver_matches(image: bytes, entry: int) -> bool:
    if entry & 1 or entry < 0 or entry + _DRIVER_SIZE > len(image):
        return False
    actual = image[entry:entry + _DRIVER_SIZE]
    if any((actual[i] ^ _DRIVER[i]) & _MASK[i] for i in range(_DRIVER_SIZE)):
        return False
    # Keep the MOVS opcode and destination fixed; only the report code varies.
    return struct.unpack_from("<H", image, entry + 0xD6)[0] & 0xFF00 == 0x2000


def _callers(image: bytes, target: int) -> list[int]:
    return [m.start() for m in _BL_PATTERN.finditer(image)
            if not m.start() & 1 and thumb_bl_target(image, m.start()) == target]


def _callee_intervals(image: bytes, targets: list[int], excluded: tuple[tuple[int, int], ...]):
    entries = sorted(set(targets))
    intervals = []
    for target in entries:
        if target & 1 or target < 0 or target + 2 > len(image):
            return None, "dmd5100-callee-outside-image"
        entry_span = (target, target + 2)
        if any(entry_span[0] < end and start < entry_span[1]
               for start, end in (*excluded, *intervals)):
            return None, "dmd5100-callee-aliases-source-data"
        first = struct.unpack_from("<H", image, target)[0]
        if first in (0x0000, 0xFFFF):
            return None, "dmd5100-callee-empty-or-unreadable"
        intervals.append(entry_span)
        if first & 0xF800 == 0x4800:
            literal = ((target + 4) & ~3) + (first & 0xFF) * 4
            if literal + 4 > len(image):
                return None, "dmd5100-callee-literal-outside-image"
            literal_span = (literal, literal + 4)
            if any(literal_span[0] < end and start < literal_span[1]
                   for start, end in (*excluded, *intervals)):
                return None, "dmd5100-callee-literal-aliases-source-data"
            intervals.append(literal_span)
    return tuple(intervals), "accepted"


def _profile_at(image: bytes, entry: int) -> tuple[dict | None, str]:
    if not _driver_matches(image, entry):
        return None, "dmd5100-driver-shape-unclosed"
    calls = [thumb_bl_target(image, entry + offset)
             for offset in (0x0E, 0x26, 0x4E, 0x56, 0xD0, 0xD8)]
    if (any(target is None or not 0 <= target < len(image) for target in calls)
            or calls[1] != calls[2]):
        return None, "dmd5100-relocated-call-shape-unclosed"

    completion = thumb_literal_value(image, entry + 0x08, 1)
    descriptor = thumb_literal_value(image, entry + 0x1C, 3)
    filename = thumb_literal_value(image, entry + 0xD4, 1)
    literal_checks = (
        (entry + 0x16, 1, 0x03000050), (entry + 0x1E, 1, 0x03000050),
        (entry + 0x2A, 0, 0x03000050), (entry + 0xC4, 1, 0x03000050),
        (entry + 0x5A, 6, 0x030007E0), (entry + 0x74, 6, 0x030007E0),
        (entry + 0x8A, 2, 0x030007E0), (entry + 0xBE, 1, completion),
        (entry + 0x2C, 3, descriptor), (entry + 0x32, 3, descriptor),
        (entry + 0x46, 3, descriptor), (entry + 0x66, 7, descriptor),
    )
    if (completion is None or not 0x01000000 <= completion < 0x02000000
            or descriptor is None or filename is None
            or any(thumb_literal_value(image, at, reg) != value
                   for at, reg, value in literal_checks)):
        return None, "dmd5100-linked-literals-unclosed"
    if not 0 <= filename < len(image):
        return None, "dmd5100-filename-reference-outside-image"

    if descriptor & 3 or descriptor + 8 > len(image):
        return None, "dmd5100-descriptor-outside-image"
    payload, mode, halfwords = struct.unpack_from("<IHH", image, descriptor)
    if mode != 0:
        return None, "dmd5100-mode-unsupported"
    # shortcut: 0x1400 is the largest observed logical burst; expand after independent source proof.
    if not 0 < halfwords <= 0x1400 or halfwords & 1:
        return None, "dmd5100-halfword-count-out-of-range"
    payload_size = halfwords * 2
    payload_end = payload + payload_size
    if (payload & 1 or payload < 0 or payload_end != descriptor
            or payload_end > len(image)):
        return None, "dmd5100-payload-range-unclosed"
    filename_limit = min(descriptor + 0x40, len(image))
    if not descriptor + 8 <= filename < filename_limit:
        return None, "dmd5100-readonly-reference-unlinked"
    terminator = image.find(b"\0", filename, filename_limit)
    if terminator <= filename:
        return None, "dmd5100-readonly-string-unclosed"
    filename_span = (filename, terminator + 1)

    callers = _callers(image, entry)
    if len(callers) != 1:
        return None, "dmd5100-caller-missing-or-ambiguous"
    caller = callers[0]
    intervals = ((entry, entry + _DRIVER_SIZE), (payload, payload_end),
                 (descriptor, descriptor + 8), filename_span, (caller, caller + 4))
    for index, (start, end) in enumerate(intervals):
        if not 0 <= start < end <= len(image):
            return None, "dmd5100-loaded-interval-outside-image"
        if any(start < other_end and other_start < end
               for other_start, other_end in intervals[index + 1:]):
            return None, "dmd5100-loaded-interval-overlap"
    callee_intervals, reason = _callee_intervals(image, calls, intervals)
    if callee_intervals is None:
        return None, reason
    all_intervals = intervals + callee_intervals

    return {
        "signature": _PROFILE_SIGNATURE,
        "admission": "temporary-evidence-gated",
        "entry_file_offset": entry,
        "caller_file_offset": caller,
        "callee_entries": tuple(sorted(set(calls))),
        "descriptor_file_offset": descriptor,
        "filename_file_interval": filename_span,
        "payload_file_offset": payload,
        "mode": mode,
        "halfword_count": halfwords,
        "pair_count": halfwords // 2,
        "payload_bytes": payload_size,
        "completion_byte_address": completion,
        "failure_report_code": struct.unpack_from("<H", image, entry + 0xD6)[0] & 0xFF,
        "source_intervals": tuple(sorted(set(all_intervals))),
    }, "accepted"


def find_dmd5100_profile(image: bytes) -> tuple[dict | None, str]:
    """Return one fully linked source profile; this is not hardware identity."""
    if not isinstance(image, bytes):
        return None, "dmd5100-image-not-bytes"
    candidates = []
    offset = image.find(DMD_DOWNLOAD_SIGNATURE)
    while offset >= 0:
        if _driver_matches(image, offset):
            candidates.append(offset)
        offset = image.find(DMD_DOWNLOAD_SIGNATURE, offset + 1)
    if not candidates:
        return None, "dmd5100-typed-driver-not-found"
    if len(candidates) != 1:
        return None, "dmd5100-typed-driver-ambiguous"
    return _profile_at(image, candidates[0])
