"""Firmware input and board-status detection."""
from __future__ import annotations

import re
import struct

from ..core.config import BoardStatusInput

from .arm import thumb_bl_target, thumb_literal_value
from .rex import THUMB_BL_PATTERN, _normalized_thumb_sha256
from .signatures import find_all


LG_INPUT_PATTERN = re.compile(
    rb"\x00\xb5.{4}.{4}\x08\xbc\x18\x47\x00\x00"
    rb"\x90\xb5\x07\x1c\x0c\x1c.{4}\x39\x88\x21\x43\x39\x80"
    rb"\x00\x28\x01\xd1.{4}\x90\xbc\x08\xbc\x18\x47"
    rb"\x90\xb5\x07\x1c\x0c\x1c.{4}\x39\x88\x21\x40\x39\x80"
    rb"\x00\x28\x01\xd1",
    re.S,
)
LG_DECODED_ENQUEUE_SIGNATURE = bytes.fromhex(
    "f7b50c1c151c17480121490240188078202803db0020febc08bc1847"
)
SAMSUNG_INPUT_PATTERN = re.compile(
    rb"\x54\x2f.{2}\x55\x2f.{2}.{0,120}"
    rb"\x50\x78\x13\x78\x41\x1c\xc9\x06\xc9\x0e\x99\x42\x07\xd0"
    rb"\x80\x18\x87\x70\x50\x78\x01\x30\xc0\x06\xc0\x0e\x50\x70",
    re.S,
)


BOARD_ADC_READER_PREFIX = bytes.fromhex("90b5071c")
BOARD_ADC_READER_BODY = bytes.fromhex(
    "1e48802301781943017001789f2319400170022f03d10178402319430ae0"
    "032f03d101786023194304e0002f03d101782023194301700178071c0a20"
)
BOARD_ADC_READER_MID_BODY = bytes.fromhex("387880239843387039780a20")
BOARD_ADC_READER_TAIL = bytes.fromhex("0548808907063f0e002c01d1")
BOARD_ADC_READER_BL_OFFSETS = (0x04, 0x0C, 0x12, 0x52, 0x56, 0x5A,
                               0x6A, 0x6E, 0x74, 0x78, 0x88)
BOARD_ADC_READER_SIZE = 0x98
BOARD_ADC_READER_LITERAL = 0x03000780
BOARD_ADC_READER_DATA_ADDRESS = BOARD_ADC_READER_LITERAL + 0x0C
BOARD_ADC_READER_VARIANT_SIZE = BOARD_ADC_READER_SIZE + 4
BOARD_ADC_READER_VARIANT_BL_OFFSETS = (0x04, 0x0C, 0x12, 0x4E, 0x52,
                                       0x56, 0x68, 0x6C, 0x72, 0x76, 0x86)
BOARD_ADC_READER_ANCHOR = bytes.fromhex("0404240c")
BOARD_ADC_READER_VARIANT_FIXED = (
    (0, BOARD_ADC_READER_PREFIX),
    (8, BOARD_ADC_READER_ANCHOR),
    (0x10, bytes.fromhex("2a20")),
    (0x16, bytes.fromhex(
        "1f48802201781143017001789f2319400170022f02d10178202208e0"
        "032f02d10178602203e0002f03d10178402211430170071c01780a20")),
    (0x5A, bytes.fromhex("3878802398430106090e38700a20")),
    (0x70, bytes.fromhex("0b20")),
    (0x7A, bytes.fromhex("0748808907063f0e002c01d1")),
    (0x8A, bytes.fromhex("381c90bc08bc1847")),
)
BOARD_ADC_READER_REORDERED_FIXED = (
    (0x2E, b"\x40"),
    (0x42, b"\x20"),
    (0, BOARD_ADC_READER_PREFIX),
    (8, BOARD_ADC_READER_ANCHOR),
    (0x10, bytes.fromhex("2a20")),
    (0x16, bytes.fromhex(
        "1f48802201781143017001789f2319400170022f02d10178402208e0"
        "032f02d10178602203e0002f03d10178202211430170071c01780a20")),
    (0x5A, bytes.fromhex("3878802398430106090e38700a20")),
    (0x70, bytes.fromhex("0b20")),
    (0x7A, bytes.fromhex("0748808907063f0e002c01d1")),
    (0x8A, bytes.fromhex("381c90bc08bc1847")),
)
BOARD_ADC_READER_EXTENDED_SIZE = BOARD_ADC_READER_VARIANT_SIZE + 12
BOARD_ADC_READER_EXTENDED_BL_OFFSETS = (
    0x04, 0x0C, 0x12, 0x4E, 0x52, 0x56, 0x68,
    0x6C, 0x74, 0x78, 0x7E, 0x82, 0x92,
)
BOARD_ADC_READER_EXTENDED_FIXED = (
    (0, BOARD_ADC_READER_PREFIX),
    (8, BOARD_ADC_READER_ANCHOR),
    (0x10, bytes.fromhex("2a20")),
    (0x16, bytes.fromhex(
        "2248802201781143017001789f2319400170022f02d10178202208e0"
        "032f02d10178602203e0002f03d10178402211430170071c01780a20")),
    (0x5A, bytes.fromhex("3878802398430106090e38700a20")),
    (0x70, bytes.fromhex("80210c20")),
    (0x7C, bytes.fromhex("0b20")),
    (0x86, bytes.fromhex("0748808907063f0e002c01d1")),
    (0x96, bytes.fromhex("381c90bc08bc1847")),
)
BOARD_ADC_READER_FIXED = (
    (0, BOARD_ADC_READER_PREFIX),
    (8, BOARD_ADC_READER_ANCHOR),
    (0x10, bytes.fromhex("2a20")),
    (0x16, BOARD_ADC_READER_BODY),
    (0x5E, BOARD_ADC_READER_MID_BODY),
    (0x72, bytes.fromhex("0b20")),
    (0x7C, BOARD_ADC_READER_TAIL),
    (0x8C, bytes.fromhex("381c90bd")),
)


DC0_BOARD_ADC_SCALE_PREFIX = bytes.fromhex("88b569461520")
DC0_BOARD_ADC_SCALE_SHAPE = (
    "e5621ef56171f9454c9ce7e229f69400a217419ccd18f07410960033ba863af5",
    (0x06, 0x1A, 0x36),
)
DC0_BOARD_ADC_GETTER_SHAPE = (
    "5518153f5d945817368f2ff4faddb98c18e50956cf987f966883943b3026aa7b",
    (0x12,),
)
DC0_BOARD_ADC_SERVICE_SHAPE = (
    "0b27f75b80031a871db2964a6d942894fc7f8214c2cabf88549b1352ed4856fe",
    (0x04, 0x10, 0x3E, 0x5C, 0x70, 0x7A, 0x80, 0x92, 0xAA, 0xB2),
)
DC0_BOARD_ADC_SEND_SHAPE = (
    "1346c57a455f6cde6eacdd0af0101d755515b61e6d4fcb467fd8ba8e3693cbc1",
    (0x5E,),
)
DC0_BOARD_ADC_RECEIVE_SHAPE = (
    "2ae667b7657c17780af982024b29ecb9be362d0bda978ee98e6a794d3d96c069",
    (0x64,),
)
DC0_BOARD_ADC_FILTER_SHAPE = (
    "e0682467707ce4f868e0d6779bab9834c97f7fe433a02ecf574dde949a68f430",
    (0x12, 0x74, 0x7A, 0x94, 0x9E, 0xBC, 0xC2, 0xD6, 0xE0,
     0xFE, 0x104, 0x112, 0x12E, 0x13A, 0x144, 0x148, 0x162),
)


BOARD_STATUS_INPUT_BODY = bytes.fromhex(
    "007808231840082801d1012100e00021002700260124002936484ad0"
)


def board_adc_reader_read_offset_at(image: bytes, position: int) -> int | None:
    """Return the data-read PC offset for one pristine reader layout."""
    if position & 1 or position < 0:
        return None
    if (position + BOARD_ADC_READER_SIZE <= len(image)
            and not any(image[position + offset:position + offset + len(expected)] != expected
                        for offset, expected in BOARD_ADC_READER_FIXED)
            and struct.unpack_from("<I", image, position + 0x94)[0]
            == BOARD_ADC_READER_LITERAL):
        return 0x7E
    if (position + BOARD_ADC_READER_VARIANT_SIZE <= len(image)
            and not any(image[position + offset:position + offset + len(expected)] != expected
                        for offset, expected in BOARD_ADC_READER_VARIANT_FIXED)
            and struct.unpack_from("<I", image, position + 0x98)[0]
            == BOARD_ADC_READER_LITERAL):
        return 0x7C
    if (position + BOARD_ADC_READER_VARIANT_SIZE <= len(image)
            and not any(image[position + offset:position + offset + len(expected)] != expected
                        for offset, expected in BOARD_ADC_READER_REORDERED_FIXED)
            and struct.unpack_from("<I", image, position + 0x98)[0]
            == BOARD_ADC_READER_LITERAL):
        return 0x7C
    if (position + BOARD_ADC_READER_EXTENDED_SIZE <= len(image)
            and not any(image[position + offset:position + offset + len(expected)]
                        != expected
                        for offset, expected in BOARD_ADC_READER_EXTENDED_FIXED)
            and struct.unpack_from("<I", image, position + 0xA4)[0]
            == BOARD_ADC_READER_LITERAL):
        return 0x88
    return None


def board_adc_reader_at(image: bytes, position: int) -> bool:
    """Validate one shared ADC reader without matching unrelated MMIO users."""
    offset = board_adc_reader_read_offset_at(image, position)
    offsets = {
        0x7E: BOARD_ADC_READER_BL_OFFSETS,
        0x7C: BOARD_ADC_READER_VARIANT_BL_OFFSETS,
        0x88: BOARD_ADC_READER_EXTENDED_BL_OFFSETS,
    }.get(offset)
    return (offsets is not None
            and _reader_targets_in_image(image, position, offsets))


def _reader_targets_in_image(image: bytes, position: int,
                             offsets: tuple[int, ...]) -> bool:
    return all((target := thumb_bl_target(image, position + offset)) is not None
               and 0 <= target < len(image) for offset in offsets)


def find_board_adc_reader(image: bytes) -> int | None:
    """Return unique shared Thumb ADC reader, never loose ADC MMIO literal hits."""
    matches = [anchor - 8 for anchor in find_all(image, BOARD_ADC_READER_ANCHOR)
               if anchor >= 8 and board_adc_reader_at(image, anchor - 8)]
    return matches[0] if len(matches) == 1 else None


SBI_BOOTSTRAP_BASE = 0x03000780
SBI_BOOTSTRAP = [
    [0, 1, 0x45], [0, 1, 0xC5], [4, 2, 0x085F], [0x0C, 2, 0x041F],
    [0x10, 1, 0], [0x10, 1, 1],
]
SBI_BOOTSTRAP_VALIDATION = [[0, 2, None], [0x0C, 2, 0x0900], [0, 2, None]]


def _sbi_words_match(image: bytes, position: int,
                     expected: dict[int, int]) -> bool:
    """Match one fixed Thumb SBI bootstrap layout without loose literals."""
    return (position >= 0
            and all(position + offset <= len(image) - 2
                    and struct.unpack_from("<H", image, position + offset)[0]
                    == word
                    for offset, word in expected.items()))


def _sbi_literals_match(image: bytes, position: int,
                        expected: tuple[tuple[int, int, int], ...]) -> bool:
    return all(thumb_literal_value(image, position + offset, register) == value
               for offset, register, value in expected)


def _sbi_bootstrap_layout_at(image: bytes, position: int) -> str | None:
    """Recognize only the two static layouts that close bootstrap plus R/W/R."""
    m330_words = {
        0: 0x2045, 4: 0x7008, 6: 0x20C5, 8: 0x7008,
        0x0C: 0x303D, 0x0E: 0x8088, 0x12: 0x38F4, 0x14: 0x8188,
        0x16: 0x2000, 0x1A: 0x3110, 0x1C: 0x7008, 0x1E: 0x2001,
        0x20: 0x7008, 0x24: 0x8800, 0x26: 0x0840, 0x28: 0xD2FB,
        0x2C: 0x30DE, 0x30: 0x8188, 0x34: 0x8800, 0x36: 0x0840,
        0x38: 0xD306,
    }
    if (_sbi_words_match(image, position, m330_words)
            and _sbi_literals_match(image, position, (
                (2, 1, SBI_BOOTSTRAP_BASE), (0x0A, 0, 0x0822),
                (0x10, 0, 0x0513), (0x18, 1, SBI_BOOTSTRAP_BASE),
                (0x22, 0, SBI_BOOTSTRAP_BASE), (0x2A, 0, 0x0822),
                (0x2E, 1, SBI_BOOTSTRAP_BASE),
                (0x32, 0, SBI_BOOTSTRAP_BASE),
            ))):
        return "thumb-sbi-bootstrap-literal-arithmetic-v1"
    sd100_words = {
        0: 0x2045, 4: 0x7008, 6: 0x20C5, 8: 0x7008,
        0x0C: 0x8088, 0x10: 0x8188, 0x12: 0x2000, 0x16: 0x7008,
        0x18: 0x2001, 0x1A: 0x7008, 0x1E: 0x8800, 0x20: 0x07C0,
        0x22: 0x0FC0, 0x24: 0x2801, 0x26: 0xD100, 0x28: 0xE7F8,
        0x2A: 0x2009, 0x2C: 0x0200, 0x30: 0x8188, 0x34: 0x8800,
        0x36: 0x07C0, 0x38: 0x0FC0, 0x3A: 0x2801, 0x3C: 0xD100,
        0x3E: 0xE7F8,
    }
    if (_sbi_words_match(image, position, sd100_words)
            and _sbi_literals_match(image, position, (
                (2, 1, SBI_BOOTSTRAP_BASE), (0x0A, 0, 0x085F),
                (0x0E, 0, 0x041F), (0x14, 1, SBI_BOOTSTRAP_BASE + 0x10),
                (0x1C, 0, SBI_BOOTSTRAP_BASE),
                (0x2E, 1, SBI_BOOTSTRAP_BASE),
                (0x32, 0, SBI_BOOTSTRAP_BASE),
            ))):
        return "thumb-sbi-bootstrap-direct-literal-v1"
    return None


def find_sbi_bootstrap_profile(image: bytes) -> dict[str, object] | None:
    """Admit one exact SBI bootstrap; all later SBI semantics stay fail-closed."""
    matches: list[tuple[int, str]] = []
    position = 0
    while (position := image.find(b"\x45\x20", position)) >= 0:
        candidate = position
        position += 2
        if candidate & 1:
            continue
        if (layout := _sbi_bootstrap_layout_at(image, candidate)) is not None:
            matches.append((candidate, layout))
    if len(matches) != 1:
        return None
    entry, layout = matches[0]
    return {
        "signature": "thumb-sbi-bootstrap-only-v1",
        "admission": "temporary-evidence-gated",
        "accepted": True,
        "base_address": SBI_BOOTSTRAP_BASE,
        "bootstrap": SBI_BOOTSTRAP,
        "validation": SBI_BOOTSTRAP_VALIDATION,
        "entries": [entry],
        "layout": layout,
    }


def _dc0_board_adc_profile_at(
        image: bytes, scale: int,
) -> tuple[dict[str, object] | None, str]:
    """Close one selector-2 raw-byte path through its battery policy."""
    def exact_shape(position: int, size: int,
                    expected: tuple[str, tuple[int, ...]]) -> bool:
        return (_normalized_thumb_sha256(image, position, size) == expected
                and all((target := thumb_bl_target(image, position + offset))
                        is not None and 0 <= target < len(image)
                        for offset in expected[1]))

    if not exact_shape(scale, 0x4C, DC0_BOARD_ADC_SCALE_SHAPE):
        return None, "selector2-helper-not-unique"
    getter = thumb_bl_target(image, scale + 0x1A)
    if (image[scale + 0x18:scale + 0x1A] != b"\x02\x20"
            or getter is None
            or not exact_shape(getter, 0x1C, DC0_BOARD_ADC_GETTER_SHAPE)):
        return None, "raw-getter/service-grammar-mismatch"
    service = thumb_bl_target(image, getter + 0x12)
    if (service is None
            or not exact_shape(service, 0xBE, DC0_BOARD_ADC_SERVICE_SHAPE)):
        return None, "raw-getter/service-grammar-mismatch"
    cache_roots = (
        thumb_literal_value(image, getter + 0x04, 3),
        thumb_literal_value(image, service + 0x14, 1),
        thumb_literal_value(image, service + 0x66, 0),
        thumb_literal_value(image, service + 0x96, 1),
    )
    if (cache_roots[0] is None
            or not 0x01000000 <= cache_roots[0] < 0x02000000
            or len(set(cache_roots)) != 1):
        return None, "raw-getter/service-grammar-mismatch"

    send = thumb_bl_target(image, service + 0x5C)
    receive = thumb_bl_target(image, service + 0x92)
    if (send is None or receive is None
            or not exact_shape(send, 0x74, DC0_BOARD_ADC_SEND_SHAPE)
            or not exact_shape(receive, 0xAE, DC0_BOARD_ADC_RECEIVE_SHAPE)):
        return None, "dc0-receive-mmio-mismatch"
    if (thumb_literal_value(image, receive + 0x04, 1) != 0x8840
            or any(thumb_literal_value(image, receive + offset, 4)
                   != 0x03000DC0 for offset in (0x2E, 0x7E, 0x8A, 0x96))
            or thumb_literal_value(image, receive + 0x0A, 0) != 0x03000DC0
            or any(thumb_literal_value(image, receive + offset, 0)
                   != 0x03000C80 for offset in (0x44, 0x68))):
        return None, "dc0-receive-mmio-mismatch"

    callers = [
        match.start()
        for match in THUMB_BL_PATTERN.finditer(image)
        if not match.start() & 1
        and thumb_bl_target(image, match.start()) == scale
        and thumb_bl_target(image, match.start() + 4) is not None
    ]
    filter_addresses = {
        thumb_bl_target(image, caller + 4) for caller in callers
    }
    if len(callers) != 2 or len(filter_addresses) != 1:
        return None, "battery-filter-consumer-not-unique"
    filter_address = filter_addresses.pop()
    if not exact_shape(filter_address, 0x1B4, DC0_BOARD_ADC_FILTER_SHAPE):
        return None, "battery-filter-policy-mismatch"
    filter_calls = {
        offset: thumb_bl_target(image, filter_address + offset)
        for offset in DC0_BOARD_ADC_FILTER_SHAPE[1]
    }
    same_targets = (
        (0x12, 0x148), (0x7A, 0xC2, 0x104), (0x94, 0xD6, 0x112),
        (0x9E, 0xE0), (0xBC, 0xFE),
    )
    if (any(len({filter_calls[offset] for offset in group}) != 1
            for group in same_targets)
            or thumb_literal_value(image, filter_address + 0x9C, 0)
            != 0x4000001B
            or thumb_literal_value(image, filter_address + 0xDE, 0)
            != 0x4000001A):
        return None, "battery-filter-policy-mismatch"
    return {
        "signature": "static-dc0-selector2-battery-policy-v1",
        "accepted": True,
        "scope": "temporary-evidence-gated",
        "transport": "dc0-887e-b200-start01-lowbyte-v1",
        "selector": 2,
        "response_raw": 0xFF,
        "low_thresholds": [0xC8, 0xDE],
        "scale_offset": scale,
        "raw_getter_offset": getter,
        "service_offset": service,
        "receive_offset": receive,
        "filter_offset": filter_address,
        "caller_offsets": callers,
    }, ""


def find_dc0_board_adc_profile(image: bytes) -> dict[str, object] | None:
    """Return one fail-closed virtual full-battery policy, never a model gate."""
    scales = [position for position in find_all(image, DC0_BOARD_ADC_SCALE_PREFIX)
              if not position & 1]
    if not scales:
        return None
    profiles: list[dict[str, object]] = []
    reasons: list[str] = []
    for scale in scales:
        profile, reason = _dc0_board_adc_profile_at(image, scale)
        if profile is not None:
            profiles.append(profile)
        else:
            reasons.append(reason)
    if len(profiles) == 1:
        return profiles[0]
    return {
        "signature": "static-dc0-selector2-battery-policy-v1",
        "accepted": False,
        "reject_reason": (
            "battery-policy-ambiguous" if profiles
            else reasons[0] if len(scales) == 1
            else "selector2-helper-not-unique"
        ),
    }


def detect_input_profile(image: bytes, load_address: int = 0
                         ) -> tuple[str, int, int | None] | None:
    """Locate LG/Samsung input signatures for diagnostics only."""
    lg_matches = list(LG_INPUT_PATTERN.finditer(image))
    if len(lg_matches) == 1:
        wrapper = lg_matches[0].start()
        decoder = thumb_bl_target(image, wrapper + 2)
        drain = thumb_bl_target(image, wrapper + 6)
        enqueue = decoder + 0x6C if decoder is not None else -1
        if (drain is not None
                and image[enqueue:enqueue + len(LG_DECODED_ENQUEUE_SIGNATURE)]
                == LG_DECODED_ENQUEUE_SIGNATURE):
            return "lg-decoded", load_address + enqueue, load_address + drain

    samsung_matches = list(SAMSUNG_INPUT_PATTERN.finditer(image))
    if len(samsung_matches) == 1:
        match = samsung_matches[0].start()
        for entry in range(match & ~1, max(-1, match - 0xC0), -2):
            if image[entry:entry + 4] in (b"\x80\xb5\x07\x1c",
                                           b"\xb0\xb5\x07\x1c"):
                return "samsung-queue", load_address + entry, None
    return None


def find_board_status_input(image: bytes) -> BoardStatusInput | None:
    """Accept one unique Thumb byte-status mask/branch/debounce control shape."""
    found: set[BoardStatusInput] = set()
    offset = 0
    while (offset := image.find(b"\xf0\xb5", offset)) >= 0:
        address = thumb_literal_value(image, offset + 2, 0)
        candidate = (BoardStatusInput(address, 0x08, 0x08)
                     if address is not None
                     and 0x03000000 <= address < 0x03800000 else None)
        if (image[offset + 4:offset + 4 + len(BOARD_STATUS_INPUT_BODY)]
                == BOARD_STATUS_INPUT_BODY):
            if candidate is not None:
                found.add(candidate)
        elif candidate is not None and image[offset + 4:offset + 6] == b"\x00\x78":
            body_end = min(offset + 0x400, len(image) - 1)
            pop = next((position for position in range(offset + 6, body_end, 2)
                        if struct.unpack_from("<H", image, position)[0] == 0xBDF0),
                       None)
            early_end = min(offset + 0x100, pop if pop is not None else offset)
            debounced = (pop is not None
                         and b"\x5f\x27" in image[offset + 6:pop]
                         and b"\x60\x27" in image[offset + 6:pop])
            for movs in range(offset + 6, early_end, 2):
                move = struct.unpack_from("<H", image, movs)[0]
                if move & 0xF8FF != 0x2008:
                    continue
                mask_register = (move >> 8) & 7
                if mask_register == 0:
                    continue
                for ands in range(movs + 2, min(movs + 10, early_end), 2):
                    word = struct.unpack_from("<H", image, ands)[0]
                    if word & 0xFFC0 != 0x4000:
                        continue
                    result = word & 7
                    source = (word >> 3) & 7
                    if {result, source} != {0, mask_register}:
                        continue
                    compare = 0x2808 | (result << 8)
                    for position in range(ands + 2, min(ands + 16, early_end), 2):
                        if struct.unpack_from("<H", image, position)[0] != compare:
                            continue
                        for branch in range(position + 2,
                                            min(position + 8, early_end), 2):
                            if struct.unpack_from("<H", image, branch)[0] & 0xFF00 != 0xD100:
                                continue
                            if (debounced and all(
                                    (word := struct.unpack_from("<H", image, delay)[0])
                                    == 0xBF00 or word & 0xF800 == 0x4800
                                    for delay in range(position + 2, branch, 2))):
                                found.add(candidate)
                        break
        offset += 2
    return next(iter(found)) if len(found) == 1 else None
