"""Firmware input and board-status detection."""
from __future__ import annotations

import re
import struct

from ..core.config import BoardStatusInput

from .arm import thumb_bl_target, thumb_literal_value
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


BOARD_STATUS_INPUT_BODY = bytes.fromhex(
    "007808231840082801d1012100e00021002700260124002936484ad0"
)


def board_adc_reader_at(image: bytes, position: int) -> bool:
    """Validate one shared ADC reader without matching unrelated MMIO users."""
    if position & 1 or position < 0 or position + BOARD_ADC_READER_SIZE > len(image):
        return False
    fixed = (
        (0, BOARD_ADC_READER_PREFIX),
        (8, bytes.fromhex("0404240c")),
        (0x10, bytes.fromhex("2a20")),
        (0x16, BOARD_ADC_READER_BODY),
        (0x5E, BOARD_ADC_READER_MID_BODY),
        (0x72, bytes.fromhex("0b20")),
        (0x7C, BOARD_ADC_READER_TAIL),
        (0x8C, bytes.fromhex("381c90bd")),
    )
    if any(image[position + offset:position + offset + len(expected)] != expected
           for offset, expected in fixed):
        return False
    if struct.unpack_from("<I", image, position + 0x94)[0] != BOARD_ADC_READER_LITERAL:
        return False
    return all((target := thumb_bl_target(image, position + offset)) is not None
               and 0 <= target < len(image)
               for offset in BOARD_ADC_READER_BL_OFFSETS)


def find_board_adc_reader(image: bytes) -> int | None:
    """Return unique shared Thumb ADC reader, never loose ADC MMIO literal hits."""
    matches = [position for position in find_all(image, BOARD_ADC_READER_PREFIX)
               if board_adc_reader_at(image, position)]
    return matches[0] if len(matches) == 1 else None


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
