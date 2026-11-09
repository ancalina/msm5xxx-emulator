"""EEPROM driver pairing and code-derived geometry observations."""
from __future__ import annotations

from ...arm import thumb_bl_target
from ...facts import CodeAddress, facts_for
from ...signatures import find_all
from .catalog import (
    EEPROM_24LCXX_WRITE_PREFIX, EEPROM_24LCXX_READ_SIGNATURE,
    EEPROM_24LC64_CLASS_A_WRITE_PREFIX, EEPROM_24LC64_CLASS_A_READ_PREFIX,
    EEPROM_24LC64_CLASS_A_SENTINEL, EEPROM_24LC64_CLASS_B_WRITE_PREFIX,
    EEPROM_24LC64_CLASS_B_READ_PREFIX, EEPROM_24LC64_CLASS_B_BOUND,
    EEPROM_24LCXX_X430_WRITE_PREFIX, EEPROM_24LCXX_X430_READ_PREFIX,
    EEPROM_24LCXX_X430_INIT_SIGNATURE, EEPROM_24LCXX_X270_WRITE_PREFIX,
    EEPROM_24LCXX_X270_READ_PREFIX, EEPROM_24LCXX_X270_INIT_SIGNATURE,
    EEPROM_24LCXX_F6F7_WRITE_PREFIX, EEPROM_24LCXX_X7700_WRITE_PREFIX,
    EEPROM_24LCXX_X7700_READ_PREFIX, EEPROM_24LCXX_X7700_INIT_SIGNATURE,
    EEPROM_24LCXX_HALFWORD_READ_PREFIX,
)
import struct


def eeprom_24lcxx_write_at(image: bytes, position: int) -> bool:
    """Match the common ADS 24LCxx writer while ignoring its literal reach."""
    prefix = EEPROM_24LCXX_WRITE_PREFIX
    return (position & 1 == 0
            and 0 <= position <= len(image) - len(prefix)
            and image[position:position + 14] == prefix[:14]
            and image[position + 15:position + len(prefix)] == prefix[15:])


def eeprom_24lc64_class_a_write_at(image: bytes, position: int) -> bool:
    """Match both proven relocation variants of the old 8 KiB writer."""
    return (position & 1 == 0
            and 0 <= position <= len(image) - 48
            and image[position:position + 2] == b"\xf7\xb5"
            and image[position + 4:position + 6] == b"\x8c\xb0"
            and image[position + 10:position + 22]
            == EEPROM_24LC64_CLASS_A_WRITE_PREFIX[10:22]
            and image[position + 23:position + 34]
            == EEPROM_24LC64_CLASS_A_WRITE_PREFIX[23:34]
            and image[position + 35:position + 46]
            == EEPROM_24LC64_CLASS_A_WRITE_PREFIX[35:46]
            and image[position + 47:position + 48]
            == EEPROM_24LC64_CLASS_A_WRITE_PREFIX[47:48])


def find_24lc64_class_a_driver(image: bytes) -> tuple[int, int, int] | None:
    """Return the uniquely bound old 8 KiB read/write/max-literal class."""
    if b"nv24lcxx.c\0" not in image.lower():
        return None
    writes = [position for position in find_all(image, b"\xf7\xb5")
              if eeprom_24lc64_class_a_write_at(image, position)]
    reads = find_all(image, EEPROM_24LC64_CLASS_A_READ_PREFIX)
    if len(writes) != 1 or len(reads) != 1:
        return None
    write, read = writes[0], reads[0]
    if read - write not in (0x764, 0x768, 0x784):
        return None

    bindings: list[int] = []
    for delta in (0xAC8, 0xACC):
        geometry = read + delta
        if (geometry < 0x1A or geometry + 4 > len(image)
                or struct.unpack_from("<I", image, geometry)[0] != 0x1FFF
                or image[geometry - 0x1A:geometry - 0xA]
                != EEPROM_24LC64_CLASS_A_SENTINEL):
            continue
        for call in range(geometry - 0x38, geometry - 0x27, 2):
            if (call < 6 or call + 4 > len(image)
                    or image[call - 6:call - 2] != b"\x00\x21\x20\x1c"
                    or thumb_bl_target(image, call) != read):
                continue
            operation = struct.unpack_from("<H", image, call - 2)[0]
            literal = (((call + 2) & ~3) + (operation & 0xFF) * 4)
            if (operation & 0xF800 == 0x4800
                    and operation >> 8 & 7 == 2
                    and literal == geometry):
                bindings.append(geometry)
    return (read, write, bindings[0]) if len(bindings) == 1 else None


def find_24lc64_class_b_driver(image: bytes) -> tuple[int, int, int] | None:
    """Return the unique static-capacity 8 KiB transport class."""
    writes = find_all(image, EEPROM_24LC64_CLASS_B_WRITE_PREFIX)
    reads = find_all(image, EEPROM_24LC64_CLASS_B_READ_PREFIX)
    if len(writes) != 1 or len(reads) != 1:
        return None
    if len(find_all(image.lower(), b"nv24lcxx.c\0")) != 1:
        return None
    write, read = writes[0], reads[0]
    if (write & 1 or read & 1
            or image[write + 4:write + 10] != EEPROM_24LC64_CLASS_B_BOUND
            or image[read + 6:read + 12] != EEPROM_24LC64_CLASS_B_BOUND):
        return None
    return read, write, 0x2000


def _eeprom_24lcxx_variant_geometry_at(image: bytes, position: int,
                                      ldr_offset: int, literal_offset: int,
                                      geometry: int) -> bool:
    facts = facts_for(image)
    literal = facts.literal(CodeAddress(facts.base + position + ldr_offset, 'thumb'))
    return (literal is not None and literal.value == geometry
            and literal.pool == facts.base + position + literal_offset)


def _paired_eeprom_driver(image: bytes, write_prefix: bytes, read_prefix: bytes,
                          init_prefix: bytes, write_pool: int, read_pool: int,
                          *, unique_marker: bool = True,
                          initializer_literal: bool = False,
                          gpio_proof=None) -> tuple[int, int, int] | None:
    """Bind unique read/write entries to one initialized geometry global.

    Compiler differences are parameters of this evidence query. The GPIO
    consumer remains an additional predicate where the byte driver needs it.
    This legacy class uses global signature uniqueness, so its whole search
    span must be supplied before absence or uniqueness can be claimed.
    """
    facts = facts_for(image)
    if not facts.view.covers(facts.base, len(image)):
        return None
    marker = facts.memo('eeprom-source-marker', (), lambda:
                        image.lower().count(b'nv24lcxx.c\0'))
    if not marker or unique_marker and marker != 1:
        return None
    entries = [facts.string_candidates(prefix)
               for prefix in (write_prefix, read_prefix, init_prefix)]
    if any(len(matches) != 1 for matches in entries):
        return None
    write, read, initializer = (matches[0] - facts.base for matches in entries)
    if not all(facts.view.covers(facts.base + at, len(prefix))
               for at, prefix in zip((write, read, initializer),
                                     (write_prefix, read_prefix, init_prefix))):
        return None
    if initializer_literal:
        geometry = facts.thumb_literal_value(initializer + 2, 1)
    else:
        raw = facts.view.read(facts.base + initializer + 0x14, 4)
        geometry = int.from_bytes(raw, 'little') if raw is not None else None
    if (geometry is None or geometry & 3
            or not 0x00800000 <= geometry < 0x02000000
            or not _eeprom_24lcxx_variant_geometry_at(
                image, write, 0xE, write_pool, geometry)
            or not _eeprom_24lcxx_variant_geometry_at(
                image, read, 0xC, read_pool, geometry)
            or gpio_proof is not None and not gpio_proof(image, write, read)):
        return None
    return read, write, geometry


def find_24lcxx_x430_driver(image: bytes) -> tuple[int, int, int] | None:
    return _paired_eeprom_driver(
        image, EEPROM_24LCXX_X430_WRITE_PREFIX, EEPROM_24LCXX_X430_READ_PREFIX,
        EEPROM_24LCXX_X430_INIT_SIGNATURE, 0x3E8, 0x3E8)


def find_24lcxx_x270_driver(image: bytes) -> tuple[int, int, int] | None:
    return _paired_eeprom_driver(
        image, EEPROM_24LCXX_X270_WRITE_PREFIX, EEPROM_24LCXX_X270_READ_PREFIX,
        EEPROM_24LCXX_X270_INIT_SIGNATURE, 0x3EC, 0x3EC)


def find_24lcxx_f6f7_driver(image: bytes) -> tuple[int, int, int] | None:
    return _paired_eeprom_driver(
        image, EEPROM_24LCXX_F6F7_WRITE_PREFIX, EEPROM_24LCXX_X270_READ_PREFIX,
        EEPROM_24LCXX_X270_INIT_SIGNATURE, 0x3E8, 0x3EC,
        gpio_proof=_eeprom_f6f7_gpio_shape)


def _eeprom_f6f7_gpio_shape(image: bytes, write: int, read: int) -> bool:
    """Require the paired byte-level GPIO leaves and their local call shape."""
    facts = facts_for(image)
    start = max(0, write - 0x400)
    end = min(len(image) - 4, read + 0x1000)
    calls: dict[int, int] = {}
    for site, target in facts.call_candidates('thumb'):
        position = site - facts.base
        target -= facts.base
        if (start <= position < end and 0 <= target <= len(image) - 4):
            calls[target] = calls.get(target, 0) + 1

    def literals(target: int) -> set[int]:
        values = set()
        for position in range(target, min(len(image) - 2, target + 0x100), 2):
            word = struct.unpack_from("<H", image, position)[0]
            register = word >> 8 & 7
            value = facts.thumb_literal_value(position, register)
            if word & 0xF800 == 0x4800 and value is not None:
                values.add(value)
        return values

    writers = [target for target, count in calls.items()
               if count == 16
               and image[target:target + 4] == b"\xf0\xb5\x07\x1c"
               and {0x03000660, 0x03000668} <= literals(target)]
    readers = [target for target, count in calls.items()
               if count == 2
               and image[target:target + 4] == b"\xf0\xb5\x00\x27"
               and 0x03000668 in literals(target)]
    return len(writers) == len(readers) == 1


def find_24lcxx_x7700_driver(image: bytes) -> tuple[int, int, int] | None:
    return _paired_eeprom_driver(
        image, EEPROM_24LCXX_X7700_WRITE_PREFIX, EEPROM_24LCXX_X7700_READ_PREFIX,
        EEPROM_24LCXX_X7700_INIT_SIGNATURE, 0x3EC, 0x3E8, unique_marker=False)


def find_24lcxx_f7f6_driver(image: bytes) -> tuple[int, int, int] | None:
    return _paired_eeprom_driver(
        image, EEPROM_24LCXX_X7700_WRITE_PREFIX, EEPROM_24LCXX_X430_READ_PREFIX,
        EEPROM_24LCXX_X7700_INIT_SIGNATURE, 0x3EC, 0x3E8)


def find_24lcxx_halfword_driver(image: bytes) -> tuple[int, int, int] | None:
    return _paired_eeprom_driver(
        image, EEPROM_24LCXX_X430_WRITE_PREFIX, EEPROM_24LCXX_HALFWORD_READ_PREFIX,
        EEPROM_24LCXX_X430_INIT_SIGNATURE, 0x3E8, 0x3E8,
        unique_marker=False, initializer_literal=True)


def find_24lcxx_driver(image: bytes) -> tuple[int, int, int] | None:
    """Return unique read/write offsets and the firmware geometry global."""
    if b"nv24lcxx.c\0" not in image.lower():
        return None
    writes = [position for position in find_all(image, EEPROM_24LCXX_WRITE_PREFIX[:14])
              if eeprom_24lcxx_write_at(image, position)]
    reads = find_all(image, EEPROM_24LCXX_READ_SIGNATURE)
    if len(writes) == 1 and len(reads) == 1:
        write = writes[0]
        operation = struct.unpack_from("<H", image, write + 14)[0]
        if operation & 0xF800 == 0x4800 and (operation >> 8) & 7 == 1:
            literal = ((write + 18) & ~3) + (operation & 0xFF) * 4
            if literal + 4 <= len(image):
                geometry = struct.unpack_from("<I", image, literal)[0]
                read_operation = struct.unpack_from("<H", image, reads[0] + 10)[0]
                read_literal = (((reads[0] + 14) & ~3)
                                + (read_operation & 0xFF) * 4)
                if (not geometry & 3
                        and 0x00800000 <= geometry < 0x02000000
                        and read_operation & 0xF800 == 0x4800
                        and (read_operation >> 8) & 7 == 0
                        and read_literal + 4 <= len(image)
                        and struct.unpack_from("<I", image, read_literal)[0]
                        == geometry):
                    return reads[0], write, geometry
    return (find_24lc64_class_a_driver(image)
            or find_24lcxx_x430_driver(image)
            or find_24lcxx_x270_driver(image)
            or find_24lcxx_f6f7_driver(image)
            or find_24lcxx_x7700_driver(image)
            or find_24lcxx_f7f6_driver(image)
            or find_24lcxx_halfword_driver(image))
