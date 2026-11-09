"""EEPROM rules owned by the device domain."""
from __future__ import annotations

from ...arm import thumb_bl_target
from ...facts import facts_for
from .catalog import (
    EEPROM_24LCXX_READ_SIGNATURE, EEPROM_24LCXX_X270_READ_PREFIX,
    EEPROM_24LCXX_X270_WRITE_PREFIX, EEPROM_24LCXX_X430_READ_PREFIX,
    EEPROM_24LCXX_X430_WRITE_PREFIX, EEPROM_24LCXX_X7700_READ_PREFIX,
    EEPROM_24LCXX_X7700_WRITE_PREFIX,
)
from .drivers import (
    eeprom_24lcxx_write_at, find_24lcxx_f6f7_driver, find_24lcxx_f7f6_driver,
    find_24lcxx_halfword_driver, find_24lcxx_x270_driver, find_24lcxx_x7700_driver,
)
from .gpio_facts import _code_shapes_match, _literal_values_match
from .wire_rules import _byte_gpio_protocol, _descriptor_gpio_evidence
import struct


_BYTE_GPIO_PROFILE = (0x03000660, 4, 1, 0, 0x20, 0x18, 0x8000)


def _select_eeprom_gpio_profile(
        image: bytes, config: object,
        ) -> tuple[tuple[int, int, int, int, int, int, int] | None,
                   str | None]:
    """Return one detector-closed 24LCxx GPIO descriptor or reject reason."""
    read = getattr(config, "eeprom_read_address", None)
    write = getattr(config, "eeprom_write_address", None)
    geometry = getattr(config, "eeprom_geometry_address", None)
    load = getattr(config, "load_address", 0)
    if not all(isinstance(value, int) for value in (read, write, geometry)):
        return None, None
    read -= load
    write -= load
    if not (0 <= read < len(image) and 0 <= write < len(image)):
        return None, "transport-entry-outside-firmware"
    common = (
        image[read:read + len(EEPROM_24LCXX_READ_SIGNATURE)]
        == EEPROM_24LCXX_READ_SIGNATURE
        and eeprom_24lcxx_write_at(image, write)
    )
    if find_24lcxx_f6f7_driver(image) == (read, write, geometry):
        return (0x03000660, 8, 8, 0xC, 1, 0x1C, 0x8000), None
    if find_24lcxx_halfword_driver(image) == (read, write, geometry):
        from msm5xxx_emulator.detection.layout_facts import find_linker_layout
        descriptor, reason = _descriptor_gpio_evidence(
            image, read, write, linker=None, load=load,
            reader_offset=0x78, discover_linker=True,
            reader_from_write=True)
        if descriptor is None:
            return None, reason
        # These are caller-side address and page-capacity arguments; the local
        # bit-banging routines are admitted by shared function facts above.
        shapes = (
            (write + 0x74, "0e231840a0221043"),
            (write + 0x92, "4020"),
            (write + 0x16A, "2012"),
            (read + 0x142, "0e231e40a0203043"),
            (read + 0x14E, "3812"),
            (read + 0x2F0, "a12030430006000e"),
        )
        if (not _code_shapes_match(
                    image, tuple((p, bytes.fromhex(h)) for p, h in shapes))
                or any(thumb_bl_target(image, entry + offset) != target
                       for entry, offset, target in (
                           (write, 0x166, write - 0x160),
                           (write, 0x16C, write - 0x160),
                           (read, 0x14A, write - 0x160),
                           (read, 0x150, write - 0x160),
                           (read, 0x31E, write - 0x78),
                           (read, 0x3CE, write - 0x78),
                           (write - 0x160, 0xDA, write - 0x1FE)))):
            return None, "gpio-line-shape-mismatch"
        return (0x03000720, 0, 0x20, 0, 0x40, 0xC, 0x8000), None
    x7700 = (
        image[read:read + len(EEPROM_24LCXX_X7700_READ_PREFIX)]
        == EEPROM_24LCXX_X7700_READ_PREFIX
        and image[write:write + len(EEPROM_24LCXX_X7700_WRITE_PREFIX)]
        == EEPROM_24LCXX_X7700_WRITE_PREFIX
        and find_24lcxx_x7700_driver(image) == (read, write, geometry)
    )
    if x7700:
        _descriptor, reason = _descriptor_gpio_evidence(
            image, read, write, linker=getattr(config, "linker", None),
            load=load, reader_offset=0x728)
        if _descriptor is None:
            return None, reason
        return (0x03000720, 0, 0x20, 0, 0x40, 0xC, 0x8000), None
    split_bank = (
        image[read:read + len(EEPROM_24LCXX_X430_READ_PREFIX)]
        == EEPROM_24LCXX_X430_READ_PREFIX
        and image[write:write + len(EEPROM_24LCXX_X430_WRITE_PREFIX)]
        == EEPROM_24LCXX_X430_WRITE_PREFIX
    )
    if split_bank:
        writer = write - 0x12C
        ack = writer - 0xA6
        reader = read - 0x718
        if (min(ack, writer, reader) < 0
                or not _byte_gpio_protocol(facts_for(image), writer, reader,
                                           ack, _BYTE_GPIO_PROFILE)):
            return None, "gpio-line-shape-mismatch"
        return _BYTE_GPIO_PROFILE, None
    f7f6 = (
        image[read:read + len(EEPROM_24LCXX_X430_READ_PREFIX)]
        == EEPROM_24LCXX_X430_READ_PREFIX
        and image[write:write + len(EEPROM_24LCXX_X7700_WRITE_PREFIX)]
        == EEPROM_24LCXX_X7700_WRITE_PREFIX
        and find_24lcxx_f7f6_driver(image) == (read, write, geometry)
    )
    if f7f6:
        writer = write - 0x16C
        ack = write - 0x216
        reader = read - 0x754
        if (read - write != 0x6D8 or min(ack, writer, reader) < 0
                or not _byte_gpio_protocol(facts_for(image), writer, reader,
                                           ack, _BYTE_GPIO_PROFILE)):
            return None, "gpio-line-shape-mismatch"
        return _BYTE_GPIO_PROFILE, None
    x270 = (
        image[read:read + len(EEPROM_24LCXX_X270_READ_PREFIX)]
        == EEPROM_24LCXX_X270_READ_PREFIX
        and image[write:write + len(EEPROM_24LCXX_X270_WRITE_PREFIX)]
        == EEPROM_24LCXX_X270_WRITE_PREFIX
        and find_24lcxx_x270_driver(image) == (read, write, geometry)
    )
    if x270:
        writer = write - 0x2DC
        reader = read - 0x7F8
        shapes = (
            (writer, bytes.fromhex("f0b5071c")),
            (writer + 0x18, bytes.fromhex("2b7808263343")),
            (writer + 0x28, bytes.fromhex("2b702b782372")),
            (writer + 0x2E, bytes.fromhex("13780b43137013782373")),
            (writer + 0x3E, bytes.fromhex("137013782373")),
            (reader, bytes.fromhex("f0b50027")),
            (reader + 0x0E, bytes.fromhex("0a782a430a700b78")),
            (reader + 0x1A, bytes.fromhex("1373")),
            (reader + 0x1C, bytes.fromhex("2678330900d38027")),
            (reader + 0x24, bytes.fromhex("0b785b085b000b700b781373")),
            (write + 0xBE, bytes.fromhex("08251178294311701178")),
            (write + 0xCA, bytes.fromhex("1173")),
            (read + 0x304, bytes.fromhex("082311789943117011")),
            (read + 0x310, bytes.fromhex("1173")),
            (read + 0x324, bytes.fromhex("2070")),
        )
        literals = (
            (writer + 0x12, 4, 0x03000660),
            (reader + 0x04, 4, 0x03000668),
            (reader + 0x16, 2, 0x03000668),
            (write + 0xC8, 2, 0x03000670),
            (read + 0x30E, 2, 0x03000670),
        )
        if (read - write != 0x6D0 or min(writer, reader) < 0
                or not _code_shapes_match(image, shapes)
                or not _literal_values_match(image, literals)
                or thumb_bl_target(image, read + 0x320) != reader):
            return None, "gpio-line-shape-mismatch"
        return (0x03000660, 8, 8, 0xC, 1, 0x1C, 0x8000), None
    if not common:
        return None, "transport-entry-signature-mismatch"
    gpio = struct.pack("<II", 0x03000660, 0x03000670)
    if (not all(value in image[write:write + 0x700]
                for value in (gpio[:4], gpio[4:]))
            or not all(value in image[read:read + 0x700]
                       for value in (gpio[:4], gpio[4:]))):
        return None, "gpio-line-shape-mismatch"
    literal = struct.pack("<I", geometry)
    for position in range(0, len(image) - 3, 4):
        if image[position:position + 4] != literal or position < 0x14:
            continue
        initializer = image[position - 0x14:position]
        operation = struct.unpack_from("<H", initializer, 2)[0]
        literal_address = ((position - 0x14 + 6) & ~3) + (operation & 0xFF) * 4
        if (initializer[:2] == b"\x01\x21"
                and operation & 0xF800 == 0x4800
                and operation >> 8 & 7 == 0
                and literal_address == position
                and initializer[4:18]
                == bytes.fromhex("c9030180012181700021c170f746")):
            return (0x03000660, 8, 8, 0xC, 1, 0x1C, 0x8000), None
    return None, "capacity-initializer-mismatch"
