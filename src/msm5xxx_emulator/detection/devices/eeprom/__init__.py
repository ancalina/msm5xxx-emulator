"""EEPROM source evidence and its captured driver parameters."""
from __future__ import annotations
from dataclasses import dataclass
from .catalog import (EEPROM_24LCXX_WRITE_PREFIX, EEPROM_24LCXX_READ_SIGNATURE, EEPROM_24LC64_CLASS_A_WRITE_PREFIX, EEPROM_24LC64_CLASS_A_READ_PREFIX,
    EEPROM_24LC64_CLASS_A_SENTINEL, EEPROM_24LC64_CLASS_B_WRITE_PREFIX, EEPROM_24LC64_CLASS_B_READ_PREFIX, EEPROM_24LC64_CLASS_B_BOUND,
    EEPROM_24LCXX_X430_WRITE_PREFIX, EEPROM_24LCXX_X430_READ_PREFIX, EEPROM_24LCXX_X430_INIT_SIGNATURE, EEPROM_24LCXX_X270_WRITE_PREFIX,
    EEPROM_24LCXX_X270_READ_PREFIX, EEPROM_24LCXX_X270_INIT_SIGNATURE, EEPROM_24LCXX_F6F7_WRITE_PREFIX, EEPROM_24LCXX_X7700_WRITE_PREFIX,
    EEPROM_24LCXX_X7700_READ_PREFIX, EEPROM_24LCXX_X7700_INIT_SIGNATURE, EEPROM_24LCXX_HALFWORD_READ_PREFIX)
from .drivers import (eeprom_24lcxx_write_at, eeprom_24lc64_class_a_write_at, find_24lc64_class_a_driver, find_24lc64_class_b_driver,
    _eeprom_24lcxx_variant_geometry_at, _paired_eeprom_driver, find_24lcxx_x430_driver, find_24lcxx_x270_driver, find_24lcxx_f6f7_driver,
    _eeprom_f6f7_gpio_shape, find_24lcxx_x7700_driver, find_24lcxx_f7f6_driver, find_24lcxx_halfword_driver, find_24lcxx_driver)
from .projection import (eeprom_gpio_plan, eeprom_gpio_profile, eeprom_gpio_property, eeprom_gpio_window, eeprom_gpio_capacity,)

@dataclass(frozen=True, slots=True)
class DriverEntries:
    read: int | None = None
    write: int | None = None
    geometry: int | None = None
    capacity: int | None = None
    notes: tuple[str, ...] = ()

def capture_entries(image: bytes) -> DriverEntries:
    driver = find_24lcxx_driver(image)
    notes = []
    read = write = geometry = capacity = None
    if driver is not None:
        read, write, geometry = driver
        notes.append("24LCxx EEPROM read/write driver and geometry descriptor detected")
    else:
        static = find_24lc64_class_b_driver(image)
        if static is not None:
            read, write, capacity = static
            notes.append("24LC64 EEPROM read/write driver and static 0x2000-byte " "capacity guards detected")
        elif ((EEPROM_24LC64_CLASS_B_READ_PREFIX[:6] in image or EEPROM_24LC64_CLASS_B_WRITE_PREFIX[:4] in image) and b"nv24lcxx.c\0" in image.lower()):
            notes.append("24LC64 static-capacity EEPROM candidate rejected: " "marker, read/write pair, or bound guards are incomplete")
    if (driver is None and EEPROM_24LCXX_HALFWORD_READ_PREFIX in image and EEPROM_24LCXX_X430_WRITE_PREFIX in image):
        notes.append("24LCxx halfword EEPROM candidate rejected: missing or ambiguous " "paired read/write entries or initialized geometry")
    return DriverEntries(read, write, geometry, capacity, tuple(notes))

from .configuration import configuration_fields
