"""Pure settings schema, parsing, and validation helpers."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .locale import UI_TEXT, resolve_ui_language

from ..core.config import FirmwareConfig
from ..core.constants import (MAX_NAND_BACKING_SIZE, MAX_NAND_DATA_SIZE,
                              MAX_RAM_SIZE, PAGE)
from ..detection.firmware import MAX_FLASH_SIZE
from ..detection.firmware_image import load_firmware_image


SETTINGS_SECTIONS = tuple((title, tuple(tuple(field) for field in fields)) for title, fields in UI_TEXT["ko"]["_sections"])


BOOLEAN_FIELDS = frozenset({"key_active_low", "nand_enabled"})


ADDRESS_FIELDS = (
    'load_address',
    'key_register',
    'board_revision_register',
    'board_revision_value',
    'rex_idle_address',
    'rex_tick_address',
    'board_adc_value',
    'flash_id_address',
    'flash_id_value',
    'dmd_download_address',
    'primary_flash_probe_address',
    'secondary_flash_address',
    'secondary_flash_write_address',
    'framebuffer_address',
)


def settings_values(firmware: Path, detected: FirmwareConfig,
                    overrides: Mapping[str, object]) -> dict[str, str]:
    def current(name: str) -> object:
        return overrides[name] if name in overrides else getattr(detected, name)

    def shown(name: str, *, hexadecimal: bool = False) -> str:
        value = current(name)
        if value is None:
            return ""
        return hex(int(value)) if hexadecimal else str(value)

    return {
        "firmware": str(firmware),
        "model": shown("model"),
        "chipset": shown("chipset"),
        "width": shown("width"),
        "height": shown("height"),
        "framebuffer_address": shown("framebuffer_address", hexadecimal=True),
        "framebuffer_stride": shown("framebuffer_stride", hexadecimal=True),
        "framebuffer_format": shown("framebuffer_format"),
        "board_revision": shown("board_revision"),
        "image_offset": shown("image_offset", hexadecimal=True),
        "load_address": shown("load_address", hexadecimal=True),
        "flash_size": shown("flash_size", hexadecimal=True),
        "secondary_flash_address": shown("secondary_flash_address", hexadecimal=True),
        "secondary_flash_size": shown("secondary_flash_size", hexadecimal=True),
        "secondary_flash_image": shown("secondary_flash_image"),
        "secondary_flash_state": shown("secondary_flash_state"),
        "secondary_flash_write_address": shown("secondary_flash_write_address",
                                               hexadecimal=True),
        "ram_base": shown("ram_base", hexadecimal=True),
        "ram_size": shown("ram_size", hexadecimal=True),
        "ram_image_offset": shown("ram_image_offset", hexadecimal=True),
        "ram_image_size": shown("ram_image_size", hexadecimal=True),
        "entry": shown("entry", hexadecimal=True),
        "board_revision_register": shown("board_revision_register", hexadecimal=True),
        "board_revision_value": shown("board_revision_value", hexadecimal=True),
        "key_register": shown("key_register", hexadecimal=True),
        "key_active_low": "true" if current("key_active_low") else "false",
        "rex_idle_address": shown("rex_idle_address", hexadecimal=True),
        "rex_tick_address": shown("rex_tick_address", hexadecimal=True),
        "rex_tick_ms": shown("rex_tick_ms"),
        "board_adc_value": shown("board_adc_value", hexadecimal=True),
        "flash_id_address": shown("flash_id_address", hexadecimal=True),
        "flash_id_value": shown("flash_id_value", hexadecimal=True),
        "dmd_download_address": shown("dmd_download_address", hexadecimal=True),
        "primary_flash_probe_address": shown("primary_flash_probe_address",
                                             hexadecimal=True),
        "flash_state": shown("flash_state"),
        "nand_enabled": "true" if current("nand_enabled") else "false",
        "nand_image": shown("nand_image"),
        "nand_data_size": shown("nand_data_size", hexadecimal=True),
        "nand_page_size": shown("nand_page_size", hexadecimal=True),
        "nand_spare_size": shown("nand_spare_size", hexadecimal=True),
        "nand_pages_per_block": shown("nand_pages_per_block"),
        "nand_bus_width": shown("nand_bus_width"),
    }


def _error(key: str, language: str | None) -> str:
    return UI_TEXT[resolve_ui_language(language)][key]


def parse_settings_values(values: Mapping[str, str], language: str | None = None) -> dict[str, object]:
    def integer(name: str) -> int:
        return int(values[name], 0)

    def optional_integer(name: str) -> int | None:
        return int(values[name], 0) if values[name] else None

    def boolean(name: str) -> bool:
        text = values[name].lower()
        if text == "true":
            return True
        if text == "false":
            return False
        raise ValueError(f"{name}: {_error('validation_boolean', language)}")

    nand_image_text = values["nand_image"]
    secondary_image_text = values["secondary_flash_image"]
    secondary_state_text = values["secondary_flash_state"]
    return {
        "model": values["model"],
        "chipset": values["chipset"],
        "image_offset": integer("image_offset"),
        "load_address": integer("load_address"),
        "flash_size": integer("flash_size"),
        "secondary_flash_address": optional_integer("secondary_flash_address"),
        "secondary_flash_size": integer("secondary_flash_size"),
        "secondary_flash_image": (
            str(Path(secondary_image_text).expanduser().resolve())
            if secondary_image_text else None),
        "secondary_flash_state": (
            str(Path(secondary_state_text).expanduser().resolve())
            if secondary_state_text else ""),
        "secondary_flash_write_address": optional_integer(
            "secondary_flash_write_address"),
        "ram_base": integer("ram_base"),
        "ram_size": integer("ram_size"),
        "ram_image_offset": integer("ram_image_offset"),
        "ram_image_size": integer("ram_image_size"),
        "entry": integer("entry"),
        "width": integer("width"),
        "height": integer("height"),
        "framebuffer_address": optional_integer("framebuffer_address"),
        "framebuffer_stride": integer("framebuffer_stride"),
        "framebuffer_format": values["framebuffer_format"],
        "board_revision": values["board_revision"],
        "board_revision_register": optional_integer("board_revision_register"),
        "board_revision_value": optional_integer("board_revision_value"),
        "key_register": optional_integer("key_register"),
        "key_active_low": boolean("key_active_low"),
        "rex_idle_address": optional_integer("rex_idle_address"),
        "rex_tick_address": optional_integer("rex_tick_address"),
        "rex_tick_ms": integer("rex_tick_ms"),
        "board_adc_value": integer("board_adc_value"),
        "flash_id_address": optional_integer("flash_id_address"),
        "flash_id_value": optional_integer("flash_id_value"),
        "dmd_download_address": optional_integer("dmd_download_address"),
        "primary_flash_probe_address": optional_integer(
            "primary_flash_probe_address"),
        "flash_state": str(Path(values["flash_state"]).expanduser().resolve()),
        "nand_enabled": boolean("nand_enabled"),
        "nand_image": (str(Path(nand_image_text).expanduser().resolve())
                       if nand_image_text else None),
        "nand_data_size": integer("nand_data_size"),
        "nand_page_size": integer("nand_page_size"),
        "nand_spare_size": integer("nand_spare_size"),
        "nand_pages_per_block": integer("nand_pages_per_block"),
        "nand_bus_width": integer("nand_bus_width"),
    }


def validate_settings_values(
        firmware: Path, effective: FirmwareConfig, overrides: dict[str, object],
        edited: set[str], flash_state_text: str, language: str | None = None) -> None:
    if ("model" in edited and (not isinstance(overrides["model"], str)
                               or not overrides["model"].strip())):
        raise ValueError(_error("validation_00", language))
    if overrides["chipset"] not in (
            "MSM5000", "MSM5100", "MSM5105", "MSM5500", "MSM5xxx"):
        raise ValueError(_error("validation_01", language))
    if not 32 <= overrides["width"] <= 1024 or not 32 <= overrides["height"] <= 1024:
        raise ValueError(_error("validation_02", language))
    framebuffer_address = overrides["framebuffer_address"]
    if framebuffer_address is None:
        if overrides["framebuffer_format"] != "none":
            raise ValueError(_error("validation_03", language))
    else:
        if overrides["framebuffer_format"] == "none":
            raise ValueError(_error("validation_04", language))
        if overrides["framebuffer_stride"] < overrides["width"] * 2:
            raise ValueError(_error("validation_05", language))
    file_size = len(load_firmware_image(firmware).image)
    if ("image_offset" in edited
            and not 0 <= overrides["image_offset"] < file_size):
        raise ValueError(_error("validation_06", language))
    available = file_size - overrides["image_offset"]
    if (({"flash_size", "image_offset"} & edited)
            and (overrides["flash_size"] <= 0
                 or overrides["flash_size"] > MAX_FLASH_SIZE
                 or overrides["flash_size"] - available > PAGE)):
        raise ValueError(_error("validation_07", language))
    if overrides["load_address"] + overrides["flash_size"] > 0x100000000:
        raise ValueError(_error("validation_08", language))
    if not 0 <= overrides["entry"] < overrides["flash_size"]:
        raise ValueError(_error("validation_09", language))
    if min(overrides["ram_base"], overrides["ram_size"]) <= 0:
        raise ValueError(_error("validation_10", language))
    if overrides["ram_size"] > MAX_RAM_SIZE:
        raise ValueError(_error("validation_11", language))
    if overrides["ram_base"] + overrides["ram_size"] > 0x100000000:
        raise ValueError(_error("validation_12", language))
    flash_start = overrides["load_address"]
    flash_end = flash_start + overrides["flash_size"]
    ram_start = overrides["ram_base"]
    ram_end = ram_start + overrides["ram_size"]
    if max(flash_start, ram_start) < min(flash_end, ram_end):
        raise ValueError(_error("validation_13", language))
    if framebuffer_address is not None:
        framebuffer_end = (framebuffer_address
                           + overrides["framebuffer_stride"]
                           * overrides["height"])
        if not ram_start <= framebuffer_address < framebuffer_end <= ram_end:
            raise ValueError(_error("validation_14", language))
    if min(overrides["ram_image_offset"], overrides["ram_image_size"]) < 0:
        raise ValueError(_error("validation_15", language))
    if (overrides["ram_image_size"]
            and (overrides["ram_image_offset"] + overrides["ram_image_size"]
                 > available)):
        raise ValueError(_error("validation_16", language))
    if overrides["ram_image_size"] > overrides["ram_size"]:
        raise ValueError(_error("validation_17", language))
    if any(value is not None and not 0 <= value <= 0xFFFFFFFF
           for value in (overrides[name] for name in ADDRESS_FIELDS)):
        raise ValueError(_error("validation_18", language))
    if not 0 <= overrides["rex_tick_ms"] <= 60_000:
        raise ValueError(_error("validation_19", language))
    if not flash_state_text:
        raise ValueError(_error("validation_20", language))
    secondary_address = overrides["secondary_flash_address"]
    if overrides["secondary_flash_size"] < 0:
        raise ValueError(_error("validation_21", language))
    effective_secondary_address = (
        secondary_address if secondary_address is not None
        else effective.secondary_flash_address
    )
    if effective_secondary_address not in (None, 0):
        secondary_address = effective_secondary_address
        secondary_size = overrides["secondary_flash_size"]
        secondary_end = secondary_address + secondary_size
        primary_start = overrides["load_address"]
        primary_end = primary_start + overrides["flash_size"]
        ram_start = overrides["ram_base"]
        ram_end = ram_start + overrides["ram_size"]
        if (not 0 < secondary_size <= MAX_FLASH_SIZE
                or secondary_end > 0x100000000):
            raise ValueError(_error("validation_22", language))
        if max(secondary_address, primary_start) < min(secondary_end, primary_end):
            raise ValueError(_error("validation_23", language))
        if max(secondary_address, ram_start) < min(secondary_end, ram_end):
            raise ValueError(_error("validation_24", language))
        if not overrides["secondary_flash_state"]:
            raise ValueError(_error("validation_25", language))
        if overrides["secondary_flash_image"]:
            image = Path(overrides["secondary_flash_image"])
            if not image.is_file():
                raise ValueError(_error("validation_26", language))
            if image.stat().st_size > secondary_size:
                raise ValueError(_error("validation_27", language))
    nand_values = (overrides["nand_data_size"], overrides["nand_page_size"],
                   overrides["nand_spare_size"],
                   overrides["nand_pages_per_block"])
    if min(nand_values) <= 0:
        raise ValueError(_error("validation_28", language))
    if overrides["nand_data_size"] > MAX_NAND_DATA_SIZE:
        raise ValueError(_error("validation_29", language))
    if not 256 <= overrides["nand_page_size"] <= 0x4000:
        raise ValueError(_error("validation_30", language))
    if not 1 <= overrides["nand_spare_size"] <= 0x1000:
        raise ValueError(_error("validation_31", language))
    if not 1 <= overrides["nand_pages_per_block"] <= 0x1000:
        raise ValueError(_error("validation_32", language))
    if overrides["nand_data_size"] % overrides["nand_page_size"]:
        raise ValueError(_error("validation_33", language))
    if overrides["nand_bus_width"] not in (1, 2):
        raise ValueError(_error("validation_34", language))
    raw_backing = (overrides["nand_data_size"]
                   // overrides["nand_page_size"]
                   * (overrides["nand_page_size"] + overrides["nand_spare_size"]))
    if raw_backing > MAX_NAND_BACKING_SIZE:
        raise ValueError(_error("validation_35", language))
    if (overrides["nand_enabled"] and overrides["nand_image"]
            and not Path(overrides["nand_image"]).is_file()):
        raise ValueError(_error("validation_36", language))
