"""GUI-free QEMU MSM5xxx transport shared by desktop and Android."""
from __future__ import annotations

import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from collections import deque

from gdb_remote import Remote
from msm5xxx_emulator.core import FirmwareConfig, GenericMSMEmulator
from msm5xxx_emulator.core.constants import STABLE_MSM_MMIO
from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.arm import (
    thumb_bl_target,
    thumb_literal_value,
)
from msm5xxx_emulator.detection.boot import (
    DMD_DOWNLOAD_5500_SIZE,
    DMD_DOWNLOAD_SIGNATURE,
    detect_dmd_download_5500,
    find_ma2_silent_boot_wait,
)
from msm5xxx_emulator.detection.firmware_image import load_firmware_image
from msm5xxx_emulator.detection.memory_layout import restore_sparse_nor_gap
from msm5xxx_emulator.detection.rex import UIS_IDLE_BODY_DELTAS
from msm5xxx_emulator.detection.storage import (
    EEPROM_24LCXX_READ_SIGNATURE,
    EEPROM_24LCXX_F6F7_WRITE_PREFIX,
    EEPROM_24LCXX_X270_READ_PREFIX,
    EEPROM_24LCXX_X270_WRITE_PREFIX,
    EEPROM_24LCXX_X430_READ_PREFIX,
    EEPROM_24LCXX_X430_WRITE_PREFIX,
    EEPROM_24LCXX_X7700_WRITE_PREFIX,
    direct_amd_x16_nor_profile,
    direct_intel_x16_nor_profile,
    eeprom_24lcxx_write_at,
    flash_id_for_size,
    fujitsu_x16_flash_ids,
    find_24lcxx_f6f7_driver,
    find_24lcxx_f7f6_driver,
    find_24lcxx_x270_driver,
    find_adjacent_amd_x16_nor,
    find_adjacent_fujitsu_x16_nor,
    find_embedded_fujitsu_x16_nor,
    find_primary_fsd_amd_x16_nor,
    mapped_primary_intel_x16_nor_profile,
    primary_probe_x16_nor_profile,
)
from msm5xxx_emulator.detection.upper_nor import (
    UPPER_FLASH_ADDRESS,
    UPPER_FLASH_SIZE,
    find_upper_amd_x16_nor,
)
from msm5xxx_emulator.devices.storage.nor import NORFlash
from msm5xxx_emulator.state_io import (
    atomic_write_bytes,
    atomic_write_text,
    exclusive_path_lock,
)
from unicorn import arm_const


RECORD_SIZE = 16
LCD_WRITE = 1
TELEMETRY = 2
DEVICE_TELEMETRY = 3
INPUT_TELEMETRY = 4
AUDIO_WRITE = 5
AUDIO_STATUS = 6
AUDIO_PCM_TELEMETRY = 7
AUDIO_TIMING_TELEMETRY = 8
AUDIO_REJECT_TELEMETRY = 9
AUDIO_STATUS_OVERFLOW = 1
AUDIO_STATUS_RESET = 2
AUDIO_STATUS_REJECTED = 3
AUDIO_STATUS_NATIVE = 4
AUDIO_PACKET_BYTES = 1796
AUDIO_SOCKET_SEND_BUFFER = 4096
HOST_INPUT = 0x80
REGISTER_NAMES = tuple(f"r{index}" for index in range(13)) + (
    "sp", "lr", "pc", "cpsr",
)
PAUSE_TIMER_ADDRESS = 0x04800020
PERSISTENT_STATE_FILES = (
    "primary-writable.raw", "secondary.raw", "upper.raw", "upper-x16.raw",
    "eeprom.raw", "nand-main.raw", "intel-x16.raw", "amd-x16.raw",
)
LEGACY_STATE_OWNER = ".firmware-sha256"
PAUSE_TIMER_LDR_OFFSETS = (0x26, 0x4E, 0x78, 0xA4)
PAUSE_TIMER_FIXED_HELPER = bytes.fromhex(
    "90b4322813dc00211423041c5c431f23e318223b9b1106d414214843031c1f21"
    "5918223989110048198090bc704700211424322363431f241b19223b9b1106d4"
    "1421322359431f23c9182239891100481980c11f2b39081c322813dd00211424"
    "322363431f241b199b1105d41421322359431f23c918891100481980c11f2b39"
    "081ce9e70028d0dd00211423041c5c431f23e3189b1105d414214843031c1f21"
    "5918891100481980bfe7"
)
AUDIO_SITE_LIMIT = 64
READY_POLL_SITE_LIMIT = 8
RAW_NAND_STATUS_SIGNATURE = bytes.fromhex(
    "00200521c9051522520580b4702717700b78c02b08d0c12b03d0044b01309842"
    "f5d3022080bc70470120fbe7"
)
RAW_NAND_RESET_SIGNATURE = bytes.fromhex("ff201521490508707047")
RAW_NAND_PAGE_SIGNATURE = bytes.fromhex("510a2031d205d20d")
RAW_NAND_BLOCK_PREFIX = bytes.fromhex("80b501277801")
RAW_NAND_BLOCK_SUFFIX = bytes.fromhex("013701239b029f42f7db")
RAW_NAND_X16_PREFIX = bytes.fromhex("0526f605")
RAW_NAND_X16_TRANSFER = bytes.fromhex("20883080")
RAW_NAND_LOW_PORT_RESET_SIGNATURE = bytes.fromhex("ff200521490508707047")
RAW_NAND_LOW_PORT_STATUS_SIGNATURE = bytes.fromhex(
    "00200121c9050522520580b4702717700b78c02b08d0c12b03d0044b01309842"
    "f5d3022080bc70470120fbe7"
)
RAW_NAND_LOW_PORT_READ_SIGNATURE = bytes.fromhex(
    "f0b5010a07063f0e00220c06240e50250026fff7e7ff05204005057009210905"
    "0e70381c104308700c70fff7e0ff0120c0050088064b984203d0"
)
RAW_NAND_LOW_PORT_ERASE_SIGNATURE = bytes.fromhex(
    "80b5010a0f063f0e0206120efff778ff60200521490508700920000502700770"
    "d0200870fff771fffff752"
)
RAW_NAND_LOW_PORT_PROGRAM_SIGNATURE = bytes.fromhex(
    "05204005ff2301339a4201d2002100e05021017080210170092202991205117015"
    "7001991170e107c90f0125ed05002907d103e04a00a25a2a800131b142f9d30ce0"
    "002108e06218167800ab1e7056785e701a882a800231b942f4d310210170"
)

def matrix_senses(profile: dict[str, object]) -> tuple[int, ...]:
    """Return the detector-admitted, unique physical sense values."""
    senses = tuple(int(value) for value in profile.get(
        "senses", profile.get("single_key_column_sense", ())
    ))
    no_key = int(profile["no_key"])
    if (not senses or len(set(senses)) != len(senses)
            or any(not 0 <= value <= 0x0F or value == no_key
                   for value in senses)):
        raise ValueError("invalid detector-resolved matrix senses")
    return senses


def unicorn_state(emulator: GenericMSMEmulator) -> dict[str, int]:
    return {
        name: emulator.uc.reg_read(
            getattr(arm_const, f"UC_ARM_REG_{name.upper()}")
        )
        for name in REGISTER_NAMES
    }


def qemu_memory_profile(config: object,
                        registers: dict[str, int]) -> str:
    """Encode only the memory/reset state represented by the machine."""
    expected = {name: 0 for name in REGISTER_NAMES}
    expected["sp"] = registers["sp"]
    expected["cpsr"] = 0xD3
    flash_size = int(config.flash_size)
    ram_base = int(config.ram_base)
    ram_end = ram_base + int(config.ram_size)
    if (not 0x1000 <= flash_size <= ram_base or registers != expected
            or registers["sp"] & 3
            or not ram_base <= registers["sp"] <= ram_end - 4):
        raise ValueError("QEMU memory profile cannot represent initial state")
    return f"{flash_size:x}:{ram_base:x}:{registers['sp']:x}"


def qemu_uis_idle_observer_addresses(
        config: object,
) -> tuple[int, int] | None:
    """Return only the detector-closed UI-idle entry/body pair."""
    entry = getattr(config, "uis_idle_entry_address", None)
    body = getattr(config, "uis_idle_body_address", None)
    if (type(entry) is not int or type(body) is not int
            or not 0 < entry < body <= 0xFFFFFFFF
            or entry & 1 or body & 1
            or body - entry not in UIS_IDLE_BODY_DELTAS):
        return None
    return entry, body


def qemu_rex_idle_candidate_observer_address(config: object) -> int | None:
    """Return one detector-derived, read-only REX-idle candidate address."""
    address = getattr(config, "rex_idle_address", None)
    if (type(address) is not int or not 0 < address <= 0xFFFFFFFF
            or address & 1):
        return None
    return address


def qemu_upper_nor_enabled(config: object) -> bool:
    """Accept only the detector's closed fixed upper-NOR range."""
    address = getattr(config, "upper_flash_address", None)
    size = int(getattr(config, "upper_flash_size", 0))
    if address is None and size == 0:
        return False
    if address != UPPER_FLASH_ADDRESS or size != UPPER_FLASH_SIZE:
        raise ValueError("QEMU cannot represent the detected upper NOR")
    return True


def qemu_raw_nand_main_profile(
        image: bytes, config: object,
) -> tuple[tuple[int, int, int, int, int, int, int] | None,
           str | None]:
    """Admit the closed, main-area-only small-page x16 NAND class."""
    if not getattr(config, "nand_enabled", False):
        return None, None
    if b"fs_ks_nand.c" not in image.lower():
        return None, "marker-missing"
    if getattr(config, "upper_flash_address", None) is not None:
        return None, "upper-nor-conflict"
    geometry = tuple(getattr(config, name, None) for name in (
        "nand_data_size", "nand_page_size", "nand_pages_per_block",
        "nand_bus_width",
    ))
    if geometry != (0x800000, 0x200, 0x20, 2):
        return None, "unsupported-main-geometry"

    sites: list[int] = []
    start = 0
    while True:
        site = image.find(RAW_NAND_STATUS_SIGNATURE, start)
        if site < 0:
            break
        reset = site + 0x30
        if (image[reset:reset + len(RAW_NAND_RESET_SIGNATURE)] ==
                RAW_NAND_RESET_SIGNATURE
                and bytes.fromhex("29210905") in image[site:site + 0x100]):
            sites.append(site)
        start = site + 2
    status_reset_shape = (
        bool(sites) and image.count(RAW_NAND_RESET_SIGNATURE) >= 2
    )
    page_shape = image.count(RAW_NAND_PAGE_SIGNATURE) >= 2
    block_shape = any(
        image[position:position + len(RAW_NAND_BLOCK_PREFIX)] ==
        RAW_NAND_BLOCK_PREFIX
        and image[position + 10:position + 10 + len(RAW_NAND_BLOCK_SUFFIX)] ==
        RAW_NAND_BLOCK_SUFFIX
        for position in range(0, len(image) - 20, 2)
    )
    x16 = image.find(RAW_NAND_X16_PREFIX)
    x16_shape = (
        x16 >= 0
        and RAW_NAND_X16_TRANSFER in image[x16 + 4:x16 + 20]
    )
    if status_reset_shape and page_shape and block_shape and x16_shape:
        return (0x02800000, 0x02900000, 0x02A00000,
                0x800000, 0x200, 0x20, 2), None

    low_port_shape = (
        getattr(config, "flash_size", None) == 0x800000
        and all(signature in image for signature in (
            RAW_NAND_LOW_PORT_RESET_SIGNATURE,
            RAW_NAND_LOW_PORT_STATUS_SIGNATURE,
            RAW_NAND_LOW_PORT_READ_SIGNATURE,
            RAW_NAND_LOW_PORT_ERASE_SIGNATURE,
            RAW_NAND_LOW_PORT_PROGRAM_SIGNATURE,
        ))
    )
    if low_port_shape:
        return (0x00800000, 0x00900000, 0x00A00000,
                0x800000, 0x200, 0x20, 2), None
    if not status_reset_shape:
        return None, "incomplete-status-reset-shape"
    return None, "incomplete-main-geometry-shape"


def qemu_audio_sites(audio: object) -> str | None:
    """Serialize detector-owned audio bus PCs for the native QEMU gate."""
    if not isinstance(audio, dict):
        return None
    family = audio.get("family")
    grammar = audio.get("grammar")
    base = audio.get("base")
    data_offset = audio.get("data_offset")
    ma2 = (
        family == "ma2"
        and type(base) is int and 0x02001000 <= base < 0x02800000
        and type(data_offset) is int and data_offset == 2
        and base + data_offset < 0x02800000
        and (base + data_offset < 0x02200000 or base >= 0x02201000)
    )
    ma5_signature = {
        "write_0": [0x582, 0x58A, 0x10566, 0x1056E, 0x37CAE2],
        "write_2": [
            0x586, 0x58E, 0x1056A, 0x10572,
            0x37CB1E, 0x37CB48, 0x37CB74,
        ],
    }
    ma5 = (
        family == "ma5"
        and type(base) is int and base == 0x02840000
        and type(data_offset) is int and data_offset == 2
        and audio.get("aperture_write_sites") == ma5_signature
    )
    begin = audio.get("begin")
    opaque_sites = audio.get("sites")
    opaque = (
        family == "opaque" and grammar == "command-status-data-v1"
        and base == 0x02880000 and data_offset == 2
        and type(begin) is int and not begin & 1
        and audio.get("end") == begin + 0x36
        and opaque_sites == {
            "read_0": [begin + 0x10], "read_2": [begin + 0x34],
            "write_0": [begin], "write_2": [begin + 0x24],
        }
    )
    sites = audio.get(
        "sites" if ma2 or opaque else "aperture_write_sites"
    )
    if (not ma2 and not ma5 and not opaque) or not isinstance(sites, dict):
        return None

    entries: list[tuple[str, int, int]] = []
    seen: set[int] = set()
    write_ports: set[int] = set()
    for name, values in sites.items():
        if not isinstance(name, str):
            return None
        is_write = name.startswith("write_")
        is_data_read = (
            ma2 and name == f"read_{data_offset}"
            or opaque and name in ("read_0", f"read_{data_offset}")
        )
        if ma5 and not is_write:
            return None
        if not is_write and not is_data_read:
            continue
        suffix = name[name.index("_") + 1:]
        if (not suffix or len(suffix) > 2
                or any(character not in "0123456789"
                               for character in suffix)):
            return None
        port = int(suffix, 10)
        if (str(port) != suffix or port > data_offset or port >= 16
                or not isinstance(values, (list, tuple)) or not values):
            return None
        if is_write:
            write_ports.add(port)
        if len(values) > AUDIO_SITE_LIMIT:
            return None
        for value in values:
            if (type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                    or value & 1):
                return None
            if value in seen:
                return None
            seen.add(value)
            entry = ("w" if is_write else "r", port, value)
            entries.append(entry)
            if len(entries) > AUDIO_SITE_LIMIT:
                return None
    if 0 not in write_ports or data_offset not in write_ports:
        return None
    entries.sort()
    return ";".join(f"{kind}{port:x}/{pc:x}"
                    for kind, port, pc in entries)


def qemu_ready_poll_property(
        profile: object) -> tuple[str | None, str | None]:
    """Serialize only recognized, unambiguous ready-poll contracts."""
    if profile is None:
        return None, None
    if not isinstance(profile, dict):
        return None, "malformed-profile"
    entries = profile.get("entries")
    if not isinstance(entries, list):
        return None, "malformed-entries"
    if not entries:
        return None, "ambiguous-entry-count"
    signature = profile.get("signature")
    if len(entries) > 1 and signature != "thumb-lsrs-bhs-pulse-v1":
        return None, "ambiguous-entry-count"
    if len(entries) > READY_POLL_SITE_LIMIT:
        return None, "entry-count-limit"
    if signature == "thumb-lsrs-bhs-pulse-v1":
        property_name = (
            "ready-poll-sites" if len(entries) > 1 else "ready-poll"
        )
        fields = ("status_address", "mask", "pulse_address")
    elif (signature == "thumb-uart-csr-sr-rx-empty-v1"
          and profile.get("admission") == "temporary-evidence-gated"):
        property_name = "ready-poll"
        fields = (
            "status_address", "mask", "pulse_address",
            "status_read_pc_offset", "pulse_set_pc_offset",
            "pulse_clear_pc_offset", "uart_rx_empty_read_pc_offset",
        )
        if "uart_rx_empty_frame_read_pc_offset" in profile:
            fields += ("uart_rx_empty_frame_read_pc_offset",)
    elif (signature == "thumb-lsrs-bcc-pulse-rotated-v1"
          and profile.get("admission") == "temporary-evidence-gated"):
        property_name = "ready-poll"
        fields = (
            "status_address", "mask", "pulse_address",
            "status_read_pc_offset", "pulse_set_pc_offset",
            "pulse_clear_pc_offset",
        )
    elif (signature in (
            "thumb-byte-ready-pulse-control-v1",
            "thumb-byte-ready-pulse-control-uart-empty-v1",
          )
          and profile.get("admission") == "temporary-evidence-gated"):
        property_name = "ready-poll-control"
        fields = (
            "status_address", "mask", "pulse_address", "control_address",
            "control_value", "status_read_pc_offset",
            "pulse_set_pc_offset", "pulse_clear_pc_offset",
            "control_pc_offset",
        )
        if signature == "thumb-byte-ready-pulse-control-uart-empty-v1":
            fields += ("uart_rx_empty_read_pc_offset",)
    elif (signature == "thumb-lcd-halfword-busy-clear-v1"
          and profile.get("admission") == "temporary-evidence-gated"):
        property_name = "lcd-status-poll"
        fields = (
            "status_address", "mask", "command_address", "command_value",
            "status_read_pc_offset", "command_write_pc_offset",
        )
    elif signature in (
            "thumb-lsrs-bcc-pulse-rotated-v1",
            "thumb-byte-ready-pulse-control-v1",
            "thumb-byte-ready-pulse-control-uart-empty-v1",
            "thumb-lcd-halfword-busy-clear-v1",
            "thumb-uart-csr-sr-rx-empty-v1",
    ):
        return None, "unsupported-admission"
    else:
        return None, "unsupported-signature"
    values = [profile.get(field) for field in fields] + entries
    if any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
           for value in values):
        return None, "malformed-fields"
    if any(entry & 1 for entry in entries) or len(set(entries)) != len(entries):
        return None, "malformed-entries"
    if property_name == "ready-poll-sites":
        prefix = ":".join(f"{value:x}" for value in values[:-len(entries)])
        sites = ";".join(f"{entry:x}" for entry in entries)
        return f"{property_name}={prefix}:{sites}", None
    if property_name == "ready-poll-control":
        values.insert(5, values.pop())
    elif property_name == "lcd-status-poll":
        values.insert(4, values.pop())
    elif property_name == "ready-poll" and len(fields) > 3:
        values.insert(3, values.pop())
    return f"{property_name}=" + ":".join(f"{value:x}" for value in values), None


def qemu_sbi_property(config: object) -> tuple[str | None, str | None]:
    """Enable only legacy SBI or a complete bootstrap-only contract."""
    profile = getattr(config, "sbi_bootstrap_profile", None)
    if getattr(config, "chipset", None) != "MSM5000":
        return (None, "unsupported-chipset") if profile is not None else (None, None)
    if getattr(config, "board_adc_reader_address", None) is not None:
        return "sbi=on", None
    if profile is None:
        return None, None
    expected_bootstrap = [
        [0, 1, 0x45], [0, 1, 0xC5], [4, 2, 0x085F],
        [0x0C, 2, 0x041F], [0x10, 1, 0], [0x10, 1, 1],
    ]
    expected_validation = [[0, 2, None], [0x0C, 2, 0x0900], [0, 2, None]]
    if not isinstance(profile, dict):
        return None, "malformed-profile"
    if (profile.get("signature") != "thumb-sbi-bootstrap-only-v1"
            or profile.get("admission") != "temporary-evidence-gated"
            or profile.get("accepted") is not True):
        return None, "unsupported-contract"
    if (profile.get("base_address") != 0x03000780
            or profile.get("bootstrap") != expected_bootstrap
            or profile.get("validation") != expected_validation):
        return None, "malformed-contract"
    entries = profile.get("entries")
    if (not isinstance(entries, list) or not entries
            or any(type(entry) is not int or entry < 0 or entry & 1
                   for entry in entries)
            or len(set(entries)) != len(entries)):
        return None, "malformed-entries"
    return "sbi=on,sbi-bootstrap-only=on", None


def qemu_board_revision_property(
        config: object) -> tuple[str | None, str | None]:
    """Serialize only a complete detector-owned MSM revision readback."""
    register = getattr(config, "board_revision_register", None)
    value = getattr(config, "board_revision_value", None)
    if register is None and value is None:
        return None, None
    if type(register) is not int or type(value) is not int:
        return None, "malformed-pair"
    if register & 3 or not 0x03000000 <= register <= 0x03FFFFFC:
        return None, "unsupported-register"
    if not 0 <= value <= 0xFFFFFFFF:
        return None, "malformed-value"
    return f"board-revision={register:x}:{value:x}", None


def adjacent_amd_x16_flash_ids(
        config: object, image: bytes) -> tuple[int, int] | None:
    """Admit a closed adjacent GEFS/AMD NOR class."""
    load = getattr(config, "load_address", None)
    primary_size = getattr(config, "flash_size", None)
    base = getattr(config, "secondary_flash_address", None)
    size = getattr(config, "secondary_flash_size", None)
    ram_base = getattr(config, "ram_base", None)
    identity = getattr(config, "flash_id_value", None)
    if (any(type(value) is not int for value in (
                load, primary_size, base, size, ram_base, identity,
            ))
            or size != 0x800000 or base != load + primary_size
            or base + size != ram_base
            or identity != flash_id_for_size(size)):
        return None
    native = (
        getattr(config, "chipset", None) == "MSM5500"
        and b"fsd_amd.c\0" in image
        and b"\x0b$USER_DIRS\0" in image
    )
    exact = (
        getattr(config, "chipset", None) == "MSM5100"
        and find_adjacent_amd_x16_nor(
            image[:primary_size], primary_size,
        ) == (base, size, identity & 0xFFFF, identity >> 16)
    )
    if not native and not exact:
        return None
    return identity & 0xFFFF, identity >> 16 & 0xFFFF


def qemu_dmd_5500_property(
        image: bytes, config: object,
        immutable_limit: int | None = None,
) -> tuple[str | None, str | None]:
    """Admit only the unique complete MSM5500 DMD completion grammar."""
    entry = getattr(config, "dmd_download_address", None)
    if entry is None:
        return None, None
    load = getattr(config, "load_address", None)
    flash_size = getattr(config, "flash_size", None)
    if (type(entry) is not int or type(load) is not int
            or type(flash_size) is not int or flash_size <= 0):
        return None, "malformed-config"
    limit = min(len(image), flash_size,
                immutable_limit if immutable_limit is not None else len(image))
    primary = image[:limit]
    detected = detect_dmd_download_5500(primary)
    if detected is None:
        return None, None
    if getattr(config, "chipset", None) != "MSM5500":
        return None, "unsupported-chipset"
    if entry != load + detected:
        return None, "address-mismatch"
    if detected + DMD_DOWNLOAD_5500_SIZE > limit:
        return None, "outside-immutable-primary-nor"
    return f"dmd-5500={entry:x}:{primary[detected + 16]:x}", None


def matrix_input_command(profile: dict[str, object],
                         position: tuple[int, int, int] | None,
                         pressed: bool) -> bytes:
    """Encode one detector-resolved physical matrix transition."""
    if not pressed:
        return bytes((HOST_INPUT, 0, 0, 0))
    if position is None:
        raise ValueError("matrix key position is unavailable")
    _event, row, column = position
    senses = matrix_senses(profile)
    rows = int(profile["rows"])
    no_key = int(profile["no_key"])
    if (not 0 <= row < rows or not 0 <= column < len(senses)
            or int(senses[column]) == no_key):
        raise ValueError("invalid detector-resolved matrix position")
    return bytes((HOST_INPUT, 1, row, int(senses[column])))


def sideband_input_command(producer: dict[str, object],
                           pressed: bool) -> bytes:
    """Encode one detector-resolved active-low sideband transition."""
    if not pressed:
        return bytes((HOST_INPUT, 0, 0, 0))
    mask = int(producer.get("mask", 0))
    if (producer.get("register_width") != 1
            or producer.get("polarity") != "active-low"
            or not 0 < mask <= 0xF0 or mask & 0x0F
            or mask & (mask - 1)):
        raise ValueError("invalid detector-resolved sideband producer")
    return bytes((HOST_INPUT, 1, 0xFF, mask))


def loopback_listener() -> socket.socket:
    """Open a private TCP listener supported by every release platform."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
    except Exception:
        listener.close()
        raise
    return listener


def bounded_audio_socket_pair() -> tuple[socket.socket, socket.socket]:
    """Return host/QEMU endpoints with a bounded QEMU send queue."""
    host, qemu = socket.socketpair()
    try:
        qemu.setsockopt(
            socket.SOL_SOCKET, socket.SO_SNDBUF, AUDIO_SOCKET_SEND_BUFFER
        )
    except Exception:
        host.close()
        qemu.close()
        raise
    return host, qemu


def qemu_state_directory(root: Path | None,
                         config: FirmwareConfig) -> Path | None:
    """Keep writable QEMU devices isolated by detected firmware identity."""
    if root is None:
        return None
    identity = str(config.firmware_sha256).lower()
    if len(identity) != 64 or any(character not in "0123456789abcdef"
                                  for character in identity):
        raise ValueError("invalid firmware identity for QEMU state")
    marker = root / LEGACY_STATE_OWNER
    if (not marker.exists()
            and not any((root / name).exists()
                        for name in PERSISTENT_STATE_FILES)):
        return root / identity
    with exclusive_path_lock(marker):
        try:
            owner = marker.read_text(encoding="ascii").strip().lower()
        except FileNotFoundError:
            owner = identity
            atomic_write_text(marker, owner + "\n")
        if len(owner) != 64 or any(character not in "0123456789abcdef"
                                   for character in owner):
            raise ValueError("invalid legacy QEMU state owner")
    if owner == identity:
        return root
    return root / identity


def load_legacy_nor_state(
        seed: bytes, candidates: tuple[Path, ...]) -> tuple[bytes, bool]:
    """Read the first existing stable JSON state without modifying it."""
    for path in candidates:
        if path.is_file():
            return bytes(NORFlash(seed, path).data), True
    return seed, False


def load_legacy_raw_state(seed: bytes, path: Path) -> tuple[bytes, bool]:
    """Read one same-size stable raw state without modifying it."""
    if not path.is_file():
        return seed, False
    data = path.read_bytes()
    if len(data) != len(seed):
        raise ValueError(f"persistent state size mismatch: {path}")
    return data, True


def migrate_erased_raw_state(path: Path, old_size: int,
                             new_size: int) -> bool:
    """Atomically preserve one old raw extent and append erased bytes."""
    if not 0 < old_size < new_size:
        raise ValueError("invalid persistent state extent migration")
    backup = path.with_name(f"{path.name}.pre-{old_size:08x}")
    with exclusive_path_lock(path):
        data = path.read_bytes()
        if len(data) == new_size:
            return False
        if len(data) != old_size:
            raise ValueError(f"persistent state size mismatch: {path}")
        if backup.exists():
            if backup.read_bytes() != data:
                raise ValueError(f"persistent state backup mismatch: {backup}")
        else:
            atomic_write_bytes(backup, data)
        atomic_write_bytes(path, data + b"\xff" * (new_size - old_size))
    return True


def detector_firmware_image(image: bytes, image_offset: int) -> bytes:
    """Match the canonical detector's header and sparse-gap normalization."""
    if not 0 <= image_offset < len(image):
        raise ValueError("image offset outside firmware")
    return restore_sparse_nor_gap(image[image_offset:])[0]


def select_primary_x16_nor_profile(
        legacy: tuple[int, int, int, int, int] | None,
        probe: tuple[
            int, int, tuple[tuple[int, int], ...], int, int,
        ] | None,
) -> tuple[
    tuple[int, int, int, int, int] | None,
    tuple[tuple[int, int], ...] | None,
    str | None,
]:
    """Prefer exact probe geometry only when detectors agree."""
    if probe is None:
        return legacy, None, None
    base, size, regions, id0, id1 = probe
    profile = base, size, regions[0][1], id0, id1
    if legacy is not None:
        legacy_base, legacy_size, sector_size, legacy_id0, legacy_id1 = legacy
        if ((legacy_base, legacy_size, legacy_id0, legacy_id1)
                != (base, size, id0, id1)
                or regions != ((size // sector_size, sector_size),)):
            return None, None, "detector-conflict"
    return profile, regions, None


def raw_loader_arguments(image: Path, max_size: int,
                         temporary: Path,
                         size: int | None = None,
                         exclude: tuple[int, int] | None = None) -> list[str]:
    """Split raw NOR around an excluded device and the loader size limit."""
    data = image.read_bytes()
    if size is not None:
        if not 0 <= size <= len(data):
            raise ValueError("raw loader size is outside the image")
        data = data[:size]
    ranges = [(0, len(data))]
    if exclude is not None:
        begin, end = exclude
        if not 0 <= begin < end <= len(data):
            raise ValueError("raw loader exclusion is outside the image")
        ranges = [(start, stop) for start, stop in (
            (0, begin), (end, len(data)),
        ) if start < stop]
    parts = [(image, 0)]
    if (ranges != [(0, image.stat().st_size)]
            or len(data) > max_size):
        parts = []
        for begin, end in ranges:
            for offset in range(begin, end, max_size):
                stop = min(offset + max_size, end)
                part = temporary / f"primary-{offset:08x}.raw"
                part.write_bytes(data[offset:stop])
                parts.append((part, offset))
    return [argument for part, offset in parts for argument in (
        "-device", f"loader,file={part},addr=0x{offset:x},force-raw=on",
    )]


def qemu_pause_timer_profile(
        image: bytes, config: object,
        immutable_limit: int | None = None,
        ) -> tuple[str | None, str | None]:
    """Return one exact fixed-rate pause timer or its reject reason."""
    load = int(getattr(config, "load_address", 0))
    limit = min(
        len(image), int(getattr(config, "flash_size", len(image))),
        immutable_limit if immutable_limit is not None else len(image),
    )
    template = PAUSE_TIMER_FIXED_HELPER
    prefix = template[:PAUSE_TIMER_LDR_OFFSETS[0]]
    starts: list[int] = []
    anchored = bounded = literal_match = False
    cursor = 0
    while True:
        start = image.find(prefix, cursor, limit)
        if start < 0:
            break
        anchored = True
        cursor = start + 1
        if start & 1 or start + len(template) + 6 > limit:
            continue
        bounded = True
        candidate = bytearray(image[start:start + len(template)])
        if any(thumb_literal_value(image, start + offset, 3)
               != PAUSE_TIMER_ADDRESS
               for offset in PAUSE_TIMER_LDR_OFFSETS):
            continue
        literal_match = True
        for offset in PAUSE_TIMER_LDR_OFFSETS:
            struct.pack_into("<H", candidate, offset, 0x4800)
        if bytes(candidate) == template:
            starts.append(start)
    if not starts:
        reason = None
        if literal_match:
            reason = "fixed-helper-shape-mismatch"
        elif bounded:
            reason = "pause-register-literal-mismatch"
        elif anchored:
            reason = "fixed-helper-outside-immutable-nor"
        return None, reason
    if len(starts) != 1:
        return None, "fixed-helper-ambiguous"

    start = starts[0]
    literal = struct.pack("<I", 100_000)
    pool = image.find(literal, 0, limit)
    while pool >= 0:
        first = max(0, pool - 0x400) & ~1
        for caller in range(first, min(pool + 1, limit - 5), 2):
            if (thumb_literal_value(image, caller, 0) == 100_000
                    and thumb_bl_target(image, caller + 2) == start):
                return (
                    f"{PAUSE_TIMER_ADDRESS:x}:{312_500:x}:"
                    f"{load + start:x}:{load + start + len(template):x}",
                    None,
                )
        pool = image.find(literal, pool + 1, limit)
    return None, "100ms-caller-not-found"


def legacy_dmd_loader_patch(
        image: bytes, config: object,
        immutable_limit: int | None = None) -> tuple[int, bytes] | None:
    """Return the existing legacy DMD completion contract as Thumb code."""
    entry = getattr(config, "dmd_download_address", None)
    load = int(getattr(config, "load_address", 0))
    if type(entry) is not int:
        return None
    offset = entry - load
    signature = DMD_DOWNLOAD_SIGNATURE
    if (not 0 <= offset <= len(image) - 0xF4
            or image[offset:offset + len(signature)] != signature
            or image.find(signature) != offset
            or image.find(signature, offset + 1) >= 0):
        return None
    try:
        completion, control, _, dmd = struct.unpack_from(
            "<4I", image, offset + 0xE0
        )
        file_load = struct.unpack_from("<H", image, offset + 0xD4)[0]
        if file_load == 0x4906:
            filename = struct.unpack_from("<I", image, offset + 0xF0)[0]
        elif file_load == 0xA106:
            filename = entry + 0xF0
        else:
            return None
    except struct.error:
        return None
    filename_offset = filename - load
    ram_base = int(getattr(config, "ram_base", 0))
    ram_end = ram_base + int(getattr(config, "ram_size", 0))
    if (control != 0x03000050 or dmd != 0x030007E0
            or not ram_base <= completion < ram_end
            or not 0 <= filename_offset <= len(image) - 12
            or not image[filename_offset:filename_offset + 12].startswith(
                b"dmddown_"
            )):
        return None
    halfwords = (
        0xB406,              # push {r1, r2}
        0x4906, 0x4A06,     # completion, 2
        0x700A,              # strb r2, [r1]
        0x4906, 0x4A07,     # control, 1
        0x730A,              # strb r2, [r1, #12]
        0x4907, 0x4A07,     # dmd, 0
        0x608A, 0x818A,     # clear dmd + 8 through + 13
        0xBC06,              # pop {r1, r2}
        0x4803, 0x4770,     # r0 = 1; bx lr
    )
    patch = struct.pack(
        "<14H6I", *halfwords,
        completion, 2, control, 1, dmd, 0,
    )
    limit = min(len(image), int(config.flash_size),
                immutable_limit if immutable_limit is not None else len(image))
    if offset + len(patch) > limit:
        return None
    return offset, patch


def ma2_silent_boot_loader_patch(
        image: bytes, config: object,
        immutable_limit: int | None = None) -> tuple[int, bytes] | None:
    """Return the detector-qualified MA2 wait success contract as Thumb code."""
    entry = getattr(config, "ma2_silent_boot_address", None)
    load = int(getattr(config, "load_address", 0))
    detected = find_ma2_silent_boot_wait(image)
    if (type(entry) is not int or detected is None
            or entry != load + detected or entry & 3):
        return None
    patch = bytes.fromhex("0048704700000000")  # ldr r0, [pc]; bx lr; 0
    limit = min(len(image), int(config.flash_size),
                immutable_limit if immutable_limit is not None else len(image))
    if detected + len(patch) > limit:
        return None
    return detected, patch


def c80_rex_irq_profile(config: object, enabled: bool) -> str | None:
    """Encode the proven exact class or an explicitly enabled experiment."""
    candidate = getattr(config, "rex_static_controller_candidate", None)
    if not isinstance(candidate, dict):
        return None
    signature = candidate.get("signature")
    automatic = (
        signature == "static-c80-controller-callback-v1"
        and candidate.get("promotion") == "temporary-evidence-gated"
        and candidate.get("status_bank_count") == 2
        and candidate.get("group_row_size") == 10
        and candidate.get("pending_read_semantics") == "latched-read"
        and candidate.get("pending_ack_semantics") == "write-one-to-clear"
        and candidate.get("time_tick_status_bank") == 0x03000C80
        and candidate.get("time_tick_clear_bank") == 0x03000C80
        and candidate.get("time_tick_mask") == 0x0200
    )
    if not enabled and not automatic:
        return None
    overlay = signature == "static-c80-overlay-controller-callback-v1"
    required = {
        "signature": signature,
        "controller_class": (
            "legacy-c80-three-bank-group14-v1" if overlay else
            "legacy-c80-index1e-delta5-controller-candidate-v1"
        ),
        "accepted": True,
        "active": False,
        "vector": 0x18,
        "mask": 0x0200,
        "callback_delta": 5,
        "callback_validation_size": 68,
    }
    if (signature not in (
            "static-c80-controller-callback-v1",
            "static-c80-overlay-controller-callback-v1",
    ) or any(candidate.get(key) != value
             for key, value in required.items())):
        return None
    integer_fields = (
        "vector_target", "status", "enable", "wrapper_file_offset",
        "handler_slot", "handler_file_offset", "handler_validation_size",
        "callback_slot", "callback_file_offset", "wrapper_validation_size",
    ) + (("wrapper_runtime_address", "handler_runtime_address",
          "callback_runtime_address") if overlay else ())
    if any(type(candidate.get(field)) is not int for field in integer_fields):
        return None
    status = int(candidate["status"])
    enable = int(candidate["enable"])
    ram_base = int(getattr(config, "ram_base", 0))
    ram_end = ram_base + int(getattr(config, "ram_size", 0))
    flash_size = int(getattr(config, "flash_size", 0))
    wrapper = int(candidate["wrapper_file_offset"])
    wrapper_size = int(candidate["wrapper_validation_size"])
    handler = int(candidate["handler_file_offset"])
    handler_size = int(candidate["handler_validation_size"])
    callback = int(candidate["callback_file_offset"])
    callback_size = int(candidate["callback_validation_size"])
    handler_slot = int(candidate["handler_slot"])
    callback_slot = int(candidate["callback_slot"])
    vector_target = int(candidate["vector_target"])
    runtime_wrapper = int(candidate.get("wrapper_runtime_address", wrapper))
    runtime_handler = int(candidate.get("handler_runtime_address", handler))
    runtime_callback = int(candidate.get("callback_runtime_address", callback))
    direct_fields = (
        "rex_irq_wrapper_address", "rex_irq_handler_address",
        "rex_irq_handler_slot",
        "rex_irq_callback_slot", "rex_irq_status_address",
        "rex_irq_enable_address", "rex_irq_arm_address",
    )
    if not overlay:
        direct_fields = ("rex_tick_address", *direct_fields)
    common_invalid = (
            getattr(config, "load_address", None) != 0
            or any(getattr(config, field, None) is not None
                   for field in direct_fields)
            or getattr(config, "rex_irq_mask", 0)
            or status != 0x03000C80 or enable != status + 0x14
            or not ram_base <= vector_target <= ram_end - 4
            or any(address & 3 or not ram_base <= address <= ram_end - 4
                   for address in (handler_slot, callback_slot))
            or wrapper & 3 or handler & 1 or callback & 1
            or runtime_wrapper & 3 or runtime_handler & 1
            or runtime_callback & 1
            or any(not 0 <= address < flash_size
                   for address in (wrapper, handler, callback))
            or any(size <= 0 or address + size > flash_size
                   for address, size in (
                       (wrapper, wrapper_size),
                       (handler, handler_size),
                       (callback, callback_size),
                   )))
    if overlay:
        linker = getattr(config, "linker", None)
        overlays = getattr(config, "overlays", ())
        handler_overlays = [
            item for item in overlays
            if all(type(getattr(item, field, None)) is int
                   for field in ("source", "target", "size"))
            and item.source <= handler
            and handler + handler_size <= item.source + item.size
            and item.target + handler - item.source == runtime_handler
        ]
        class_invalid = (
                candidate.get("promotion") != "temporary-evidence-gated"
                or candidate.get("pending_read_semantics") != "latched-read"
                or candidate.get("status_bank_count") != 3
                or candidate.get("group_row_size") != 14
                or tuple(candidate.get("status_banks", ()))
                   != (status, status + 4, status + 0x30)
                or tuple(candidate.get("clear_banks", ()))
                   != (status, status + 4, enable + 0x38)
                or tuple(candidate.get("controller_write_banks", ()))
                   != (enable, enable + 4, enable + 0x30)
                or tuple(candidate.get("controller_aperture", ()))
                   != (status, enable + 0x3A)
                or candidate.get("time_tick_status_bank") != status
                or candidate.get("time_tick_clear_bank") != status
                or candidate.get("time_tick_mask") != 0x0200
                or linker is None
                or any(type(getattr(linker, field, None)) is not int
                       for field in ("data_source", "data_target", "data_size"))
                or linker.data_target != vector_target
                or linker.data_size < 4
                or not 0 <= linker.data_source <= flash_size - linker.data_size
                or len(handler_overlays) != 1
                or runtime_wrapper != wrapper
                or runtime_callback != callback
        )
    else:
        class_invalid = (
                not ram_base <= vector_target <= ram_end - 4
                or tuple(candidate.get("status_banks", ()))
                   != (status, status + 4)
                or tuple(candidate.get("clear_banks", ()))
                   != (status, status + 4)
                or tuple(candidate.get("controller_write_banks", ()))
                   != (enable, enable + 4)
                or tuple(candidate.get("controller_aperture", ()))
                   != (status, enable + 6)
                or (runtime_wrapper, runtime_handler, runtime_callback)
                   != (wrapper, handler, callback)
        )
    if common_invalid or class_invalid:
        return None
    values = (
        status, enable, 0x0200, 5_000_000,
        vector_target, runtime_wrapper, handler_slot, runtime_handler,
        handler_size, callback_slot, runtime_callback,
    )
    if overlay:
        values += (3,)
    return ":".join(f"{value:x}" for value in values)


def _legacy_620_rex_irq_profile(
        config: object, enabled: bool, classes: dict[str, int],
        promotion: str, pending_read_semantics: str,
) -> str | None:
    """Validate and encode one detector-closed legacy 0x620 route."""
    if not enabled:
        return None
    candidate = getattr(config, "rex_static_controller_candidate", None)
    required = {
        "signature": "static-msm5000-620-controller-callback-v1",
        "accepted": True,
        "active": False,
        "promotion": promotion,
        "vector": 0x18,
        "mask": 0x0200,
        "callback_delta": 5,
        "callback_validation_size": 68,
        "pending_read_semantics": pending_read_semantics,
        "time_tick_control_address": 0x030006E0,
    }
    if (not isinstance(candidate, dict)
            or any(candidate.get(key) != value
                   for key, value in required.items())
            or candidate.get("controller_class") not in classes
            or candidate.get("group_row_size")
               != classes.get(candidate.get("controller_class"))):
        return None
    integer_fields = (
        "vector_target", "vector_copy_source", "vector_copy_size",
        "descriptor_file_offset", "descriptor_runtime_address",
        "mask_table", "status", "enable", "wrapper_file_offset",
        "wrapper_validation_size", "handler_slot", "handler_file_offset",
        "handler_validation_size", "callback_slot",
        "callback_file_offset",
    )
    if any(type(candidate.get(field)) is not int for field in integer_fields):
        return None
    status = int(candidate["status"])
    enable = int(candidate["enable"])
    arm = int(candidate["time_tick_control_address"])
    vector_target = int(candidate["vector_target"])
    copy_source = int(candidate["vector_copy_source"])
    copy_size = int(candidate["vector_copy_size"])
    descriptor = int(candidate["descriptor_file_offset"])
    descriptor_runtime = int(candidate["descriptor_runtime_address"])
    mask_table = int(candidate["mask_table"])
    ram_base = int(getattr(config, "ram_base", 0))
    ram_end = ram_base + int(getattr(config, "ram_size", 0))
    flash_size = int(getattr(config, "flash_size", 0))
    wrapper = int(candidate["wrapper_file_offset"])
    wrapper_size = int(candidate["wrapper_validation_size"])
    handler = int(candidate["handler_file_offset"])
    handler_size = int(candidate["handler_validation_size"])
    callback = int(candidate["callback_file_offset"])
    callback_size = int(candidate["callback_validation_size"])
    handler_slot = int(candidate["handler_slot"])
    callback_slot = int(candidate["callback_slot"])
    direct_fields = (
        "rex_tick_address", "rex_irq_wrapper_address",
        "rex_irq_handler_address", "rex_irq_handler_slot",
        "rex_irq_callback_slot", "rex_irq_status_address",
        "rex_irq_enable_address", "rex_irq_arm_address",
    )
    if (getattr(config, "load_address", None) != 0
            or any(getattr(config, field, None) is not None
                   for field in direct_fields)
            or getattr(config, "rex_irq_mask", 0)
            or status != 0x03000620 or enable != status + 8
            or tuple(candidate.get("status_banks", ()))
               != (status, status + 4)
            or tuple(candidate.get(
                "clear_banks" if pending_read_semantics == "latched-read"
                else "mask_set_banks", ()))
               != (status, status + 4)
            or (pending_read_semantics == "latched-read"
                and candidate.get("pending_ack_semantics")
                != "write-one-to-clear")
            or tuple(candidate.get("mask_output_banks", ()))
               != (enable, enable + 4)
            or tuple(candidate.get("controller_aperture", ()))
               != (status, enable + 8)
            or vector_target & 3
            or not ram_base <= vector_target <= ram_end - 4
            or copy_size <= 0 or vector_target + copy_size > ram_end
            or copy_source < 0 or copy_source + copy_size > flash_size
            or not copy_source <= descriptor
            or descriptor + 0x1C > copy_source + copy_size
            or descriptor_runtime
               != vector_target + descriptor - copy_source
            or descriptor_runtime != mask_table + 8 + 0x1C * 0x1C
            or callback_slot != descriptor_runtime + 0x14
            or any(address & 3 or not ram_base <= address <= ram_end - 4
                   for address in (handler_slot, callback_slot))
            or wrapper & 3 or handler & 1 or callback & 1
            or any(not 0 <= address < flash_size
                   for address in (wrapper, handler, callback))
            or any(size <= 0 or address + size > flash_size
                   for address, size in (
                       (wrapper, wrapper_size),
                       (handler, handler_size),
                       (callback, callback_size),
                   ))):
        return None
    values = (
        status, enable, arm, 0x0200, 5_000_000, vector_target,
        wrapper, handler_slot, handler, handler_size, callback_slot, callback,
    )
    return ":".join(f"{value:x}" for value in values)


def read_consume_rex_irq_profile(config: object, enabled: bool) -> str | None:
    """Encode the proven exact class or an explicitly enabled experiment."""
    profile = _legacy_620_rex_irq_profile(
        config, True,
        {
            "legacy-msm5000-620-two-bank-read-consume-v1": 12,
            "legacy-msm5000-620-two-bank-read-consume-group10-v1": 10,
        },
        "temporary-evidence-gated", "consume-on-read",
    )
    if profile is not None:
        return profile
    return _legacy_620_rex_irq_profile(
        config, enabled,
        {
            "legacy-msm5000-620-two-bank-read-consume-v1": 12,
            "legacy-msm5000-620-two-bank-read-consume-group10-v1": 10,
        },
        "experimental-only", "consume-on-read",
    )


def w1c_rex_irq_profile(config: object) -> str | None:
    """Use the existing direct W1C lane for the two-peer closed class."""
    profile = _legacy_620_rex_irq_profile(
        config, True,
        {"legacy-msm5000-620-two-bank-w1c-8call-v1": 12},
        "temporary-evidence-gated", "latched-read",
    )
    return ":".join(profile.split(":")[:5]) if profile is not None else None


def eeprom_gpio_profile(
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
        shapes = (
            (writer, bytes.fromhex("f0b5071c8025")),
            (writer + 0x16,
             bytes.fromhex("0122087810430870087826490871")),
            (writer + 0x2E,
             bytes.fromhex("202108431070107821490870")),
            (writer + 0x44,
             bytes.fromhex("202311789943117011781b4a1170")),
            (writer + 0x5A,
             bytes.fromhex("0878400840000870087815490871")),
            (writer + 0x72,
             bytes.fromhex("202108431070107810490870")),
            (writer + 0x88,
             bytes.fromhex("202311789943117011780a4a1170")),
            (ack, b"\xf0\xb5"),
            (ack + 0x06,
             bytes.fromhex("234a11784908490011701178214a1172")),
            (ack + 0x24,
             bytes.fromhex("202229781c4c114329702978103c2170")),
            (ack + 0x40,
             bytes.fromhex("21790126301c490800d2002007063f0e")),
            (ack + 0x5A,
             bytes.fromhex("20239943297029782170")),
            (ack + 0x78,
             bytes.fromhex("0a7832430a700978064a1172")),
            (reader, bytes.fromhex("f0b50027164d")),
            (reader + 0x10,
             bytes.fromhex("20220878104308700878114904390870")),
            (reader + 0x28,
             bytes.fromhex("28783f0e400801d301200743")),
            (reader + 0x36,
             bytes.fromhex("20230878984308700878074904390870")),
        )
        literals = (
            (writer + 0x20, 1, 0x03000660),
            (writer + 0x36, 1, 0x03000660),
            (writer + 0x4E, 2, 0x03000660),
            (writer + 0x64, 1, 0x03000660),
            (writer + 0x7A, 1, 0x03000660),
            (writer + 0x92, 2, 0x03000660),
            (ack + 0x12, 2, 0x03000670),
            (ack + 0x28, 4, 0x03000670),
            (ack + 0x80, 2, 0x03000670),
            (reader + 0x04, 5, 0x03000664),
            (reader + 0x1A, 1, 0x03000664),
            (reader + 0x40, 1, 0x03000664),
        )
        if (min(ack, writer, reader) < 0
                or any(image[position:position + len(expected)] != expected
                       for position, expected in shapes)
                or any(thumb_literal_value(image, position, register) != value
                       for position, register, value in literals)):
            return None, "gpio-line-shape-mismatch"
        return (0x03000660, 4, 1, 0, 0x20, 0x18, 0x8000), None
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
        shapes = (
            (writer, bytes.fromhex("f0b5071c80260724")),
            (writer + 0x1A,
             bytes.fromhex("01231178194311701178304a1171")),
            (writer + 0x3C,
             bytes.fromhex("20231178194311701178")),
            (writer + 0x5C,
             bytes.fromhex("20231178994311701178")),
            (writer + 0x74,
             bytes.fromhex("1b4a11784908490011701178")),
            (writer + 0x98,
             bytes.fromhex("20231178194311701178")),
            (writer + 0xB8,
             bytes.fromhex("20231178994311701178")),
            (ack, b"\xf0\xb5"),
            (ack + 0x06,
             bytes.fromhex("234a11784908490011701178214a1172")),
            (ack + 0x24,
             bytes.fromhex("202229781c4c114329702978103c2170")),
            (ack + 0x40,
             bytes.fromhex("21790126301c490800d2002007063f0e")),
            (ack + 0x5C,
             bytes.fromhex("20239943297029782170")),
            (ack + 0x7A,
             bytes.fromhex("0a7832430a700978054a1172")),
            (reader, bytes.fromhex("f0b500271b4e0024")),
            (reader + 0x12,
             bytes.fromhex("194a20231178194311701178154a043a1170")),
            (reader + 0x30,
             bytes.fromhex("7800070630783f0e400801d301200743")),
            (reader + 0x44,
             bytes.fromhex("0c4a20231178994311701178084a043a1170")),
        )
        literals = (
            (writer + 0x24, 2, 0x03000660),
            (writer + 0x46, 2, 0x03000660),
            (writer + 0x66, 2, 0x03000660),
            (writer + 0x80, 2, 0x03000660),
            (writer + 0xA2, 2, 0x03000660),
            (writer + 0xC2, 2, 0x03000660),
            (ack + 0x12, 2, 0x03000670),
            (ack + 0x28, 4, 0x03000670),
            (ack + 0x82, 2, 0x03000670),
            (reader + 0x04, 6, 0x03000664),
            (reader + 0x1E, 2, 0x03000664),
            (reader + 0x50, 2, 0x03000664),
        )
        if (read - write != 0x6D8 or min(ack, writer, reader) < 0
                or any(image[position:position + len(expected)] != expected
                       for position, expected in shapes)
                or any(thumb_literal_value(image, position, register) != value
                       for position, register, value in literals)):
            return None, "gpio-line-shape-mismatch"
        return (0x03000660, 4, 1, 0, 0x20, 0x18, 0x8000), None
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
                or any(image[position:position + len(expected)] != expected
                       for position, expected in shapes)
                or any(thumb_literal_value(image, position, register) != value
                       for position, register, value in literals)
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


class Transport:
    def __init__(self, qemu: Path, firmware: Path,
                 state_dir: Path | None = None,
                 experimental_c80: bool = False,
                 config: FirmwareConfig | None = None,
                 qemu_prefix: tuple[str, ...] = (),
                 audio_stream: bool = False,
                 audio_pcm: bool = True,
                 icount_shift: int = 6,
                 observe_uis_idle: bool = True,
                 observe_rex_idle_candidate: bool = False) -> None:
        if not 0 <= icount_shift <= 10:
            raise ValueError("invalid QEMU icount shift")
        if type(observe_uis_idle) is not bool:
            raise ValueError("invalid UI-idle observer setting")
        if type(observe_rex_idle_candidate) is not bool:
            raise ValueError("invalid REX-idle observer setting")
        self.config = config if config is not None else detect(firmware)
        state_dir = qemu_state_directory(state_dir, self.config)
        self.temporary = tempfile.TemporaryDirectory(prefix="msm5xxx-qemu-gui-")
        temporary = Path(self.temporary.name)
        if state_dir is not None:
            state_dir.mkdir(parents=True, exist_ok=True)
        firmware_image = load_firmware_image(firmware).image
        detector_image = detector_firmware_image(
            firmware_image, self.config.image_offset
        )
        upper_x16_profile = find_upper_amd_x16_nor(detector_image)
        self.rex_c80_profile = c80_rex_irq_profile(
            self.config, experimental_c80
        )
        self.rex_read_consume_profile = read_consume_rex_irq_profile(
            self.config, experimental_c80
        )
        self.rex_w1c_profile = w1c_rex_irq_profile(self.config)
        self.config.rex_static_controller_experimental = (
            self.rex_c80_profile is not None
            or self.rex_read_consume_profile is not None
        )
        upper_nor_enabled = qemu_upper_nor_enabled(self.config)
        if upper_nor_enabled and upper_x16_profile is not None:
            raise ValueError("conflicting upper NOR detector profiles")
        upper_nor_present = upper_nor_enabled or upper_x16_profile is not None
        legacy_primary_state = Path(self.config.flash_state)
        legacy_secondary_state = Path(self.config.secondary_flash_state)
        legacy_upper_state = (Path(self.config.upper_flash_state)
                              if upper_nor_enabled else None)
        legacy_eeprom_state = Path(str(self.config.flash_state) + ".eeprom.bin")
        if (legacy_upper_state is not None
                and legacy_upper_state.resolve() in {
                    legacy_primary_state.resolve(),
                    legacy_secondary_state.resolve(),
                }):
            raise ValueError("persistent upper NOR path collides")
        os.environ["MSM5XXX_STATE_DIR"] = str(temporary / "state")
        os.environ["MSM5XXX_LOG_DIR"] = str(temporary / "logs")
        self.instructions = 0
        self.pc = 0
        self.ready_status = 0
        self.ready_phase = 0
        self.ready_cycles = 0
        self.ready_reads = 0
        self.ready_responses = 0
        self.input_pressed = False
        self.input_row = 0
        self.input_sense = 0
        self.input_host_events = 0
        self.input_active_reads = 0
        self.input_rejections = 0
        self._uis_idle_addresses = (
            qemu_uis_idle_observer_addresses(self.config)
            if observe_uis_idle else None
        )
        self._uis_idle_lock = threading.Lock()
        self._uis_idle_stop = threading.Event()
        self._uis_idle_socket: socket.socket | None = None
        self._uis_idle_worker: threading.Thread | None = None
        self._uis_idle_status = (
            "pending" if self._uis_idle_addresses is not None
            else "not-detected"
        )
        self._uis_idle_entry_instructions: int | None = None
        self._uis_idle_body_instructions: int | None = None
        self._rex_idle_candidate_address = (
            qemu_rex_idle_candidate_observer_address(self.config)
            if observe_rex_idle_candidate and self._uis_idle_addresses is None
            else None
        )
        self._rex_idle_candidate_lock = threading.Lock()
        self._rex_idle_candidate_stop = threading.Event()
        self._rex_idle_candidate_socket: socket.socket | None = None
        self._rex_idle_candidate_worker: threading.Thread | None = None
        self._rex_idle_candidate_status = (
            "pending" if self._rex_idle_candidate_address is not None
            else "not-detected"
        )
        self._rex_idle_candidate_instructions: int | None = None
        self.audio_stream_enabled = False
        self.audio_stream_seen = False
        self.audio_stream_order = 0
        self.audio_stream_status = "disabled"
        self.audio_stream_reject_reason: str | None = None
        self.audio_stream_dropped = 0
        self.audio_pcm_underflow_frames = 0
        self.audio_pcm_overflow_frames = 0
        self.audio_pcm_epoch = 0
        self.audio_socket_send_buffer = 0
        self.audio_timing_late_events = 0
        self.audio_timing_collapsed_events = 0
        self.audio_timing_max_lateness_ns = 0
        self.audio_reject_witness: (
            tuple[int, int, int, int, int, int, int] | None
        ) = None
        self.audio_native = False
        self._audio_lock = threading.RLock()
        self._audio_ready = threading.Condition(self._audio_lock)
        self.native_audio_packets: deque[bytes] = deque(maxlen=4)
        self.native_audio_epoch = 0
        self.native_audio_sequence = 0
        self.native_audio_end_frame = 0
        self.native_audio_reset_epoch = 0
        self.matrix_input_profile: dict[str, object] | None = None
        self.matrix_input_sideband_producer: dict[str, object] | None = None
        self.matrix_held: dict[int, tuple[int, int, int]] = {}
        self.sideband_held: set[int] = set()
        self.state_imports: list[str] = []
        self.config.flash_state = str(temporary / "primary.flash.json")
        self.config.secondary_flash_state = str(temporary / "secondary.flash.json")
        if upper_nor_enabled:
            self.config.upper_flash_state = str(temporary / "upper.flash.json")
        self.decoder = GenericMSMEmulator(
            self.config, approximate_audio=False
        )
        if self.config.load_address != 0:
            raise ValueError("QEMU PoC requires NOR=0")
        memory_profile = qemu_memory_profile(
            self.config, unicorn_state(self.decoder)
        )

        lcd_listener = loopback_listener()
        input_listener = None
        audio_listener = None
        audio_host_socket = None
        audio_qemu_socket = None
        desktop_audio_driver = None
        try:
            input_listener = loopback_listener()
            if audio_stream and audio_pcm:
                if os.name == "posix":
                    audio_host_socket, audio_qemu_socket = \
                        bounded_audio_socket_pair()
                    self.audio_socket_send_buffer = audio_qemu_socket.getsockopt(
                        socket.SOL_SOCKET, socket.SO_SNDBUF
                    )
                else:
                    audio_listener = loopback_listener()
            gdb_listener = loopback_listener()
        except Exception:
            lcd_listener.close()
            if input_listener is not None:
                input_listener.close()
            if audio_listener is not None:
                audio_listener.close()
            if audio_host_socket is not None:
                audio_host_socket.close()
            if audio_qemu_socket is not None:
                audio_qemu_socket.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise
        lcd_host, lcd_port = lcd_listener.getsockname()
        input_host, input_port = input_listener.getsockname()
        if audio_listener is not None:
            audio_host, audio_port = audio_listener.getsockname()
        gdb_host, gdb_port = gdb_listener.getsockname()
        machine = (
            "msm5xxx-poc,lcd-trace-chardev=lcd,input-chardev=input,"
            f"memory-profile={memory_profile}"
        )
        board_adc_value = self.config.board_adc_value
        if type(board_adc_value) is int and 0 <= board_adc_value <= 0xFF:
            machine += f",board-adc-value={board_adc_value}"
        dc0_profile = self.config.dc0_board_adc_profile
        dc0_board_adc_value = (
            dc0_profile.get("response_raw")
            if isinstance(dc0_profile, dict)
            and dc0_profile.get("accepted") is True
            else board_adc_value
        )
        if (type(dc0_board_adc_value) is int
                and 0 <= dc0_board_adc_value <= 0xFF):
            machine += f",dc0-board-adc-value={dc0_board_adc_value}"
        sbi_property, sbi_reject = qemu_sbi_property(self.config)
        if sbi_property is not None:
            machine += f",{sbi_property}"
        elif sbi_reject is not None:
            self.config.detection_notes.append(
                f"QEMU SBI bridge rejected: {sbi_reject}; "
                "native fallback retained"
            )
        ready_property, ready_reject = qemu_ready_poll_property(
            self.config.ready_poll
        )
        if ready_property is not None:
            machine += f",{ready_property}"
        elif ready_reject is not None:
            self.config.detection_notes.append(
                f"QEMU ready-poll bridge rejected: {ready_reject}; "
                "native fallback retained"
            )
        revision_property, revision_reject = qemu_board_revision_property(
            self.config
        )
        if revision_property is not None:
            machine += f",{revision_property}"
        elif revision_reject is not None:
            self.config.detection_notes.append(
                f"QEMU board-revision bridge rejected: {revision_reject}; "
                "native fallback retained"
            )
        board_status = self.config.board_status_input
        if board_status is not None:
            machine += (
                f",board-status-input={board_status.address:x}:"
                f"{board_status.mask:x}:{board_status.default:x}"
            )
        direct = self.decoder.direct_input_profile
        if (direct is not None
                and direct.get("grammar") == "direct-low-nibble-6-row-v1"
                and int(direct.get("sense_bits", 0)) == 4):
            register = int(direct["register"])
            reset = next((value[0] for address, value in STABLE_MSM_MMIO
                          if address == register and len(value) == 1), None)
            if reset is not None:
                sideband_producers = [
                    producer
                    for producer in
                    self.decoder._validated_direct_sideband_producers()
                    if int(producer["register"]) == register
                    and int(producer["register_width"]) == 1
                    and producer["polarity"] == "active-low"
                    and int(producer["mask"]) & 0x0f == 0
                    and int(producer["mask"]) &
                    (int(producer["mask"]) - 1) == 0
                    and int(producer["mask"]) & reset ==
                    int(producer["mask"])
                ]
                sideband = (sideband_producers[0]
                            if len(sideband_producers) == 1 else None)
                sideband_mask = int(sideband["mask"]) if sideband else 0
                sense_bitmap = sum(
                    1 << sense for sense in matrix_senses(direct)
                )
                machine += (
                    f",matrix-input={register:x}:"
                    f"{int(direct['sense_site']):x}:"
                    f"{int(direct['no_key']):x}:{reset:x}:"
                    f"{int(direct['row_register']):x}:"
                    f"{int(direct['rows']):x}:{sideband_mask:x}:"
                    f"{sense_bitmap:x}"
                )
                self.matrix_input_profile = direct
                self.matrix_input_sideband_producer = sideband
        audio = self.config.audio_transport
        audio_family = audio.get("family") if audio is not None else None
        audio_grammar = audio.get("grammar") if audio is not None else None
        if (audio is not None
                and audio.get("static_status") == "accepted"
                and audio_family == "ma2"
                and audio_grammar == "ma2-command-v1"
                and self.config.ma2_silent_boot_address is not None):
            audio_sites = qemu_audio_sites(audio)
            if audio_sites is not None:
                machine += (
                    f",audio-aperture={int(audio['base']):x}:"
                    f"{int(audio['data_offset']):x}:{audio_family}"
                    f",audio-sites={audio_sites}"
                )
                self.audio_stream_enabled = True
                self.audio_stream_status = "pending"
                if not audio_pcm:
                    machine += ",audio-pcm=off"
                elif (audio_listener is not None
                      or audio_qemu_socket is not None):
                    machine += ",audio-stream-chardev=audio"
                else:
                    desktop_audio_driver = (
                        "coreaudio" if sys.platform == "darwin" else
                        "dsound" if sys.platform == "win32" else "alsa"
                    )
                    machine += ",audiodev=msm5xxx"
        elif (audio is not None
              and audio.get("static_status") == "accepted"
              and (audio_family, audio_grammar) in {
                  ("ma5", "indexed-rw-v1"),
                  ("opaque", "command-status-data-v1"),
              }
              and not upper_nor_present):
            audio_sites = qemu_audio_sites(audio)
            if audio_sites is not None:
                machine += (
                    f",audio-aperture={int(audio['base']):x}:"
                    f"{int(audio['data_offset']):x}:{audio_family}"
                    f",audio-sites={audio_sites}"
                )
                self.config.detection_notes.append(
                    "QEMU MA5 indexed write-only boot aperture enabled; "
                    "reads remain fail-closed"
                    if audio_family == "ma5" else
                    "QEMU command/status/data boot aperture enabled with "
                    "inactive zero readback"
                )
        if audio is not None and not self.audio_stream_enabled:
            static_status = audio.get("static_status")
            if static_status == "accepted":
                self.audio_stream_status = "rejected"
                self.audio_stream_reject_reason = (
                    "qemu-audio-adapter-unsupported"
                    if (audio_family, audio_grammar) !=
                    ("ma2", "ma2-command-v1") else
                    "qemu-audio-admission-rejected"
                )
            elif static_status == "rejected":
                self.audio_stream_status = "rejected"
                self.audio_stream_reject_reason = (
                    "qemu-audio-detector-" +
                    str(audio.get("reject_reason") or "rejected")
                )
        if audio_listener is not None and not self.audio_stream_enabled:
            audio_listener.close()
            audio_listener = None
        if audio_host_socket is not None and not self.audio_stream_enabled:
            audio_host_socket.close()
            audio_host_socket = None
        if audio_qemu_socket is not None and not self.audio_stream_enabled:
            audio_qemu_socket.close()
            audio_qemu_socket = None
        rex_fields = (
            self.config.rex_irq_status_address,
            self.config.rex_irq_enable_address,
            self.config.rex_irq_arm_address,
            self.config.rex_idle_address,
        )
        if (self.config.rex_tick_ms == 5 and self.config.rex_irq_mask
                and all(isinstance(value, int) for value in rex_fields)):
            status, enable, arm, idle = rex_fields
            machine += (
                f",rex-irq={status:x}:{enable:x}:{arm:x}:"
                f"{self.config.rex_irq_mask:x}:"
                f"{self.config.rex_tick_ms * 1_000_000:x}:{idle:x}"
            )
        if self.rex_c80_profile is not None:
            machine += f",rex-static-c80={self.rex_c80_profile}"
        if self.rex_read_consume_profile is not None:
            machine += (
                ",rex-static-read-consume="
                f"{self.rex_read_consume_profile}"
            )
        if self.rex_w1c_profile is not None:
            machine += f",rex-irq={self.rex_w1c_profile}"
        primary_profile = find_primary_fsd_amd_x16_nor(
            detector_image[:self.config.flash_size],
            self.config.flash_id_address, self.config.flash_size,
        )
        intel_profile, intel_reject = direct_intel_x16_nor_profile(
            detector_image, self.config.primary_flash_probe_address,
            self.config.load_address, self.config.flash_size,
            0, self.config.ram_base, self.config.ram_size,
        )
        amd_profile, amd_reject = direct_amd_x16_nor_profile(
            detector_image, self.config.load_address, self.config.flash_size,
            0, self.config.ram_base, self.config.ram_size,
        )
        if intel_profile is not None and amd_profile is not None:
            intel_profile = None
            amd_profile = None
            self.config.detection_notes.append(
                "direct x16 NOR protocol detectors conflict; "
                "native fallback retained"
            )
        mapped_primary_profile, mapped_primary_reject = (
            mapped_primary_intel_x16_nor_profile(
                bytes(self.decoder.flash.data), self.config.flash_size,
                self.config.ram_base,
            )
        )
        probe_profile, probe_reject = primary_probe_x16_nor_profile(
            detector_image, self.config.primary_flash_probe_address,
            self.config.load_address, self.config.flash_size,
            0, self.config.ram_base,
            self.config.ram_image_offset, self.config.ram_image_size,
            self.config.ram_size,
        )
        primary_profile, primary_regions, profile_reject = (
            select_primary_x16_nor_profile(primary_profile, probe_profile)
        )
        if profile_reject is not None:
            self.config.detection_notes.append(
                "primary x16 detectors conflict; native NOR fallback retained"
            )
        elif (primary_profile is None and intel_profile is None
              and amd_profile is None
              and probe_reject is not None):
            self.config.detection_notes.append(
                f"primary x16 probe detector rejected: {probe_reject}; "
                "native NOR fallback retained"
            )
        if (intel_profile is None and amd_profile is None
                and primary_profile is None
                and intel_reject not in (None, "probe-shape-mismatch")):
            self.config.detection_notes.append(
                f"direct Intel x16 detector rejected: {intel_reject}; "
                "native fallback retained"
            )
        if (amd_profile is None and intel_profile is None
                and primary_profile is None and amd_reject is not None):
            self.config.detection_notes.append(
                f"direct AMD x16 detector rejected: {amd_reject}; "
                "native fallback retained"
            )
        if mapped_primary_reject is not None:
            self.config.detection_notes.append(
                "mapped primary Intel x16 detector rejected: "
                f"{mapped_primary_reject}; native fallback retained"
            )
        primary_seed, primary_imported = load_legacy_nor_state(
            bytes(self.decoder.flash.data), (legacy_primary_state,)
        )
        dmd_patch = legacy_dmd_loader_patch(
            primary_seed, self.config,
            primary_profile[0] if primary_profile is not None else None,
        )
        ma2_patch = ma2_silent_boot_loader_patch(
            primary_seed, self.config,
            primary_profile[0] if primary_profile is not None else None,
        )
        if (dmd_patch is not None and ma2_patch is not None
                and max(dmd_patch[0], ma2_patch[0])
                < min(dmd_patch[0] + len(dmd_patch[1]),
                      ma2_patch[0] + len(ma2_patch[1]))):
            ma2_patch = None
        if dmd_patch is not None or ma2_patch is not None:
            patched = bytearray(primary_seed)
            for candidate in (dmd_patch, ma2_patch):
                if candidate is None:
                    continue
                offset, patch = candidate
                patched[offset:offset + len(patch)] = patch
            primary_seed = bytes(patched)
        dmd_5500_property, dmd_5500_reject = qemu_dmd_5500_property(
            primary_seed, self.config,
            primary_profile[0] if primary_profile is not None else None,
        )
        if dmd_5500_property is not None:
            machine += f",{dmd_5500_property}"
        elif dmd_5500_reject is not None:
            self.config.detection_notes.append(
                f"QEMU DMD5500 bridge rejected: {dmd_5500_reject}; "
                "native fallback retained"
            )
        if len(primary_seed) != self.config.flash_size:
            raise ValueError("primary seed size does not match flash size")
        loader = temporary / "primary.raw"
        loader.write_bytes(primary_seed)
        if primary_imported:
            self.state_imports.append("primary-nor-json")
        pause_timer, pause_timer_reject = qemu_pause_timer_profile(
            primary_seed, self.config,
            primary_profile[0] if primary_profile is not None else None,
        )
        if pause_timer is not None:
            machine += f",pause-timer={pause_timer}"
        elif pause_timer_reject is not None:
            self.config.detection_notes.append(
                f"pause timer detector rejected: {pause_timer_reject}"
            )
        loader_size = None
        loader_exclude = None
        storage_args: list[str] = []
        pflash_unit = 0
        if primary_profile is not None:
            base, size, sector_size, id0, id1 = primary_profile
            primary_state = ((state_dir / "primary-writable.raw")
                             if state_dir is not None else
                             (temporary / "primary-writable.raw"))
            primary_writable_seed = primary_seed[base:base + size]
            if primary_state.exists():
                if primary_state.stat().st_size != size:
                    raise ValueError("persistent primary NOR size mismatch")
            else:
                primary_state.write_bytes(primary_writable_seed)
            machine += (
                f",primary-x16-nor={base:x}:{size:x}:{sector_size:x}:"
                f"{id0:x}:{id1:x}"
            )
            if primary_regions is not None:
                machine += "".join(
                    f":{count:x}:{length:x}"
                    for count, length in primary_regions
                )
            storage_args.extend((
                "-drive",
                f"file={primary_state},if=pflash,format=raw,unit=0",
            ))
            if base + size == self.config.flash_size:
                loader_size = base
            else:
                loader_exclude = base, base + size
            pflash_unit += 1
            if primary_regions is None:
                self.config.detection_notes.append(
                    "primary x16 NOR writable tail selected from unique "
                    "fsd_amd descriptor/writer/ID linkage"
                )
            else:
                self.config.detection_notes.append(
                    "primary x16 NOR selected from unique "
                    "probe/table/descriptor/geometry linkage"
                )
        if mapped_primary_profile is not None:
            logical_base, base, size, sector_size = mapped_primary_profile
            mapped_state = ((state_dir / "mapped-primary-x16.raw")
                            if state_dir is not None else
                            (temporary / "mapped-primary-x16.raw"))
            mapped_upper_state = (
                (state_dir / "mapped-primary-x16-upper.raw")
                if state_dir is not None else
                (temporary / "mapped-primary-x16-upper.raw")
            )
            mapped_seed = primary_seed[logical_base:logical_base + size]
            if len(mapped_seed) != size:
                raise ValueError("mapped primary NOR seed size mismatch")
            if mapped_state.exists():
                if mapped_state.stat().st_size != size:
                    raise ValueError(
                        "persistent mapped primary NOR size mismatch"
                    )
            else:
                mapped_state.write_bytes(mapped_seed)
            if mapped_upper_state.exists():
                if mapped_upper_state.stat().st_size != size:
                    raise ValueError(
                        "persistent mapped primary upper NOR size mismatch"
                    )
            else:
                mapped_upper_state.write_bytes(b"\xff" * size)
            machine += (
                f",mapped-primary-x16-nor={base:x}:{size:x}:"
                f"{sector_size:x}"
            )
            storage_args.extend((
                "-drive",
                f"file={mapped_state},if=pflash,format=raw,"
                f"unit={pflash_unit}",
                "-drive",
                f"file={mapped_upper_state},if=pflash,format=raw,"
                f"unit={pflash_unit + 1}",
            ))
            pflash_unit += 2
            self.config.detection_notes.append(
                "temporary mapped primary Intel x16 NOR selected from "
                "exact code-signature/map/geometry linkage"
            )
        if intel_profile is not None:
            base, size, sector_size, id0, id1 = intel_profile
            intel_state = ((state_dir / "intel-x16.raw")
                           if state_dir is not None else
                           (temporary / "intel-x16.raw"))
            if intel_state.exists():
                if intel_state.stat().st_size != size:
                    raise ValueError("persistent Intel x16 NOR size mismatch")
            else:
                intel_state.write_bytes(b"\xff" * size)
            machine += (
                f",intel-x16-nor={base:x}:{size:x}:{sector_size:x}:"
                f"{id0:x}:{id1:x}"
            )
            storage_args.extend((
                "-drive",
                f"file={intel_state},if=pflash,format=raw,unit={pflash_unit}",
            ))
            pflash_unit += 1
            self.config.detection_notes.append(
                "external direct Intel x16 NOR selected from unique "
                "probe/caller/ordered-descriptor linkage"
            )
        if amd_profile is not None:
            base, size, sector_size, id0, id1, options = amd_profile
            amd_state = ((state_dir / "amd-x16.raw")
                         if state_dir is not None else
                         (temporary / "amd-x16.raw"))
            if amd_state.exists():
                if amd_state.stat().st_size != size:
                    raise ValueError("persistent AMD x16 NOR size mismatch")
            else:
                amd_state.write_bytes(b"\xff" * size)
            machine += (
                f",amd-x16-nor={base:x}:{size:x}:{sector_size:x}:"
                f"{id0:x}:{id1:x}:{options:x}"
            )
            storage_args.extend((
                "-drive",
                f"file={amd_state},if=pflash,format=raw,unit={pflash_unit}",
            ))
            pflash_unit += 1
            self.config.detection_notes.append(
                "direct AMD x16 NOR selected from unique "
                "probe/caller/ordered-descriptor linkage"
            )
        secondary = self.decoder.secondary_flash
        secondary_base = self.config.secondary_flash_address
        secondary_size = self.config.secondary_flash_size
        adjacent_amd = find_adjacent_amd_x16_nor(
            detector_image[:self.config.flash_size], self.config.flash_size,
        )
        embedded_secondary = None
        if secondary_base is None and primary_profile is None:
            embedded_secondary = find_embedded_fujitsu_x16_nor(
                detector_image, self.config.flash_size,
            )
            if embedded_secondary is not None:
                secondary_base, secondary_size, id0, id1 = embedded_secondary
                loader_exclude = (
                    secondary_base, secondary_base + secondary_size,
                )
        if (secondary_base is None
                and self.config.secondary_flash_write_address is not None):
            candidate = self.config.load_address + self.config.flash_size
            candidate_ids = fujitsu_x16_flash_ids(
                detector_image,
                self.config.secondary_flash_write_address,
                self.config.load_address, candidate,
            )
            if (candidate_ids is not None
                    and candidate + self.config.secondary_flash_size
                    <= self.config.ram_base):
                secondary_base = candidate
        secondary_ids = (
            (id0, id1) if embedded_secondary is not None else
            fujitsu_x16_flash_ids(
                detector_image, self.config.secondary_flash_write_address,
                self.config.load_address, int(secondary_base or 0),
            )
        )
        if secondary_ids is None:
            secondary_ids = adjacent_amd_x16_flash_ids(
                self.config, detector_image,
            )
        if secondary_base is not None and secondary_ids:
            secondary_state = ((state_dir / "secondary.raw")
                               if state_dir is not None else
                               (temporary / "secondary.raw"))
            secondary_seed = (
                bytes(secondary.data) if secondary is not None else
                primary_seed[secondary_base:secondary_base + secondary_size]
                if embedded_secondary is not None else
                b"\xff" * secondary_size
            )
            if secondary_state.exists():
                if secondary_state.stat().st_size != len(secondary_seed):
                    adjacent = find_adjacent_fujitsu_x16_nor(
                        detector_image, self.config.flash_size,
                    )
                    if (secondary_state.stat().st_size == 0x200000
                            and len(secondary_seed) == 0x400000
                            and embedded_secondary is None
                            and adjacent == (
                                secondary_base, len(secondary_seed),
                                *secondary_ids,
                            )):
                        if migrate_erased_raw_state(
                                secondary_state, 0x200000, 0x400000):
                            self.state_imports.append(
                                "secondary-nor-erased-tail-extension"
                            )
                    else:
                        raise ValueError(
                            "persistent secondary NOR size mismatch"
                        )
            else:
                candidates = [legacy_secondary_state]
                if self.config.secondary_flash_address is None:
                    candidates.insert(0, legacy_primary_state.with_name(
                        legacy_primary_state.stem +
                        f".lazy-secondary-{secondary_base:08x}-"
                        f"{len(secondary_seed):x}.json"
                    ))
                secondary_seed, imported = load_legacy_nor_state(
                    secondary_seed, tuple(candidates)
                )
                if imported:
                    self.state_imports.append("secondary-nor-json")
                secondary_state.write_bytes(secondary_seed)
            machine += (
                f",fujitsu-x16-nor={self.config.flash_size:x}:"
                f"{secondary_base:x}:{len(secondary_seed):x}:"
                f"{secondary_ids[0]:x}:{secondary_ids[1]:x}"
            )
            storage_args.extend((
                "-drive",
                f"file={secondary_state},if=pflash,format=raw,unit={pflash_unit}",
            ))
            pflash_unit += 1
            if embedded_secondary is not None:
                self.config.detection_notes.append(
                    "embedded x16 NOR selected from unique "
                    "descriptor/writer/geometry linkage"
                )
        if upper_nor_enabled:
            upper = self.decoder.upper_flash
            assert upper is not None and legacy_upper_state is not None
            upper_state = ((state_dir / "upper.raw")
                           if state_dir is not None else
                           (temporary / "upper.raw"))
            upper_seed = bytes(upper.data)
            if upper_state.exists():
                if upper_state.stat().st_size != len(upper_seed):
                    raise ValueError("persistent upper NOR size mismatch")
            else:
                upper_seed, imported = load_legacy_nor_state(
                    upper_seed, (legacy_upper_state,)
                )
                if imported:
                    self.state_imports.append("upper-nor-json")
                upper_state.write_bytes(upper_seed)
            machine += ",upper-x8-nor=on"
            storage_args.extend((
                "-drive",
                f"file={upper_state},if=pflash,format=raw,unit={pflash_unit}",
            ))
        elif upper_x16_profile is not None:
            _, upper_size, _ = upper_x16_profile
            upper_state = ((state_dir / "upper-x16.raw")
                           if state_dir is not None else
                           (temporary / "upper-x16.raw"))
            if upper_state.exists():
                if upper_state.stat().st_size != upper_size:
                    raise ValueError("persistent upper x16 NOR size mismatch")
            else:
                upper_state.write_bytes(b"\xff" * upper_size)
            machine += ",upper-x16-nor=on"
            storage_args.extend((
                "-drive",
                f"file={upper_state},if=pflash,format=raw,unit={pflash_unit}",
            ))
            self.config.detection_notes.append(
                "QEMU mapped upper AMD x16 NOR selected from unique "
                "mapper/descriptor/writer/erase linkage"
            )
        raw_nand_profile, raw_nand_reject = qemu_raw_nand_main_profile(
            detector_image, self.config
        )
        eeprom_profile, eeprom_reject = eeprom_gpio_profile(
            detector_image, self.config
        )
        if raw_nand_profile is not None and upper_nor_present:
            raw_nand_profile = None
            raw_nand_reject = "upper-nor-conflict"
        elif raw_nand_profile is not None and eeprom_profile is not None:
            raw_nand_profile = None
            raw_nand_reject = "mtd-owner-conflict"
        if raw_nand_reject is not None:
            self.config.detection_notes.append(
                f"QEMU raw NAND bridge rejected: {raw_nand_reject}; "
                "native fallback retained"
            )
        if raw_nand_profile is not None:
            (data, address, command, data_size, page_size,
             pages_per_block, bus_width) = raw_nand_profile
            raw_nand_state = ((state_dir / "nand-main.raw")
                              if state_dir is not None else
                              (temporary / "nand-main.raw"))
            if raw_nand_state.exists():
                if raw_nand_state.stat().st_size != data_size:
                    raise ValueError("persistent raw NAND main size mismatch")
            else:
                raw_nand_state.write_bytes(b"\xff" * data_size)
            machine += (
                f",raw-nand-main={data:x}:{address:x}:{command:x}:"
                f"{data_size:x}:{page_size:x}:{pages_per_block:x}:"
                f"{bus_width:x}"
            )
            storage_args.extend((
                "-drive",
                f"file={raw_nand_state},if=none,format=raw,"
                "id=msm5xxx-raw-nand-main",
            ))
            self.config.detection_notes.append(
                "QEMU main-area-only small-page x16 NAND bridge enabled"
            )
        if eeprom_reject is not None:
            self.config.detection_notes.append(
                f"24LCxx GPIO bridge rejected: {eeprom_reject}"
            )
        if eeprom_profile is not None:
            (gpio_base, data_offset, data_mask, clock_offset, clock_mask,
             direction_offset, capacity) = eeprom_profile
            eeprom_state = ((state_dir / "eeprom.raw")
                            if state_dir is not None else
                            (temporary / "eeprom.raw"))
            if eeprom_state.exists():
                if eeprom_state.stat().st_size != capacity:
                    raise ValueError("persistent EEPROM size mismatch")
            else:
                eeprom_seed, imported = load_legacy_raw_state(
                    b"\xff" * capacity, legacy_eeprom_state
                )
                if imported:
                    self.state_imports.append("eeprom-raw")
                eeprom_state.write_bytes(eeprom_seed)
            machine += (
                f",eeprom-24lcxx-gpio={gpio_base:x}:{data_offset:x}:"
                f"{data_mask:x}:{clock_offset:x}:{clock_mask:x}:"
                f"{direction_offset:x}:"
                f"{capacity:x}"
            )
            storage_args.extend((
                "-drive", f"file={eeprom_state},if=mtd,format=raw,unit=0",
            ))
        self.stderr = tempfile.TemporaryFile(mode="w+t")
        try:
            popen_options = (
                {"pass_fds": (audio_qemu_socket.fileno(),)}
                if audio_qemu_socket is not None else {}
            )
            self.process = subprocess.Popen(
                [
                    *qemu_prefix, str(qemu), "-M", machine, "-cpu", "ti925t",
                    "-m", f"{self.config.ram_size // (1024 * 1024)}M",
                    *raw_loader_arguments(
                        loader, self.config.ram_size, temporary, loader_size,
                        loader_exclude,
                    ),
                    *storage_args,
                    *(
                        ("-audiodev",
                         ("coreaudio,id=msm5xxx"
                          if desktop_audio_driver == "coreaudio" else
                          f"{desktop_audio_driver},id=msm5xxx,"
                          "out.buffer-length=40000"))
                        if desktop_audio_driver is not None else ()
                    ),
                    "-chardev",
                    f"socket,id=lcd,host={lcd_host},port={lcd_port},"
                    "server=off,nodelay=on",
                    "-chardev",
                    f"socket,id=input,host={input_host},port={input_port},"
                    "server=off,nodelay=on",
                    *(
                        ("-chardev",
                         f"socket,id=audio,fd={audio_qemu_socket.fileno()},"
                         "server=off")
                        if audio_qemu_socket is not None else
                        (("-chardev",
                          f"socket,id=audio,host={audio_host},port={audio_port},"
                          "server=off,nodelay=on")
                         if audio_listener is not None else ())
                    ),
                    "-chardev",
                    f"socket,id=gdb,host={gdb_host},port={gdb_port},"
                    "server=off,nodelay=on",
                    "-nographic", "-monitor", "none", "-serial", "none",
                    "-S", "-gdb", "chardev:gdb",
                    "-icount", f"shift={icount_shift},align=on,sleep=on",
                    "-no-reboot", "-no-shutdown",
                ],
                stdout=subprocess.DEVNULL,
                stderr=self.stderr,
                text=True,
                **popen_options,
            )
            if audio_qemu_socket is not None:
                audio_qemu_socket.close()
                audio_qemu_socket = None
        except Exception:
            lcd_listener.close()
            input_listener.close()
            if audio_listener is not None:
                audio_listener.close()
            if audio_host_socket is not None:
                audio_host_socket.close()
            if audio_qemu_socket is not None:
                audio_qemu_socket.close()
            gdb_listener.close()
            self.stderr.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise
        try:
            try:
                self.audio_socket = audio_host_socket
                self.lcd_socket = self._accept_qemu(lcd_listener)
                self.input_socket = self._accept_qemu(input_listener)
                if audio_listener is not None:
                    self.audio_socket = self._accept_qemu(audio_listener)
                gdb_socket = self._accept_qemu(gdb_listener)
            finally:
                lcd_listener.close()
                input_listener.close()
                if audio_listener is not None:
                    audio_listener.close()
                gdb_listener.close()
            self.lcd_socket.settimeout(0.2)
            self.input_socket.settimeout(0.2)
            if self.audio_socket is not None:
                self.audio_socket.settimeout(0.2)
                if self.audio_socket.family == socket.AF_INET:
                    self.audio_socket.setsockopt(
                        socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
                    )
            self.input_socket.setsockopt(
                socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
            )
            gdb_socket.settimeout(10)
            remote = Remote(gdb_socket)
            remote.command("qSupported:qXfer:features:read+")
            if (self._uis_idle_addresses is None
                    and self._rex_idle_candidate_address is None):
                if remote.command("D") != "OK":
                    raise RuntimeError("QEMU GDB detach failed")
                gdb_socket.close()
            elif self._uis_idle_addresses is not None:
                gdb_socket.settimeout(None)
                self._start_uis_idle_observer(remote, gdb_socket)
                gdb_socket = None
            else:
                gdb_socket.settimeout(None)
                self._start_rex_idle_candidate_observer(remote, gdb_socket)
                gdb_socket = None
        except Exception:
            if 'gdb_socket' in locals() and gdb_socket is not None:
                gdb_socket.close()
            lcd_listener.close()
            input_listener.close()
            gdb_listener.close()
            if hasattr(self, "lcd_socket"):
                self.lcd_socket.close()
            if hasattr(self, "input_socket"):
                self.input_socket.close()
            if hasattr(self, "audio_socket") and self.audio_socket is not None:
                self.audio_socket.close()
            self._terminate_process()
            self.stderr.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise

    def uis_idle_snapshot(self) -> dict[str, int | str | None]:
        """Return read-only exact UI-idle observation state."""
        with self._uis_idle_lock:
            addresses = self._uis_idle_addresses
            return {
                "status": self._uis_idle_status,
                "entry_address": addresses[0] if addresses else None,
                "body_address": addresses[1] if addresses else None,
                "entry_instructions": self._uis_idle_entry_instructions,
                "body_instructions": self._uis_idle_body_instructions,
            }

    def _set_uis_idle_status(
            self, status: str, entry: int | None = None,
            body: int | None = None,
    ) -> None:
        with self._uis_idle_lock:
            self._uis_idle_status = status
            if entry is not None:
                self._uis_idle_entry_instructions = entry
            if body is not None:
                self._uis_idle_body_instructions = body

    @staticmethod
    def _uis_idle_read_u32(remote: Remote, address: int) -> int:
        raw = bytes.fromhex(remote.command(f"m{address:x},4"))
        if len(raw) != 4:
            raise RuntimeError("QEMU UI-idle observer short memory read")
        return int.from_bytes(raw, "little")

    @staticmethod
    def _uis_idle_pc(remote: Remote, registers: dict[str, int]) -> int:
        raw = bytes.fromhex(remote.command(f"p{registers['pc']:x}"))
        if len(raw) != 4:
            raise RuntimeError("QEMU UI-idle observer short PC read")
        return int.from_bytes(raw, "little") & ~1

    def _wait_for_uis_idle(
            self, remote: Remote, registers: dict[str, int], address: int,
    ) -> int:
        remote.continue_execution()
        if self._uis_idle_pc(remote, registers) != address:
            raise RuntimeError("QEMU UI-idle observer unexpected stop")
        return self._uis_idle_read_u32(remote, 0x10000010)

    def _observe_uis_idle(
            self, remote: Remote, registers: dict[str, int],
    ) -> None:
        assert self._uis_idle_addresses is not None
        entry_address, body_address = self._uis_idle_addresses
        entry_armed = True
        body_armed = False
        try:
            entry = self._wait_for_uis_idle(remote, registers, entry_address)
            remote.breakpoint(entry_address, False)
            entry_armed = False
            self._set_uis_idle_status("entry-seen", entry=entry)
            remote.breakpoint(body_address, True)
            body_armed = True
            body = self._wait_for_uis_idle(remote, registers, body_address)
            remote.breakpoint(body_address, False)
            body_armed = False
            self._set_uis_idle_status("confirmed", entry=entry, body=body)
        except Exception:
            if not self._uis_idle_stop.is_set():
                self._set_uis_idle_status("observer-failed")
        finally:
            for address, armed in ((entry_address, entry_armed),
                                   (body_address, body_armed)):
                if armed:
                    try:
                        remote.breakpoint(address, False)
                    except Exception:
                        pass
            if (not self._uis_idle_stop.is_set()
                    and self.process.poll() is None):
                try:
                    if remote.command("D") != "OK":
                        self._set_uis_idle_status("observer-failed")
                except Exception:
                    self._set_uis_idle_status("observer-failed")
            try:
                remote.sock.close()
            except OSError:
                pass
            self._uis_idle_socket = None

    def _start_uis_idle_observer(self, remote: Remote,
                                  sock: socket.socket) -> None:
        assert self._uis_idle_addresses is not None
        registers = remote.register_map()
        if "pc" not in registers:
            raise RuntimeError("QEMU UI-idle observer missing PC register")
        remote.breakpoint(self._uis_idle_addresses[0], True)
        self._uis_idle_socket = sock
        self._uis_idle_worker = threading.Thread(
            target=self._observe_uis_idle, args=(remote, registers),
            name="msm5xxx-qemu-uis-idle", daemon=True,
        )
        self._uis_idle_worker.start()

    def _stop_uis_idle_observer(self) -> None:
        self._uis_idle_stop.set()
        sock = self._uis_idle_socket
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        worker = self._uis_idle_worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(1)

    def rex_idle_candidate_snapshot(self) -> dict[str, int | str | None]:
        """Return a read-only observation of one exact REX-idle candidate."""
        with self._rex_idle_candidate_lock:
            return {
                "status": self._rex_idle_candidate_status,
                "address": self._rex_idle_candidate_address,
                "instructions": self._rex_idle_candidate_instructions,
            }

    def _set_rex_idle_candidate_status(
            self, status: str, instructions: int | None = None,
    ) -> None:
        with self._rex_idle_candidate_lock:
            self._rex_idle_candidate_status = status
            if instructions is not None:
                self._rex_idle_candidate_instructions = instructions

    def _observe_rex_idle_candidate(
            self, remote: Remote, registers: dict[str, int],
    ) -> None:
        assert self._rex_idle_candidate_address is not None
        address = self._rex_idle_candidate_address
        armed = True
        try:
            instructions = self._wait_for_uis_idle(remote, registers, address)
            remote.breakpoint(address, False)
            armed = False
            self._set_rex_idle_candidate_status("seen", instructions)
        except Exception:
            if not self._rex_idle_candidate_stop.is_set():
                self._set_rex_idle_candidate_status("observer-failed")
        finally:
            if armed:
                try:
                    remote.breakpoint(address, False)
                except Exception:
                    pass
            if (not self._rex_idle_candidate_stop.is_set()
                    and self.process.poll() is None):
                try:
                    if remote.command("D") != "OK":
                        self._set_rex_idle_candidate_status("observer-failed")
                except Exception:
                    self._set_rex_idle_candidate_status("observer-failed")
            try:
                remote.sock.close()
            except OSError:
                pass
            self._rex_idle_candidate_socket = None

    def _start_rex_idle_candidate_observer(
            self, remote: Remote, sock: socket.socket,
    ) -> None:
        assert self._rex_idle_candidate_address is not None
        registers = remote.register_map()
        if "pc" not in registers:
            raise RuntimeError("QEMU REX-idle observer missing PC register")
        remote.breakpoint(self._rex_idle_candidate_address, True)
        self._rex_idle_candidate_socket = sock
        self._rex_idle_candidate_worker = threading.Thread(
            target=self._observe_rex_idle_candidate, args=(remote, registers),
            name="msm5xxx-qemu-rex-idle", daemon=True,
        )
        self._rex_idle_candidate_worker.start()

    def _stop_rex_idle_candidate_observer(self) -> None:
        self._rex_idle_candidate_stop.set()
        sock = self._rex_idle_candidate_socket
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        worker = self._rex_idle_candidate_worker
        if worker is not None and worker is not threading.current_thread():
            worker.join(1)

    def _accept_qemu(self, listener: socket.socket) -> socket.socket:
        listener.settimeout(0.1)
        for _ in range(50):
            try:
                return listener.accept()[0]
            except socket.timeout:
                status = self.process.poll()
                if status is not None:
                    detail = self._stderr_text()
                    raise RuntimeError(
                        f"QEMU exited with status {status} before transport"
                        f" connection{': ' + detail if detail else ''}"
                    )
        raise TimeoutError("timed out waiting for QEMU transport connection")

    def _stderr_text(self) -> str:
        self.stderr.flush()
        self.stderr.seek(0)
        return self.stderr.read().strip()

    def _terminate_process(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def interrupt(self) -> None:
        """Wake the replay worker before its owned decoder is closed."""
        self._stop_uis_idle_observer()
        self._stop_rex_idle_candidate_observer()
        try:
            self.lcd_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.input_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        if self.audio_socket is not None:
            try:
                self.audio_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self._terminate_process()

    def _reject_audio_stream(self, reason: str, dropped: int = 0) -> None:
        with self._audio_lock:
            first_rejection = self.audio_stream_status != "rejected"
            if first_rejection:
                self.audio_stream_status = "rejected"
                self.audio_stream_reject_reason = reason
                self.audio_native = False
                self.native_audio_packets.clear()
                self._audio_ready.notify_all()
            self.audio_stream_dropped = max(self.audio_stream_dropped, dropped)
        transport = getattr(self.decoder, "audio_transport", None)
        if transport is not None and first_rejection:
            transport.renderer_submission(
                False, self.audio_stream_reject_reason
            )

    def _replay_audio_write(self, record: bytes | bytearray) -> None:
        if self.audio_stream_status == "rejected":
            return
        if (not self.audio_stream_enabled or record[1] != 1
                or record[2:4] != b"\0\0"):
            self._reject_audio_stream("qemu-audio-write-shape")
            return
        pc, packed, order = struct.unpack_from("<III", record, 4)
        if packed & 0xFFFF0000:
            self._reject_audio_stream("qemu-audio-write-shape")
            return
        expected = 1 if not self.audio_stream_seen else (
            self.audio_stream_order + 1
        ) & 0xFFFFFFFF
        if order != expected:
            self._reject_audio_stream("qemu-audio-order-gap")
            return
        port = packed & 0xFF
        value = packed >> 8 & 0xFF
        transport = self.decoder.audio_transport
        if (port > transport.data_offset or not transport.write(
                pc, transport.base + port, 1, value)):
            self._reject_audio_stream("qemu-audio-site-mismatch")
            return
        self.audio_stream_seen = True
        self.audio_stream_order = order
        if not getattr(self, "audio_native", False):
            self.audio_stream_status = "active"

    def _replay_audio_status(self, record: bytes | bytearray) -> None:
        if (self.audio_stream_status == "rejected"
                and record[1] != AUDIO_STATUS_RESET):
            return
        status = record[1]
        order, dropped, detail = struct.unpack_from("<III", record, 4)
        if (not self.audio_stream_enabled or record[2:4] != b"\0\0"):
            self._reject_audio_stream("qemu-audio-status-shape")
        elif status == AUDIO_STATUS_OVERFLOW and dropped and detail == 0:
            self.audio_stream_order = order
            self._reject_audio_stream("qemu-audio-overflow", dropped)
        elif (status == AUDIO_STATUS_RESET and (order or dropped)
              and detail == 0):
            reset_epoch = order | dropped << 32
            with self._audio_lock:
                self.audio_stream_seen = False
                self.audio_stream_order = 0
                self.audio_stream_dropped = 0
                self.audio_stream_reject_reason = None
                self.audio_pcm_underflow_frames = 0
                self.audio_pcm_overflow_frames = 0
                self.audio_pcm_epoch = 0
                self.audio_timing_late_events = 0
                self.audio_timing_collapsed_events = 0
                self.audio_timing_max_lateness_ns = 0
                self.audio_reject_witness = None
                self.audio_native = True
                self.audio_stream_status = "native"
                current_is_newer = self.native_audio_epoch and (
                    (self.native_audio_epoch - reset_epoch)
                    & 0xFFFFFFFFFFFFFFFF
                ) < 0x8000000000000000
                if (self.native_audio_epoch == reset_epoch
                        or current_is_newer):
                    self.native_audio_reset_epoch = 0
                else:
                    self.native_audio_packets.clear()
                    self.native_audio_reset_epoch = reset_epoch
                self._audio_ready.notify_all()
            player = getattr(self.decoder, "audio_player", None)
            if player is not None:
                player.close()
                self.decoder.audio_player = None
        elif (status == AUDIO_STATUS_REJECTED and order >= dropped > 0
              and detail != 0):
            self.audio_stream_dropped = dropped
            first_order = order - dropped + 1
            witness = self.audio_reject_witness
            suffix = ""
            if witness is not None and witness[0] == first_order:
                (_order, pc, port, value, page, index, control) = witness
                suffix = (
                    f":pc=0x{pc:08x}:port={port}:value=0x{value:02x}:"
                    f"page={page}:index=0x{index:02x}:control=0x{control:02x}"
                )
            self._reject_audio_stream(
                f"qemu-audio-core-rejected:0x{detail:08x}:"
                f"order={first_order}{suffix}"
            )
        elif status == AUDIO_STATUS_NATIVE and order == dropped == detail == 0:
            self.audio_native = True
            self.audio_stream_status = "native"
            player = getattr(self.decoder, "audio_player", None)
            if player is not None:
                player.close()
                self.decoder.audio_player = None
        else:
            self._reject_audio_stream("qemu-audio-status-shape")

    def _replay_record(self, record: bytes | bytearray) -> None:
        if record[0] == LCD_WRITE:
            self.decoder._lcd_write(
                self.decoder.uc, 0,
                int.from_bytes(record[4:8], "little"),
                record[1],
                int.from_bytes(record[8:12], "little"),
                None,
            )
        elif record[0] == TELEMETRY:
            self.decoder._lcd_page_flush_current()
            self.decoder._flush_indexed_frame()
            self.pc = int.from_bytes(record[4:8], "little")
            self.instructions = int.from_bytes(record[8:16], "little")
        elif record[0] == DEVICE_TELEMETRY:
            phase_cycles = int.from_bytes(record[4:8], "little")
            self.ready_status = record[1]
            self.ready_phase = phase_cycles & 0xff
            self.ready_cycles = phase_cycles >> 8
            self.ready_reads = int.from_bytes(record[8:12], "little")
            self.ready_responses = int.from_bytes(record[12:16], "little")
        elif record[0] == INPUT_TELEMETRY:
            matrix = int.from_bytes(record[4:8], "little")
            self.input_pressed = bool(record[1])
            self.input_row = matrix & 0xff
            self.input_sense = matrix >> 8 & 0xff
            self.input_rejections = matrix >> 16
            self.input_host_events = int.from_bytes(record[8:12], "little")
            self.input_active_reads = int.from_bytes(record[12:16], "little")
        elif record[0] == AUDIO_WRITE:
            self._replay_audio_write(record)
        elif record[0] == AUDIO_STATUS:
            self._replay_audio_status(record)
        elif record[0] == AUDIO_PCM_TELEMETRY:
            with self._audio_lock:
                self.audio_pcm_underflow_frames = int.from_bytes(
                    record[4:8], "little"
                )
                self.audio_pcm_overflow_frames = int.from_bytes(
                    record[8:12], "little"
                )
                self.audio_pcm_epoch = int.from_bytes(record[12:16], "little")
        elif record[0] == AUDIO_TIMING_TELEMETRY:
            with self._audio_lock:
                self.audio_timing_late_events = int.from_bytes(
                    record[4:8], "little"
                )
                self.audio_timing_collapsed_events = int.from_bytes(
                    record[8:12], "little"
                )
                self.audio_timing_max_lateness_ns = int.from_bytes(
                    record[12:16], "little"
                )
        elif record[0] == AUDIO_REJECT_TELEMETRY:
            pc, order, packed = struct.unpack_from("<III", record, 4)
            if self.audio_stream_enabled and record[2:4] == b"\0\0" and order:
                self.audio_reject_witness = (
                    order, pc, packed & 0xFF, packed >> 8 & 0xFF,
                    packed >> 16 & 0xFF, packed >> 24 & 0xFF, record[1],
                )

    def audio_pcm_snapshot(self) -> tuple[int, int, int]:
        with self._audio_lock:
            return (self.audio_pcm_underflow_frames,
                    self.audio_pcm_overflow_frames,
                    self.audio_pcm_epoch)

    def audio_timing_snapshot(self) -> tuple[int, int, int]:
        with self._audio_lock:
            return (self.audio_timing_late_events,
                    self.audio_timing_collapsed_events,
                    self.audio_timing_max_lateness_ns)

    def _native_audio_has_capacity(self) -> bool:
        with self._audio_lock:
            return (len(self.native_audio_packets)
                    < self.native_audio_packets.maxlen)

    def _replay_native_audio(self, stop: threading.Event) -> None:
        pending = bytearray()
        audio_socket = self.audio_socket
        while not stop.is_set() and self.process.poll() is None:
            with self._audio_ready:
                while (len(self.native_audio_packets)
                       >= self.native_audio_packets.maxlen
                       and not stop.is_set()
                       and self.process.poll() is None):
                    self._audio_ready.wait(0.02)
            if stop.is_set() or self.process.poll() is not None:
                return
            if len(pending) >= 1796:
                record = bytes(pending[:1796])
                del pending[:1796]
                self._queue_native_audio(record)
                continue
            try:
                readable, _, _ = select.select((audio_socket,), (), (), 0.02)
            except (OSError, ValueError):
                if stop.is_set() or self.process.poll() is not None:
                    return
                raise
            if not readable:
                continue
            try:
                chunk = audio_socket.recv(AUDIO_PACKET_BYTES - len(pending))
            except TimeoutError:
                continue
            except OSError:
                if stop.is_set() or self.process.poll() is not None:
                    return
                raise
            if not chunk:
                if not stop.is_set() and self.process.poll() is None:
                    self.decoder.input_error = "QEMU audio channel closed"
                    self._terminate_process()
                return
            pending.extend(chunk)

    def replay(self, stop: threading.Event) -> None:
        input_pending = bytearray()
        lcd_pending = bytearray()
        audio_socket = getattr(self, "audio_socket", None)
        audio_errors: list[Exception] = []
        audio_worker = None
        if audio_socket is not None:
            def replay_audio() -> None:
                try:
                    self._replay_native_audio(stop)
                except Exception as error:
                    audio_errors.append(error)
                    stop.set()

            audio_worker = threading.Thread(
                target=replay_audio,
                name="msm5xxx-qemu-audio-replay",
                daemon=True,
            )
            audio_worker.start()
        streams = (
            (self.input_socket, input_pending),
            (self.lcd_socket, lcd_pending),
        )
        try:
            while not stop.is_set() and self.process.poll() is None:
                try:
                    readable, _, _ = select.select(
                        tuple(stream for stream, _pending in streams),
                        (), (), 0.02,
                    )
                except (OSError, ValueError):
                    if stop.is_set() or self.process.poll() is not None:
                        break
                    raise
                for stream, pending in streams:
                    if stream not in readable:
                        continue
                    try:
                        chunk = stream.recv(4096)
                    except TimeoutError:
                        continue
                    except OSError:
                        if stop.is_set() or self.process.poll() is not None:
                            return
                        raise
                    if not chunk:
                        if not stop.is_set() and self.process.poll() is None:
                            channel = (
                                "input" if stream is self.input_socket
                                else "LCD"
                            )
                            self.decoder.input_error = (
                                f"QEMU {channel} channel closed"
                            )
                            self._terminate_process()
                        return
                    pending.extend(chunk)
                    complete = len(pending) // RECORD_SIZE * RECORD_SIZE
                    for offset in range(0, complete, RECORD_SIZE):
                        record = bytes(pending[offset:offset + RECORD_SIZE])
                        self._replay_record(record)
                    del pending[:complete]
        finally:
            stop.set()
            if audio_worker is not None:
                with self._audio_ready:
                    self._audio_ready.notify_all()
                audio_worker.join(1)
        if audio_worker is not None and audio_worker.is_alive():
            raise RuntimeError("QEMU audio replay worker did not stop")
        if audio_errors:
            raise audio_errors[0]

    def _queue_native_audio(self, record: bytes) -> None:
        with self._audio_lock:
            if self.audio_stream_status == "rejected":
                return
            if len(record) != 1796 or record[:8] != b"M5P2\x02\0\0\0":
                self._reject_audio_stream("qemu-audio-pcm-shape")
                return
            epoch, sequence, start_frame = struct.unpack_from("<QQQ", record, 8)
            end_frame = start_frame + (len(record) - 32) // 4
            if not epoch or not sequence or end_frame > 0x7FFFFFFFFFFFFFFF:
                self._reject_audio_stream("qemu-audio-pcm-shape")
                return
            if self.native_audio_reset_epoch:
                reset_is_newer = epoch != self.native_audio_reset_epoch and (
                    (epoch - self.native_audio_reset_epoch)
                    & 0xFFFFFFFFFFFFFFFF
                ) < 0x8000000000000000
                if epoch != self.native_audio_reset_epoch and not reset_is_newer:
                    return
                if sequence != 1:
                    self._reject_audio_stream("qemu-audio-pcm-sequence")
                    return
                self.native_audio_packets.clear()
                self.native_audio_reset_epoch = 0
            if epoch != self.native_audio_epoch:
                if self.native_audio_epoch and (
                    (self.native_audio_epoch - epoch) & 0xFFFFFFFFFFFFFFFF
                ) < 0x8000000000000000:
                    return
                if sequence != 1:
                    self._reject_audio_stream("qemu-audio-pcm-sequence")
                    return
                self.native_audio_packets.clear()
            elif (sequence != self.native_audio_sequence + 1
                  or start_frame != self.native_audio_end_frame):
                self._reject_audio_stream("qemu-audio-pcm-sequence")
                return
            self.native_audio_epoch = epoch
            self.native_audio_sequence = sequence
            self.native_audio_end_frame = end_frame
            self.native_audio_packets.append(record)
            self._audio_ready.notify()

    def take_native_audio(self, timeout: float = 0.0) -> bytes:
        with self._audio_ready:
            if (not self.native_audio_packets and timeout > 0
                    and self.audio_stream_status != "rejected"):
                self._audio_ready.wait(timeout)
            if self.audio_stream_status == "rejected":
                return b""
            record = (self.native_audio_packets.popleft()
                      if self.native_audio_packets else b"")
            if record:
                self._audio_ready.notify()
            return record

    def _sideband_input_producer(
            self, bit: int, event_code: int | None,
    ) -> dict[str, object] | None:
        producer = self.decoder._direct_sideband_producer(bit, event_code)
        return (producer if producer == self.matrix_input_sideband_producer
                else None)

    def can_set_key(self, bit: int, event_code: int | None = None) -> bool:
        profile = self.matrix_input_profile
        return (profile is not None and
                (self._sideband_input_producer(bit, event_code) is not None
                 or self.decoder._direct_matrix_position(bit, event_code)
                 is not None))

    def set_key(self, bit: int, pressed: bool,
                event_code: int | None = None) -> bool:
        profile = self.matrix_input_profile
        if profile is None:
            return False
        if pressed:
            if bit in self.matrix_held or bit in self.sideband_held:
                return True
            if self.matrix_held or self.sideband_held:
                self.decoder.input_error = (
                    "direct input supports one key at a time"
                )
                return False
            sideband = self._sideband_input_producer(bit, event_code)
            position = self.decoder._direct_matrix_position(bit, event_code)
            if sideband is not None:
                packet = sideband_input_command(sideband, True)
            elif position is not None:
                packet = matrix_input_command(profile, position, True)
            else:
                return False
        else:
            sideband = self._sideband_input_producer(bit, event_code)
            position = self.matrix_held.get(bit)
            if bit in self.sideband_held and sideband is not None:
                packet = sideband_input_command(sideband, False)
            elif position is not None:
                packet = matrix_input_command(profile, position, False)
            else:
                return False
        try:
            self.input_socket.sendall(packet)
        except OSError as error:
            self.decoder.input_error = f"QEMU input transport failed: {error}"
            return False
        if pressed:
            if sideband is not None:
                self.sideband_held.add(bit)
            else:
                assert position is not None
                self.matrix_held[bit] = position
        else:
            self.sideband_held.discard(bit)
            self.matrix_held.pop(bit, None)
        self.decoder.input_error = ""
        return True

    def close(self) -> None:
        self._stop_uis_idle_observer()
        self._stop_rex_idle_candidate_observer()
        self.lcd_socket.close()
        self.input_socket.close()
        if self.audio_socket is not None:
            self.audio_socket.close()
        self._terminate_process()
        self.stderr.close()
        self.decoder.close()
        self.temporary.cleanup()
