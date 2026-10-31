"""GUI-free QEMU MSM5xxx transport shared by desktop and Android."""
from __future__ import annotations

import os
import hashlib
import json
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections import deque
from dataclasses import asdict

from .gdb_remote import Remote
from msm5xxx_emulator.core import FirmwareConfig
from .decoder import QemuDecoder
from ..core.initial_state import REGISTER_NAMES, initial_register_state
from msm5xxx_emulator.core.constants import STABLE_MSM_MMIO
from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.bootstrap_sdram import reset_copy_ram_profile
from msm5xxx_emulator.detection.boot_keysense import find_boot_keysense_release
from msm5xxx_emulator.detection.spi_nv import find_spi_nv_profile
from msm5xxx_emulator.detection.small_page_nand import small_page_nand_profile
from . import nand_state as native_nand_state
from msm5xxx_emulator.detection.input_halfword import resolve_indirect_matrix_input
from msm5xxx_emulator.detection.input_halfword_status import resolve_indirect_board_status
from msm5xxx_emulator.detection.input_matrix import (
    _samsung_sideband_51_family_metadata,
    resolve_distributed_matrix_input,
)
from msm5xxx_emulator.devices.input import SAMSUNG_RING32_KEY_EVENTS
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
from msm5xxx_emulator.detection.audio import find_audio_transport, find_ma5_readback_candidate
from msm5xxx_emulator.detection.ma5_gpio_irq import find_ma5_gpio_irq_candidate
from msm5xxx_emulator.detection.rex import (
    UIS_IDLE_BODY_DELTAS, find_rex_static_controller_callback_candidate,
    find_rex_legacy_row0_profile,
)
from msm5xxx_emulator.detection.storage import (
    EEPROM_24LCXX_READ_SIGNATURE,
    EEPROM_24LCXX_F6F7_WRITE_PREFIX,
    EEPROM_24LCXX_X270_READ_PREFIX,
    EEPROM_24LCXX_X270_WRITE_PREFIX,
    EEPROM_24LCXX_X430_READ_PREFIX,
    EEPROM_24LCXX_X430_WRITE_PREFIX,
    EEPROM_24LCXX_X7700_READ_PREFIX,
    EEPROM_24LCXX_X7700_WRITE_PREFIX,
    direct_amd_x16_nor_profile,
    direct_intel_x16_nor_profile,
    eeprom_24lcxx_write_at,
    flash_id_for_size,
    fujitsu_x16_flash_ids,
    find_24lcxx_halfword_driver,
    find_24lcxx_f6f7_driver,
    find_24lcxx_f7f6_driver,
    find_24lcxx_x270_driver,
    find_24lcxx_x7700_driver,
    find_adjacent_amd_x16_nor,
    find_adjacent_fujitsu_x16_nor,
    find_catalog_amd_x16_nor,
    find_embedded_fujitsu_x16_nor,
    find_primary_fsd_amd_x16_nor,
    find_record_amd_x16_nor,
    mapped_primary_intel_x16_nor_profile,
    primary_probe_x16_nor_profile,
    seeded_amd_x16_nor_profile,
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
    lock_path,
)


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
BOARD_STATUS_TELEMETRY = 10
AUDIO_STATUS_OVERFLOW = 1
AUDIO_STATUS_RESET = 2
AUDIO_STATUS_REJECTED = 3
AUDIO_STATUS_NATIVE = 4
AUDIO_PACKET_BYTES = 1796
AUDIO_SOCKET_SEND_BUFFER = 1048576
HOST_INPUT = 0x80
HOST_BOARD_STATUS = 0x81
PAUSE_TIMER_ADDRESS = 0x04800020
PERSISTENT_STATE_FILES = (
    "primary-writable.raw", "secondary.raw", "upper.raw", "upper-x16.raw",
    "eeprom.raw", "spi-nv.raw", "protected-nor.raw", "nand-main.raw", "intel-x16.raw", "amd-x16.raw",
    "record-x16.raw", "catalog-x16.raw", "mapped-primary-x16.raw",
    "mapped-primary-x16-upper.raw",
    "native-nand.json",
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
    low5 = profile.get("grammar") in {"lg-descriptor-low5-6x5-raw-v1", "descriptor-row734-low5-6x5-v1"}
    loop = profile.get("grammar") == "indirect-halfword-loop-six-row-v1"
    if loop and (no_key != 31 or senses != (30, 29, 27, 23)):
        raise ValueError("invalid detector-resolved loop senses")
    if low5 and (no_key != 0x1F or set(senses) != {30, 29, 27, 23, 15}):
        raise ValueError("invalid detector-resolved five-column senses")
    if (not senses or len(set(senses)) != len(senses)
            or any(not 0 <= value <= (0x1F if low5 or loop else 0x0F) or value == no_key
                   for value in senses)):
        raise ValueError("invalid detector-resolved matrix senses")
    return senses


def qemu_low5_matrix_property(
        image: bytes, config: object, profile: dict[str, object] | None,
) -> tuple[str | None, str | None]:
    """Serialize an admitted scanner; native reads also gate descriptor/selector.

    Temporary electrical approximation: released columns follow the firmware's
    no-key predicate. Other reads and upper sense bits retain native backing.
    """
    if profile is None or profile.get("grammar") != "lg-descriptor-low5-6x5-raw-v1":
        return None, None
    if getattr(config, "board_status_input", None) is not None:
        return None, "conflicting-status-profile"
    if (profile.get("rows") != 6 or profile.get("columns") != 5
            or profile.get("sense_bits") != 5
            or profile.get("register") != 0x0300072C
            or profile.get("event_sink_validation") != "validated-raw-enqueue-callsites"
            or not profile.get("descriptor_mmio_provenance")
            or not profile.get("timer_bridge")):
        return None, "unclosed-scanner-profile"
    try:
        matrix_senses(profile)
    except (KeyError, TypeError, ValueError):
        return None, "invalid-sense-table"
    descriptor = profile.get("descriptor_pointer")
    if (type(descriptor) is not int or descriptor & 3
            or not config.ram_base <= descriptor <= config.ram_base + config.ram_size - 0x38):
        return None, "descriptor-outside-ram"
    sites = []
    for role in ("global_sense_sites", "row_sense_sites"):
        candidates = profile.get(role)
        if (not isinstance(candidates, (list, tuple)) or len(candidates) != 1
                or type(candidates[0]) is not int or candidates[0] & 1):
            return None, "ambiguous-sense-roles"
        offset = candidates[0] - config.load_address
        if not 0 <= offset <= min(len(image), config.flash_size) - 4:
            return None, "sense-outside-primary-nor"
        pointer, read = struct.unpack_from("<HH", image, offset)
        register = pointer & 7
        if (pointer & 0xF800 != 0x6800 or (pointer >> 6 & 31) != 0x34 // 4
                or read != 0x8800 | register << 3 | register):
            return None, "sense-load-shape-mismatch"
        sites.append(candidates[0] + 2)  # Actual LDRH, not its pointer load.
    if sites[0] == sites[1]:
        return None, "ambiguous-sense-roles"
    return f"matrix-low5={descriptor:x}:{sites[0]:x}:{sites[1]:x}", None


def qemu_ram_argument(size: int) -> str:
    """Preserve exact bytes; keep MiB spelling for aligned RAM allocations."""
    if type(size) is not int or size <= 0:
        raise ValueError("QEMU RAM size must be a positive integer byte count")
    mib = 1024 * 1024
    return f"{size // mib}M" if size % mib == 0 else f"{size}B"


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


def qemu_ram_reserved_property(image: bytes, config: object, sp: int) -> str | None:
    """Bind the reserved bus window to the same reset-consumed RAM class."""
    profile = getattr(config, "ram_bootstrap_profile", None)
    if profile is None:
        return None
    flash_size = getattr(config, "flash_size", None)
    if (type(profile) is not dict or type(flash_size) is not int
            or flash_size <= 0 or type(getattr(config, "load_address", None)) is not int
            or config.load_address != 0):
        raise ValueError("invalid reset-linked RAM profile")
    expected = reset_copy_ram_profile(image[:flash_size])
    if (expected is None or profile != expected
            or profile.get("experimental") is not True
            or any(type(profile.get(key)) is not int for key in
                   ("ram_base", "ram_size", "reserved_base", "reserved_size"))
            or any(type(getattr(config, key, None)) is not int
                   or getattr(config, key) != expected[key]
                   for key in ("ram_base", "ram_size"))):
        raise ValueError("reset-linked RAM profile does not match firmware or memory layout")
    linker = getattr(config, "linker", None)
    try:
        if linker is not None and asdict(linker) != expected["bootstrap_linker"]:
            raise ValueError("reset-linked RAM linker does not match firmware")
    except TypeError as exc:
        raise ValueError("invalid reset-linked RAM linker") from exc
    base, size = expected["reserved_base"], expected["reserved_size"]
    if (type(sp) is not int or sp & 3
            or not expected["ram_base"] + 4 <= sp <=
                   expected["ram_base"] + expected["ram_size"] - 4
            or sp <= base + size and sp + 4 > base):
        raise ValueError("reset-linked RAM stack overlaps the reserved bus window")
    return f"ram-reserved={base:x}:{size:x}"


def qemu_native_nand_profile(image: bytes, config: object
                             ) -> tuple[dict | None, str | None]:
    """Bind the temporary native protocol to this loaded image and RAM gap."""
    profile = getattr(config, "native_nand_profile", None)
    if profile is None or not getattr(config, "nand_enabled", False):
        return None, None
    if (type(profile) is not dict or type(getattr(config, "flash_size", None)) is not int
            or not 0 < config.flash_size <= len(image)):
        return None, "invalid-profile"
    image = image[:config.flash_size]
    expected = small_page_nand_profile(image)
    ram = reset_copy_ram_profile(image)
    if expected is None or expected != profile:
        return None, "producer-shape-mismatch"
    if (ram is None or ram != getattr(config, "ram_bootstrap_profile", None)
            or type(getattr(config, "load_address", None)) is not int
            or config.load_address != 0
            or any(getattr(config, key, None) != ram[key]
                   for key in ("ram_base", "ram_size"))):
        return None, "reset-copy-memory-mismatch"
    geometry = tuple(getattr(config, key, None) for key in (
        "nand_data_size", "nand_page_size", "nand_spare_size",
        "nand_pages_per_block", "nand_bus_width"))
    if (any(type(value) is not int for value in geometry)
            or geometry != (0x2000000, 512, 16, 32, 2)):
        return None, "unsupported-main-oob-geometry"
    return expected, None


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


def qemu_audio_irq_property(audio: object, config: FirmwareConfig) -> tuple[str | None, str | None]:
    """Provisional route for owned MA2 accessors; native readback gates use."""
    if not isinstance(audio, dict) or audio.get('static_status') != 'accepted':
        return None, 'audio-transport-unavailable'
    route = audio.get('irq_controller_candidate')
    if (audio.get('family') != 'ma2' or audio.get('grammar') != 'ma2-command-v1'
            or not isinstance(route, dict) or route.get('status') != 'candidate'
            or route.get('profile') != 'two-bank-callback-descriptor-v1'):
        return None, 'descriptor-class-unavailable'
    link = route.get('callback_linkage')
    words = route.get('words')
    if (not isinstance(link, dict) or not isinstance(words, list) or len(words) != 7
            or any(type(word) is not int for word in words)):
        return None, 'callback-linkage-unavailable'
    fields = [route.get('descriptor_address'), *words[:5],
              route.get('dispatcher_offset'), link.get('state_address'),
              link.get('table_address'), link.get('callback_offset')]
    read = link.get('data_read_offset')
    if (any(type(value) is not int or not 0 <= value <= 0xffffffff for value in fields)
            or type(read) is not int or config.load_address != 0
            or read not in audio.get('sites', {}).get('read_2', [])
            or any(not 0 <= address < config.flash_size or address & 1
                   for address in (fields[6], fields[9]))):
        return None, 'audio-route-mapping-unverified'
    start, end = config.ram_base, config.ram_base + config.ram_size
    if (any(not start <= fields[index] <= end - size or fields[index] % alignment
            for index, size, alignment in ((0, 28, 4), (4, 2, 2), (5, 2, 2),
                                           (7, 8, 4), (8, 16, 4)))
            or fields[1:3] != [0x03000624, 0x0300062c]
            or not 0 < fields[3] <= 0x8000 or fields[3] & (fields[3] - 1)
            or words[6] != 0
            or config.rex_irq_status_address != 0x03000620
            or config.rex_irq_enable_address != 0x03000628):
        return None, 'audio-route-controller-unverified'
    return 'audio-irq-route=' + ':'.join(f'{value:x}' for value in fields), None


def qemu_audio_packet_property(image: bytes, config: object,
                               audio: object) -> tuple[str | None, str | None]:
    if (not isinstance(audio, dict)
            or audio.get("grammar") != "repeated-bit-sequence-v1"):
        return None, "protocol-unmatched"
    if (getattr(config, "load_address", None) != 0
            or type(getattr(config, "flash_size", None)) is not int
            or config.flash_size < 0x1000):
        return None, "primary-nor-unmapped"
    if (audio.get("static_status") != "accepted"
            or find_audio_transport(image) != audio):
        return None, "same-image-contract-mismatch"
    spans = [(audio["begin"] - 6, 72), (audio["sequence_producer"], 86),
             (audio["timer_producer"], 170), (audio["timer_stop_producer"], 76),
             (audio["immediate_sender"], 112), (audio["reset_producer"], 0xb0),
             (audio["status_consumers"][0] - 0x112, 0x112 + 138)]
    spans += audio["nor_dependencies"]
    if any(type(offset) is not int or not 0 <= offset <= config.flash_size - length
           for offset, length in spans):
        return None, "primary-nor-out-of-bounds"
    ram_base = getattr(config, "ram_base", None)
    ram_size = getattr(config, "ram_size", None)
    if (type(ram_base) is not int or type(ram_size) is not int or ram_size < 8
            or any((size > 1 and address & 3) or not ram_base <= address <= ram_base + ram_size - size
                   for address, size in audio["ram_dependencies"])):
        return None, "consumer-state-unmapped"
    clear = ",audio-packet-clear-pulse=on" if audio.get("control_clear_status") == "accepted" else ""
    return (f"experimental-audio-packet-bus={audio['begin']:x},"
            "audio-packet-sequence=on" + clear), None


def qemu_virtual_cell_property(image: bytes, config: object,
                               scenario: object) -> tuple[str | None, str | None]:
    """Bind an explicit experimental cell to this image; never enable SIP."""
    if scenario is None:
        return None, None
    required = {"pilot_phase", "raw_energy", "virtual_delay_ns",
                "decoder_init_delay_ns", "sync_message_hex", "paging_messages_hex"}
    fields = {"sid": ((0, 32, 15), (1, 31, 15)),
              "nid": ((0, 47, 16), (1, 46, 16)),
              "channel": ((0, 167, 11), (4, 31, 11))}
    if (not isinstance(scenario, dict) or not required <= scenario.keys()
            or scenario.keys() - required - fields.keys() - {
                "tx_init_delay_ns", "tx_frame_period_ns", "access_response_probe",
                "access_assignment_code", "traffic_decoder_probe", "traffic_frame_hex",
                "allow_receive_only"}):
        raise ValueError("invalid virtual cell fields")
    allow_receive_only = scenario.get("allow_receive_only", False)
    if type(allow_receive_only) is not bool:
        raise ValueError("invalid virtual cell allow_receive_only")
    access_response = scenario.get("access_response_probe", False)
    if type(access_response) is not bool:
        raise ValueError("invalid experimental access_response_probe")
    if access_response and "tx_frame_period_ns" not in scenario:
        raise ValueError("experimental access_response_probe requires tx_frame_period_ns")
    assignment_code = scenario.get("access_assignment_code", 0)
    if type(assignment_code) is not int or not 0 <= assignment_code <= 128:
        raise ValueError("invalid experimental access_assignment_code")
    if assignment_code and not access_response:
        raise ValueError("experimental access_assignment_code requires access_response_probe")
    traffic_decoder = scenario.get("traffic_decoder_probe", False)
    if type(traffic_decoder) is not bool:
        raise ValueError("invalid experimental traffic_decoder_probe")
    if traffic_decoder and not assignment_code:
        raise ValueError("experimental traffic_decoder_probe requires access_assignment_code")
    traffic_frame = None
    if "traffic_frame_hex" in scenario:
        value = scenario["traffic_frame_hex"]
        if (type(value) is not str or (value != "auto" and (
                len(value) != 48
                or any(char not in "0123456789abcdefABCDEF" for char in value)
                or value[-2:] != "00"))):
            raise ValueError("invalid virtual cell traffic_frame_hex")
        if traffic_decoder is not True:
            raise ValueError("traffic_frame_hex requires traffic_decoder_probe")
        traffic_frame = value.lower()
    tx_delay = scenario.get("tx_init_delay_ns")
    if "tx_init_delay_ns" in scenario and (type(tx_delay) is not int
                                            or not 1 <= tx_delay <= 1000000000):
        raise ValueError("invalid virtual cell tx_init_delay_ns")
    tx_period = scenario.get("tx_frame_period_ns")
    if "tx_frame_period_ns" in scenario:
        if type(tx_period) is not int or not 1 <= tx_period <= 1000000000:
            raise ValueError("invalid virtual cell tx_frame_period_ns")
        if "tx_init_delay_ns" not in scenario:
            raise ValueError("tx_frame_period_ns requires tx_init_delay_ns")
    for name, sites in fields.items():
        if name in scenario and (type(scenario[name]) is not int
                                 or not 0 <= scenario[name] < 1 << sites[0][2]):
            raise ValueError(f"invalid virtual cell {name}")
    for key, maximum in (("pilot_phase", 0x3ffff), ("raw_energy", 0xffff),
                         ("virtual_delay_ns", 1000000000),
                         ("decoder_init_delay_ns", 1000000000)):
        value = scenario[key]
        minimum = 1 if key.endswith("_ns") else 0
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f"invalid virtual cell {key}")
    if scenario["decoder_init_delay_ns"] != 80000000:
        raise ValueError("virtual cell sync requires an 80ms decoder initialization")

    def crc30(value, bits):
        crc = 0x3fffffff
        for bit in range(bits - 1, -1, -1):
            feedback = ((crc >> 29) ^ (value >> bit)) & 1
            crc = ((crc << 1) ^ (0x6030b9c7 if feedback else 0)) & 0x3fffffff
        return (~crc) & 0x3fffffff

    def packet(value, maximum, message_type):
        if not isinstance(value, str) or not 10 <= len(value) <= maximum * 2:
            raise ValueError("invalid virtual cell packet")
        try:
            data = bytes.fromhex(value)
        except ValueError:
            raise ValueError("invalid virtual cell packet") from None
        if len(data) < 5 or len(data) > maximum or data[0] != len(data):
            raise ValueError("invalid virtual cell packet length")
        if data[1] != message_type:
            raise ValueError("invalid virtual cell message type")
        if crc30(int.from_bytes(data, "big"), len(data) * 8) != 0x0b105aa5:
            raise ValueError("invalid virtual cell packet CRC")
        return data.hex()

    sync = packet(scenario["sync_message_hex"], 147, 1)
    messages = scenario["paging_messages_hex"]
    if not isinstance(messages, (list, tuple)) or len(messages) != 4:
        raise ValueError("virtual cell requires four paging messages")
    paging_messages = [packet(value, 255, index + 1)
                       for index, value in enumerate(messages)]
    if access_response or scenario.keys() & fields.keys():
        packets = [bytes.fromhex(value) for value in (sync, *paging_messages)]
        # Longer System messages enable extra firmware features; preserve this layout.
        if tuple(map(len, packets)) != (26, 33, 19, 9, 9) or packets[0][2] >= 6:
            if access_response:
                raise ValueError("experimental access_response_probe requires legacy packet layout")
            raise ValueError("unsupported virtual cell field layout")
        for name, sites in fields.items():
            if name not in scenario:
                continue
            for index, bit, width in sites:
                data = packets[index]
                bits = len(data) * 8
                shift = bits - bit - width
                value = int.from_bytes(data, "big")
                value = (value & ~(((1 << width) - 1) << shift)) | (scenario[name] << shift)
                prefix = value >> 30
                packets[index] = ((prefix << 30) | crc30(prefix, bits - 30)).to_bytes(len(data), "big")
        sync, *paging_messages = [value.hex() for value in packets]
    if (getattr(config, "load_address", None) != 0
            or getattr(config, "image_offset", None) != 0):
        return None, "primary-map-unsupported"
    if getattr(config, "rex_static_controller_experimental", False):
        return None, "controller-mode-unsupported"

    from msm5xxx_emulator.detection.baseband import (
        find_search1_transport_profile, find_search1_abort_profile,
        find_finger_transport_profile, find_decoder_init_profile,
        find_combiner_clock_profile, find_paging_decoder_profile,
    )
    from msm5xxx_emulator.detection.rex import find_rex_5ms_sleep_timer

    timer = find_rex_5ms_sleep_timer(image)
    if timer is None or timer[1] != getattr(config, "rex_tick_address", None):
        return None, "tick-image-mismatch"
    tick = timer[1]
    profiles = []
    for finder in (find_search1_transport_profile, find_search1_abort_profile,
                   find_finger_transport_profile, find_decoder_init_profile,
                   find_combiner_clock_profile, find_paging_decoder_profile):
        profile = finder(image, tick)
        if profile.get("accepted") is not True:
            return None, str(profile.get("reject_reason", "protocol-unmatched"))
        profiles.append(profile)
    legacy, abort, finger, decoder, clock, paging = profiles
    transport = legacy["shared_search2_profile"]

    def words(values):
        return ":".join(format(value, "x") for value in values)

    route = [transport["write_sites"][0], transport["consumer"]["loop_file_offset"],
             transport["irq_callback_slot"], transport["callback"], transport["worker"],
             transport["irq_handler_slot"], transport["irq_handler"],
             transport["irq_wrapper"], transport["irq_mask"],
             scenario["virtual_delay_ns"], scenario["pilot_phase"], scenario["raw_energy"]]
    properties = [
        "search2-virtual=" + words(route),
        "search1-virtual=" + words([legacy["first_store"],
            legacy["consumer"]["loop_file_offset"], abort["first_store"]]),
        "finger-virtual=" + words([finger["rss_word_read"], *finger["mask_tables"]]),
        "decoder-init-probe=" + words([decoder["reader"], decoder["init_write"],
            decoder["isr"], scenario["decoder_init_delay_ns"]]),
        "decoder-sync-source=" + words([clock["position_getter"], clock["roll_isr"],
            clock["sync_consumer"]]) + ":" + sync,
        "decoder-paging-source=" + words([paging[key] for key in (
            "isr", "reader", "status_reader", "initializer", "wordcount_address",
            "consumer", "pipeline_cache", "pipeline_layout")]) + ":" + ":".join(paging_messages),
    ]
    receiver_properties = tuple(properties)
    def optional_unavailable(reason):
        if allow_receive_only:
            return ",".join(receiver_properties), "receive-only:" + reason
        return None, reason

    if tx_delay is not None:
        if tx_period is None:
            from msm5xxx_emulator.detection.baseband import find_tx_init_profile as find_tx_profile
        else:
            from msm5xxx_emulator.detection.baseband import find_tx_frame_profile as find_tx_profile
        tx = find_tx_profile(image, tick)
        if tx.get("accepted") is not True:
            return optional_unavailable(str(tx.get("reject_reason", "tx-init-unmatched")))
        flash = getattr(config, "flash_size", None)
        ram_base = getattr(config, "ram_base", None)
        ram_size = getattr(config, "ram_size", None)
        if (type(flash) is not int or flash <= 0
                or any(not 0 <= offset <= min(flash, len(image)) - size
                       for offset, size in tx["code_dependencies"])):
            return optional_unavailable("tx-init-code-unmapped")
        if (type(ram_base) is not int or type(ram_size) is not int or ram_size < 24
                or tx["callback_slot"] & 3 or tx["tx_tcb"] & 3
                or tx["counter_address"] & 1 or tx["control_shadow"] & 1
                or any(not ram_base <= address <= ram_base + ram_size - size
                       for address, size in tx["ram_dependencies"])):
            return optional_unavailable("tx-init-state-unmapped")
        if (tx["callback_slot"] != transport["irq_callback_slot"] - 56
                or tx["irq_mask"] != 8 or tx["irq_status"] != transport["irq_status"]
                or tx["irq_enable"] != transport["irq_enable"]):
            return optional_unavailable("tx-init-controller-mismatch")
        tx_fields = [
            tx["callback"], tx["callback_slot"], tx["armed_flag"], tx["tx_tcb"],
            tx["signal10_call"], tx["control_helper"], tx["registrations"][0], tx_delay]
        if tx_period is not None:
            tx_fields.extend((tx_period, tx["mode_base"], tx["fixed_writer"]))
        properties.append("tx-init-probe=" + words(tx_fields))
    if access_response:
        properties.append("access-response-probe=on")
    if assignment_code:
        properties.append(f"access-assignment-code={assignment_code:x}")
    service_source = None
    service_limit = None
    if traffic_decoder:
        from msm5xxx_emulator.detection.baseband import find_traffic_decoder_profile
        traffic = find_traffic_decoder_profile(image, tick)
        if traffic.get("accepted") is not True:
            return optional_unavailable(str(traffic.get("reject_reason", "traffic-decoder-unmatched")))
        flash = getattr(config, "flash_size", None)
        ram_base = getattr(config, "ram_base", None)
        ram_size = getattr(config, "ram_size", None)
        if (type(flash) is not int or flash <= 0
                or any(not 0 <= offset <= min(flash, len(image)) - size
                       for offset, size in traffic["code_dependencies"])):
            return optional_unavailable("traffic-decoder-code-unmapped")
        if (type(ram_base) is not int or type(ram_size) is not int or ram_size < 48
                or any(not ram_base <= address <= ram_base + ram_size - size
                       for address, size in traffic["ram_dependencies"])):
            return optional_unavailable("traffic-decoder-state-unmapped")
        if any(traffic[key] != decoder[key] for key in (
                "descriptor_template", "irq_callback_slot", "irq_status",
                "irq_enable", "irq_mask")):
            return optional_unavailable("traffic-decoder-controller-mismatch")
        if traffic_frame is not None:
            layout_source = traffic["layout_source"]
            if (type(layout_source) is not int
                    or not 0 <= layout_source <= min(flash, len(image)) - 13):
                return optional_unavailable("traffic-full-frame-layout-unsupported")
            if traffic_frame == "auto":
                traffic_frame = ("00000000000000000000000000000000000000000003d700"
                                 if image[layout_source + 12] == 24 else None)
                if traffic_frame is not None:
                    from msm5xxx_emulator.detection.service import find_origination_service_profile
                    service = find_origination_service_profile(image, ram_base, ram_size)
                    if service.get("accepted") is not True:
                        service_limit = str(service.get("reject_reason", "service-packer-unmatched"))
                    elif any(not 0 <= offset <= min(flash, len(image)) - size
                             for offset, size in service["code_dependencies"]):
                        service_limit = "service-packer-code-unmapped"
                    elif any(not ram_base <= address <= ram_base + ram_size - size
                             for address, size in service["ram_dependencies"]):
                        service_limit = "service-packer-state-unmapped"
                    else:
                        service_source = words(service[key] for key in (
                            "entry", "header_packer", "dispatcher", "revision_address"))
                        traffic_frame = None
            elif image[layout_source + 12] != 24:
                return optional_unavailable("traffic-full-frame-layout-unsupported")
        properties.append("decoder-traffic-source=" + words([traffic[key] for key in (
            "isr", "reader", "status_reader", "initializer", "mode_base",
            "layout_address", "layout_source", "linker_table_offset")]))
        if service_source is not None:
            properties.append("traffic-service-source=" + service_source)
        elif traffic_frame is not None:
            properties.append("decoder-traffic-frame=" + traffic_frame)
    return ",".join(properties), service_limit


def qemu_ma5_readback_property(
        image: bytes, config: object, byte_ns: int | None,
        *, upper_nor_present: bool = False, clki_hz: int | None = None,
        target_rate_hz: int | None = None,
) -> tuple[str | None, str | None]:
    """Recheck the image for an explicit or temporary evidence-gated MA5 profile."""
    if clki_hz is not None and target_rate_hz is not None:
        raise ValueError("explicit CLKI and inferred target rate are mutually exclusive")
    if clki_hz is not None and (type(clki_hz) is not int or
                                not 1 <= clki_hz <= 1_000_000_000 or
                                byte_ns is None):
        raise ValueError("invalid experimental MA5 CLKI or missing byte period")
    if target_rate_hz is not None and (
            type(target_rate_hz) is not int or not 8000 <= target_rate_hz <= 96000 or
            byte_ns is None):
        raise ValueError("invalid experimental MA5 target rate or missing byte period")
    if byte_ns is None:
        return None, None
    if type(upper_nor_present) is not bool:
        raise ValueError("invalid upper NOR presence")
    if type(byte_ns) is not int or not 1 <= byte_ns <= 1_000_000_000:
        raise ValueError("invalid experimental MA5 byte service period")
    if (getattr(config, "load_address", None) != 0
            or type(getattr(config, "flash_size", None)) is not int):
        return None, "primary-nor-unmapped"
    candidate = find_ma5_readback_candidate(image)
    if candidate["static_status"] != "candidate":
        return None, str(candidate["reject_reason"])
    audio = getattr(config, "audio_transport", None)
    if (audio is not None and audio.get("static_status") == "accepted"
            and (audio.get("family") != "ma5" or audio.get("grammar") != "indexed-rw-v1"
                 or audio.get("base") != candidate["base"]
                 or audio.get("data_offset") != candidate["data_offset"]
                 or audio.get("sites") != candidate["sites"])):
        return None, "conflicting-audio-profile"
    if any(not 0 <= offset <= config.flash_size - length
           for offset, length in candidate["nor_dependencies"]):
        return None, "primary-nor-out-of-bounds"
    ram_base, ram_size = getattr(config, "ram_base", None), getattr(config, "ram_size", None)
    if (type(ram_base) is not int or type(ram_size) is not int or ram_size < 8
            or any(not ram_base <= address <= ram_base + ram_size - length
                   for address, length in candidate["ram_dependencies"])):
        return None, "consumer-state-unmapped"
    base, stride = candidate["base"], candidate["data_offset"]
    timed = candidate.get("structural_evidence", {}).get("transport_class") == "local-counter-direction-timing-v1"
    shared_lcd = timed and stride == 4 and any(
        lcd <= base and base + stride < lcd + 0x1000
        for lcd in (0x02000000, 0x02800000, 0x02C00000, 0x02200000))
    if (not 0x02001000 <= base <= 0x02FFFF00
            or not (stride in (2, 128) or (timed and stride == 4))
            or base < config.flash_size
            or (upper_nor_present and base < UPPER_FLASH_ADDRESS + UPPER_FLASH_SIZE
                and base + stride + 1 > UPPER_FLASH_ADDRESS)
            or (base < ram_base + ram_size and base + stride + 1 > ram_base)
            or (not shared_lcd and any(
                base < lcd + 0x1000 and base + stride + 1 > lcd
                for lcd in (0x02000000, 0x02800000, 0x02C00000, 0x02200000)))):
        return None, "aperture-unmapped-or-conflicting"
    sites = candidate["sites"]
    entries = [f"{kind}{port:x}/{pc:x}"
               for key, kind, port in (("write_0", "w", 0), ("read_0", "r", 0),
                                       (f"write_{stride}", "w", stride),
                                       (f"read_{stride}", "r", stride))
               for pc in sites[key]]
    clock = "" if clki_hz is None else f",experimental-ma5-clki-hz={clki_hz}"
    target_rate = ("" if target_rate_hz is None else
                   f",experimental-ma5-target-rate-hz={target_rate_hz}")
    return (f"audio-aperture={base:x}:{stride:x}:ma5,"
            f"audio-sites={';'.join(entries)},experimental-ma5-byte-ns={byte_ns}"
            f"{clock}{target_rate}"), None


def qemu_ma5_temporary_auto_property(
        image: bytes, config: object, *, audio_pcm: bool,
        upper_nor_present: bool = False,
) -> tuple[str | None, str | None]:
    """Select witnessed MA5 readback candidates with explicitly provisional timing."""
    if type(audio_pcm) is not bool:
        raise ValueError("invalid MA5 PCM request")
    if not audio_pcm:
        return None, None
    candidate = find_ma5_readback_candidate(image)
    if (candidate.get("static_status") != "candidate" or
            candidate.get("protocol_status") != "temporary-evidence-gated" or
            candidate.get("structural_evidence", {}).get("transport_class") !=
            "ram-counter-synthesized-data-v1" and
            candidate.get("structural_evidence", {}).get("transport_class") !=
            "local-counter-literal-data-v1" and
            candidate.get("structural_evidence", {}).get("transport_class") !=
            "local-counter-direction-timing-v1"):
        return None, None
    return qemu_ma5_readback_property(
        image, config, 1000, upper_nor_present=upper_nor_present,
        target_rate_hz=48000)


def qemu_ma5_gpio_irq_property(image: bytes, config: object) -> tuple[str | None, str | None]:
    """Serialize a fresh static route; native live gates still own admission."""
    flash = getattr(config, "flash_size", None)
    if (type(getattr(config, "load_address", None)) is not int
            or config.load_address != 0 or type(flash) is not int or flash <= 0):
        return None, "primary-nor-unmapped"
    audio = find_ma5_readback_candidate(image)
    route = find_ma5_gpio_irq_candidate(image, audio)
    if route.get("status") != "candidate":
        return None, str(route.get("reject_reason") or "ma5-irq-route-unavailable")
    if (route.get("family") != "ma5" or route.get("grammar") != "ma5-gpio-parent-irq-v1"
            or route.get("static_status") != "candidate"
            or route.get("source_profile") != "three-bank-gpio-parent-descriptor-v1"
            or route.get("runtime_admitted") is not False):
        return None, "ma5-irq-class-unavailable"
    nor = route.get("nor_dependencies")
    ram = route.get("ram_dependencies")
    if (not isinstance(nor, list) or not nor
            or any(not isinstance(span, (list, tuple)) or len(span) != 2
                   or any(type(value) is not int for value in span)
                   or span[1] <= 0 or not 0 <= span[0] <= min(flash, len(image)) - span[1]
                   for span in nor)):
        return None, "primary-nor-out-of-bounds"
    start, size = getattr(config, "ram_base", None), getattr(config, "ram_size", None)
    if (type(start) is not int or type(size) is not int or size <= 0
            or not 0 <= start < start + size <= 0x100000000):
        return None, "consumer-state-unmapped"
    end = start + size
    if (not isinstance(ram, list) or not ram
            or any(not isinstance(span, (list, tuple)) or len(span) != 2
                   or any(type(value) is not int for value in span)
                   or span[1] <= 0 or not start <= span[0] <= end - span[1]
                   for span in ram)):
        return None, "consumer-state-unmapped"
    auxiliaries = route.get("aux_addresses")
    if not isinstance(auxiliaries, list):
        return None, "auxiliary-state-unmapped"
    for auxiliary in auxiliaries:
        if not isinstance(auxiliary, dict):
            return None, "auxiliary-state-unmapped"
        address, width = auxiliary.get("address"), auxiliary.get("width")
        width = 1 if width is None else width
        if (type(address) is not int or type(width) is not int or width not in (1, 2, 4)
                or not start <= address <= end - width or address % width):
            return None, "auxiliary-state-unmapped"
        accessor = auxiliary.get("direct_accessor")
        if accessor is not None:
            if not isinstance(accessor, dict):
                return None, "auxiliary-state-unmapped"
            address, width = accessor.get("address"), accessor.get("width")
            if (type(address) is not int or type(width) is not int or width not in (1, 2, 4)
                    or not start <= address <= end - width or address % width):
                return None, "auxiliary-state-unmapped"
    required = {
        "gpio": ("table_ram", "callbacks_ram", "pin", "dispatcher"),
        "parent": ("descriptor_ram", "status_ack", "enable", "mask", "enable_shadow",
                   "priority_shadow", "installed_gpio_dispatcher", "installed_soc_dispatcher",
                   "exception_callback_slot", "dispatcher"),
        "installation": ("direct_callback",),
        "chip": ("context_holder", "isr"),
    }
    if any(not isinstance(route.get(name), dict)
           or any(type(route[name].get(key)) is not int
                  or not 0 <= route[name][key] <= 0xFFFFFFFF for key in keys)
           for name, keys in required.items()):
        return None, "ma5-irq-route-unmapped"
    gpio, parent = route["gpio"], route["parent"]
    install, chip = route["installation"], route["chip"]
    first_gate = override_gate = 0
    deferred = install.get("deferred_callback")
    installed_flag = install.get("installed_flag")
    no_flag = install.get("profile") == "direct-install-no-flag-v1"
    if (install.get("polarity_argument") != 0
            or (no_flag and (installed_flag is not None or install.get("installed_value") is not None))
            or (not no_flag and (type(installed_flag) is not int or installed_flag <= 0
                                 or install.get("installed_value") != 1))):
        return None, "ma5-irq-installation-unverified"
    if no_flag:
        if (deferred is not None or install.get("direct_gate") is not None
                or install.get("deferred_gate") is not None or install.get("trigger_argument") != 0):
            return None, "ma5-irq-installation-unverified"
        installed_flag = deferred = 0
    elif install.get("profile") == "conditional-install-direct-or-task-v1":
        direct = install.get("direct_gate")
        if not isinstance(direct, dict) or not isinstance(direct.get("any"), list):
            return None, "ma5-irq-installation-unverified"
        gates = direct["any"]
        if (len(gates) != 2 or any(not isinstance(gate, dict) for gate in gates)
                or gates[0].get("op") != "eq" or gates[0].get("value") != 0
                or gates[1].get("op") != "ne" or gates[1].get("value") != 0):
            return None, "ma5-irq-installation-unverified"
        first_gate, override_gate = gates[0].get("address"), gates[1].get("address")
        if (type(first_gate) is not int or type(override_gate) is not int
                or first_gate != install["installed_flag"] + 0x1D
                or not first_gate or not override_gate or type(deferred) is not int or not deferred
                or install.get("deferred_gate") != {"all": [
                    {"address": first_gate, "op": "ne", "value": 0},
                    {"address": override_gate, "op": "eq", "value": 0}]}):
            return None, "ma5-irq-installation-unverified"
    elif install.get("profile") == "explicit-sense-direct-install-v1":
        if (deferred is not None or install.get("direct_gate") is not None
                or install.get("deferred_gate") is not None or install.get("trigger_argument") != 0):
            return None, "ma5-irq-installation-unverified"
        deferred = 0
    else:
        return None, "ma5-irq-installation-unverified"
    fields = [gpio["table_ram"], gpio["callbacks_ram"], gpio["pin"],
              parent["descriptor_ram"], parent["status_ack"], parent["enable"], parent["mask"],
              parent["enable_shadow"], parent["priority_shadow"], parent["installed_gpio_dispatcher"],
              parent["installed_soc_dispatcher"], parent["exception_callback_slot"],
              install["direct_callback"], deferred, installed_flag, first_gate,
              override_gate, chip["context_holder"]]
    if (any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in fields)
            or not 0 <= fields[2] < 48
            or fields[9] != gpio["dispatcher"] | 1
            or fields[10] != parent["dispatcher"] | 1 or fields[12] != chip["isr"] | 1):
        return None, "ma5-irq-route-unmapped"
    if any(not pointer & 1 or not 0 <= pointer - 1 <= min(flash, len(image)) - 2
           for pointer in (fields[9], fields[10], fields[12], *([fields[13]] if fields[13] else []))):
        return None, "primary-nor-out-of-bounds"
    spans = [(fields[0], 72, 4), (fields[1], 192, 4), (fields[3], 28, 4),
             (fields[7], 2, 2), (fields[8], 2, 2), (fields[11], 4, 4),
             (fields[17], 4, 4)]
    if fields[14]:
        spans.append((fields[14], 1, 1))
    spans.extend((gate, 1, 1) for gate in (first_gate, override_gate) if gate)
    if any(not start <= address <= end - length or address % alignment
           for address, length, alignment in spans):
        return None, "consumer-state-unmapped"
    direct = (getattr(config, "rex_irq_status_address", None) == 0x03000C80
              and getattr(config, "rex_irq_enable_address", None) == 0x03000C94)
    if not direct:
        controller = find_rex_static_controller_callback_candidate(
            image, ram_base=start, ram_size=size)
        if (controller is None
                or controller != getattr(config, "rex_static_controller_candidate", None)
                or c80_rex_irq_profile(config, False) is None
                or controller.get("signature") != "static-c80-controller-callback-v1"
                or controller.get("status") != 0x03000C80
                or controller.get("enable") != 0x03000C94
                or controller.get("handler_slot") != fields[11]
                or controller.get("handler_file_offset") != (fields[10] & ~1)):
            return None, "ma5-irq-controller-unverified"
    if (fields[4:6] != [0x03000C84, 0x03000C98]
            or not 0 < fields[6] <= 0x8000 or fields[6] & (fields[6] - 1)):
        return None, "ma5-irq-controller-unverified"
    return "experimental-ma5-irq-route=" + ":".join(f"{value:x}" for value in fields), None


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


def qemu_mapped_scan_gate_property(image: bytes, config: object,
                                   matrix: dict) -> tuple[str | None, str | None]:
    """Qualify provisional scan levels without assigning physical contact roles."""
    gates = matrix.get("scan_gates")
    if (config.load_address != 0 or not isinstance(gates, dict)
            or gates.get("grammar") != "mapped-halfword-contact-status-gates-v1"
            or gates.get("promotion") != "temporary-evidence-gated"
            or gates.get("runtime_admitted") is not False
            or gates.get("physical_role", False) is not None
            or gates.get("default_level", False) is not None):
        return None, "unclosed-mapped-scan-gates"
    contract = {"contact_mask": 16, "status_mask": 2,
                "contact_pointer_offset": 0x34, "configuration_pointer_offset": 8,
                "status_pointer_offset": 0x24, "contact_width": 2, "status_width": 2,
                "status_state_offset": 8, "status_set_bit_state": 0,
                "status_clear_bit_state": 1}
    if any(type(gates.get(k)) is not int or gates[k] != v for k, v in contract.items()):
        return None, "invalid-mapped-gate-contract"
    try:
        sink = int(matrix.get("queue_sink", ""), 16)
    except (TypeError, ValueError):
        return None, "mapped-gate-sink-mismatch"
    descriptor, state = gates.get("descriptor"), gates.get("scanner_state")
    if (descriptor != matrix.get("descriptor") or type(gates.get("queue_sink")) is not int
            or gates["queue_sink"] != sink
            or any(type(p) is not int or p & 3
                   or not config.ram_base <= p <= config.ram_base + config.ram_size - n
                   for p, n in ((descriptor, 0x38), (state, 0x20)))
            or descriptor < state + 0x20 and state < descriptor + 0x38):
        return None, "mapped-gate-state-mismatch"
    spans = gates.get("ram_spans")
    if (not isinstance(spans, list) or not spans
            or any(not isinstance(span, (list, tuple)) or len(span) != 2
                   or any(type(value) is not int for value in span)
                   or span[1] <= 0 or not config.ram_base <= span[0]
                   <= config.ram_base + config.ram_size - span[1] for span in spans)):
        return None, "mapped-gate-ram-spans-mismatch"
    ordered = sorted(tuple(span) for span in spans)
    if ((descriptor, 0x38) not in ordered or (state, 0x20) not in ordered
            or any(start + size > following[0]
                   for (start, size), following in zip(ordered, ordered[1:]))):
        return None, "mapped-gate-ram-spans-mismatch"
    sites = (gates.get("contact_site"), gates.get("status_site"),
             matrix.get("presence_site"), matrix.get("sense_site"))
    extent = min(len(image), config.flash_size)
    if (any(type(p) is not int or p & 1 or not 2 <= p <= extent - 2 for p in sites)
            or len(set(sites)) != 4 or not 0 <= sink <= extent - 2
            or image[sites[0]-2:sites[0]+2] != bytes.fromhex("706b0088")
            or image[sites[1]-2:sites[1]+2] != bytes.fromhex("406a0088")):
        return None, "mapped-gate-site-mismatch"
    copy = matrix.get("descriptor_copy")
    if not isinstance(copy, dict):
        return None, "unclosed-mapped-gate-copy"
    rom, source, target, size = (copy.get(k) for k in
                                ("descriptor_rom", "source", "target", "size"))
    if (any(type(p) is not int for p in (rom, source, target, size))
            or (rom | source | target) & 3 or size < 0x38
            or not 0 <= source <= extent - size
            or not config.ram_base <= target <= config.ram_base + config.ram_size - size
            or copy.get("descriptor_ram") != descriptor
            or not target <= descriptor <= target + size - 0x38
            or rom != source + descriptor - target
            or [struct.unpack_from("<I", image, rom + off)[0] for off in (8, 0x24, 0x34)]
               != [0x0300072c, 0x03000728, 0x0300072c]):
        return None, "unclosed-mapped-gate-copy"
    if getattr(config, "board_status_input", None) is not None:
        return None, "conflicting-status-profile"
    revision, _ = qemu_board_revision_property(config)
    ready = getattr(config, "ready_poll", None)
    ready_property, _ = qemu_ready_poll_property(ready)
    for address in (0x03000728, 0x0300072c):
        if (revision and config.board_revision_register < address + 2
                and config.board_revision_register + 4 > address):
            return None, "mapped-gate-mmio-owner-conflict"
        if (ready_property and not ready_property.startswith("lcd-status-poll=")
                and any(type(ready.get(k)) is int and address <= ready[k] < address + 2
                        for k in ("status_address", "pulse_address", "control_address"))):
            return None, "mapped-gate-mmio-owner-conflict"
    eeprom, _ = eeprom_gpio_profile(image, config)
    if eeprom is None:
        return None, "mapped-gate-eeprom-owner-missing"
    base, data, data_mask, clock, clock_mask, direction, _ = eeprom
    if not base <= 0x03000728 < 0x0300072e <= base + 0x20:
        return None, "mapped-gate-eeprom-aperture-mismatch"
    for address, mask in ((0x03000728, 2), (0x0300072c, 16)):
        if any(base + offset == address and pins & mask
               for offset, pins in ((data, data_mask), (clock, clock_mask), (direction, data_mask))):
            return None, "mapped-gate-eeprom-pin-conflict"
    # Temporary scan-enabling policy verified through ordinary numeric UI input.
    # These levels do not identify a physical switch or its released default.
    return (f"experimental-matrix-contact={sites[0]:x}:10,"
            f"experimental-matrix-status={sites[1]:x}:2"), None


def qemu_halfword_matrix_property(image: bytes, config: object,
                                  profile: dict, *, enabled: bool = True) -> tuple[str | None, str | None]:
    """Serialize closed classes; explicit opt-in retains raw mapped gate backing."""
    grammar = profile.get("grammar")
    automatic_mapped = (not enabled and grammar == "indirect-halfword-mapped-row-v1"
                        and isinstance(profile.get("scan_gates"), dict))
    if not enabled and not automatic_mapped and not (
            grammar == "indirect-halfword-loop-six-row-v1"
            and profile.get("promotion") == "temporary-evidence-gated"):
        return None, "experimental-only-halfword-profile"
    if grammar not in ("indirect-halfword-six-row-v1",
                       "indirect-halfword-mapped-row-v1",
                       "indirect-halfword-loop-six-row-v1"):
        return None, "unsupported-halfword-grammar"
    descriptor = profile.get("descriptor")
    sites = (profile.get("presence_site"), profile.get("sense_site"))
    if (type(descriptor) is not int or descriptor & 3
            or not config.ram_base <= descriptor <= config.ram_base + config.ram_size - 0x38
            or any(type(site) is not int or site & 1
                   or not 0 <= site < config.flash_size - 2 for site in sites)):
        return None, "outside-memory-map"
    if grammar == "indirect-halfword-loop-six-row-v1":
        if (profile.get("rows") != 6 or profile.get("columns") != 4
                or profile.get("no_key") != 31
                or profile.get("single_key_column_sense") != [30, 29, 27, 23]):
            return None, "invalid-loop-row-contract"
        if getattr(config, "board_status_input", None) is not None:
            return None, "conflicting-status-profile"
        contact = profile.get("contact_site")
        all_sites = (contact, *sites)
        if (any(type(site) is not int or site & 1 or site < 2
                or site + 2 > min(len(image), config.flash_size)
                for site in all_sites) or len(set(all_sites)) != 3
                or any(image[site-2:site+2] != bytes.fromhex("686b0088")
                       for site in all_sites)):
            return None, "sense-load-shape-mismatch"
        copied = profile.get("copied_descriptor")
        copy = profile.get("descriptor_copy")
        if (type(copied) is not int or copied & 3 or not isinstance(copy, dict)
                or copy.get("target") != copied
                or type(copy.get("size")) is not int or not 0x38 <= copy["size"] <= 0x100
                or not config.ram_base <= copied <= config.ram_base + config.ram_size - copy["size"]
                or type(copy.get("source")) is not int or copy["source"] & 3
                or not 0 <= copy["source"] <= min(len(image), config.flash_size) - copy["size"]
                or type(copy.get("copy_loop")) is not int or copy["copy_loop"] & 1
                or not 0 <= copy["copy_loop"] < min(len(image), config.flash_size)):
            return None, "unclosed-descriptor-copy"
        if [struct.unpack_from("<I", image, copy["source"] + off)[0]
                for off in (0, 8, 0x20, 0x34)] != [0x3000720, 0x300072c, 0x3000728, 0x300072c]:
            return None, "descriptor-port-mismatch"
        return f"matrix-halfword-loop={descriptor:x}:{contact:x}:{sites[0]:x}:{sites[1]:x}", None
    value = f"matrix-halfword={descriptor:x}:{sites[0]:x}:{sites[1]:x}"
    if grammar == "indirect-halfword-mapped-row-v1":
        mask = profile.get("row_select_mask")
        if (type(mask) is not int or not 0 < mask <= 0xFFFF
                or mask.bit_count() != 7 or profile.get("rows") != 7
                or profile.get("columns") != 4 or profile.get("no_key") != 15
                or profile.get("single_key_column_sense") != [14, 13, 11, 7]
                or profile.get("row_select_bits") != [bit for bit in range(16) if mask & (1 << bit)]):
            return None, "invalid-mapped-row-contract"
        if (sites[0] == sites[1] or any(site < 2 or site + 2 > len(image)
                or image[site - 2:site + 2] != bytes.fromhex("706b0088") for site in sites)):
            return None, "sense-load-shape-mismatch"
        value += f":{mask:x}"
        if automatic_mapped:
            gates, reason = qemu_mapped_scan_gate_property(image, config, profile)
            if gates is None:
                return None, reason
            value += "," + gates
    return value, None


def qemu_distributed_sideband_producer(image: bytes, config: object,
                                     profile: dict) -> tuple[dict | None, str | None]:
    """Optional electrical producer must agree with the same source queue."""
    raw = profile.get("sideband_producers")
    if raw is None:
        reasons = profile.get("sideband_detection_reject_reasons", ())
        if not isinstance(reasons, (list, tuple)):
            return None, "invalid-sideband-rejection-reasons"
        return None, (";".join(map(str, reasons)) if reasons else None)
    if (profile.get("grammar") != "distributed-six-byte-numeric-v1"
            or config.load_address != 0
            or profile.get("sideband_detection_status") != "accepted"
            or not isinstance(raw, list) or len(raw) != 1
            or not isinstance(raw[0], dict)):
        return None, "invalid-distributed-sideband"
    producer = raw[0]
    integers = ("semantic_key", "event", "event_register", "register",
                "register_width", "mask", "press_callsite", "release_event",
                "release_callsite", "event_sink")
    queue = profile.get("producer")
    sites = (profile.get("function"), profile.get("sense_site"),
             queue.get("enqueue") if isinstance(queue, dict) else None)
    if (any(type(site) is not int or site & 1 or not 0 <= site
            <= min(len(image), config.flash_size) - 4 for site in sites)
            or any(type(producer.get(key)) is not int for key in integers)):
        return None, "invalid-sideband-source-bounds"
    expected = _samsung_sideband_51_family_metadata(
        image[:min(len(image), config.flash_size)], *sites, 0)
    if expected.get("sideband_producers") != raw:
        return None, "sideband-source-contract-mismatch"
    release_sites = producer.get("release_callsites", [producer["release_callsite"]])
    events = profile.get("event_codes")
    if (not isinstance(release_sites, list)
            or not isinstance(events, (list, tuple))
            or any(type(site) is not int or site & 1 or not 0 <= site
                   <= min(len(image), config.flash_size) - 4
                   for site in [producer["press_callsite"], *release_sites])
            or producer["register"] != profile.get("register")
            or producer["event"] in events):
        return None, "sideband-source-ownership-conflict"
    return dict(producer), None


def qemu_distributed_matrix_property(image: bytes, config: object,
                                     profile: dict) -> tuple[str | None, str | None]:
    """Temporary numeric-only byte class; GPIO ownership stays with native devices."""
    if (profile.get("grammar") != "distributed-six-byte-numeric-v1"
            or config.load_address != 0 or profile.get("rows") != 6
            or profile.get("columns") != 4 or profile.get("register_width") != 1
            or profile.get("no_key") != 15
            or profile.get("single_key_column_sense") != [14, 13, 11, 7]):
        return None, "unsupported-distributed-contract"
    ports = profile.get("gpio_ports")
    if (not isinstance(ports, list) or len(ports) != 3
            or any(not isinstance(port, dict)
                   or type(port.get("address")) is not int
                   or type(port.get("mask")) is not int
                   or not 0 < port["mask"] <= 255 for port in ports)):
        return None, "invalid-gpio-ports"
    base = ports[0]["address"] - 12
    address = profile.get("register")
    masks = [port["mask"] for port in ports]
    if (not 0x03000000 <= base <= 0x03001000 - 53 or base & 31
            or type(address) is not int or address != base + 52
            or [p["address"] for p in ports] != [base + n for n in (12, 8, 4)]):
        return None, "invalid-gpio-ports"
    rows = []
    for index, mask in enumerate(masks):
        for bit in range(8):
            if mask & (1 << bit):
                values = masks.copy()
                values[index] &= ~(1 << bit)
                rows.append(values)
    if (len(rows) != 6 or profile.get("row_values") != rows
            or profile.get("global_values") != [0, 0, 0]):
        return None, "invalid-gpio-row-order"
    producer = profile.get("producer", {})
    if (not isinstance(producer, dict)
            or producer.get("family") != "distributed-filtered-byte-ring32-v1"
            or producer.get("slots") != 32 or producer.get("wrap_mask") != 31):
        return None, "unclosed-ring-profile"
    spans = [(profile.get("scanner_state"), 0xA),
             (profile.get("batch_state"), 0xE),
             (producer.get("state"), 0x34), (producer.get("ring"), 34)]
    spans += [(port.get("shadow"), 1) for port in ports]
    if (any(type(start) is not int or not config.ram_base <= start
            <= config.ram_base + config.ram_size - size for start, size in spans)
            or len({port["shadow"] for port in ports}) != 3):
        return None, "state-outside-ram"
    sites = (profile.get("presence_site"), profile.get("sense_site"))
    if (any(type(site) is not int or site & 1 or not 2 <= site
            <= min(len(image), config.flash_size) - 2 for site in sites)
            or sites[0] == sites[1]):
        return None, "sense-outside-primary-nor"
    for site, instruction in zip(sites, (b"\x01\x79", b"\x00\x79")):
        if (image[site:site + 2] != instruction
                or thumb_literal_value(image, site - 2, 0) != address - 4):
            return None, "sense-load-shape-mismatch"
    status = getattr(config, "board_status_input", None)
    if status is not None and status.address in [address] + [p["address"] for p in ports]:
        return None, "conflicting-status-profile"
    fields = [address, *sites]
    for port in ports:
        fields.extend((port["address"], port["mask"]))
    sideband, reject = qemu_distributed_sideband_producer(image, config, profile)
    if sideband is not None:
        fields.append(sideband["mask"])
    return "matrix-gpio=" + ":".join(f"{value:x}" for value in fields), reject


def qemu_halfword_status_property(image: bytes, load_address: int,
                                  matrix: dict | None, level: int | None,
                                  existing_status: object = None
                                  ) -> tuple[str | None, str | None]:
    """Use the closed loop's provisional scan level; no physical fold claim."""
    if level is None:
        if not (isinstance(matrix, dict)
                and matrix.get("grammar") == "indirect-halfword-loop-six-row-v1"
                and matrix.get("promotion") == "temporary-evidence-gated"):
            return None, None
        # Provisional full-scan level, verified through public-key UI response.
        # Its physical contact role remains unassigned; explicit 0 is preserved.
        level = 16
    if type(level) is not int or level not in (0, 4, 16):
        return None, "invalid-level"
    if existing_status is not None:
        return None, "conflicting-status-profile"
    if not isinstance(matrix, dict) or matrix.get("grammar") not in (
            "indirect-halfword-six-row-v1", "indirect-halfword-loop-six-row-v1"):
        return None, "halfword-matrix-not-admitted"
    loop = matrix["grammar"] == "indirect-halfword-loop-six-row-v1"
    mask = 16 if loop else 4
    if level not in (0, mask):
        return None, "invalid-level"
    profile, status, _ = resolve_indirect_board_status(image, load_address)
    if profile is None:
        return None, status
    try:
        sink = int(matrix.get("queue_sink", ""), 16)
    except (ValueError, TypeError):
        return None, "matrix-status-mismatch"
    descriptor = matrix.get("descriptor")
    if (not isinstance(profile, dict) or type(descriptor) is not int
            or descriptor & 3 or not 0x1000000 <= descriptor <= 0x2000000-0x38
            or profile.get("descriptor") != descriptor
            or type(profile.get("descriptor")) is not int
            or profile.get("queue_sink") != sink
            or type(profile.get("queue_sink")) is not int):
        return None, "matrix-status-mismatch"
    if not loop and profile.get("grammar") not in (None, "indirect-halfword-status-events-v1"):
        return None, "matrix-status-mismatch"
    if loop and (profile.get("grammar") != "indirect-halfword-loop-status-events-v1"
                 or type(profile.get("mask")) is not int or profile["mask"] != mask
                 or type(profile.get("width")) is not int or profile["width"] != 2
                 or type(profile.get("pointer_offset")) is not int or profile["pointer_offset"] != 4
                 or profile.get("promotion") != "temporary-evidence-gated"
                 or profile.get("runtime_admitted") is not False
                 or profile.get("default_level") is not None
                 or profile.get("physical_role") is not None
                 or not 0 <= sink <= len(image)-4):
        return None, "unsupported-loop-status-contract"
    # Temporary GPIO class; native verifies live descriptor+4 before each read.
    return (f"board-status-input=3000720:{mask:x}:{level:x},"
            f"board-status-descriptor={profile['descriptor']:x}"), None


def _boot_storage_profile(config: object, image: bytes, field: str, finder):
    profile = getattr(config, field, None)
    if profile is None:
        return None, None
    if (not isinstance(profile, dict) or config.load_address != 0
            or config.image_offset != 0 or config.entry != 0):
        return None, field + "-unverified-layout"
    found, reason = finder(image[:config.flash_size])
    if found is None:
        return None, field + "-source-" + reason
    try:
        # JSON roundtrips may replace tuple intervals with lists.
        if json.loads(json.dumps(profile)) != json.loads(json.dumps(found)):
            return None, field + "-source-profile-mismatch"
    except (TypeError, ValueError, OverflowError):
        return None, field + "-malformed-profile"
    return found, None


def qemu_boot_keysense_property(config: object, image: bytes, *,
                                input_claimed: bool = False):
    profile, reason = _boot_storage_profile(
        config, image, "boot_keysense_release", find_boot_keysense_release)
    if profile is None:
        return None, reason
    if (input_claimed or getattr(config, "key_register", None) is not None
            or getattr(config, "board_status_input", None) is not None):
        return None, "boot-key-input-owner-unclosed"
    return "boot-keysense-release=" + ":".join(
        f"{pc:x}" for pc in profile["read_pcs"]), None


def qemu_spi_nv_properties(config: object, image: bytes, *,
                           input_claimed: bool = False,
                           eeprom_claimed: bool = False):
    profile, reason = _boot_storage_profile(
        config, image, "spi_nv_profile", find_spi_nv_profile)
    if profile is None:
        return None, reason
    if (input_claimed or eeprom_claimed
            or getattr(config, "key_register", None) is not None):
        return None, "spi-nv-gpio-owner-unclosed"
    status = getattr(config, "board_status_input", None)
    if status is not None and 0x03000660 <= status.address < 0x03000680:
        return None, "spi-nv-status-owner-conflict"
    spans = ((profile["descriptor_address"], 6),
             (profile["shadow_address"] - 2, 8),
             (profile["cache_address"], profile["cache_size"]))
    if any(not config.ram_base <= start <= config.ram_base + config.ram_size - size
           for start, size in spans):
        return None, "spi-nv-source-state-outside-ram"
    reserved = getattr(config, "ram_bootstrap_profile", None)
    if isinstance(reserved, dict):
        begin = reserved.get("reserved_base")
        size = reserved.get("reserved_size")
        if (type(begin) is int and type(size) is int
                and any(start < begin + size and start + length > begin
                        for start, length in spans)):
            return None, "spi-nv-source-state-in-reserved-span"
    # shortcut: virtual 5ms policy; replace only after physical timing is measured.
    return ("experimental-spi-nv-write-ns=5000000,"
            f"spi-nv-source-geometry={profile['descriptor_address']:x}"), None


def qemu_basic_row0_property(config: object, image: bytes):
    profile, reason = _boot_storage_profile(
        config, image, "rex_basic_irq_profile",
        lambda primary: find_rex_legacy_row0_profile(
            primary, config.ram_base, config.ram_size, config.overlays),
    )
    if profile is None:
        return None, reason
    actual = (config.rex_irq_wrapper_address, config.rex_irq_handler_address,
              config.rex_irq_handler_slot, config.rex_irq_callback_slot,
              config.rex_irq_status_address, config.rex_irq_enable_address,
              config.rex_irq_mask)
    if (config.rex_idle_address is not None or config.rex_tick_ms != 5
            or actual != tuple(profile["route"])
            or config.rex_tick_address != profile["callback_file_offset"]
            or config.rex_irq_arm_address != profile["arm_address"]):
        return None, "row0-configuration-source-mismatch"
    # Zero disables the optional native observer; config idle remains None.
    return (f"rex-irq={actual[4]:x}:{actual[5]:x}:"
            f"{profile['arm_address']:x}:{actual[6]:x}:4c4b40:0"), None


def prepare_spi_nv_state(path: Path, inputs: tuple[Path, ...]) -> Path:
    """Preserve an existing virtual image; never seed over an input or bad state."""
    if path.is_symlink():
        raise ValueError("serial NVM state must not be a symlink")
    for original in inputs:
        if path.resolve() == original.resolve():
            raise ValueError("serial NVM state collides with an input")
        if path.exists() and original.exists() and os.path.samefile(path, original):
            raise ValueError("serial NVM state aliases an input")
    with exclusive_path_lock(path):
        if path.exists():
            if not path.is_file() or path.stat().st_size != 0x4000:
                raise ValueError("persistent serial NVM size mismatch")
        else:
            atomic_write_bytes(path, b"\xff" * 0x4000)
    return path


def prepare_protected_nor_state(path: Path, seed: bytes, inputs: tuple[Path, ...]) -> Path:
    """Keep existing native state and seed only from provided NOR bytes."""
    if not isinstance(seed, bytes) or not seed or len(seed) > 32 * 1024 * 1024 or len(seed) % 256:
        raise ValueError("invalid protected NOR seed extent")
    if path.is_symlink():
        raise ValueError("protected NOR state must not be a symlink")
    for original in inputs:
        if path.resolve() == original.resolve():
            raise ValueError("protected NOR state collides with an input")
        if path.exists() and original.exists() and os.path.samefile(path, original):
            raise ValueError("protected NOR state aliases an input")
    with exclusive_path_lock(path):
        if path.exists():
            if not path.is_file() or path.stat().st_size != len(seed):
                raise ValueError("persistent protected NOR size mismatch")
        else:
            atomic_write_bytes(path, seed)
    return path


def qemu_loaded_source_matches(profile: dict, original: bytes, loaded: bytes) -> bool:
    """State may change its writable array, while source guards stay identical."""
    if not isinstance(profile, dict) or not profile.get("code_intervals"):
        return False
    for role in ("code_intervals", "literal_intervals", "data_intervals", "boot_guard_intervals"):
        intervals = profile.get(role, [])
        if not isinstance(intervals, (tuple, list)):
            return False
        for span in intervals:
            if (not isinstance(span, (tuple, list)) or len(span) != 2
                    or any(type(v) is not int for v in span)):
                return False
            start, end = span
            if not 0 <= start < end <= min(len(original), len(loaded)):
                return False
            if original[start:end] != loaded[start:end]:
                return False
    return True


def _source_class_limit(image: bytes, config: object) -> int | None:
    flash = getattr(config, "flash_size", None)
    load, entry = getattr(config, "load_address", None), getattr(config, "entry", None)
    if (not isinstance(image, bytes) or getattr(config, "image_kind", None) != "firmware"
            or type(load) is not int or type(entry) is not int or load != 0 or entry != 0
            or type(flash) is not int or not 0 < flash <= 0xffffffff):
        return None
    return min(len(image), flash)


def qemu_amd_bank_profile(original: bytes, loaded: bytes, config: object, *,
                          nor_claimed: bool = False) -> tuple[dict | None, str | None]:
    """Bind a bounded bank to the actual loaded immutable producer graph."""
    from msm5xxx_emulator.detection.amd_bank import find_amd_bank_profile
    limit = _source_class_limit(original, config)
    if limit is None or limit != config.flash_size or len(loaded) != limit:
        return None, "amd-bank-source-layout-unverified"
    args = (config.load_address, config.flash_size, config.ram_base, config.ram_size)
    from msm5xxx_emulator.detection.efs_nor import find_inline_efs_nor_profile
    profile, reason = find_amd_bank_profile(original[:limit], *args)
    inline, inline_reason = find_inline_efs_nor_profile(original[:limit], *args)
    if profile is not None and inline is not None:
        return None, "amd-bank-inline-efs-owner-conflict"
    finder = find_amd_bank_profile
    if inline is not None or inline_reason is not None:
        if profile is not None:
            return None, "amd-bank-inline-efs-candidate-conflict"
        profile, reason, finder = inline, inline_reason, find_inline_efs_nor_profile
    if profile is None:
        return None, reason
    if nor_claimed:
        return None, "amd-bank-owner-conflict"
    try:
        if (profile['signature'] not in ('thumb-copy-selected-amd-x16-bank-v1',
                                             'inline-copy-selected-efs-amd-x16-v1')
                or profile['admission'] != 'temporary-evidence-gated'):
            return None, "amd-bank-contract-unclosed"
        base, size, sector = (profile[k] for k in ('base', 'size', 'sector_size'))
        if (any(type(profile[k]) is not int for k in
                ('base', 'size', 'sector_size', 'backing_size', 'id0', 'id1'))
                or not 0 < base < base + size <= limit
                or sector < 0x1000 or sector & (sector - 1)
                or base % sector or size % sector
                or profile['backing_size'] != 1 << (size - 1).bit_length()
                or not 0 <= profile['id0'] <= 0xffff
                or not 0 <= profile['id1'] <= 0xffff):
            return None, "amd-bank-geometry-unclosed"
        guards = profile['guard_intervals']
        if not qemu_loaded_source_matches({'code_intervals': guards}, original, loaded):
            return None, "amd-bank-loaded-source-mismatch"
        if any(max(start, base) < min(end, base + size) for start, end in guards):
            return None, "amd-bank-source-overlaps-array"
        current, _ = finder(loaded, *args)
        if current != profile:
            return None, "amd-bank-loaded-contract-mismatch"
    except (KeyError, TypeError, ValueError):
        return None, "amd-bank-contract-unclosed"
    return profile, None


def qemu_row734_property(image: bytes, config: object, profile: dict | None, *,
                         input_claimed: bool = False,
                         eeprom_window: tuple[int, int] | None = None) -> tuple[str | None, str | None]:
    if profile is None:
        return None, None
    limit = _source_class_limit(image, config)
    if limit is None:
        return None, "row734-source-layout-unverified"
    if input_claimed or getattr(config, "key_register", None) is not None or getattr(config, "board_status_input", None) is not None:
        return None, "row734-input-owner-conflict"
    expected = dict(grammar="descriptor-row734-low5-6x5-v1", admission="temporary-evidence-gated",
                    family="descriptor-row734-byte-ring32-v1", rows=6, columns=5, no_key=31,
                    row_mask=0x9f, row_output=0x03000728, row_select=0x03000734,
                    sense_address=0x0300072c)
    if not isinstance(profile, dict) or any(profile.get(k) != v for k, v in expected.items()):
        return None, "row734-contract-unclosed"
    aux = profile.get("auxiliary_status", {})
    if not isinstance(aux, dict) or any(aux.get(k) != v for k, v in dict(address=0x03000720, width=2, mask=4, level=4).items()):
        return None, "row734-auxiliary-contract-unclosed"
    try:
        senses = tuple(profile["senses"])
        sites = [*profile["presence_sites"], *profile["row_sense_sites"]]
        if (len(profile["presence_sites"]) != 2 or len(profile["row_sense_sites"]) != 2
                or len(senses) != 5 or set(senses) != {30, 29, 27, 23, 15}
                or any(type(v) is not int for v in senses)):
            return None, "row734-sense-roles-unclosed"
        descriptor, boot, tables = profile["descriptor_pointer"], profile["boot_sense_site"], profile["row_tables"]
        rb, rs = config.ram_base, config.ram_size
        if type(rb) is not int or type(rs) is not int or rb < 0 or rs <= 0 or rb + rs > 0x100000000:
            return None, "row734-ram-layout-unverified"
        if type(descriptor) is not int or descriptor & 3 or not rb <= descriptor <= rb + rs - 0x38:
            return None, "row734-descriptor-outside-ram"
        if not isinstance(tables, (list, tuple)) or len(tables) != 2 or any(type(v) is not int or v & 1 or not rb <= v <= rb + rs - 12 for v in tables):
            return None, "row734-row-tables-outside-ram"
        if any(type(v) is not int or v & 1 or not 2 <= v <= limit - 4 for v in [*sites, boot]) or len(set([*sites, boot])) != 5:
            return None, "row734-source-sites-unclosed"
        for site in sites:
            pointer, read = struct.unpack_from("<HH", image, site - 2)
            reg = pointer & 7
            if pointer & 0xf800 != 0x6800 or (pointer >> 6 & 31) != 13 or read != 0x8800 | reg << 3 | reg:
                return None, "row734-source-load-mismatch"
        literal, read = struct.unpack_from("<HH", image, boot - 2)
        pool = ((boot + 2) & ~3) + (literal & 255) * 4
        if (literal & 0xff00 != 0x4800 or read != 0x8980 or pool > limit - 4
                or struct.unpack_from("<I", image, pool)[0] != 0x03000720
                or not profile.get("boot_guard_intervals")):
            return None, "row734-boot-source-unclosed"
        if eeprom_window is not None:
            base, size = eeprom_window
            if any(type(v) is not int for v in (base, size)) or base < 0 or size <= 0 or base + size > 0x100000000:
                return None, "row734-eeprom-owner-unverified"
            if any(base < port + 2 and port < base + size for port in (0x03000720, 0x03000728, 0x0300072c, 0x03000734)):
                return None, "row734-eeprom-owner-conflict"
    except (KeyError, TypeError, ValueError, AttributeError, struct.error):
        return None, "row734-malformed-profile"
    p, r = profile["presence_sites"], profile["row_sense_sites"]
    return "matrix-row734=" + ":".join(f"{v:x}" for v in (descriptor, p[0], r[0], p[1], r[1], boot, *tables)), None


def qemu_protected_nor_properties(image: bytes, config: object, profile: dict | None, *,
                                  nor_claimed: bool = False) -> tuple[str | None, str | None]:
    if profile is None:
        return None, None
    limit = _source_class_limit(image, config)
    if limit is None:
        return None, "protected-nor-source-layout-unverified"
    if nor_claimed:
        return None, "protected-nor-existing-owner-retained"
    if (not isinstance(profile, dict) or profile.get("signature") != "arm-thumb-copy-selected-protected-nor-x16-v1"
            or profile.get("admission") != "temporary-evidence-gated" or profile.get("bus_width") != 2
            or profile.get("initial_base") != 0):
        return None, "protected-nor-contract-unclosed"
    try:
        base, size, sectors = profile["address"], profile["size"], profile["sector_sizes"]
        if (any(type(v) is not int for v in (base, size)) or base & 255 or size <= 0
                or not 0 <= base < base + size <= limit or not isinstance(sectors, (tuple, list))
                or not 0 < len(sectors) <= 42 or any(type(v) is not int or v <= 0 or v & 255 for v in sectors)
                or len(set(sectors)) != 1 or sum(sectors) != size):
            return None, "protected-nor-geometry-unclosed"
        rb, rs = config.ram_base, config.ram_size
        obj, global_, selected, state = (profile[k] for k in ("selected_object", "object_global", "selection_cell", "state_global"))
        probe = profile["discarded_probe"];pram, prom = probe["address"], probe["source"]
        fields = [global_, obj, selected, state, pram, prom]
        if (any(type(v) is not int or not 0 <= v <= 0xffffffff for v in fields)
                or any(v & 3 for v in (global_, obj, selected, state)) or (pram | prom) & 1
                or probe.get("size") != 20 or type(rb) is not int or type(rs) is not int
                or rb < 0 or rs <= 0 or rb + rs > 0x100000000):
            return None, "protected-nor-source-pointers-unclosed"
        for at, length in ((global_, 4), (selected, 4), (state, 12), (pram, 20)):
            if not rb <= at <= rb + rs - length:
                return None, "protected-nor-source-state-outside-ram"
        for at, length in ((obj, 0xd0), (prom, 20)):
            if not 0 <= at <= limit - length or at < base + size and base < at + length:
                return None, "protected-nor-source-ro-owner-conflict"
        guards = profile.get("runtime_guards", {})
        if (not isinstance(guards, dict) or any(guards.get(k) != v for k, v in {
                "active_object": global_, "expected_object": obj,
                "selection_cell": selected, "expected_selection": obj,
                "base_address": state, "expected_base": 0,
                "mode_address": state + 4, "operation_address": state + 8}.items())):
            return None, "protected-nor-runtime-contract-unclosed"
    except (KeyError, TypeError, ValueError, AttributeError):
        return None, "protected-nor-malformed-profile"
    # Deterministic virtual erase policy; the physical part and latency are unverified.
    return (f"experimental-protected-nor={base:x}:{size:x}:{sectors[0]:x}:f4240,"
            "protected-nor-source=" + ":".join(f"{v:x}" for v in fields)), None


_UART_WORD_FLAG_FF_SIGNATURE = "thumb-byte-uart-word-flag-fixed-ff-mixed-v1"
_UART_PROBE_FF_DD_SIGNATURE = "thumb-byte-uart-finite-ff-dd-console-v1"
_UART_PROBE_FF_CC_SIGNATURE = "thumb-byte-uart-finite-ff-cc-99-console-v1"
_UART_SOURCE_GUARDED_SIGNATURES = (
    _UART_WORD_FLAG_FF_SIGNATURE, _UART_PROBE_FF_DD_SIGNATURE,
    _UART_PROBE_FF_CC_SIGNATURE,
)


def qemu_uart_console_property(
        profile: object, image_size: int) -> tuple[str | None, str | None]:
    """Admit only a source-bound isolated console class and its fixed aliases."""
    if profile is None:
        return None, None
    if not isinstance(profile, dict):
        return None, "malformed-profile"
    signature = profile.get("signature")
    expected = {
        "thumb-uart-sync-console-v1": (2, 0x99),
        "thumb-uart-byte-sync-console-v1": (1, 0xFF),
        "thumb-uart-byte-tfwr16-sync-console-v1": (1, 0xFF),
        "thumb-uart-sync-console-dd-v1": (2, 0xDD),
        _UART_WORD_FLAG_FF_SIGNATURE: (2, 0xFF),
        _UART_PROBE_FF_DD_SIGNATURE: (2, 0xFF),
        _UART_PROBE_FF_CC_SIGNATURE: (2, 0xFF),
    }.get(signature) if isinstance(signature, str) else None
    if (expected is None
            or profile.get("admission") != "temporary-evidence-gated"
            or profile.get("policy") != "provisional-synchronous-null-console"):
        return None, "unsupported-contract"
    width = profile.get("register_width", 2 if expected == (2, 0x99) else None)
    csr = profile.get("csr_value", 0x99 if expected == (2, 0x99) else None)
    if (type(width) is not int or type(csr) is not int
            or (width, csr) != expected):
        return None, "unsupported-register-wire"
    base = profile.get("base")
    if (type(base) is not int or base % 4
            or not 0x03000000 <= base <= 0x04000000-0x24):
        return None, "invalid-register-window"
    for field, offset in (("status_address", 8), ("fifo_address", 12),
                          ("control_address", 16), ("isr_address", 20)):
        value = profile.get(field)
        if type(value) is not int or value != base+offset:
            return None, "inconsistent-register-aliases"
    pulse = profile.get("pulse_address")
    if (type(pulse) is not int or not 0x03000000 <= pulse < 0x04000000
            or base <= pulse < base+0x24):
        return None, "invalid-pulse-owner"
    if type(image_size) is not int or image_size <= 0:
        return None, "invalid-image-size"
    sites = [profile.get(name) for name in
             ("primary_entry", "init_entry", "tx_entry")]
    if (any(type(site) is not int or site % 2 or not 0 <= site < image_size
            for site in sites) or len(set(sites)) != len(sites)):
        return None, "invalid-bound-consumers"
    if signature in (_UART_PROBE_FF_DD_SIGNATURE, _UART_PROBE_FF_CC_SIGNATURE):
        sequence = ([0xFF, 0xDD] if signature == _UART_PROBE_FF_DD_SIGNATURE
                    else [0xFF, 0xCC, 0x99])
        if base != 0x03000F0C or profile.get("csr_sequence") != sequence:
            return None, "unsupported-probe-register-wire"
        wire = f"uart-console-probe={base:x}:" + ":".join(f"{v:x}" for v in sequence)
        reentry = profile.get("reset_reentry")
        if reentry is not None:
            if signature != _UART_PROBE_FF_DD_SIGNATURE or not isinstance(reentry, dict):
                return None, "unsupported-reset-reentry-contract"
            primary = profile["primary_entry"]
            init = profile["init_entry"]
            root = profile.get("console_root")
            if type(root) is not int or root % 2 or not 0 <= root < image_size:
                return None, "invalid-reset-reentry-root"
            expected_reentry = dict(
                write_pcs=[primary + 4, primary + 6],
                status_read_pc=primary + 0xA, root_lr=(root + 6) | 1,
                config_lr=(init + 0x1A) | 1, address=base + 0x10,
                width=1, value=0x20, status_address=base + 8, status_mask=8,
            )
            if reentry != expected_reentry or any(
                    type(value) is not int for key, value in reentry.items()
                    if key != "write_pcs") or any(
                    type(value) is not int for value in reentry["write_pcs"]):
                return None, "inconsistent-reset-reentry-sites"
            sites = [*reentry["write_pcs"], reentry["status_read_pc"],
                     reentry["root_lr"], reentry["config_lr"]]
            intervals = profile.get("code_intervals", [])
            if (not isinstance(intervals, (list, tuple))
                    or any(not 0 <= site <= 0xFFFFFFFF for site in sites)):
                return None, "reset-reentry-code-owner-unclosed"
            references = [(site, 2) for site in sites[:3]] + [
                ((site & ~1) - 4, 4) for site in sites[3:]]
            if any(not 0 <= address <= image_size - size or not any(
                    isinstance(span, (list, tuple)) and len(span) == 2
                    and all(type(value) is int for value in span)
                    and span[0] <= address and address + size <= span[1]
                    for span in intervals) for address, size in references):
                return None, "reset-reentry-code-owner-unclosed"
            wire += ",uart-console-rearm=" + ":".join(f"{site:x}" for site in sites)
        return wire, None
    wire = f"uart-console={base:x}"
    if signature == "thumb-uart-byte-tfwr16-sync-console-v1":
        return wire + f":{width:x}:{csr:x}:2", None
    return (wire if expected == (2, 0x99) else wire + f":{width:x}:{csr:x}"), None


def qemu_loaded_uart_console_property(
        profile: dict, original: bytes, loaded: bytes, config: object,
        *, ram_claimed: bool = False,
) -> tuple[str | None, str | None]:
    """Qualify source-bound boot consoles against their actual loaded source."""
    if not isinstance(profile, dict) or profile.get("signature") not in _UART_SOURCE_GUARDED_SIGNATURES:
        return None, "console-loaded-contract-unsupported"
    if not isinstance(original, bytes) or not isinstance(loaded, bytes):
        return None, "console-loaded-layout-unverified"
    wire, reason = qemu_uart_console_property(profile, len(loaded))
    if wire is None:
        return None, reason
    limit = _source_class_limit(original, config)
    if limit is None or limit != config.flash_size or len(loaded) != limit:
        return None, "console-loaded-layout-unverified"
    if not all(profile.get(field) for field in
               ("code_intervals", "literal_intervals", "data_intervals", "boot_guard_intervals")):
        return None, "console-boot-guards-unclosed"
    if not qemu_loaded_source_matches(profile, original, loaded):
        return None, "console-loaded-source-mismatch"
    if ram_claimed:
        return None, "console-loaded-memory-owner-unclosed"
    if getattr(config, "ram_bootstrap_profile", None) is not None:
        return None, "console-loaded-reserved-owner-unclosed"
    for field, begin, end in (("ram_intervals", config.ram_base,
                               config.ram_base + config.ram_size),
                              ("iram_intervals", 0x03800000, 0x03A00000)):
        spans = profile.get(field)
        if (field == "iram_intervals" and spans == []
                and profile["signature"] == _UART_PROBE_FF_DD_SIGNATURE):
            continue
        if (not isinstance(spans, (list, tuple)) or not spans
                or any(not isinstance(span, (list, tuple)) or len(span) != 2
                       or any(type(value) is not int for value in span)
                       or not begin <= span[0] < span[1] <= end for span in spans)):
            return None, "console-loaded-" + field + "-unverified"
    from msm5xxx_emulator.detection.uart_console import find_uart_console_profile
    current, _ = find_uart_console_profile(loaded, getattr(config, "ready_poll", None))
    if current != profile:
        return None, "console-loaded-owner-mismatch"
    return wire, None


def qemu_watchdog_property(profile: object, image: bytes) -> tuple[str | None, str | None]:
    """Emit only a profile independently reproduced from the loaded firmware."""
    if profile is None:
        return None, None
    from msm5xxx_emulator.detection.watchdog import find_watchdog_profile
    if not isinstance(profile, dict):
        return None, "invalid profile"
    size = profile.get("image_size")
    if type(size) is not int or not 0 < size <= len(image):
        return None, "invalid source window"
    current, reason = find_watchdog_profile(image[:size])
    if current is None:
        return None, f"source not admitted ({reason})"
    # Timeout is an explicit tunable, while every evidence field stays bound.
    timeout = profile.get("timeout_ms")
    if type(timeout) is not int or not 1000 <= timeout <= 3600000:
        return None, "invalid timeout"
    if {**profile, "timeout_ms": current["timeout_ms"]} != current:
        return None, "source profile mismatch"
    return (f"watchdog-register={current['register']},"
            f"watchdog-mask={current['mask']},watchdog-timeout-ms={timeout}"), None


def qemu_ready_poll_property(
        profile: object) -> tuple[str | None, str | None]:
    """Serialize only recognized, unambiguous ready-poll contracts."""
    if profile is None:
        return None, None
    if not isinstance(profile, dict):
        return None, "malformed-profile"
    if profile.get("signature") == "thumb-byte-ready-pulse-variants-v1":
        if profile.get("admission") != "temporary-evidence-gated":
            return None, "unsupported-admission"
        variants = profile.get("variants")
        if not isinstance(variants, list) or not 2 <= len(variants) <= READY_POLL_SITE_LIMIT:
            return None, "malformed-variants"
        fields = ("status_address", "mask", "pulse_address")
        common = tuple(profile.get(field) for field in fields)
        if (any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                for value in common)
                or not 0x03000000 <= common[0] < 0x04000000
                or not 0x03000000 <= common[2] < 0x04000000
                or common[0] == common[2] or not 0 < common[1] <= 0xFF
                or common[1] & (common[1] - 1)):
            return None, "malformed-fields"
        sites = []
        entries_seen = set()
        owned_pcs = set()
        for variant in variants:
            if (not isinstance(variant, dict) or variant.get("signature") not in (
                    "thumb-lsrs-bhs-pulse-v1",
                    "thumb-lsrs-bcc-pulse-rotated-v1",
                    "thumb-uart-csr-sr-rx-empty-v1")):
                return None, "unsupported-variant"
            if tuple(variant.get(field) for field in fields) != common:
                return None, "variant-contract-mismatch"
            argument, reason = qemu_ready_poll_property(variant)
            if reason is not None or argument is None:
                return None, "variant-" + (reason or "malformed-profile")
            if variant["signature"] == "thumb-lsrs-bhs-pulse-v1":
                offsets = [2, 0xC, 0x10]
            else:
                offsets = [variant[field] for field in (
                    "status_read_pc_offset", "pulse_set_pc_offset",
                    "pulse_clear_pc_offset")]
                if variant["signature"] == "thumb-uart-csr-sr-rx-empty-v1":
                    offsets.append(variant["uart_rx_empty_read_pc_offset"])
                    if "uart_rx_empty_frame_read_pc_offset" in variant:
                        offsets.append(variant["uart_rx_empty_frame_read_pc_offset"])
            if (any(offset & 1 or offset > 0x1000 for offset in offsets)
                    or len(set(offsets)) != len(offsets)
                    or offsets[1] >= offsets[2]
                    or (len(offsets) > 3 and
                        (common[1] != 8 or offsets[3] <= offsets[2]))
                    or (len(offsets) > 4 and offsets[4] <= offsets[3])):
                return None, "malformed-variant-offsets"
            for entry in variant["entries"]:
                if entry in entries_seen:
                    return None, "duplicate-variant-entry"
                pcs = {entry + offset for offset in offsets}
                if max(pcs) > 0xFFFFFFFF:
                    return None, "wrapped-variant-pc"
                if pcs & owned_pcs:
                    return None, "overlapping-variant-sites"
                entries_seen.add(entry)
                owned_pcs.update(pcs)
                # QEMU -M encodes literal value commas as doubled commas.
                sites.append(",,".join(f"{value:x}" for value in [entry, *offsets]))
                if len(sites) > READY_POLL_SITE_LIMIT:
                    return None, "entry-count-limit"
        if len(sites) < 2:
            return None, "ambiguous-entry-count"
        prefix = ":".join(f"{value:x}" for value in common)
        return f"ready-poll-sites={prefix}:" + ";".join(sites), None
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


def qemu_sbi_raw_input_property(
        config: object, profile: object) -> tuple[str | None, str | None]:
    """Bind a configured virtual byte to a proven raw-data consumer only."""
    if profile is None:
        return None, None
    if not isinstance(profile, dict):
        return None, "raw-input-malformed-profile"
    if (profile.get("signature") != "thumb-sbi-raw-sample-086a-v1"
            or profile.get("admission") != "temporary-evidence-gated"
            or profile.get("accepted") is not True
            or profile.get("policy") != "configured-virtual-raw-byte-uncalibrated"):
        return None, "raw-input-unsupported-contract"
    expected = {"base_address": 0x03000780, "control": 0x086A,
                "request_prefix": 0x0A80, "read_command": 0x8B00,
                "selector_mask": 0x60}
    if any(type(profile.get(key)) is not int or profile[key] != value
           for key, value in expected.items()):
        return None, "raw-input-malformed-wire"
    clocks = profile.get("clock_values")
    if (type(clocks) is not list or clocks != [0x4A, 0xCA]
            or any(type(value) is not int for value in clocks)):
        return None, "raw-input-clock-unclosed"
    source = profile.get("source_selector")
    selected = profile.get("selector_value")
    if (type(source) is not int or type(selected) is not int
            or {0: 0x20, 0x40: 0x40, 0x60: 0x60}.get(source) != selected):
        return None, "raw-input-selector-unclosed"
    entry, read_pc = profile.get("entry"), profile.get("read_pc")
    size, load = getattr(config, "flash_size", None), getattr(config, "load_address", 0)
    # This source family is verified in low primary NOR; rebasing needs a witness.
    if type(load) is not int or load != 0:
        return None, "raw-input-unverified-code-layout"
    if (type(size) is not int or size <= 0 or type(entry) is not int
            or entry < 0 or entry % 2 or type(read_pc) is not int
            or read_pc != entry + 0x86 or not read_pc <= min(size - 2, 0xFFFFFFFE)
            or profile.get("entries") != [entry]
            or type(profile.get("entries")) is not list
            or any(type(site) is not int for site in profile["entries"])):
        return None, "raw-input-consumer-unclosed"
    value = getattr(config, "board_adc_value", None)
    if type(value) is not int or not 0 <= value <= 0xFF:
        return None, "raw-input-byte-unavailable"
    return f"sbi-raw-input-profile={read_pc:x}:60:{selected:x}", None


def qemu_sbi_property(config: object) -> tuple[str | None, str | None]:
    """Keep legacy full SBI chip-bound; admit the closed bootstrap wire class."""
    profile = getattr(config, "sbi_bootstrap_profile", None)
    if (getattr(config, "chipset", None) == "MSM5000"
            and getattr(config, "board_adc_reader_address", None) is not None):
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
    if (type(profile.get("base_address")) is not int
            or profile.get("base_address") != 0x03000780
            or profile.get("bootstrap") != expected_bootstrap
            or profile.get("validation") != expected_validation):
        return None, "malformed-contract"
    for actual, expected in zip(
            profile["bootstrap"] + profile["validation"],
            expected_bootstrap + expected_validation):
        if any(type(value) is not type(wanted)
               for value, wanted in zip(actual, expected)):
            return None, "malformed-contract"
    entries = profile.get("entries")
    if (not isinstance(entries, list) or not entries
            or any(type(entry) is not int or entry < 0 or entry & 1
                   for entry in entries)
            or len(set(entries)) != len(entries)):
        return None, "malformed-entries"
    raw, raw_reject = qemu_sbi_raw_input_property(config, profile.get("raw_input"))
    if raw is not None:
        return "sbi=on," + raw, None
    return "sbi=on,sbi-bootstrap-only=on", raw_reject


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


def qemu_dmd5100_property(
        original: bytes, loaded: bytes, config: object, *,
        immutable_limit: int | None = None, layout_claimed: bool = False,
        input_profile: dict | None = None,
        eeprom_window: tuple[int, int] | None = None,
) -> tuple[str | None, str | None]:
    """Bind the paired program protocol to the immutable image actually loaded."""
    from msm5xxx_emulator.detection.dmd5100 import find_dmd5100_profile

    profile, reason = find_dmd5100_profile(original)
    if profile is None:
        return None, None if reason == "dmd5100-typed-driver-not-found" else reason
    fields = ("load_address", "image_offset", "entry", "flash_size", "ram_base", "ram_size")
    if (any(type(getattr(config, name, None)) is not int for name in fields)
            or getattr(config, "image_kind", None) != "firmware"
            or (config.load_address, config.image_offset, config.entry) != (0, 0, 0)
            or not isinstance(loaded, bytes)
            or not 0 < config.flash_size <= min(len(original), 0xFFFFFFFF)
            or not 0 <= config.ram_base < 0x100000000
            or not 0 < config.ram_size <= 0x100000000 - config.ram_base
            or len(loaded) != config.flash_size):
        return None, "dmd5100-source-layout-unclosed"
    if (layout_claimed or getattr(config, "ram_bootstrap_profile", None) is not None
            or getattr(config, "missing_overlays", None)
            or getattr(config, "ram_image_size", 0)):
        return None, "dmd5100-memory-owner-unclosed"
    windows = []
    status = getattr(config, "board_status_input", None)
    if status is not None:
        windows.append((getattr(status, "address", None), getattr(status, "width", 1)))
    key = getattr(config, "key_register", None)
    if key is not None:
        windows.append((key, 4))
    uart = getattr(config, "uart_console", None)
    if isinstance(uart, dict):
        windows.extend(((uart.get("base"), 0x24), (uart.get("pulse_address"), 1)))
    if input_profile is not None:
        if not isinstance(input_profile, dict):
            return None, "dmd5100-input-owner-unclosed"
        width = (2 if str(input_profile.get("grammar", "")).startswith("indirect-halfword")
                 else input_profile.get("register_width", 1))
        windows.append((input_profile.get("register", input_profile.get("sense_address")), width))
    if eeprom_window is not None:
        windows.append(eeprom_window)
    ports = (0x0300004C, 0x03000050, 0x0300005C, 0x030007E8, 0x030007EC)
    for start, size in windows:
        if (type(start) is not int or type(size) is not int
                or not 0 <= start < start + size <= 0x100000000):
            return None, "dmd5100-input-owner-unclosed"
        if any(start < port + 4 and port < start + size for port in ports):
            return None, "dmd5100-input-owner-conflict"
    limit = config.flash_size if immutable_limit is None else immutable_limit
    if type(limit) is not int or not 0 < limit <= config.flash_size:
        return None, "dmd5100-immutable-prefix-unclosed"
    # Keep every active callee byte pristine, not just the typed entry spans.
    if original[:limit] != loaded[:limit]:
        return None, "dmd5100-loaded-immutable-source-changed"
    if (profile.get("signature") != "dmd5100-paired-program-readback-v1"
            or profile.get("admission") != "temporary-evidence-gated"
            or profile.get("mode") != 0
            or any(not 0 <= start < end <= limit
                   for start, end in profile["source_intervals"])
            or getattr(config, "dmd_download_address", None) != profile["entry_file_offset"]
            or not config.ram_base <= profile["completion_byte_address"] <
                   config.ram_base + config.ram_size <= 0x100000000):
        return None, "dmd5100-source-owner-unclosed"
    current, _ = find_dmd5100_profile(loaded)
    if current != profile:
        return None, "dmd5100-loaded-profile-changed"
    values = (profile["entry_file_offset"], profile["descriptor_file_offset"],
              profile["payload_file_offset"], profile["pair_count"])
    return "dmd5100-program=" + ":".join(f"{value:x}" for value in values), None


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
                             new_size: int, *, prepend: bool = False) -> bool:
    """Atomically preserve one old raw extent and add erased bytes."""
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
        erased = b"\xff" * (new_size - old_size)
        atomic_write_bytes(path, erased + data if prepend else data + erased)
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
        and candidate.get("group_row_size") in (10, 12)
        and candidate.get("pending_read_semantics") == "latched-read"
        and candidate.get("pending_ack_semantics") == "write-one-to-clear"
        and candidate.get("time_tick_status_bank") == 0x03000C80
        and candidate.get("time_tick_clear_bank") == 0x03000C80
        and candidate.get("time_tick_mask") == 0x0200
    )
    if not enabled and not automatic:
        return None
    fb0 = signature == "static-fb0-controller-callback-v1"
    overlay = signature == "static-c80-overlay-controller-callback-v1"
    required = {
        "signature": signature,
        "controller_class": (
            "legacy-c80-three-bank-group14-v1" if overlay else
            "legacy-fb0-index1b-delta5-controller-candidate-v1" if fb0 else
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
            "static-fb0-controller-callback-v1",
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
            or status != (0x03000FB0 if fb0 else 0x03000C80)
            or enable != status + 0x14
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
        if fb0:
            class_invalid |= (
                candidate.get("promotion") != "experimental-only"
                or candidate.get("status_bank_count") != 2
                or candidate.get("group_row_size") != 10
                or candidate.get("pending_read_semantics") != "latched-read"
                or candidate.get("pending_ack_semantics") != "write-one-to-clear"
                or candidate.get("time_tick_status_bank") != status
                or candidate.get("time_tick_clear_bank") != status
                or candidate.get("time_tick_mask") != 0x0200
                or candidate.get("time_tick_control_address") != 0x030006E0
                or handler_size != 0x182
            )
    if common_invalid or class_invalid:
        return None
    # The experimental FB0 class shares the provisional 5-unit cadence;
    # physical timer frequency is not inferred from the callback alone.
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
    """Encode closed callback-then-W1C classes without an unproven idle PC."""
    profile = _legacy_620_rex_irq_profile(
        config, True,
        {"legacy-msm5000-620-two-bank-w1c-8call-v1": 12,
         "legacy-msm5000-620-two-bank-w1c-group10-v1": 10,
         "legacy-msm5000-620-two-bank-w1c-group12-v1": 12},
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
    if find_24lcxx_halfword_driver(image) == (read, write, geometry):
        from msm5xxx_emulator.detection.memory_layout import find_linker_layout
        # Paired transport calls prove ownership of these byte-level leaves.
        # Their halfword stores use a shared RAM GPIO descriptor; resolve its
        # ROM initializer through the detected linker scatter copy.
        writer, reader, ack = write - 0x160, write - 0x78, write - 0x1FE
        # Close every instruction in the three byte-level leaves, including
        # loop bounds and reloads between the explicit pin operations below.
        # BL displacements vary with linking; validate their callee roles and
        # hash the remaining compiler shape, as the NOR driver gates do.
        lock = thumb_bl_target(image, ack + 2)
        unlock = thumb_bl_target(image, ack + 0x1A)
        delay = thumb_bl_target(image, ack + 0x38)
        timed_delay = thumb_bl_target(image, ack + 0x50)
        leaf_shapes = (
            (ack, 0x96,
             "bcdb33d7918091c733d5eebbb9e57029d3c462a11b765161b1a9aba0f032b165",
             ((lock, (2, 0x1E, 0x54, 0x74)),
              (unlock, (0x1A, 0x34, 0x6A, 0x8A)),
              (delay, (0x38,)), (timed_delay, (0x50,)))),
            (writer, 0xE4,
             "f1bb5fe4d4979831d36076a4b3591ceffe9905eec0b352152a5cb9f9d926ea04",
             ((lock, (8, 0x14, 0x36, 0x56, 0x70, 0x92, 0xB2)),
              (unlock, (0x2C, 0x4E, 0x88, 0xAA, 0xCA, 0xD2)),
              (delay, (0x52, 0xAE)), (ack, (0xDA,)))),
            (reader, 0x70,
             "966f0169bb7ce3de0b0d6bf51bd34de3f27291d366ca03294ca2dedfedc6d333",
             ((lock, (0xA, 0x10, 0x40)),
              (unlock, (0x26, 0x56, 0x5E)), (delay, (0x2A,)))),
        )
        if (len({lock, unlock, delay, timed_delay}) != 4
                or any(target is None or not 0 <= target < len(image)
                       for target in (lock, unlock, delay, timed_delay))):
            return None, "gpio-line-shape-mismatch"
        for entry, extent, digest, groups in leaf_shapes:
            if entry < 0 or entry + extent > len(image):
                return None, "gpio-line-shape-mismatch"
            body = bytearray(image[entry:entry + extent])
            for target, offsets in groups:
                for offset in offsets:
                    if thumb_bl_target(image, entry + offset) != target:
                        return None, "gpio-line-shape-mismatch"
                    body[offset:offset + 4] = b"\0" * 4
            if hashlib.sha256(body).hexdigest() != digest:
                return None, "gpio-line-shape-mismatch"
        shapes = (
            (writer, "f0b5071c80260724"),
            (writer + 0x18, "324a2023918919439181918912681180"),
            (writer + 0x3A, "2a4a4023918919439181918912681180"),
            (writer + 0x5A, "224a4023918999439181918912681180"),
            (writer + 0x74, "1b4a2023918999439181918912681180"),
            (writer + 0x96, "134a4023918919439181918912681180"),
            (writer + 0xB6, "0b4a4023918999439181918912681180"),
            (reader, "f0b500271b4e1a480024"),
            (reader + 0x14, "b18940221143b181b18932681180"),
            (reader + 0x36, "0078800901d301200743"),
            (reader + 0x44, "b18940239943b181b18932681180"),
            (ack + 0x08, "2023e1899943e181e189a2681180"),
            (ack + 0x78, "e18920221143e181e189a2681180"),
            (ack + 0x3C, "616801250988281c890900d2002007063f0e"),
            (write + 0x74, "0e231840a0221043"),
            (write + 0x92, "4020"),
            (write + 0x16A, "2012"),
            (read + 0x142, "0e231e40a0203043"),
            (read + 0x14E, "3812"),
            (read + 0x2F0, "a12030430006000e"),
        )
        descriptor = thumb_literal_value(image, writer + 0x18, 2)
        literals = (
            (writer + offset, 2, descriptor)
            for offset in (0x3A, 0x5A, 0x74, 0x96, 0xB6)
        )
        if (min(writer, reader, ack) < 0 or descriptor is None
                or any(image[p:p + len(bytes.fromhex(h))] != bytes.fromhex(h)
                       for p, h in shapes)
                or any(thumb_literal_value(image, p, r) != value
                       for p, r, value in literals)
                or thumb_literal_value(image, reader + 4, 6) != descriptor
                or thumb_literal_value(image, reader + 6, 0) != 0x03000720
                or thumb_literal_value(image, reader + 0x32, 0) != 0x03000720
                or thumb_literal_value(image, ack + 6, 4) != descriptor
                or any(thumb_bl_target(image, entry + offset) != target
                       for entry, offset, target in (
                           (write, 0x166, writer), (write, 0x16C, writer),
                           (read, 0x14A, writer), (read, 0x150, writer),
                           (read, 0x31E, reader), (read, 0x3CE, reader),
                           (writer, 0xDA, ack)))):
            return None, "gpio-line-shape-mismatch"
        linker = find_linker_layout(image, load, required_span=(descriptor, 12))
        if (linker is None or not linker.data_target <= descriptor
                <= linker.data_target + linker.data_size - 12):
            return None, "gpio-descriptor-linkage-mismatch"
        source = linker.data_source + descriptor - linker.data_target
        if (source < 0 or source + 12 > len(image)
                or struct.unpack_from("<III", image, source)
                != (0x03000720, 0x03000720, 0x0300072C)):
            return None, "gpio-descriptor-linkage-mismatch"
        return (0x03000720, 0, 0x20, 0, 0x40, 0xC, 0x8000), None
    x7700 = (
        image[read:read + len(EEPROM_24LCXX_X7700_READ_PREFIX)]
        == EEPROM_24LCXX_X7700_READ_PREFIX
        and image[write:write + len(EEPROM_24LCXX_X7700_WRITE_PREFIX)]
        == EEPROM_24LCXX_X7700_WRITE_PREFIX
        and find_24lcxx_x7700_driver(image) == (read, write, geometry)
    )
    if x7700:
        writer = write - 0x160
        reader = read - 0x728
        shapes = (
            (writer, bytes.fromhex("f0b5071c80260724")),
            (writer + 0x18, bytes.fromhex("324a202391891943918191891268")),
            (writer + 0x3A, bytes.fromhex("2a4a402391891943918191891268")),
            (writer + 0x5A, bytes.fromhex("224a402391899943918191891268")),
            (writer + 0x74, bytes.fromhex("1b4a202391899943918191891268")),
            (writer + 0x96, bytes.fromhex("134a402391891943918191891268")),
            (writer + 0xB6, bytes.fromhex("0b4a402391899943918191891268")),
            (reader, bytes.fromhex("f0b500271a4e0024")),
            (reader + 0x12, bytes.fromhex("184a402391891943918191891268")),
            (reader + 0x32, bytes.fromhex("30783f0e800901d301200743")),
            (reader + 0x42, bytes.fromhex("0c4a402391899943918191891268")),
        )
        descriptor = thumb_literal_value(image, writer + 0x18, 2)
        linker = getattr(config, "linker", None)
        if (min(writer, reader) < 0
                or any(image[position:position + len(expected)] != expected
                       for position, expected in shapes)
                or not isinstance(descriptor, int)
                or any(thumb_literal_value(image, position, register)
                       != expected
                       for position, register, expected in (
                           (writer + 0x3A, 2, descriptor),
                           (writer + 0x5A, 2, descriptor),
                           (writer + 0x74, 2, descriptor),
                           (writer + 0x96, 2, descriptor),
                           (writer + 0xB6, 2, descriptor),
                           (reader + 0x04, 6, 0x03000720),
                           (reader + 0x12, 2, descriptor),
                           (reader + 0x42, 2, descriptor),
                       ))):
            return None, "gpio-line-shape-mismatch"
        if (linker is None
                or not linker.data_target <= descriptor
                <= linker.data_target + linker.data_size - 12):
            return None, "gpio-descriptor-linkage-mismatch"
        source = linker.data_source + descriptor - linker.data_target
        if (source < 0 or source + 12 > len(image)
                or struct.unpack_from("<III", image, source)
                != (0x03000720, 0x03000720, 0x0300072C)):
            return None, "gpio-descriptor-linkage-mismatch"
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
                 observe_rex_idle_candidate: bool = False,
                 experimental_halfword: bool = False,
                 experimental_status_level: int | None = None,
                 experimental_audio_refill: bool = True,
                 experimental_low5: bool = False,
                 experimental_distributed: bool = True,
                 virtual_cell: dict | None = None,
                 experimental_ma5_byte_ns: int | None = None,
                 experimental_ma5_clki_hz: int | None = None,
                 experimental_ma5_target_rate_hz: int | None = None,
                 experimental_ma5_irq: bool = False,
                 experimental_ma5_pcm_output: bool = False) -> None:
        if type(experimental_ma5_irq) is not bool:
            raise ValueError("invalid experimental MA5 IRQ setting")
        if type(experimental_ma5_pcm_output) is not bool:
            raise ValueError("invalid experimental MA5 PCM output setting")
        if experimental_ma5_pcm_output and (
                experimental_ma5_byte_ns is None or not audio_pcm):
            raise ValueError("experimental MA5 PCM output requires byte period and host PCM")
        if experimental_ma5_irq and (
                experimental_ma5_byte_ns is None or experimental_ma5_clki_hz is None):
            raise ValueError("experimental MA5 IRQ requires explicit byte period and CLKI")
        if experimental_ma5_clki_hz is not None and (
                type(experimental_ma5_clki_hz) is not int or
                not 1 <= experimental_ma5_clki_hz <= 1_000_000_000 or
                experimental_ma5_byte_ns is None):
            raise ValueError("invalid experimental MA5 CLKI or missing byte period")
        if experimental_ma5_target_rate_hz is not None and (
                experimental_ma5_clki_hz is not None or
                type(experimental_ma5_target_rate_hz) is not int or
                not 8000 <= experimental_ma5_target_rate_hz <= 96000 or
                experimental_ma5_byte_ns is None):
            raise ValueError("invalid experimental MA5 target rate or missing byte period")
        if (experimental_ma5_byte_ns is not None and
                (type(experimental_ma5_byte_ns) is not int or
                 not 1 <= experimental_ma5_byte_ns <= 1_000_000_000)):
            raise ValueError("invalid experimental MA5 byte service period")
        if type(experimental_audio_refill) is not bool:
            raise ValueError("invalid experimental audio refill setting")
        if not 0 <= icount_shift <= 10:
            raise ValueError("invalid QEMU icount shift")
        if type(observe_uis_idle) is not bool:
            raise ValueError("invalid UI-idle observer setting")
        if type(observe_rex_idle_candidate) is not bool:
            raise ValueError("invalid REX-idle observer setting")
        if type(experimental_halfword) is not bool:
            raise ValueError("invalid halfword matrix setting")
        if type(experimental_low5) is not bool:
            raise ValueError("invalid five-column matrix setting")
        if type(experimental_distributed) is not bool:
            raise ValueError("invalid distributed matrix setting")
        if (experimental_status_level is not None and
                (not experimental_halfword or type(experimental_status_level) is not int
                 or experimental_status_level not in (0, 4, 16))):
            raise ValueError("status level requires halfword opt-in and integer 0, 4 or 16")
        self.config = config if config is not None else detect(firmware)
        self._native_nand_lock = None
        self._native_nand_listener = None
        self._native_nand_socket = None
        self._native_nand_reader = None
        self._native_nand_id = 0
        self.native_nand_status = "disabled"
        state_dir = qemu_state_directory(state_dir, self.config)
        self.temporary = tempfile.TemporaryDirectory(prefix="msm5xxx-qemu-gui-")
        temporary = Path(self.temporary.name)
        if state_dir is not None:
            state_dir.mkdir(parents=True, exist_ok=True)
        loaded_firmware = load_firmware_image(firmware)
        firmware_image = loaded_firmware.image
        detector_image = detector_firmware_image(
            firmware_image, self.config.image_offset
        )
        from msm5xxx_emulator.detection.input_row734 import find_row734_input_profile
        from msm5xxx_emulator.detection.protected_nor import find_protected_nor_profile
        self.row734_source_profile = self.protected_nor_source_profile = None
        self.amd_bank_source_profile = None
        self.amd_bank_reject_reason = None
        self.row734_reject_reason = self.protected_nor_reject_reason = None
        source_limit = _source_class_limit(detector_image, self.config)
        if source_limit is not None:
            source_image = detector_image[:source_limit]
            self.row734_source_profile, self.row734_reject_reason = find_row734_input_profile(
                source_image, self.config.ram_base, self.config.ram_size, 0)
            self.protected_nor_source_profile, self.protected_nor_reject_reason = find_protected_nor_profile(
                source_image, self.config.ram_base, self.config.ram_size, 0)
        if self.row734_source_profile is not None:
            self.row734_reject_reason = None
        if self.protected_nor_source_profile is not None:
            self.protected_nor_reject_reason = None
        for label, reason in (("row734", self.row734_reject_reason),
                              ("protected-nor", self.protected_nor_reject_reason)):
            if reason is not None and reason.endswith(("profiles-ambiguous", "candidates-unclosed")):
                self.config.detection_notes.append(
                    f"QEMU {label} source rejected: {reason}; native fallback retained")
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
        cell_property, cell_reject = qemu_virtual_cell_property(
            detector_image, self.config, virtual_cell
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
        self.board_status_snapshot: dict[str, int] | None = None
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
        self.audio_native_ma5_pcm = False
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
        decoder_options = {}
        if getattr(self.config, "native_nand_profile", None) is not None:
            decoder_options["native_nand"] = True
        self.decoder = QemuDecoder(self.config, **decoder_options)
        if self.config.load_address != 0:
            raise ValueError("QEMU PoC requires NOR=0")
        try:
            initial_state = initial_register_state(self.config)
            memory_profile = qemu_memory_profile(self.config, initial_state)
            ram_reserved = qemu_ram_reserved_property(
                detector_image, self.config, initial_state["sp"]
            )
        except Exception:
            self.decoder.close()
            self.temporary.cleanup()
            raise

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
        if ram_reserved is not None:
            machine += "," + ram_reserved
        self.virtual_cell_status = "native"
        self.virtual_cell_limit_reason = None
        if cell_property is not None:
            machine += "," + cell_property
            self.virtual_cell_status = "configured"
            self.config.detection_notes.append(
                "QEMU virtual cell provisional: explicit ideal signal/clock/packets; SIP disabled"
            )
            if cell_reject is not None:
                self.virtual_cell_limit_reason = cell_reject
                self.config.detection_notes.append(
                    f"QEMU virtual cell limited: {cell_reject}; unavailable features retain native fallback"
                )
        elif cell_reject is not None:
            self.virtual_cell_status = "rejected"
            self.config.detection_notes.append(
                f"QEMU virtual cell rejected: {cell_reject}; native fallback retained"
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
        if sbi_reject is not None:
            fallback = "bootstrap-only retained" if sbi_property else "native fallback retained"
            self.config.detection_notes.append(
                f"QEMU SBI bridge rejected: {sbi_reject}; "
                f"{fallback}"
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
        uart_property, uart_reject = qemu_uart_console_property(
            getattr(self.config, "uart_console", None), len(self.decoder.image)
        )
        uart_deferred = (isinstance(getattr(self.config, "uart_console", None), dict)
                         and self.config.uart_console.get("signature") in _UART_SOURCE_GUARDED_SIGNATURES)
        if uart_property is not None:
            if not uart_deferred:
                machine += f",{uart_property}"
        elif uart_reject is not None:
            self.config.detection_notes.append(
                f"QEMU UART console rejected: {uart_reject}; native fallback retained"
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
        if experimental_low5:
            low5_property, low5_reject = qemu_low5_matrix_property(
                detector_image, self.config, direct
            )
            if low5_property is not None:
                machine += f",{low5_property}"
                self.matrix_input_profile = direct
                self.config.detection_notes.append(
                    "QEMU five-column matrix temporary: descriptor/selector-gated electrical input"
                )
            elif low5_reject is not None:
                self.config.detection_notes.append(
                    f"QEMU five-column matrix rejected: {low5_reject}; native fallback retained"
                )
        if experimental_halfword or direct is None:
            halfword, status, _ = resolve_indirect_matrix_input(
                detector_image, self.config.load_address
            )
            if halfword is not None and direct is None:
                halfword_property, status = qemu_halfword_matrix_property(
                    detector_image, self.config, halfword, enabled=experimental_halfword
                )
                if halfword_property is not None:
                    machine += f",{halfword_property}"
                    self.matrix_input_profile = halfword
                    self.config.detection_notes.append(
                        "QEMU halfword matrix temporary: static scanner; live descriptor gates"
                    )
                    if not experimental_halfword and halfword.get("scan_gates") is not None:
                        self.config.detection_notes.append(
                            "QEMU mapped input provisional: scan-enabled contact/status levels; "
                            "physical roles unassigned; live descriptor/read-site gates"
                        )
            elif halfword is not None:
                status = "conflicting-direct-profile"
            if self.matrix_input_profile is not halfword or halfword is None:
                self.config.detection_notes.append(
                    f"QEMU halfword matrix rejected: {status}; native fallback retained"
                )
        if experimental_distributed:
            distributed, status, _ = resolve_distributed_matrix_input(
                detector_image, self.config.load_address
            )
            if distributed is not None and direct is None and self.matrix_input_profile is None:
                distributed_property, status = qemu_distributed_matrix_property(
                    detector_image, self.config, distributed
                )
                if distributed_property is not None:
                    machine += f",{distributed_property}"
                    self.matrix_input_profile = distributed
                    self.matrix_input_sideband_producer, _ = qemu_distributed_sideband_producer(
                        detector_image, self.config, distributed)
                    if status is not None:
                        self.config.detection_notes.append(
                            f"QEMU distributed sideband rejected: {status}; native fallback retained")
                    self.config.detection_notes.append(
                        "QEMU distributed matrix temporary: numeric-only; live GPIO selectors"
                    )
            elif distributed is not None:
                status = "conflicting-matrix-profile"
            if distributed is None or self.matrix_input_profile is not distributed:
                self.config.detection_notes.append(
                    f"QEMU distributed matrix rejected: {status}; native fallback retained"
                )
        status_property, status_reject = qemu_halfword_status_property(
            detector_image, self.config.load_address, self.matrix_input_profile,
            experimental_status_level, board_status
        )
        if status_property is not None:
            machine += f",{status_property}"
            self.config.detection_notes.append(
                "QEMU status input provisional: scan-enabled electrical level; "
                "live descriptor gate; physical role unassigned"
                if experimental_status_level is None else
                "QEMU status input experimental: explicit electrical level; "
                "live descriptor gate; physical role unassigned"
            )
        elif status_reject is not None:
            self.config.detection_notes.append(
                f"QEMU status input rejected: {status_reject}; native fallback retained"
            )
        audio = self.config.audio_transport
        audio_family = audio.get("family") if audio is not None else None
        audio_grammar = audio.get("grammar") if audio is not None else None
        ma5_property = None
        ma5_auto_profile = False
        ma5_auto_irq = False
        if experimental_ma5_byte_ns is not None:
            ma5_property, ma5_reason = qemu_ma5_readback_property(
                detector_image, self.config, experimental_ma5_byte_ns,
                upper_nor_present=upper_nor_present,
                clki_hz=experimental_ma5_clki_hz,
                target_rate_hz=experimental_ma5_target_rate_hz)
            if ma5_property is not None:
                self.config.detection_notes.append(
                    f"QEMU experimental MA5 cold readback: uncalibrated byte "
                    f"period {experimental_ma5_byte_ns} ns; "
                    "GPIO IRQ requires a separate explicit route")
                if experimental_ma5_clki_hz is not None:
                    self.config.detection_notes.append(
                        f"QEMU experimental MA5 CLKI {experimental_ma5_clki_hz} Hz: "
                        "START-driven empty-FIFO counter and cumulative delayed "
                        "deadlines/late-packet catchup are experimental")
                if experimental_ma5_target_rate_hz is not None:
                    self.config.detection_notes.append(
                        f"QEMU experimental MA5 target rate "
                        f"{experimental_ma5_target_rate_hz} Hz: PLL-derived CLKI "
                        "and timing are uncalibrated")
            else:
                self.config.detection_notes.append(
                    f"QEMU experimental MA5 rejected: {ma5_reason}; native fallback retained")
        elif experimental_ma5_clki_hz is None:
            ma5_property, ma5_reason = qemu_ma5_temporary_auto_property(
                detector_image, self.config, audio_pcm=audio_pcm,
                upper_nor_present=upper_nor_present)
            ma5_auto_profile = ma5_property is not None
            if ma5_property is not None:
                candidate = find_ma5_readback_candidate(detector_image)
                ma5_auto_irq = (
                    candidate.get("structural_evidence", {}).get("transport_class")
                    == "local-counter-direction-timing-v1"
                )
                self.config.detection_notes.append(
                    "QEMU temporary MA5 class: matched static readback producer; "
                    "1000 ns byte period and 48 kHz target are provisional; CLKI is "
                    "derived at runtime from guest PLL bytes; no ready response; "
                    "unsupported protocol/PLL retains native fallback")
            elif ma5_reason is not None:
                self.config.detection_notes.append(
                    f"QEMU temporary MA5 class rejected: {ma5_reason}; native fallback retained")
        if ma5_property is not None:
            machine += "," + ma5_property
            if experimental_ma5_pcm_output or ma5_auto_profile:
                machine += ",experimental-ma5-pcm-output=on"
                self.audio_native = True
                self.audio_native_ma5_pcm = True
                self.config.detection_notes.append(
                    "QEMU MA5 PCM: bounded uploaded WT subset; 48 kHz PC-model "
                    "converted to 44.1 kHz with linear interpolation; unsupported "
                    "voices skipped locally; sample clock is not silicon-calibrated")
                if not audio_pcm:
                    machine += ",audio-pcm=off"
                elif (audio_stream and (audio_listener is not None or
                                        audio_qemu_socket is not None)):
                    self.audio_stream_enabled = True
                    self.audio_stream_status = "pending"
                    machine += ",audio-stream-chardev=audio"
                else:
                    desktop_audio_driver = (
                        "coreaudio" if sys.platform == "darwin" else
                        "dsound" if sys.platform == "win32" else "alsa"
                    )
                    machine += ",audiodev=msm5xxx"
            if experimental_ma5_irq or ma5_auto_irq:
                irq_property, irq_reject = qemu_ma5_gpio_irq_property(detector_image, self.config)
                if irq_property is not None:
                    machine += "," + irq_property
                    if ma5_auto_irq:
                        self.config.detection_notes.append(
                            "QEMU temporary MA5 GPIO/parent route: same-image callback signature "
                            "matched; IRQ remains gated until guest PLL-derived CLKI and live "
                            "callback/exception state qualify")
                    else:
                        self.config.detection_notes.append(
                            "QEMU experimental MA5 GPIO/parent route candidate: auxiliary paths "
                            "remain unverified; native live callback/exception gates own admission")
                else:
                    label = "temporary" if ma5_auto_irq else "experimental"
                    self.config.detection_notes.append(
                        f"QEMU {label} MA5 IRQ rejected: {irq_reject}; native fallback retained")
        elif (audio is not None
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
                if experimental_audio_refill:
                    irq_property, irq_reject = qemu_audio_irq_property(audio, self.config)
                    if irq_property is not None:
                        machine += ',' + irq_property
                    self.config.detection_notes.append(
                        'QEMU audio refill provisional: half-full/empty occupancy approximation; live route gate'
                        if irq_property else f'QEMU audio refill rejected: {irq_reject}; native fallback retained')
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
        elif (audio is not None
              and audio_grammar == "repeated-bit-sequence-v1"
              and not upper_nor_present):
            packet_property, packet_reject = qemu_audio_packet_property(
                detector_image, self.config, audio)
            if packet_property is not None:
                machine += "," + packet_property
                self.config.detection_notes.append(
                    "QEMU temporary sequence receiver: actual reset/release required; "
                    "raw register/RAM consumption only, no renderer or FIFO timing")
            else:
                self.config.detection_notes.append(
                    f"QEMU sequence receiver rejected: {packet_reject}; native fallback retained")
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
        if ma5_property is not None:
            if experimental_ma5_pcm_output or ma5_auto_profile:
                if not self.audio_stream_enabled:
                    self.audio_stream_status = "native"
                    self.audio_stream_reject_reason = None
            else:
                self.audio_stream_status = "unavailable"
                self.audio_stream_reject_reason = "experimental-ma5-cold-readback-no-renderer"
        if audio_listener is not None and not self.audio_stream_enabled:
            audio_listener.close()
            audio_listener = None
        if audio_host_socket is not None and not self.audio_stream_enabled:
            audio_host_socket.close()
            audio_host_socket = None
        if audio_qemu_socket is not None and not self.audio_stream_enabled:
            audio_qemu_socket.close()
            audio_qemu_socket = None
        boot_property, boot_reject = qemu_boot_keysense_property(
            self.config, detector_image,
            input_claimed=(self.matrix_input_profile is not None
                           or self.decoder.direct_input_profile is not None),
        )
        if boot_property is not None:
            machine += "," + boot_property
            self.config.detection_notes.append(
                "QEMU source-PC-bound boot key release enabled; active keys unchanged"
            )
        elif boot_reject is not None:
            self.config.detection_notes.append(
                f"QEMU boot key release rejected: {boot_reject}; native fallback retained"
            )
        rex_fields = (
            self.config.rex_irq_status_address,
            self.config.rex_irq_enable_address,
            self.config.rex_irq_arm_address,
            self.config.rex_idle_address,
        )
        if getattr(self.config, "rex_basic_irq_profile", None) is not None:
            basic_property, basic_reject = qemu_basic_row0_property(
                self.config, detector_image)
            if self.rex_c80_profile is not None or self.rex_read_consume_profile is not None:
                basic_property, basic_reject = None, "row0-controller-owner-conflict"
            if basic_property is not None:
                machine += "," + basic_property
            elif basic_reject is not None:
                self.config.detection_notes.append(
                    f"QEMU row0 IRQ rejected: {basic_reject}; native fallback retained"
                )
        elif (self.config.rex_tick_ms == 5 and self.config.rex_irq_mask
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
        direct_protocol_conflict = intel_profile is not None and amd_profile is not None
        if direct_protocol_conflict:
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
        if not direct_protocol_conflict and all(profile is None for profile in (
                primary_profile, probe_profile, intel_profile, amd_profile,
                mapped_primary_profile)):
            seeded_profile, seeded_reject = seeded_amd_x16_nor_profile(
                detector_image, self.config.load_address, self.config.flash_size,
                self.config.ram_base, self.config.ram_size,
            )
            if seeded_profile is not None:
                probe_profile = seeded_profile
                self.config.detection_notes.append(
                    "temporary seeded x16 NOR descriptor/driver class; "
                    "byte-sector geometry and read/write context verified"
                )
            elif seeded_reject is not None:
                self.config.detection_notes.append(
                    f"seeded x16 NOR detector rejected: {seeded_reject}; "
                    "native fallback retained"
                )
        primary_profile, primary_regions, profile_reject = (
            select_primary_x16_nor_profile(primary_profile, probe_profile)
        )
        record_profile = find_record_amd_x16_nor(
            detector_image[:self.config.flash_size], self.config.flash_size,
        )
        if record_profile is not None:
            record_base, record_size, _ = record_profile
            if (primary_profile is None
                    or record_base + record_size != primary_profile[0]
                    or primary_profile[0] + primary_profile[1]
                       != self.config.flash_size):
                record_profile = None
                self.config.detection_notes.append(
                    "Record x16 NOR detector rejected: primary-tail-"
                    "adjacency-mismatch; native fallback retained"
                )
        catalog_profile = (
            find_catalog_amd_x16_nor(
                detector_image[:self.config.flash_size],
                self.config.flash_size, self.config.ram_base,
            )
            if record_profile is not None else None
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
        eeprom_profile, eeprom_reject = eeprom_gpio_profile(detector_image, self.config)
        ma2_patch = ma2_silent_boot_loader_patch(
            primary_seed, self.config,
            primary_profile[0] if primary_profile is not None else None,
        )
        dmd5100_property, dmd5100_reject = qemu_dmd5100_property(
            detector_image, primary_seed, self.config,
            immutable_limit=primary_profile[0] if primary_profile is not None else None,
            input_profile=self.matrix_input_profile,
            eeprom_window=(eeprom_profile[0], 32) if eeprom_profile is not None else None,
            layout_claimed=ma2_patch is not None or any(value is not None for value in (
                ram_reserved, primary_profile, record_profile, mapped_primary_profile,
                upper_x16_profile, intel_profile, amd_profile,
                self.config.upper_flash_address, self.config.secondary_flash_address,
                self.config.native_nand_profile, self.config.nand_image)),
        )
        self.dmd5100_program_property = dmd5100_property
        self.dmd5100_program_reject = dmd5100_reject
        if dmd5100_property is not None:
            machine += f",{dmd5100_property}"
            self.config.detection_notes.append(
                "temporary paired DMD program/readback class; actual guest words only; "
                "DSP execution, clocks and IRQ unqualified")
            dmd_patch = None
        else:
            if dmd5100_reject is not None:
                self.config.detection_notes.append(
                    f"DMD program detector rejected: {dmd5100_reject}; native fallback retained")
            dmd_patch = legacy_dmd_loader_patch(
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
        watchdog_property, watchdog_reject = qemu_watchdog_property(
            getattr(self.config, "watchdog", None), primary_seed
        )
        if watchdog_property is not None:
            machine += f",{watchdog_property}"
        elif watchdog_reject is not None:
            self.config.detection_notes.append(
                f"QEMU watchdog rejected: {watchdog_reject}")
        if len(primary_seed) != self.config.flash_size:
            raise ValueError("primary seed size does not match flash size")
        # New source-bound page producers must match the image actually loaded.
        if primary_seed != self.decoder.image:
            self.decoder._lcd_page_loaded_image = primary_seed
        self.decoder._lcd_bind_source_window(
            detector_image, primary_seed,
            ram_claimed=any(value is not None for value in (
                ram_reserved, primary_profile, record_profile, mapped_primary_profile,
                upper_x16_profile, intel_profile, amd_profile,
                self.config.upper_flash_address, self.config.secondary_flash_address,
                self.config.native_nand_profile, self.config.nand_image)))
        if uart_property is not None and uart_deferred:
            loaded_uart, loaded_uart_reject = qemu_loaded_uart_console_property(
                self.config.uart_console, detector_image, primary_seed, self.config,
                ram_claimed=any(value is not None for value in (
                    ram_reserved, mapped_primary_profile, upper_x16_profile, intel_profile, amd_profile,
                    self.config.upper_flash_address, self.config.secondary_flash_address,
                    self.config.nand_image)))
            if loaded_uart is not None:
                machine += f",{loaded_uart}"
            else:
                self.config.detection_notes.append(
                    f"QEMU UART console rejected: {loaded_uart_reject}; native fallback retained")
        if ram_reserved is not None:
            try:
                # Writable NOR overlay ownership is not closed for this bootstrap class.
                if any(profile is not None for profile in
                       (primary_profile, record_profile, mapped_primary_profile,
                        intel_profile, amd_profile)):
                    raise ValueError("reset-linked RAM profile requires a stable primary NOR image")
                if qemu_ram_reserved_property(primary_seed, self.config,
                                              initial_state["sp"]) != ram_reserved:
                    raise ValueError("loaded NOR changed the reset-linked RAM profile")
            except Exception:
                for channel in (lcd_listener, input_listener, gdb_listener,
                                audio_listener, audio_host_socket, audio_qemu_socket):
                    if channel is not None:
                        channel.close()
                self.decoder.close()
                self.temporary.cleanup()
                raise
        self.amd_bank_source_profile, self.amd_bank_reject_reason = qemu_amd_bank_profile(
            detector_image, primary_seed, self.config,
            nor_claimed=direct_protocol_conflict or any(value is not None for value in (
                profile_reject, primary_profile, probe_profile, record_profile, mapped_primary_profile,
                intel_profile, amd_profile, self.protected_nor_source_profile,
                ram_reserved, upper_x16_profile, self.config.secondary_flash_address,
                self.config.secondary_flash_image, self.config.upper_flash_address,
            )),
        )
        if self.amd_bank_source_profile is not None:
            if find_embedded_fujitsu_x16_nor(detector_image[:self.config.flash_size],
                                            self.config.flash_size) is not None:
                self.amd_bank_source_profile = None
                self.amd_bank_reject_reason = "amd-bank-secondary-owner-conflict"
            else:
                profile = self.amd_bank_source_profile
                record_profile = profile['base'], profile['size'], profile['sector_size']
        if self.amd_bank_reject_reason is not None:
            self.config.detection_notes.append(
                f"QEMU bounded AMD bank rejected: {self.amd_bank_reject_reason}; "
                "native fallback retained"
            )
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
                machine += ",primary-x16-write-while-suspended=on"
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
        if record_profile is not None:
            base, size, sector_size = record_profile
            device_size = 1 << (size - 1).bit_length()
            record_state = ((state_dir / "record-x16.raw")
                            if state_dir is not None else
                            (temporary / "record-x16.raw"))
            record_seed = (primary_seed[base:base + size]
                           + b"\xff" * (device_size - size))
            if len(record_seed) != device_size:
                raise ValueError("Record x16 NOR seed size mismatch")
            if self.amd_bank_source_profile is not None:
                inputs = tuple(Path(path) for path in (
                    firmware, loader, legacy_primary_state, legacy_secondary_state,
                    legacy_upper_state, legacy_eeprom_state, self.config.nand_image,
                    self.config.secondary_flash_image,
                ) if path is not None)
                inputs += tuple(record_state.parent / name for name in PERSISTENT_STATE_FILES
                                if name != "record-x16.raw")
                try:
                    prepare_protected_nor_state(record_state, record_seed, inputs)
                except Exception:
                    for channel in (lcd_listener, input_listener, gdb_listener,
                                    audio_listener, audio_host_socket, audio_qemu_socket):
                        if channel is not None:
                            channel.close()
                    self.decoder.close()
                    self.temporary.cleanup()
                    raise
            elif record_state.exists():
                if record_state.stat().st_size != device_size:
                    if (record_state.stat().st_size == size
                            and migrate_erased_raw_state(
                                record_state, size, device_size
                            )):
                        self.state_imports.append(
                            "record-nor-erased-tail-extension"
                        )
                    elif (record_profile == (0xA80000, 0x380000, 0x10000)
                            and record_state.stat().st_size == 0x200000
                            and migrate_erased_raw_state(
                                record_state, 0x200000, device_size,
                                prepend=True
                            )):
                        self.state_imports.append(
                            "record-nor-erased-base-extension"
                        )
                    else:
                        raise ValueError(
                            "persistent Record x16 NOR size mismatch"
                        )
            else:
                record_state.write_bytes(record_seed)
            machine += f",record-x16-nor={base:x}:{size:x}:{sector_size:x}"
            if self.amd_bank_source_profile is not None:
                profile = self.amd_bank_source_profile
                machine += f":{profile['id0']:x}:{profile['id1']:x}"
            storage_args.extend((
                "-drive",
                f"file={record_state},if=pflash,format=raw,unit={pflash_unit}",
            ))
            pflash_unit += 1
            if self.amd_bank_source_profile is not None:
                loader_exclude = base, base + size
                self.config.detection_notes.append(
                    "temporary source-bound AMD x16 bank enabled; logical window only, "
                    "source-derived IDs; physical part and timing unverified"
                )
            else:
                loader_size = base
                self.config.detection_notes.append(
                    "temporary Record x16 NOR selected from exact "
                    "descriptor/map/read-write linkage"
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
        catalog_secondary = False
        if secondary_base is None and catalog_profile is not None:
            secondary_base, secondary_size, _ = catalog_profile
            catalog_secondary = True
        adjacent_amd = find_adjacent_amd_x16_nor(
            detector_image[:self.config.flash_size], self.config.flash_size,
        )
        embedded_secondary = None
        if secondary_base is None and primary_profile is None:
            embedded_secondary = find_embedded_fujitsu_x16_nor(
                bytes(self.decoder.flash.data), self.config.flash_size,
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
            (0xFFFF, 0xFFFF) if catalog_secondary else
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
            secondary_device_size = (
                1 << (secondary_size - 1).bit_length()
                if catalog_secondary else secondary_size
            )
            secondary_name = (
                "catalog-x16.raw" if catalog_secondary else "secondary.raw"
            )
            secondary_state = ((state_dir / secondary_name)
                               if state_dir is not None else
                               (temporary / secondary_name))
            secondary_seed = (
                b"\xff" * secondary_device_size if catalog_secondary else
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
                    if (catalog_secondary
                            and secondary_state.stat().st_size == secondary_size
                            and migrate_erased_raw_state(
                                secondary_state, secondary_size,
                                secondary_device_size
                            )):
                        self.state_imports.append(
                            "catalog-nor-erased-tail-extension"
                        )
                    elif (secondary_state.stat().st_size == 0x200000
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
                if not catalog_secondary:
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
                f"{secondary_base:x}:{secondary_size:x}:"
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
            elif catalog_secondary:
                self.config.detection_notes.append(
                    "temporary descriptor-mapped catalog x16 NOR selected "
                    "from exact mapper/enumerator/read-write linkage"
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
                self.state_imports.append("upper-x16-erased-virtual")
            self.config.detection_notes.append(
                "upper x16 NOR admitted by bound catalog/program/erase consumers; "
                "physical contents and ID remain unverified"
            )
            machine += ",upper-x16-nor=on"
            storage_args.extend((
                "-drive",
                f"file={upper_state},if=pflash,format=raw,unit={pflash_unit}",
            ))
            self.config.detection_notes.append(
                "QEMU mapped upper AMD x16 NOR selected from unique "
                "mapper/descriptor/writer/erase linkage"
            )
        try:
            for name in ("row734", "protected_nor"):
                profile = getattr(self, name + "_source_profile")
                if profile is not None and not qemu_loaded_source_matches(profile, detector_image, primary_seed):
                    setattr(self, name + "_source_profile", None)
                    setattr(self, name + "_reject_reason", name + "-loaded-source-mismatch")
                    self.config.detection_notes.append(
                        f"QEMU {name} rejected: loaded-source-mismatch; native fallback retained")
            nor_property, nor_reject = qemu_protected_nor_properties(
                detector_image, self.config, self.protected_nor_source_profile,
                nor_claimed=bool(storage_args) or upper_nor_present
                or secondary_base is not None or bool(secondary_ids))
            if nor_property is not None:
                profile = self.protected_nor_source_profile
                nor_state = ((state_dir / "protected-nor.raw") if state_dir is not None
                             else temporary / "protected-nor.raw")
                inputs = tuple(Path(path) for path in (
                    firmware, loader, legacy_primary_state, legacy_secondary_state,
                    legacy_upper_state, legacy_eeprom_state, self.config.nand_image,
                    self.config.secondary_flash_image,
                ) if path is not None)
                inputs += tuple(nor_state.parent / name for name in PERSISTENT_STATE_FILES
                                if name != "protected-nor.raw")
                prepare_protected_nor_state(
                    nor_state, primary_seed[profile["address"]:profile["address"] + profile["size"]], inputs)
                machine += "," + nor_property
                storage_args.extend(("-drive", f"file={nor_state},if=none,format=raw,id=msm5xxx-protected-nor-state"))
                self.config.detection_notes.append(
                    "QEMU source-bound protected NOR enabled; original loaded NV seed, "
                    "1ms virtual erase; physical ID and timing unverified")
            elif nor_reject is not None:
                self.protected_nor_reject_reason = nor_reject
                self.config.detection_notes.append(
                    f"QEMU protected NOR rejected: {nor_reject}; native fallback retained")
        except Exception:
            for channel in (lcd_listener, input_listener, gdb_listener,
                            audio_listener, audio_host_socket, audio_qemu_socket):
                if channel is not None:
                    channel.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise
        raw_nand_profile, raw_nand_reject = qemu_raw_nand_main_profile(
            detector_image, self.config
        )
        native_nand, native_nand_reject = qemu_native_nand_profile(
            primary_seed, self.config
        )
        if native_nand_reject is not None:
            self.config.detection_notes.append(
                f"QEMU timed NAND rejected: {native_nand_reject}; native fallback retained"
            )
        if native_nand is not None:
            raw_nand_profile, raw_nand_reject = None, None
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
        try:
            row_property, row_reject = qemu_row734_property(
                detector_image, self.config, self.row734_source_profile,
                input_claimed=(self.matrix_input_profile is not None or boot_property is not None
                               or status_property is not None or experimental_halfword
                               or experimental_low5 or experimental_status_level is not None),
                eeprom_window=(eeprom_profile[0], 32) if eeprom_profile is not None else None)
            if row_property is not None:
                machine += "," + row_property
                self.matrix_input_profile = self.row734_source_profile
                direct_profile = dict(
                    self.row734_source_profile,
                    function=self.row734_source_profile["dispatcher"],
                    event_sink_family=self.row734_source_profile["family"],
                    evidence="source-bound descriptor/scanner/byte-ring; numeric mapping provisional",
                    grammar_fingerprint=self.row734_source_profile["grammar"])
                self.decoder.direct_input_profile = direct_profile
                self.decoder.direct_input_positions = self.decoder._direct_matrix_positions(direct_profile)
                self.decoder.direct_input_detection = "source-native-row734"
                self.config.detection_notes.append(
                    "QEMU source-bound row734 matrix enabled; numeric mappings provisional, "
                    "auxiliary identity and physical timing unverified; secondary UI consumer unverified")
            elif row_reject is not None:
                self.row734_reject_reason = row_reject
                self.config.detection_notes.append(
                    f"QEMU row734 rejected: {row_reject}; native fallback retained")
        except Exception:
            for channel in (lcd_listener, input_listener, gdb_listener,
                            audio_listener, audio_host_socket, audio_qemu_socket):
                if channel is not None:
                    channel.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise
        spi_property, spi_reject = qemu_spi_nv_properties(
            self.config, detector_image,
            input_claimed=(self.matrix_input_profile is not None
                           or self.decoder.direct_input_profile is not None),
            eeprom_claimed=eeprom_profile is not None,
        )
        if spi_property is not None:
            spi_state = ((state_dir / "spi-nv.raw") if state_dir is not None
                         else temporary / "spi-nv.raw")
            inputs = tuple(path for path in (
                firmware, legacy_primary_state, legacy_secondary_state,
                legacy_upper_state,
                Path(self.config.nand_image).expanduser()
                if self.config.nand_image else None,
                Path(self.config.secondary_flash_image).expanduser()
                if self.config.secondary_flash_image else None,
            ) if path is not None)
            try:
                prepare_spi_nv_state(spi_state, inputs)
            except Exception:
                for channel in (lcd_listener, input_listener, gdb_listener,
                                audio_listener, audio_host_socket, audio_qemu_socket):
                    if channel is not None:
                        channel.close()
                self.decoder.close()
                self.temporary.cleanup()
                raise
            machine += "," + spi_property
            storage_args.extend((
                "-drive", f"file={spi_state},if=none,format=raw,"
                "id=msm5xxx-spi-nv-state,cache=writeback",
            ))
            self.config.detection_notes.append(
                "QEMU source-bound virtual serial NVM enabled: 16KiB/page32, "
                "5ms virtual writes; original NV and physical timing unverified"
            )
        elif spi_reject is not None:
            self.config.detection_notes.append(
                f"QEMU serial NVM rejected: {spi_reject}; native fallback retained"
            )
        self.stderr = tempfile.TemporaryFile(mode="w+t")
        try:
            nand_monitor_args = []
            if native_nand is not None:
                if self.config.firmware_sha256 != loaded_firmware.source_sha256:
                    raise ValueError("timed NAND firmware identity mismatch")
                nand_monitor_args = self._prepare_native_nand(
                    native_nand, temporary, state_dir, legacy_primary_state,
                    firmware, legacy_secondary_state, legacy_upper_state,
                )
                machine += ",experimental-small-page-nand=" + ":".join(
                    f"{native_nand[key]:x}" for key in (
                        "data_address", "address_address", "command_address",
                        "ready_address", "ready_mask", "idle_reset_ns"))
                storage_args.extend((
                    "-drive", f"file={self._native_nand_working},if=none,format=raw,"
                    "id=msm5xxx-small-page-nand,cache=writeback",
                ))
            popen_options = (
                {"pass_fds": (audio_qemu_socket.fileno(),)}
                if audio_qemu_socket is not None else {}
            )
            self.process = subprocess.Popen(
                [
                    *qemu_prefix, str(qemu), "-M", machine, "-cpu", "ti925t",
                    "-m", qemu_ram_argument(self.config.ram_size),
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
                          + ("in.voices=0," if desktop_audio_driver == "dsound" else "")
                          + "out.buffer-length=40000"))
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
                    *nand_monitor_args,
                    "-nographic", "-monitor", "none", "-serial", "none",
                    "-S", "-gdb", "chardev:gdb",
                    "-icount", f"shift={icount_shift},align=on,sleep=on",
                    "-no-shutdown",
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
            self._discard_native_nand()
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
                self.lcd_socket = self._accept_qemu(lcd_listener, 'LCD')
                self.input_socket = self._accept_qemu(input_listener, 'input')
                if audio_listener is not None:
                    self.audio_socket = self._accept_qemu(audio_listener, 'audio')
                gdb_socket = self._accept_qemu(gdb_listener, 'GDB')
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
            if self._native_nand_listener is not None:
                self._connect_native_nand_monitor()
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
        except Exception as error:
            self._discard_native_nand()
            startup_error = self._startup_error(error)
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
            raise startup_error from error

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

    def _accept_qemu(self, listener: socket.socket,
                     channel: str = 'transport') -> socket.socket:
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
                        f" connection ({channel}){': ' + detail if detail else ''}"
                    )
        status = self.process.poll()
        if status is not None:
            detail = self._stderr_text()
            raise RuntimeError(
                f"QEMU exited with status {status} before transport"
                f" connection ({channel}){': ' + detail if detail else ''}"
            )
        raise TimeoutError(
            f"timed out waiting for QEMU transport connection ({channel}); "
            "QEMU is still running"
        )

    def _startup_error(self, error: Exception) -> RuntimeError:
        status = self.process.poll()
        # Reap the writer before reading: startup errors may follow socket closure.
        self._terminate_process()
        detail = self._stderr_text()
        message = f"QEMU startup failed: {error}"
        if status is not None:
            message += f"; QEMU exit status {status}"
        if detail:
            message += f"\nQEMU stderr:\n{detail}"
        return RuntimeError(message)

    def _stderr_text(self) -> str:
        self.stderr.flush()
        self.stderr.seek(0)
        return self.stderr.read().strip()

    def _prepare_native_nand(self, profile: dict, temporary: Path,
                             state_dir: Path | None, primary: Path,
                             firmware: Path, secondary: Path,
                             upper: Path | None) -> list[str]:
        state = (state_dir / "native-nand.json" if state_dir is not None else
                 primary.with_name(primary.name + ".native-nand.json"))
        state = state.expanduser().resolve()
        inputs = {path.resolve() for path in (firmware, primary, secondary, upper)
                  if path is not None}
        supplied = getattr(self.config, "nand_image", None)
        if supplied:
            inputs.add(Path(supplied).expanduser().resolve())
        if state.resolve() in inputs or lock_path(state) in inputs:
            raise ValueError("timed NAND state path collides with an input")
        self._native_nand_close_guard = threading.Lock()
        lock = exclusive_path_lock(state)
        lock.__enter__()
        self._native_nand_lock = lock
        if supplied:
            with Path(supplied).expanduser().open("rb") as source:
                seed = source.read(native_nand_state.RAW_BYTES + 1)
            if len(seed) != native_nand_state.RAW_BYTES:
                raise ValueError("timed NAND requires exact full main/OOB bytes")
            self.native_nand_status = "supplied-full-raw"
        else:
            seed = b"\xff" * native_nand_state.RAW_BYTES
            self.native_nand_status = "virtual-erased"
        self._native_nand_seed_sha = hashlib.sha256(seed).hexdigest()
        self._native_nand_firmware_sha = self.config.firmware_sha256
        restored = native_nand_state.load_state(
            state, self._native_nand_firmware_sha, self._native_nand_seed_sha)
        if restored is not None:
            seed = restored
            self.native_nand_status = "qualified-state-restored"
        self._native_nand_state_path = state
        self._native_nand_working = temporary / "nand-working.raw"
        self._native_nand_working.write_bytes(seed)
        self._native_nand_listener = loopback_listener()
        host, port = self._native_nand_listener.getsockname()
        self.config.detection_notes.append(
            "QEMU temporary timed x16 NAND enabled: " + self.native_nand_status
            + "; original resources and physical timing remain unverified")
        return ["-chardev", f"socket,id=nandqmp,host={host},port={port},"
                "server=off,nodelay=on", "-mon", "chardev=nandqmp,mode=control"]

    def _native_nand_receive(self) -> dict:
        line = self._native_nand_reader.readline(65537)
        if not line or len(line) > 65536 or not line.endswith(b"\n"):
            raise ValueError("invalid timed NAND monitor response")
        response = json.loads(line)
        if type(response) is not dict:
            raise ValueError("invalid timed NAND monitor object")
        return response

    def _native_nand_command(self, command: str, arguments: dict | None = None):
        self._native_nand_id += 1
        request = {"execute": command, "id": self._native_nand_id}
        if arguments is not None:
            request["arguments"] = arguments
        self._native_nand_socket.sendall((json.dumps(request) + "\n").encode())
        for _ in range(32):
            response = self._native_nand_receive()
            if (type(response.get("id")) is int
                    and response["id"] == self._native_nand_id):
                if "error" in response or "return" not in response:
                    raise RuntimeError("timed NAND monitor command rejected")
                return response["return"]
        raise RuntimeError("timed NAND monitor response limit")

    def _connect_native_nand_monitor(self) -> None:
        self._native_nand_socket = self._accept_qemu(
            self._native_nand_listener, "timed NAND monitor")
        self._native_nand_listener.close()
        self._native_nand_listener = None
        self._native_nand_socket.settimeout(2)
        self._native_nand_reader = self._native_nand_socket.makefile("rb")
        if "QMP" not in self._native_nand_receive():
            raise ValueError("timed NAND monitor greeting missing")
        self._native_nand_command("qmp_capabilities")

    def _discard_native_nand(self) -> None:
        for name in ("_native_nand_reader", "_native_nand_socket",
                     "_native_nand_listener"):
            channel = getattr(self, name, None)
            if channel is not None:
                channel.close()
                setattr(self, name, None)
        lock = getattr(self, "_native_nand_lock", None)
        if lock is not None:
            self._native_nand_lock = None
            lock.__exit__(None, None, None)

    def _finish_native_nand(self) -> None:
        guard = getattr(self, "_native_nand_close_guard", None)
        if guard is None:
            return
        with guard:
            if self._native_nand_lock is None:
                return
            try:
                if self.process.poll() is not None:
                    raise RuntimeError("native process exited before qualification")
                if self._native_nand_reader is None:
                    self._connect_native_nand_monitor()
                self._native_nand_command("stop")
                status = self._native_nand_command("query-status")
                if type(status) is not dict or status.get("running") is not False:
                    raise RuntimeError("native process did not stop")
                snapshot = json.loads(self._native_nand_command("qom-get", {
                    "path": "/machine", "property": "experimental-small-page-nand-state"}))
                if (type(snapshot) is not dict
                        or any(type(snapshot.get(key)) is not int or snapshot[key] != 1
                               for key in ("enabled", "initialized", "trusted", "safe_to_save"))
                        or type(snapshot.get("pending")) is not int
                        or snapshot["pending"] not in (0, 1, 4)
                        or type(snapshot.get("generation")) is not int
                        or not 0 <= snapshot["generation"] < 1 << 64
                        or type(snapshot.get("persisted")) is not int
                        or snapshot["generation"] != snapshot["persisted"]):
                    raise RuntimeError("native NAND session is unqualified")
                self._native_nand_command("quit")
                if self.process.wait(2) != 0:
                    raise RuntimeError("native process did not close cleanly")
                with self._native_nand_working.open("rb") as source:
                    raw = source.read(native_nand_state.RAW_BYTES + 1)
                native_nand_state.save_state(
                    self._native_nand_state_path, raw,
                    self._native_nand_firmware_sha, self._native_nand_seed_sha)
                self.native_nand_status = "qualified-state-saved"
            except (OSError, ValueError, TypeError, RuntimeError,
                    subprocess.TimeoutExpired) as error:
                self.native_nand_status = "discarded: " + str(error)
                self.config.detection_notes.append(
                    "QEMU timed NAND close/save incomplete; "
                    "last atomic state record remains authoritative: " + str(error))
            finally:
                self._discard_native_nand()

    def _terminate_process(self) -> None:
        self._finish_native_nand()
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
        if getattr(self, "_native_nand_lock", None) is not None:
            self._terminate_process()
        try:
            self.lcd_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.input_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._close_audio_channel()
        self._terminate_process()

    def _close_audio_channel(self) -> None:
        audio_socket = getattr(self, "audio_socket", None)
        if audio_socket is None:
            return
        try:
            audio_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            audio_socket.close()
        except OSError:
            pass

    def _reject_audio_stream(self, reason: str, dropped: int = 0) -> None:
        callback_reason = None
        with self._audio_lock:
            first_rejection = self.audio_stream_status != "rejected"
            if first_rejection:
                self.audio_stream_status = "rejected"
                self.audio_stream_reject_reason = reason
                callback_reason = reason
                self.audio_native = False
                self.native_audio_packets.clear()
                self._audio_ready.notify_all()
            self.audio_stream_dropped = max(self.audio_stream_dropped, dropped)
        transport = getattr(self.decoder, "audio_transport", None)
        if transport is not None and first_rejection:
            transport.renderer_submission(False, callback_reason)

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
        if getattr(self, "audio_native_ma5_pcm", False):
            self.audio_stream_seen = True
            self.audio_stream_order = order
            return
        port = packed & 0xFF
        value = packed >> 8 & 0xFF
        transport = getattr(self.decoder, "audio_transport", None)
        if transport is None and self.audio_native:
            self.audio_stream_seen = True
            self.audio_stream_order = order
            return
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
        admitted = (self.audio_stream_enabled
                    or getattr(self, "audio_native_ma5_pcm", False) is True)
        if (not admitted
                and status == AUDIO_STATUS_RESET
                and record[2:4] == b"\0\0"
                and order == dropped == detail == 0):
            return
        if (not admitted or record[2:4] != b"\0\0"):
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
        elif (status == AUDIO_STATUS_REJECTED and order == dropped == detail == 0
              and getattr(self, "audio_native_ma5_pcm", False)):
            self._reject_audio_stream("qemu-ma5-pcm-output-stopped")
        elif status == AUDIO_STATUS_NATIVE and order == dropped == detail == 0:
            self.audio_native = True
            self.audio_stream_status = "native"
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
        elif record[0] == BOARD_STATUS_TELEMETRY:
            profile = self.config.board_status_input
            address = int.from_bytes(record[4:8], "little")
            if (profile is not None and address == profile.address
                    and record[2] == profile.mask and record[3] == 0
                    and not record[1] & ~profile.mask):
                self.board_status_snapshot = {
                    "level": record[1],
                    "events": int.from_bytes(record[8:12], "little"),
                    "rejections": int.from_bytes(record[12:16], "little"),
                }
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
                    self._reject_audio_stream("qemu-audio-channel-closed")
                return
            pending.extend(chunk)

    def replay(self, stop: threading.Event) -> None:
        input_pending = bytearray()
        lcd_pending = bytearray()
        audio_socket = getattr(self, "audio_socket", None)
        audio_worker = None
        if audio_socket is not None:
            def replay_audio() -> None:
                try:
                    self._replay_native_audio(stop)
                except Exception:
                    if not stop.is_set() and self.process.poll() is None:
                        self._reject_audio_stream("qemu-audio-channel-error")
                finally:
                    if not stop.is_set() and self.process.poll() is None:
                        self._close_audio_channel()

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
                    if complete and audio_socket is not None:
                        # Give the audio reader a turn between bounded batches.
                        time.sleep(0)
        finally:
            stop.set()
            if audio_worker is not None:
                with self._audio_ready:
                    self._audio_ready.notify_all()
                self._close_audio_channel()
                audio_worker.join(1)
        if audio_worker is not None and audio_worker.is_alive():
            self._reject_audio_stream("qemu-audio-worker-stuck")

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

    def _matrix_input_position(
            self, bit: int, event_code: int | None,
    ) -> tuple[int, int, int] | None:
        profile = self.matrix_input_profile
        if profile is not None and profile.get("grammar") == "descriptor-row734-low5-6x5-v1":
            position = self.decoder.direct_input_positions.get(bit) if type(bit) is int and 11 <= bit <= 22 else None
            if position is None or event_code is not None and event_code != position[0]:
                return None
            return position
        if profile is None or profile.get("grammar") not in (
                "indirect-halfword-six-row-v1", "indirect-halfword-mapped-row-v1",
                "indirect-halfword-loop-six-row-v1",
                "distributed-six-byte-numeric-v1"):
            return self.decoder._direct_matrix_position(bit, event_code)
        mappings = profile.get("provisional_mappings")
        confirm = mappings.get(5) if isinstance(mappings, dict) else None
        menu = mappings.get(0) if isinstance(mappings, dict) else None
        token_cells = profile.get("token_cells")
        complete_distributed_cells = True
        complete_navigation_cells = True
        back_cells, complete_back_cells = [], True
        call_cells, complete_call_cells = [], True
        if profile["grammar"] == "distributed-six-byte-numeric-v1":
            if not isinstance(token_cells, (list, tuple)):
                return None
            valid_cells = [cell for cell in token_cells if isinstance(cell, dict)
                           and type(cell.get("event")) is int
                           and type(cell.get("row")) is int and 0 <= cell["row"] < 6
                           and type(cell.get("column")) is int and 0 <= cell["column"] < 4]
            original_back = [cell for cell in token_cells
                             if isinstance(cell, dict) and cell.get("token") == "C"]
            back_cells = [cell for cell in valid_cells if cell.get("token") == "C"]
            original_call = [cell for cell in token_cells
                             if isinstance(cell, dict) and cell.get("token") == "S"]
            call_cells = [cell for cell in valid_cells if cell.get("token") == "S"]
            complete_call_cells = len(original_call) == len(call_cells)
            complete_back_cells = len(original_back) == len(back_cells)
            token_cells = [cell for cell in token_cells if cell not in original_back + original_call]
            valid_cells = [cell for cell in valid_cells if cell.get("token") not in ("C", "S")]
            base_cells = [cell for cell in token_cells
                          if not (isinstance(cell, dict) and cell.get("token") in ("U", "D", "L", "R"))]
            complete_distributed_cells = len(base_cells) == sum(
                cell.get("token") not in ("U", "D", "L", "R") for cell in valid_cells)
            complete_navigation_cells = len(token_cells) - len(base_cells) == sum(
                cell.get("token") in ("U", "D", "L", "R") for cell in valid_cells)
            token_cells = valid_cells
        distributed_controls = (
            profile["grammar"] == "distributed-six-byte-numeric-v1"
            and type(profile.get("rows")) is int and profile["rows"] == 6
            and type(profile.get("columns")) is int and profile["columns"] == 4
            and complete_distributed_cells
            and profile.get("menu_mapping_status") == "accepted-provisional"
            and profile.get("ok_mapping_status") == "accepted-provisional"
            and isinstance(menu, dict) and isinstance(confirm, dict)
            and menu.get("rule") == "same-image-distributed-functional-menu-v1"
            and confirm.get("rule") == "same-image-distributed-functional-confirm-v1"
            and all(mapping.get("semantic_status") == "temporary-evidence-gated-provisional"
                    and mapping.get("functional_only") is True
                    and type(mapping.get("event")) is int and mapping["event"] == event
                    for mapping, event in ((menu, 0x5B), (confirm, 0x53)))
        )
        if distributed_controls:
            events = profile.get("event_codes")
            if (not isinstance(events, (list, tuple)) or len(events) != 24
                    or any(type(event) is not int or not 0 <= event <= 255 for event in events)):
                distributed_controls = False
            else:
                for token, event in (("M", 0x5B), ("O", 0x53)):
                    cells = [cell for cell in token_cells if cell.get("token") == token]
                    if (events.count(event) != 1 or len(cells) != 1
                            or type(cells[0].get("event")) is not int
                            or type(cells[0].get("row")) is not int
                            or type(cells[0].get("column")) is not int
                            or cells[0] != {"token": token, "event": event,
                                            "row": events.index(event) % 6,
                                            "column": events.index(event) // 6}):
                        distributed_controls = False
                        break
        navigation, navigation_token = None, None
        navigation_cells = ((1, "U", 0x63), (9, "D", 0x64),
                            (4, "L", 0x65), (6, "R", 0x66))
        consumer = profile.get("navigation_consumer")
        control = profile.get("control_consumer")
        navigation_valid = (
            distributed_controls
            and complete_navigation_cells
            and profile.get("navigation_mapping_status") == "accepted-provisional"
            and isinstance(consumer, dict) and isinstance(control, dict)
            and consumer.get("grammar") == "distributed-menu-grid-navigation-v1"
            and control.get("grammar") == "distributed-queued-direct-word-controls-v1"
            and type(consumer.get("grid_stride")) is int and consumer["grid_stride"] == 3
            and all(type(consumer.get(field)) is int and consumer[field] > 0
                    and type(control.get(root)) is int
                    and consumer[field] == control.get(root)
                    for field, root in (("handler", "confirm_handler"),
                                        ("status", "confirm_status"),
                                        ("global_word", "global_word")))
        )
        if navigation_valid:
            for key, token, raw in navigation_cells:
                mapping = mappings.get(key)
                cells = [cell for cell in token_cells if cell.get("token") == token]
                if (not any(type(k) is int and k == key for k in mappings)
                        or not isinstance(mapping, dict)
                        or mapping.get("rule") != "same-image-distributed-functional-navigation-v1"
                        or mapping.get("semantic_status") != "temporary-evidence-gated-provisional"
                        or mapping.get("functional_only") is not True
                        or type(mapping.get("event")) is not int or mapping["event"] != raw
                        or events.count(raw) != 1 or len(cells) != 1
                        or sum(cell["event"] == raw for cell in token_cells) != 1
                        or cells[0] != {"token": token, "event": raw,
                                        "row": events.index(raw) % 6,
                                        "column": events.index(raw) // 6}):
                    navigation_valid = False
                    break
            if navigation_valid and type(bit) is int:
                for key, token, _ in navigation_cells:
                    if bit == key:
                        navigation, navigation_token = mappings[key], token
                        break
        back = mappings.get(2) if isinstance(mappings, dict) else None
        back_consumer = profile.get("back_consumer")
        back_valid = (
            navigation_valid and complete_back_cells
            and profile.get("back_mapping_status") == "accepted-provisional"
            and isinstance(back_consumer, dict)
            and back_consumer.get("grammar") == "distributed-saved-menu-back-v1"
            and all(type(back_consumer.get(field)) is int
                    and back_consumer[field] == consumer[field]
                    for field in ("handler", "status", "global_word"))
            and all(type(back_consumer.get(field)) is int
                    and back_consumer[field] > 0 and back_consumer[field] % 4 == 0
                    for field in ("history", "comparison_descriptor", "saved_menu_comparison"))
            and any(type(key) is int and key == 2 for key in mappings)
            and isinstance(back, dict)
            and back.get("rule") == "same-image-distributed-functional-back-v1"
            and back.get("semantic_status") == "temporary-evidence-gated-provisional"
            and back.get("functional_only") is True
            and type(back.get("event")) is int and back["event"] == 0x52
            and events.count(0x52) == 1 and len(back_cells) == 1
            and sum(cell["event"] == 0x52 for cell in token_cells) == 0
            and back_cells[0] == {"token": "C", "event": 0x52,
                                  "row": events.index(0x52) % 6,
                                  "column": events.index(0x52) // 6}
        )
        call_mapping = mappings.get(3) if isinstance(mappings, dict) else None
        call_consumer = profile.get("call_consumer")
        call_valid = (
            distributed_controls and complete_call_cells
            and profile.get("call_mapping_status") == "accepted-provisional"
            and isinstance(call_consumer, dict) and isinstance(control, dict)
            and call_consumer.get("grammar") == "distributed-queued-context-exit-v1"
            and control.get("grammar") == "distributed-queued-direct-word-controls-v1"
            and all(type(call_consumer.get(field)) is int
                    and 0 < call_consumer[field] <= 0xFFFFFFFF
                    and type(control.get(root)) is int
                    and call_consumer[field] == control[root]
                    for field, root in (("handler", "confirm_handler"),
                                        ("status", "confirm_status"),
                                        ("global_word", "global_word")))
            and type(call_consumer.get("event")) is int and call_consumer["event"] == 0x50
            and type(call_consumer.get("request_code")) is int and call_consumer["request_code"] == 0x32
            and any(type(key) is int and key == 3 for key in mappings)
            and isinstance(call_mapping, dict)
            and call_mapping.get("rule") == "same-image-distributed-functional-call-v1"
            and call_mapping.get("semantic_status") == "temporary-evidence-gated-provisional"
            and call_mapping.get("functional_only") is True
            and type(call_mapping.get("event")) is int and call_mapping["event"] == 0x50
            and events.count(0x50) == 1 and len(call_cells) == 1
            and sum(cell["event"] == 0x50 for cell in token_cells) == 0
            and call_cells[0] == {"token": "S", "event": 0x50,
                                  "row": events.index(0x50) % 6,
                                  "column": events.index(0x50) // 6}
        )
        functional_call = call_valid and type(bit) is int and bit == 3
        if call_valid:
            token_cells = token_cells + call_cells
        functional_back = back_valid and type(bit) is int and bit == 2
        if back_valid:
            token_cells = token_cells + back_cells
        if profile["grammar"] == "distributed-six-byte-numeric-v1" and not navigation_valid:
            token_cells = [cell for cell in token_cells if cell.get("token") not in ("U", "D", "L", "R")]
        functional_menu = distributed_controls and type(bit) is int and bit == 0
        functional_confirm = (
            type(bit) is int and bit == 5
            and profile.get("ok_mapping_status") == "accepted-provisional"
            and isinstance(confirm, dict)
            and ((profile["grammar"] == "indirect-halfword-loop-six-row-v1"
                  and confirm.get("rule") == "same-image-loop-functional-confirm-v1")
                 or (profile["grammar"] == "indirect-halfword-mapped-row-v1"
                     and type(profile.get("rows")) is int and type(profile.get("columns")) is int
                     and (profile.get("rows"), profile.get("columns")) == (7, 4)
                     and profile.get("menu_mapping_status") == "accepted-provisional"
                     and isinstance(menu, dict)
                     and menu.get("rule") == "same-image-mapped-physical-menu-v1"
                     and menu.get("semantic_status") == "temporary-evidence-gated-provisional"
                     and menu.get("physical_only") is True
                     and type(menu.get("event")) is int and menu["event"] == 0x5B
                     and confirm.get("rule") == "same-image-mapped-functional-confirm-v1")
                 or distributed_controls)
            and confirm.get("semantic_status") == "temporary-evidence-gated-provisional"
            and confirm.get("functional_only") is True
            and type(confirm.get("event")) is int and confirm["event"] == 0x53
        )
        physical_menu = (
            profile["grammar"] == "indirect-halfword-mapped-row-v1"
            and type(bit) is int and bit == 0
            and profile.get("menu_mapping_status") == "accepted-provisional"
            and isinstance(menu, dict)
            and menu.get("rule") == "same-image-mapped-physical-menu-v1"
            and menu.get("semantic_status") == "temporary-evidence-gated-provisional"
            and menu.get("physical_only") is True
            and type(menu.get("event")) is int and menu["event"] == 0x5B
        )
        event = (call_mapping["event"] if functional_call else
                 back["event"] if functional_back else
                 navigation["event"] if navigation is not None else
                 confirm["event"] if functional_confirm else
                 menu["event"] if physical_menu or functional_menu else
                 SAMSUNG_RING32_KEY_EVENTS.get(bit)) if event_code is None else event_code
        if (profile["grammar"] in ("indirect-halfword-mapped-row-v1", "distributed-six-byte-numeric-v1",
                                  "indirect-halfword-loop-six-row-v1")
                and (type(event) is not int or event not in b"123456789*0#")):
            mapping = (call_mapping if functional_call else back if functional_back else navigation if navigation is not None else confirm if functional_confirm
                       else menu if physical_menu or functional_menu else None)
            if type(event) is not int or mapping is None or event != mapping["event"]:
                return None
            events = profile.get("event_codes", ())
            token, rows = (("S", 6) if functional_call else ("C", 6) if functional_back else
                          (navigation_token, 6) if navigation is not None else
                          ("O", 7 if profile["grammar"] == "indirect-halfword-mapped-row-v1" else 6)
                           if functional_confirm else ("M", 6 if functional_menu else 7))
            tokens = [cell for cell in token_cells if cell.get("token") == token]
            if (not isinstance(events, (list, tuple)) or len(events) != rows * 4
                    or events.count(event) != 1 or len(tokens) != 1):
                return None
            index = events.index(event)
            if tokens[0] != {"token": token, "event": event,
                             "row": index % rows, "column": index // rows}:
                return None
        cells = [cell for cell in token_cells if cell["event"] == event]
        # No table-order fallback or ambiguous semantic aliases.
        if len(cells) != 1:
            return None
        cell = cells[0]
        return cell["event"], cell["row"], cell["column"]

    def _sideband_input_producer(
            self, bit: int, event_code: int | None,
    ) -> dict[str, object] | None:
        if (self.matrix_input_profile is not None
                and self.matrix_input_profile.get("grammar") == "distributed-six-byte-numeric-v1"):
            if getattr(self, "matrix_input_sideband_producer", None) is None:
                return None
            producer = self.decoder._direct_sideband_producer(
                bit, event_code, self.matrix_input_profile)
            return (producer if producer == self.matrix_input_sideband_producer else None)
        if (self.matrix_input_profile is not None and
                self.matrix_input_profile.get("grammar") in (
                    "indirect-halfword-six-row-v1", "indirect-halfword-mapped-row-v1",
                "indirect-halfword-loop-six-row-v1",
                )):
            return None
        producer = self.decoder._direct_sideband_producer(bit, event_code)
        return (producer if producer == self.matrix_input_sideband_producer
                else None)

    def can_set_fold(self) -> bool:
        profile = self.config.board_status_input
        return (profile is not None and profile.mask > 0
                and profile.mask & (profile.mask - 1) == 0
                and self.board_status_snapshot is not None)

    def set_fold(self, opened: bool) -> bool:
        """Experimental polarity: asserted detector default means open.

        Capability and current state come from native readback, not a sent key.
        """
        if not isinstance(opened, bool) or not self.can_set_fold():
            return False
        profile = self.config.board_status_input
        level = profile.default if opened else profile.default ^ profile.mask
        try:
            self.input_socket.sendall(bytes((HOST_BOARD_STATUS, level, 0, 0)))
        except OSError as error:
            self.decoder.input_error = f"QEMU fold transport failed: {error}"
            return False
        self.decoder.input_error = ""
        return True

    def can_set_key(self, bit: int, event_code: int | None = None) -> bool:
        profile = self.matrix_input_profile
        return (profile is not None and
                (self._sideband_input_producer(bit, event_code) is not None
                 or self._matrix_input_position(bit, event_code)
                 is not None))

    def set_key(self, bit: int, pressed: bool,
                event_code: int | None = None) -> bool:
        profile = self.matrix_input_profile
        if profile is None and (pressed or bit not in self.sideband_held):
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
            position = self._matrix_input_position(bit, event_code)
            if sideband is not None:
                packet = sideband_input_command(sideband, True)
            elif position is not None:
                packet = matrix_input_command(profile, position, True)
            else:
                return False
        else:
            position = self.matrix_held.get(bit)
            if bit in self.sideband_held:
                # Release the approved physical contact even if metadata changed.
                packet = sideband_input_command({}, False)
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
        if getattr(self, "_native_nand_lock", None) is not None:
            self._terminate_process()
        self.lcd_socket.close()
        self.input_socket.close()
        self._close_audio_channel()
        self._terminate_process()
        self.stderr.close()
        self.decoder.close()
        self.temporary.cleanup()
