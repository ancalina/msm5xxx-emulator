"""Firmware detection pipeline and configuration assembly."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import struct

from ..core.config import FirmwareConfig

from .arm import arm_vector_score
from .boot import (
    AUDIO_PLAY_SIGNATURE, BOARD_ADC_SIGNATURE, BUSY_DELAY_SIGNATURE,
    CRC16_SIGNATURE, DELAY_SIGNATURE, DMD_DOWNLOAD_510X_SIGNATURE,
    DMD_DOWNLOAD_SIGNATURE, FAST_BOOT_SIGNATURE, FLASH_ID_SIGNATURE,
    LEGACY_EFS_PAGE_READ_SIGNATURE, LEGACY_SECONDARY_FLASH_READ_SIGNATURE,
    LEGACY_SECONDARY_FLASH_WRITE_SIGNATURE, MEMORY_CLEAR_128_SIGNATURE,
    MEMORY_CLEAR_LOOP_SIGNATURE, MEMORY_COPY_LOOP_SIGNATURE,
    NAND_BAD_BLOCK_SIGNATURE, NAND_READ_SIGNATURE, NAND_WRITE_SIGNATURE,
    PRIMARY_FLASH_PROBE_SIGNATURE, REGISTER_RAMP_PREFIX,
    SECONDARY_FLASH_WRAPPER_PATTERN, find_ma2_silent_boot_wait,
    detect_guest_owned_status_72c,
)
from .chipset import chipset_confidence, detect_chipset
from .display import detect_lcd_width_hint, find_framebuffer_layout
from .input import find_board_adc_reader, find_board_status_input
from .memory_layout import (
    find_arm_memory_copy_addresses, find_arm_vector_offset, find_linker_layout,
    find_missing_overlays, find_overlays, find_runtime_overlays, infer_ram_base,
    normalised_flash_size, plausible_ram_seed_size, referenced_flash_extent,
    restore_sparse_nor_gap,
)
from .model import (detect_model, embedded_model_scores,
                    verified_embedded_model)
from .rex import (REX_TICK_SIGNATURE, find_rex_5ms_irq_arm,
                  find_rex_5ms_irq_route, find_rex_5ms_sleep_timer,
                  find_rex_idle_address)
from .signatures import find_all
from .storage import (find_24lcxx_driver, find_compound_fujitsu_layout,
                      find_fujitsu_x16_bulk_write, flash_id_for_size)


_embedded_model_scores = embedded_model_scores
_verified_embedded_model = verified_embedded_model


ADDRESS_SPACE = 1 << 32


MAX_FLASH_SIZE = 0x04000000


DEFAULT_STATE_ROOT = Path(os.environ.get(
    "MSM5XXX_STATE_DIR", Path.home() / ".msm5xxx-emulator"
)).expanduser()


KNOWN_SCREENS = {
    "LG-SD810": (120, 160),
    "LG-SV130": (176, 220),
    "SCH-E100": (128, 160),
    "SCH-E170": (176, 220),
    "SCH-E370": (128, 160),
    "SCH-E135": (128, 160),
    "SCH-E470": (176, 220),
    "SCH-V540": (176, 220),
    "SCH-X430": (128, 160),
}


DISABLEABLE_ADDRESS_FIELDS = frozenset({
    "delay_address", "busy_delay_address", "secondary_flash_read_address",
    "secondary_flash_write_address", "legacy_efs_page_read_address",
    "eeprom_read_address", "eeprom_write_address", "eeprom_geometry_address",
    "nand_bad_block_address", "nand_read_address", "nand_write_address",
    "rex_idle_address", "rex_tick_address", "rex_irq_wrapper_address",
    "board_adc_address",
    "flash_id_address", "crc16_address", "dmd_download_address",
    "primary_flash_probe_address", "board_revision_register",
    "framebuffer_address", "framebuffer_flush_address",
    "framebuffer_rect_flush_address",
})


MSM_REVISION_BLOCK = 0x03000740


MSM_REVISION_REGISTER = MSM_REVISION_BLOCK + 0x1C


MSM_REVISION_RAW_F022 = 0x20F2


def _file_identity(filename: str | None) -> str:
    if not filename:
        return ""
    digest = hashlib.sha256()
    try:
        with Path(filename).expanduser().open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
    except OSError:
        # Construction reports the useful missing/unreadable-file error.  A
        # stable path token still prevents it aliasing an unrelated seed.
        digest.update(str(Path(filename).expanduser()).encode("utf-8"))
    return digest.hexdigest()[:16]


def default_state_paths(path: Path, image: bytes, flash_size: int,
                        secondary_size: int, secondary_image: str | None = None,
                        nand_image: str | None = None,
                        nand_geometry: tuple[int, int, int, int, int] | None = None,
                        secondary_generated_efs: bool = False,
                        secondary_seed: bytes | None = None,
                        ) -> tuple[str, str]:
    identity = hashlib.sha256(image[:flash_size]).hexdigest()[:16]
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", path.stem)[:48] or "firmware"
    seed_identity = _file_identity(secondary_image)
    internal_seed_identity = (hashlib.sha256(secondary_seed).hexdigest()[:16]
                              if secondary_seed is not None else "")
    nand_identity = _file_identity(nand_image)
    suffix = ((f"-s{seed_identity}" if seed_identity else "")
              + (f"-si{internal_seed_identity}"
                 if internal_seed_identity and not seed_identity else "")
              + ("-sefs" if secondary_generated_efs and not seed_identity else "")
              + (f"-n{nand_identity}" if nand_identity else "")
              + ("-g" + "-".join(f"{value:x}" for value in nand_geometry)
                 if nand_geometry else ""))
    base = (DEFAULT_STATE_ROOT / "firmware"
            / f"{stem}-{identity}-{flash_size:x}{suffix}")
    return f"{base}.flash.json", f"{base}.efs-{secondary_size:x}.json"


def _apply_overrides(
        config: FirmwareConfig, overrides: argparse.Namespace, *,
        image: bytes, primary_image: bytes,
        compound_fujitsu: tuple[int, int] | None,
        required_flash_extent: int, auto_relative: set[str],
        clear_layout: list[tuple[int | None, bool]],
        copy_layout: list[tuple[int | None, bool]],
        ramp_layout: list[tuple[int | None, bool]]) -> None:
    for key in ("model", "chipset", "width", "height",
                "framebuffer_address", "framebuffer_stride", "framebuffer_format",
                "framebuffer_flush_address", "framebuffer_rect_flush_address",
                "board_revision",
                "board_revision_register", "board_revision_value", "image_offset",
                "load_address", "flash_size", "secondary_flash_address",
                "secondary_flash_size", "secondary_flash_image",
                "secondary_flash_image_offset",
                "secondary_flash_state", "secondary_flash_read_address",
                "secondary_flash_write_address", "legacy_efs_page_read_address",
                "eeprom_read_address", "eeprom_write_address",
                "eeprom_geometry_address",
                "ram_base", "ram_size",
                "ram_image_offset", "ram_image_size", "entry",
                "key_register", "key_active_low",
                "audio_play_address", "fast_boot_address", "delay_address",
                "busy_delay_address", "nand_bad_block_address",
                "nand_read_address", "nand_write_address", "nand_enabled",
                "nand_image", "nand_data_size", "nand_page_size", "nand_spare_size",
                "nand_pages_per_block", "nand_bus_width",
                "rex_idle_address", "rex_tick_address",
                "rex_irq_wrapper_address", "rex_irq_arm_address",
                "rex_tick_ms",
                "board_adc_address", "board_adc_value",
                "flash_id_address", "flash_id_value", "crc16_address",
                "dmd_download_address",
                "primary_flash_probe_address",
                "flash_state"):
        value = getattr(overrides, key, None)
        if value is not None:
            setattr(config, key, value)
    if (getattr(overrides, "framebuffer_stride", None) is None
            and config.framebuffer_address is not None
            and (getattr(overrides, "width", None) is not None
                 or config.framebuffer_stride <= 0)):
        config.framebuffer_stride = ((config.width + 7) // 8) * 16
    if (getattr(overrides, "framebuffer_address", None) is not None
            and getattr(overrides, "framebuffer_format", None) is None):
        config.framebuffer_format = "rgb565le"
    if (getattr(overrides, "framebuffer_address", None) == 0
            or getattr(overrides, "framebuffer_format", None) == "none"):
        config.framebuffer_address = None
        config.framebuffer_stride = 0
        config.framebuffer_format = "none"
        config.framebuffer_flush_address = None
        config.framebuffer_rect_flush_address = None
    for field in DISABLEABLE_ADDRESS_FIELDS:
        if getattr(overrides, field, None) == 0:
            setattr(config, field, None)
    if getattr(overrides, "nand_enabled", None) is None and config.nand_image:
        config.nand_enabled = True
    if (getattr(overrides, "secondary_flash_image", None) is not None
            and getattr(overrides, "secondary_flash_image_offset", None) is None):
        config.secondary_flash_image_offset = None
    if config.board_revision_value is None:
        try:
            config.board_revision_value = int(config.board_revision, 0)
        except ValueError:
            pass
    if (getattr(overrides, "chipset", None) is not None
            and getattr(overrides, "ram_base", None) is None):
        config.ram_base = infer_ram_base(
            config.linker, config.chipset, primary_image
        )
    if (getattr(overrides, "model", None) is not None
            and getattr(overrides, "width", None) is None
            and getattr(overrides, "height", None) is None):
        config.width, config.height = KNOWN_SCREENS.get(
            config.model, (config.width, config.height)
        )
    if getattr(overrides, "flash_size", None) is None:
        limit = (config.ram_base - config.load_address
                 if config.ram_base > config.load_address
                 else min(MAX_FLASH_SIZE, ADDRESS_SPACE - config.load_address))
        config.flash_size = (compound_fujitsu[0] if compound_fujitsu else
                             normalised_flash_size(
                                 max(len(image), required_flash_extent), limit
                             ))
    if getattr(overrides, "secondary_flash_size", None) is None:
        config.secondary_flash_size = (compound_fujitsu[1]
                                       if compound_fujitsu
                                       else config.flash_size)
    if getattr(overrides, "ram_image_offset", None) is None:
        config.ram_image_offset = (
            config.secondary_flash_image_offset + config.secondary_flash_size
            if config.secondary_flash_image_offset is not None
            else config.flash_size
        )
    if getattr(overrides, "ram_image_size", None) is None:
        config.ram_image_size = plausible_ram_seed_size(
            len(image), config.ram_image_offset, config.ram_size
        )
    if config.secondary_flash_address in (None, 0):
        config.secondary_flash_image_offset = None
    if (getattr(overrides, "flash_id_value", None) is None
            and config.flash_id_address is not None):
        config.flash_id_value = flash_id_for_size(config.flash_size)
    if config.load_address:
        for field in auto_relative:
            if getattr(overrides, field, None) is None:
                address = getattr(config, field)
                if address is not None:
                    setattr(config, field, config.load_address + address)
        config.memory_clear_addresses = [
            config.load_address + address if relative else address
            for address, relative in clear_layout if address is not None
        ]
        config.memory_copy_addresses = [
            config.load_address + address if relative else address
            for address, relative in copy_layout if address is not None
        ]
        config.register_ramp_addresses = [
            config.load_address + address if relative else address
            for address, relative in ramp_layout if address is not None
        ]


def _infer_secondary_nor(
        config: FirmwareConfig, image: bytes,
        overrides: argparse.Namespace | None) -> None:
    # These MSM5500 boards use a second AMD NOR for EFS/NV between boot ROM
    # and SDRAM.  It is not a mirror of the firmware chip.
    secondary_nor_detected = (
        config.flash_id_address is not None
        and config.secondary_flash_read_address is not None
        and b"fsd_amd.c\0" in image
        and b"\x0b$USER_DIRS\0" in image
        and bytes.fromhex("0120c0052060") in image
        and config.flash_size == 0x800000
    )
    # The wrapper signatures above are useful when present, but several
    # otherwise identical MSM5500 builds inline their AMD routines.  The
    # physical layout and filesystem fingerprints are independent evidence:
    # an 8 MiB program NOR, another 8 MiB slot before SDRAM, the AMD driver,
    # and a GEFS root marker.  This covers the E110/V-series family without
    # treating an arbitrary partial image as a second flash chip.
    family_secondary_nor_detected = (
        config.chipset == "MSM5500"
        and config.flash_size == config.secondary_flash_size == 0x800000
        and config.ram_base - (config.load_address + config.flash_size)
        == config.secondary_flash_size
        and b"fsd_amd.c\0" in image
        and b"\x0b$USER_DIRS\0" in image
    )
    legacy_secondary_nor_detected = (
        config.legacy_efs_page_read_address is not None
        and config.secondary_flash_read_address is not None
        and config.secondary_flash_write_address is not None
        and config.chipset == "MSM5500"
        and config.flash_size == 0x800000
    )
    if (config.secondary_flash_address is None
            and (secondary_nor_detected or legacy_secondary_nor_detected
                 or family_secondary_nor_detected)
            and config.ram_base - (config.load_address + config.flash_size)
            == config.secondary_flash_size):
        config.secondary_flash_address = config.load_address + config.flash_size
        if family_secondary_nor_detected and not (
                secondary_nor_detected or legacy_secondary_nor_detected):
            config.detection_notes.append(
                "secondary AMD NOR inferred from MSM5500 8+8 MiB layout and GEFS driver"
            )
    if (config.flash_id_address is not None
            and (overrides is None or getattr(overrides, "flash_id_value", None) is None)):
        detected_size = (config.secondary_flash_size
                         if config.secondary_flash_address not in (None, 0)
                         else config.flash_size)
        config.flash_id_value = flash_id_for_size(detected_size)


def _configure_state_paths(
        config: FirmwareConfig, path: Path, image: bytes,
        overrides: argparse.Namespace | None) -> bytes | None:
    internal_secondary_seed = None
    if (config.secondary_flash_image_offset is not None
            and not config.secondary_flash_image):
        start = config.secondary_flash_image_offset
        end = start + config.secondary_flash_size
        if 0 <= start < end <= len(image):
            internal_secondary_seed = image[start:end]
    state_flash, state_secondary = default_state_paths(
        path, image, config.flash_size, config.secondary_flash_size,
        config.secondary_flash_image, config.nand_image,
        ((config.nand_data_size, config.nand_page_size, config.nand_spare_size,
         config.nand_pages_per_block, config.nand_bus_width)
         if config.nand_enabled else None),
        (config.secondary_flash_address not in (None, 0)
         and not config.secondary_flash_image
         and config.secondary_flash_image_offset is None
         and b"\x0b$USER_DIRS\0" in image),
        secondary_seed=internal_secondary_seed,
    )
    if overrides is None or getattr(overrides, "flash_state", None) is None:
        config.flash_state = state_flash
    if overrides is None or getattr(overrides, "secondary_flash_state", None) is None:
        config.secondary_flash_state = state_secondary
    return internal_secondary_seed


def _finalize_dump_status(
        config: FirmwareConfig, image: bytes,
        internal_secondary_seed: bytes | None) -> None:
    missing = max(0, config.flash_size - len(image))
    trailer = max(0, len(image) - config.flash_size)
    config.missing_overlays = find_missing_overlays(
        image, config.flash_size, config.load_address
    )
    config.runtime_overlays = find_runtime_overlays(
        image, config.ram_base, config.ram_size
    )
    if config.runtime_overlays:
        config.detection_notes.append(
            f"{len(config.runtime_overlays)} internal-RAM overlay candidate(s) "
            "use SDRAM source; runtime provenance required before "
            "partition-load inference"
        )
    if internal_secondary_seed is not None:
        config.dump_status = (
            f"complete compound NOR image; primary 0x{config.flash_size:X} + "
            f"secondary 0x{config.secondary_flash_size:X}"
        )
        config.detection_notes.append(
            "Fujitsu x16 command bus and GEFS records prove internal "
            "secondary NOR image"
        )
    elif missing:
        config.dump_status = f"partial NOR; padded 0x{missing:X} erased bytes"
        config.detection_notes.append(
            f"dump is 0x{missing:X} bytes shorter than inferred NOR capacity"
        )
        for overlay in config.missing_overlays:
            config.detection_notes.append(
                "missing executable overlay source "
                f"0x{overlay.source:X}..0x{overlay.source + overlay.size:X}"
            )
    elif trailer:
        if config.ram_image_size:
            config.dump_status = f"full NOR + 0x{trailer:X} RAM snapshot"
        else:
            config.dump_status = f"full NOR + 0x{trailer:X} small trailer"
    else:
        config.dump_status = "complete NOR image"


def detect(path: Path, overrides: argparse.Namespace | None = None) -> FirmwareConfig:
    raw = path.read_bytes()
    requested_image_offset = (getattr(overrides, "image_offset", None)
                              if overrides else None)
    vector_offset, vector_score = find_arm_vector_offset(raw)
    image_offset = (vector_offset if requested_image_offset is None
                    and vector_score >= 4 else requested_image_offset or 0)
    if not 0 <= image_offset < len(raw):
        raise ValueError(f"image offset outside firmware: 0x{image_offset:X}")
    # Keep the complete capture for model strings, EFS discovery, and an
    # optional RAM seed.  Code/layout discovery must only inspect primary NOR:
    # full dumps commonly append a live RAM snapshot containing copied code.
    image, sparse_gap = restore_sparse_nor_gap(raw[image_offset:])
    requested_load_address = (getattr(overrides, "load_address", None)
                              if overrides else None)
    requested_load_address = 0 if requested_load_address is None else requested_load_address
    if not 0 <= requested_load_address < ADDRESS_SPACE:
        raise ValueError("load address outside 32-bit address space")
    model_scores = _embedded_model_scores(image)
    model = detect_model(image, path, model_scores)
    verified_model = _verified_embedded_model(image, model_scores)
    if verified_model != model:
        verified_model = None
    override_model = (getattr(overrides, "model", None) if overrides else None)
    hardware_model = override_model or verified_model
    chipset = detect_chipset(image, hardware_model or "")
    confidence = chipset_confidence(image, chipset)
    vector_score = arm_vector_score(image)
    image_kind = "firmware" if vector_score >= 2 else "data/non-bootable"
    detection_notes: list[str] = []
    if image_kind != "firmware":
        detection_notes.append("no valid ARM exception vector table")
    elif image_offset and requested_image_offset is None:
        detection_notes.append(
            f"skipped 0x{image_offset:X}-byte dump header before ARM vectors"
        )
    if sparse_gap is not None:
        gap_offset, gap_size = sparse_gap
        detection_notes.append(
            f"restored 0x{gap_size:X}-byte erased sparse NOR gap at "
            f"0x{gap_offset:X} from boot-table and vector references"
        )
    if confidence == "unknown":
        detection_notes.append("no generation-specific clock/boot BSP marker")
    if chipset == "MSM6050":
        detection_notes.append("MSM6050 is outside the supported 5000/5100/5500 scope")
    scan_chipset = ((getattr(overrides, "chipset", None) if overrides else None)
                    or chipset)
    scan_ram_base = (getattr(overrides, "ram_base", None)
                     if overrides else None)
    if scan_ram_base is None:
        scan_ram_base = (0x01000000
                         if scan_chipset in ("MSM5000", "MSM5500")
                         else 0x01800000)
    requested_flash_size = (getattr(overrides, "flash_size", None)
                            if overrides else None)
    compound_fujitsu = (find_compound_fujitsu_layout(
        image, requested_load_address
    ) if requested_flash_size is None else None)
    required_flash_extent = referenced_flash_extent(
        image, requested_load_address
    )
    if requested_flash_size is None:
        scan_limit = (scan_ram_base - requested_load_address
                      if scan_ram_base > requested_load_address
                      else min(MAX_FLASH_SIZE,
                               ADDRESS_SPACE - requested_load_address))
        scan_flash_size = (compound_fujitsu[0] if compound_fujitsu else
                           normalised_flash_size(
                               max(len(image), required_flash_extent),
                               min(MAX_FLASH_SIZE, scan_limit),
                           ))
    else:
        if requested_flash_size <= 0:
            raise ValueError("flash size must be positive")
        scan_flash_size = requested_flash_size
    primary_image = image[:min(len(image), scan_flash_size)]
    guest_owned_status_72c, status_72c_note = detect_guest_owned_status_72c(
        primary_image
    )
    if status_72c_note is not None:
        detection_notes.append(status_72c_note)
    board_status_input = find_board_status_input(primary_image)
    if board_status_input is not None:
        detection_notes.append(
            "Thumb byte-status mask/branch/debounce shape detected board-status input"
        )
    width, height = KNOWN_SCREENS.get(hardware_model or "", (176, 220))
    revision_match = re.search(rb"(?:HW|BOARD)[ _-]?REV(?:ISION)?[^\x00\r\n]{0,24}", image, re.I)
    revision = revision_match.group().decode("ascii", "replace") if revision_match else "auto/unknown"
    auto_relative: set[str] = set()

    def direct_signature(field: str, signature: bytes) -> int | None:
        position = primary_image.find(signature)
        if (position < 0
                or primary_image.find(signature, position + 1) >= 0):
            return None
        auto_relative.add(field)
        return position

    linker = find_linker_layout(primary_image, requested_load_address)
    audio_address = direct_signature("audio_play_address", AUDIO_PLAY_SIGNATURE)
    fast_boot_address = direct_signature("fast_boot_address", FAST_BOOT_SIGNATURE)
    delay_address = direct_signature("delay_address", DELAY_SIGNATURE)
    busy_delay_address = direct_signature("busy_delay_address", BUSY_DELAY_SIGNATURE)
    rex_tick_address = direct_signature("rex_tick_address", REX_TICK_SIGNATURE)
    rex_idle_address = find_rex_idle_address(primary_image)
    rex_irq_route = None
    rex_irq_arm_address = None
    rex_tick_ms = 1000
    if rex_idle_address is not None:
        auto_relative.add("rex_idle_address")
    rex_5ms_pair = (find_rex_5ms_sleep_timer(primary_image)
                    if rex_idle_address is None and rex_tick_address is None
                    else None)
    if rex_5ms_pair is not None:
        rex_idle_address, rex_tick_address, rex_tick_ms = rex_5ms_pair
    board_adc_address = direct_signature("board_adc_address", BOARD_ADC_SIGNATURE)
    board_adc_reader_position = find_board_adc_reader(primary_image)
    overlays = find_overlays(primary_image, requested_load_address)

    def mapped_position(position: int) -> tuple[int | None, bool]:
        if position < 0:
            return None, False
        for overlay in overlays:
            if overlay.source <= position < overlay.source + overlay.size:
                return overlay.target + position - overlay.source, False
        if (linker is not None
                and linker.data_source <= position < linker.data_source + linker.data_size):
            return linker.data_target + position - linker.data_source, False
        return position, True

    def runtime_position(field: str, position: int) -> int | None:
        address, relative = mapped_position(position)
        if address is not None and relative:
            auto_relative.add(field)
        return address

    def mapped_runtime(position: int) -> int | None:
        address, relative = mapped_position(position)
        if address is not None and relative:
            address += requested_load_address
        return address

    board_adc_reader_address = (
        runtime_position("board_adc_reader_address", board_adc_reader_position)
        if board_adc_reader_position is not None else None
    )
    if board_adc_reader_address is not None:
        detection_notes.append(
            "Thumb ADC reader shape and channel-gated MMIO data path detected"
        )

    if rex_5ms_pair is not None:
        idle_position, tick_position, rex_tick_ms = rex_5ms_pair
        rex_idle_address = mapped_runtime(idle_position)
        rex_tick_address = mapped_runtime(tick_position)
        rex_irq_route = find_rex_5ms_irq_route(
            primary_image, tick_position, mapped_runtime
        )
        detection_notes.append(
            "REX sleep loop and periodic wrapper prove 5 ms timer-list advance"
        )
        if rex_irq_route is not None:
            rex_irq_arm_address = find_rex_5ms_irq_arm(
                primary_image, tick_position
            )
            detection_notes.append(
                "REX IRQ wrapper/controller route proves firmware 5 ms delivery"
            )

    def runtime_signature(field: str, signature: bytes) -> int | None:
        position = primary_image.find(signature)
        if (position < 0
                or primary_image.find(signature, position + 1) >= 0):
            return None
        return runtime_position(field, position)

    ma2_wait = find_ma2_silent_boot_wait(primary_image)
    ma2_silent_boot_address = (
        runtime_position("ma2_silent_boot_address", ma2_wait)
        if ma2_wait is not None else None
    )
    if ma2_silent_boot_address is not None:
        detection_notes.append(
            "Yamaha MA2 silent boot stub detected; status-wait calls return "
            "success without device emulation"
        )

    framebuffer = find_framebuffer_layout(primary_image)
    framebuffer_address = None
    framebuffer_stride = 0
    framebuffer_format = "none"
    framebuffer_flush_address = None
    framebuffer_rect_flush_address = None
    if framebuffer is not None:
        width, height, framebuffer_address, framebuffer_stride, row, rect = framebuffer
        framebuffer_format = "rgb565le"
        framebuffer_flush_address = runtime_position("framebuffer_flush_address", row)
        framebuffer_rect_flush_address = runtime_position(
            "framebuffer_rect_flush_address", rect
        )

    nand_bad_block_address = runtime_signature("nand_bad_block_address",
                                               NAND_BAD_BLOCK_SIGNATURE)
    nand_read_address = runtime_signature("nand_read_address", NAND_READ_SIGNATURE)
    nand_write_address = runtime_signature("nand_write_address", NAND_WRITE_SIGNATURE)
    flash_id_address = runtime_signature("flash_id_address", FLASH_ID_SIGNATURE)
    crc16_address = runtime_signature("crc16_address", CRC16_SIGNATURE)
    dmd_download_address = runtime_signature("dmd_download_address",
                                             DMD_DOWNLOAD_SIGNATURE)
    if dmd_download_address is None:
        dmd_download_address = runtime_signature(
            "dmd_download_address", DMD_DOWNLOAD_510X_SIGNATURE
        )
    primary_flash_probe_address = runtime_signature(
        "primary_flash_probe_address", PRIMARY_FLASH_PROBE_SIGNATURE
    )
    secondary_flash_read_address = None
    secondary_flash_write_address = None
    legacy_efs_page_read_address = runtime_signature(
        "legacy_efs_page_read_address", LEGACY_EFS_PAGE_READ_SIGNATURE
    )
    wrapper_offset = 0
    wrapper_reads: list[int] = []
    wrapper_writes: list[int] = []
    while match := SECONDARY_FLASH_WRAPPER_PATTERN.search(
            primary_image, wrapper_offset):
        if match.group("dispatch") == b"\xc3\x6b":
            wrapper_reads.append(match.start())
        else:
            wrapper_writes.append(match.start())
        wrapper_offset = match.start() + 2
    if len(wrapper_reads) == 1:
        secondary_flash_read_address = runtime_position(
            "secondary_flash_read_address", wrapper_reads[0])
    if len(wrapper_writes) == 1:
        secondary_flash_write_address = runtime_position(
            "secondary_flash_write_address", wrapper_writes[0])
    legacy_read = runtime_signature(
        "secondary_flash_read_address", LEGACY_SECONDARY_FLASH_READ_SIGNATURE
    )
    legacy_write = runtime_signature(
        "secondary_flash_write_address", LEGACY_SECONDARY_FLASH_WRITE_SIGNATURE
    )
    if secondary_flash_read_address is None:
        secondary_flash_read_address = legacy_read
    if secondary_flash_write_address is None:
        secondary_flash_write_address = legacy_write
    if secondary_flash_write_address is None:
        bulk_write = find_fujitsu_x16_bulk_write(
            primary_image, requested_load_address + scan_flash_size
        )
        if bulk_write is not None:
            secondary_flash_write_address = runtime_position(
                "secondary_flash_write_address", bulk_write
            )
            detection_notes.append(
                "Fujitsu x16 bulk writer proves adjacent secondary NOR command bus"
            )
    eeprom_read_address = None
    eeprom_write_address = None
    eeprom_geometry_address = None
    eeprom_driver = find_24lcxx_driver(primary_image)
    if eeprom_driver is not None:
        eeprom_read, eeprom_write, eeprom_geometry_address = eeprom_driver
        eeprom_read_address = runtime_position(
            "eeprom_read_address", eeprom_read
        )
        eeprom_write_address = runtime_position(
            "eeprom_write_address", eeprom_write
        )
        detection_notes.append(
            "24LCxx EEPROM read/write driver and geometry descriptor detected"
        )
    clear_positions = [
        *find_all(primary_image, MEMORY_CLEAR_LOOP_SIGNATURE),
        *find_all(primary_image, MEMORY_CLEAR_128_SIGNATURE),
    ]
    clear_layout = [mapped_position(position)
                    for position in dict.fromkeys(clear_positions)]
    copy_layout = [mapped_position(position)
                   for position in find_all(primary_image,
                                            MEMORY_COPY_LOOP_SIGNATURE)]
    ramp_layout = [mapped_position(position + len(REGISTER_RAMP_PREFIX))
                   for position in find_all(primary_image, REGISTER_RAMP_PREFIX)]
    memory_clear_addresses = [address for address, _relative in clear_layout
                              if address is not None]
    memory_copy_addresses = [address for address, _relative in copy_layout
                             if address is not None]
    register_ramp_addresses = [address for address, _relative in ramp_layout
                               if address is not None]
    arm_memory_copy_addresses = find_arm_memory_copy_addresses(
        primary_image, overlays, linker, requested_load_address
    )
    # Some Samsung/LG builds inline the raw small-page NAND primitives, so no
    # standalone function signature survives.  The filesystem driver marker
    # plus all three physical command/address/data port literals is a stronger
    # board-level condition than any model-name guess.
    raw_nand_ports = (
        b"fs_ks_nand.c" in primary_image.lower()
        and all(struct.pack("<I", port) in primary_image
                for port in (0x01800000, 0x01900000, 0x01A00000))
    )
    nand_enabled = (raw_nand_ports or any(item is not None for item in (
        nand_bad_block_address, nand_read_address, nand_write_address
    )))
    if raw_nand_ports and all(item is None for item in (
            nand_bad_block_address, nand_read_address, nand_write_address)):
        detection_notes.append(
            "raw NAND enabled from fs_ks_nand driver and physical port literals"
        )
    needs_msm_revision = (b" Unsupported MSM REV " in primary_image
                          and struct.pack("<I", MSM_REVISION_BLOCK)
                          in primary_image)
    ram_base = infer_ram_base(linker, chipset, primary_image)
    requested_ram_base = (getattr(overrides, "ram_base", None)
                          if overrides else None)
    if requested_ram_base is not None:
        ram_base = requested_ram_base
    flash_size = (compound_fujitsu[0] if compound_fujitsu else
                  normalised_flash_size(
                      max(len(image), required_flash_extent), ram_base
                  ))
    compound_secondary_size = compound_fujitsu[1] if compound_fujitsu else None
    compound_secondary_offset = flash_size if compound_fujitsu else None
    compound_secondary_seed = (
        image[compound_secondary_offset:
              compound_secondary_offset + compound_secondary_size]
        if compound_secondary_offset is not None
        and compound_secondary_size is not None else None
    )
    default_flash_state, default_secondary_state = default_state_paths(
        path, image, flash_size,
        compound_secondary_size or flash_size,
        secondary_seed=compound_secondary_seed,
    )
    config = FirmwareConfig(
        path=str(path), file_size=len(raw),
        firmware_sha256=hashlib.sha256(raw).hexdigest(), model=model, chipset=chipset,
        chipset_confidence=confidence, image_kind=image_kind,
        dump_status="pending", detection_notes=detection_notes,
        width=width, height=height, board_revision=revision,
        framebuffer_address=framebuffer_address,
        framebuffer_stride=framebuffer_stride,
        framebuffer_format=framebuffer_format,
        framebuffer_flush_address=framebuffer_flush_address,
        framebuffer_rect_flush_address=framebuffer_rect_flush_address,
        board_revision_register=(0x00DFFFDC if hardware_model == "SCH-E470"
                                 else MSM_REVISION_REGISTER
                                 if needs_msm_revision else None),
        board_revision_value=(0x1D if hardware_model == "SCH-E470"
                              else MSM_REVISION_RAW_F022
                              if needs_msm_revision else None),
        board_status_input=board_status_input,
        image_offset=image_offset, load_address=0,
        flash_size=flash_size,
        secondary_flash_address=(requested_load_address + flash_size
                                 if compound_fujitsu else None),
        secondary_flash_size=compound_secondary_size or flash_size,
        secondary_flash_image=None,
        secondary_flash_image_offset=compound_secondary_offset,
        secondary_flash_state=default_secondary_state,
        secondary_flash_read_address=secondary_flash_read_address,
        secondary_flash_write_address=secondary_flash_write_address,
        legacy_efs_page_read_address=legacy_efs_page_read_address,
        eeprom_read_address=eeprom_read_address,
        eeprom_write_address=eeprom_write_address,
        eeprom_geometry_address=eeprom_geometry_address,
        ram_base=ram_base,
        ram_size=0x00800000,
        ram_image_offset=(compound_secondary_offset + compound_secondary_size
                          if compound_secondary_offset is not None
                          and compound_secondary_size is not None else flash_size),
        ram_image_size=0 if compound_fujitsu else plausible_ram_seed_size(
            len(image), flash_size
        ), entry=0,
        # No generic MSM keypad data register is proven.  In particular, the
        # legacy 0x03000738 value is a Samsung GPIO control write target, not
        # a scanner read contract.  A user-supplied override remains supported.
        key_register=None, key_active_low=True,
        audio_play_address=audio_address,
        ma2_silent_boot_address=ma2_silent_boot_address,
        fast_boot_address=fast_boot_address,
        nand_bad_block_address=nand_bad_block_address,
        nand_read_address=nand_read_address,
        nand_write_address=nand_write_address,
        delay_address=delay_address,
        busy_delay_address=busy_delay_address,
        nand_enabled=nand_enabled,
        nand_image=None,
        nand_data_size=0x1000000 if nand_bad_block_address is not None else 0x800000,
        nand_page_size=512, nand_spare_size=16, nand_pages_per_block=32,
        nand_bus_width=2,
        rex_idle_address=rex_idle_address,
        rex_tick_address=rex_tick_address,
        rex_irq_wrapper_address=(rex_irq_route[0] if rex_irq_route else None),
        rex_irq_handler_address=(rex_irq_route[1] if rex_irq_route else None),
        rex_irq_handler_slot=(rex_irq_route[2] if rex_irq_route else None),
        rex_irq_callback_slot=(rex_irq_route[3] if rex_irq_route else None),
        rex_irq_status_address=(rex_irq_route[4] if rex_irq_route else None),
        rex_irq_enable_address=(rex_irq_route[5] if rex_irq_route else None),
        rex_irq_arm_address=rex_irq_arm_address,
        rex_irq_mask=(rex_irq_route[6] if rex_irq_route else 0),
        rex_tick_ms=rex_tick_ms,
        board_adc_address=board_adc_address,
        board_adc_reader_address=board_adc_reader_address,
        board_adc_value=0xC2,
        flash_id_address=flash_id_address,
        flash_id_value=(flash_id_for_size(flash_size)
                        if flash_id_address is not None else None),
        crc16_address=crc16_address,
        dmd_download_address=dmd_download_address,
        primary_flash_probe_address=primary_flash_probe_address,
        memory_clear_addresses=memory_clear_addresses,
        memory_copy_addresses=memory_copy_addresses,
        register_ramp_addresses=register_ramp_addresses,
        arm_memory_copy_addresses=arm_memory_copy_addresses,
        flash_state=default_flash_state,
        linker=linker, overlays=overlays, missing_overlays=[], runtime_overlays=[],
        verified_model=hardware_model,
        guest_owned_status_72c=guest_owned_status_72c,
    )
    if overrides is not None:
        _apply_overrides(
            config, overrides, image=image, primary_image=primary_image,
            compound_fujitsu=compound_fujitsu,
            required_flash_extent=required_flash_extent,
            auto_relative=auto_relative, clear_layout=clear_layout,
            copy_layout=copy_layout, ramp_layout=ramp_layout,
        )
    _infer_secondary_nor(config, image, overrides)
    internal_secondary_seed = _configure_state_paths(
        config, path, image, overrides
    )
    _finalize_dump_status(config, image, internal_secondary_seed)
    return config
