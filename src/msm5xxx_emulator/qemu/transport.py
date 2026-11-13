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
from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.detection.registry import device_domain
find_seven_row_input_profile = device_domain('input.distributed7').find_seven_row_input_profile
from .decoder import QemuDecoder
from ..core.initial_state import REGISTER_NAMES, initial_register_state
from msm5xxx_emulator.core.constants import STABLE_MSM_MMIO
from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.startup_sdram import reset_copy_ram_profile
find_boot_format_nor = device_domain('storage.boot_format_nor').find_boot_format_nor
find_seven_row_scanners = device_domain('input.seven_row').find_seven_row_scanners
find_seven_row_board_status = device_domain('input.seven_row').find_seven_row_board_status
find_boot_keysense_release = device_domain('input.boot_keysense').find_boot_keysense_release
find_spi_nv_profile = device_domain('storage.spi_nv').find_spi_nv_profile
EXTERNAL_BUS_BOOLEAN_PROPERTIES = device_domain('external_bus.projection').EXTERNAL_BUS_BOOLEAN_PROPERTIES
EXTERNAL_BUS_INTEGER_PROPERTIES = device_domain('external_bus.projection').EXTERNAL_BUS_INTEGER_PROPERTIES
qemu_external_bus_property = device_domain('external_bus.projection').external_bus_property
from msm5xxx_emulator.detection.contracts import (
    loaded_source_matches as _loaded_source_matches,
    source_class_limit as _firmware_source_class_limit,
)
_ready_poll_domain = device_domain('ready_poll')
qemu_ready_poll_property = _ready_poll_domain.ready_poll_property
qemu_runtime_ready_poll_property = _ready_poll_domain.runtime_ready_poll_property
eeprom_gpio_profile = device_domain('eeprom').eeprom_gpio_profile
qemu_watchdog_property = device_domain('watchdog.rules').watchdog_property
small_page_nand_profile = device_domain('storage.small_page_nand').small_page_nand_profile
find_middle_nand_profile = device_domain('storage.middle_nand').find_middle_nand_profile
find_static_middle_nand_profile = device_domain('storage.static_middle_nand').find_static_middle_nand_profile
find_low_port_nand_driver = device_domain('storage.low_port_nand').find_low_port_nand_driver
find_table7_matrix = device_domain('input.table7').find_table7_matrix
find_guarded_middle_nand_profile = device_domain('storage.guarded_middle_nand').find_guarded_middle_nand_profile
from . import nand_state as native_nand_state
resolve_indirect_matrix_input = device_domain('input.halfword').resolve_indirect_matrix_input
resolve_indirect_board_status = device_domain('input.halfword_status').resolve_indirect_board_status
_descriptor_mmio_provenance = device_domain('input.descriptor')._descriptor_mmio_provenance
find_kp_legacy_scanner = device_domain('input.lg_kp').find_kp_legacy_scanner
find_kp2600_scanner = device_domain('input.lg_kp2600').find_kp2600_scanner
sv130_keypad_source = device_domain('input.sv130').sv130_keypad_source
sd810_fold_irq_source = device_domain('input.sd810').sd810_fold_irq_source
sd810_gpio_board_status_profile = device_domain('input.sd810').sd810_gpio_board_status_profile
ASCII_KEY_EVENTS = device_domain('input.matrix').ASCII_KEY_EVENTS
_samsung_sideband_51_family_metadata = device_domain('input.matrix')._samsung_sideband_51_family_metadata
resolve_distributed_matrix_input = device_domain('input.matrix').resolve_distributed_matrix_input
from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.detection.arm import (
    _thumb_path_preserves_register,
    thumb_bl_target,
    thumb_literal_value,
)
DMD_DOWNLOAD_SIGNATURE = device_domain('dmd.boot_rules').DMD_DOWNLOAD_SIGNATURE
find_ma2_silent_boot_wait = device_domain('audio.boot_rules').find_ma2_silent_boot_wait
from msm5xxx_emulator.detection.firmware_image import load_firmware_image
from msm5xxx_emulator.detection.facts import bind_facts, source_prefix, with_fact_scope
from msm5xxx_emulator.detection.image_view import ImageView
from msm5xxx_emulator.detection.layout_queries import restore_sparse_nor_gap
_KP6200_MA3_SITES = device_domain('audio.rules')._KP6200_MA3_SITES
_SV130_MA3_SITES = device_domain('audio.rules')._SV130_MA3_SITES
find_audio_transport = device_domain('audio.rules').find_audio_transport
find_ma5_readback_candidate = device_domain('audio.rules').find_ma5_readback_candidate
find_ma5_gpio_irq_candidate = device_domain('audio.ma5_gpio_irq').find_ma5_gpio_irq_candidate
find_ma3_gpio_irq_candidate = device_domain('audio.ma3_gpio_irq').find_ma3_gpio_irq_candidate
find_stack_w1c_irq_profile = device_domain('rex.stack_w1c').find_stack_w1c_irq_profile
legacy_nv_tuple = device_domain('storage.nv_nor').legacy_nv_tuple
select_legacy_nv_nor = device_domain('storage.nv_nor').select_legacy_nv_nor
UIS_IDLE_BODY_DELTAS = device_domain('rex.rules').UIS_IDLE_BODY_DELTAS
find_rex_static_controller_callback_candidate = device_domain('rex.rules').find_rex_static_controller_callback_candidate
find_rex_legacy_row0_profile = device_domain('rex.rules').find_rex_legacy_row0_profile
direct_amd_x16_nor_profile = device_domain('storage.rules').direct_amd_x16_nor_profile
direct_intel_x16_nor_profile = device_domain('storage.rules').direct_intel_x16_nor_profile
flash_id_for_size = device_domain('storage.rules').flash_id_for_size
fujitsu_x16_flash_ids = device_domain('storage.rules').fujitsu_x16_flash_ids
find_adjacent_amd_x16_nor = device_domain('storage.rules').find_adjacent_amd_x16_nor
find_adjacent_fujitsu_x16_nor = device_domain('storage.rules').find_adjacent_fujitsu_x16_nor
find_catalog_amd_x16_nor = device_domain('storage.rules').find_catalog_amd_x16_nor
find_embedded_fujitsu_x16_nor = device_domain('storage.rules').find_embedded_fujitsu_x16_nor
find_primary_fsd_amd_x16_nor = device_domain('storage.rules').find_primary_fsd_amd_x16_nor
find_record_amd_x16_nor = device_domain('storage.rules').find_record_amd_x16_nor
mapped_primary_intel_x16_nor_profile = device_domain('storage.rules').mapped_primary_intel_x16_nor_profile
primary_probe_x16_nor_profile = device_domain('storage.rules').primary_probe_x16_nor_profile
seeded_amd_x16_nor_profile = device_domain('storage.rules').seeded_amd_x16_nor_profile
UPPER_FLASH_ADDRESS = device_domain('storage.upper_nor').UPPER_FLASH_ADDRESS
UPPER_FLASH_SIZE = device_domain('storage.upper_nor').UPPER_FLASH_SIZE
find_upper_amd_x16_nor = device_domain('storage.upper_nor').find_upper_amd_x16_nor
from msm5xxx_emulator.devices.storage.nor import NORFlash
from msm5xxx_emulator.state_io import (
    atomic_write_bytes,
    atomic_write_text,
    exclusive_path_lock,
    lock_path,
)


class IOSLauncher:
    """Launch through the app's built-in module, never through subprocess.

    The host owns one QEMU thread and must guard QEMU's exit paths. Its
    start(argv), poll(), terminate(), kill(), wait(timeout) methods form the
    process contract; wait raises TimeoutError on timeout. No POSIX signals or
    thread cancellation may be used by the host. stdout/stderr go to app logs.
    """

    supports_pass_fds = False

    def __init__(self, host=None):
        if host is None:
            import _msm5xxx_ios_host as host
        self.host = host

    def __call__(self, argv, **options):
        if options.get("pass_fds"):
            raise ValueError("iOS launcher requires TCP audio chardevs")
        arguments = list(argv)
        if not arguments or any(not isinstance(arg, str) or "\0" in arg
                                for arg in arguments):
            raise ValueError("invalid in-process QEMU arguments")
        self.host.start(arguments)
        return _IOSProcess(self.host, arguments)


class _IOSProcess:
    def __init__(self, host, args):
        self.host = host
        self.args = args

    def poll(self):
        return self.host.poll()

    def terminate(self):
        self.host.terminate()

    def kill(self):
        self.host.kill()

    def wait(self, timeout=None):
        try:
            return self.host.wait(timeout)
        except TimeoutError as error:
            raise subprocess.TimeoutExpired(self.args, timeout) from error


def launch_qemu(argv, *, launcher=None, **options):
    """Keep subprocess as the desktop/Android default; hosts opt in explicitly."""
    return (subprocess.Popen if launcher is None else launcher)(argv, **options)


RECORD_SIZE = 16
_LCD_RECORD = struct.Struct("<BB2xIII")
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
PAUSE_TIMER_ADDRESS = device_domain("boot.transport_projection").PAUSE_TIMER_ADDRESS
PERSISTENT_STATE_FILES = (
    "primary-writable.raw", "secondary.raw", "upper.raw", "upper-x16.raw",
    "eeprom.raw", "spi-nv.raw", "protected-nor.raw", "nand-main.raw", "intel-x16.raw", "amd-x16.raw",
    "record-x16.raw", "catalog-x16.raw", "mapped-primary-x16.raw",
    "mapped-primary-x16-upper.raw",
    "native-nand.json",
)
LEGACY_STATE_OWNER = ".firmware-sha256"
PAUSE_TIMER_LDR_OFFSETS = device_domain("boot.transport_projection").PAUSE_TIMER_LDR_OFFSETS
PAUSE_TIMER_FIXED_HELPER = device_domain("boot.transport_projection").PAUSE_TIMER_FIXED_HELPER
AUDIO_SITE_LIMIT = device_domain("audio.transport_projection").AUDIO_SITE_LIMIT
RAW_NAND_STATUS_SIGNATURE = device_domain("storage.transport_projection").RAW_NAND_STATUS_SIGNATURE
RAW_NAND_RESET_SIGNATURE = device_domain("storage.transport_projection").RAW_NAND_RESET_SIGNATURE
RAW_NAND_PAGE_SIGNATURE = device_domain("storage.transport_projection").RAW_NAND_PAGE_SIGNATURE
RAW_NAND_BLOCK_PREFIX = device_domain("storage.transport_projection").RAW_NAND_BLOCK_PREFIX
RAW_NAND_BLOCK_SUFFIX = device_domain("storage.transport_projection").RAW_NAND_BLOCK_SUFFIX
RAW_NAND_X16_PREFIX = device_domain("storage.transport_projection").RAW_NAND_X16_PREFIX
RAW_NAND_X16_TRANSFER = device_domain("storage.transport_projection").RAW_NAND_X16_TRANSFER

qemu_legacy_keypad_status_available = device_domain('input.transport_projection').qemu_legacy_keypad_status_available


qemu_legacy_keypad_source_matches = device_domain('input.transport_projection').qemu_legacy_keypad_source_matches


qemu_legacy_board_revision_property = device_domain('boot.transport_projection').qemu_legacy_board_revision_property


qemu_sharp_board_status_property = device_domain('storage.transport_projection').qemu_sharp_board_status_property


matrix_senses = device_domain('input.transport_projection').matrix_senses


qemu_kp2600_matrix_property = device_domain('input.transport_projection').qemu_kp2600_matrix_property


qemu_kp2600_irq_compatible = device_domain('input.transport_projection').qemu_kp2600_irq_compatible


qemu_sd810_sxs_menu_selection = device_domain('input.transport_projection').qemu_sd810_sxs_menu_selection


qemu_low5_matrix_property = device_domain('input.transport_projection').qemu_low5_matrix_property


qemu_sd840_low5_contacts = device_domain('input.transport_projection').qemu_sd840_low5_contacts


qemu_sd9210_low5_contacts = device_domain('input.transport_projection').qemu_sd9210_low5_contacts


qemu_sd840_numeric_profile = device_domain('input.transport_projection').qemu_sd840_numeric_profile


qemu_kp_low5_property = device_domain('input.transport_projection').qemu_kp_low5_property


qemu_kp2100_low5_property = device_domain('input.transport_projection').qemu_kp2100_low5_property


qemu_kp2100_status_source = device_domain('input.transport_projection').qemu_kp2100_status_source


qemu_lg_matrix_irq_property = device_domain('input.transport_projection').qemu_lg_matrix_irq_property


qemu_matching_lg_irq = device_domain('input.transport_projection').qemu_matching_lg_irq


qemu_sd840_status_source = device_domain('input.transport_projection').qemu_sd840_status_source


qemu_low5_rex_c80_property = device_domain('input.transport_projection').qemu_low5_rex_c80_property


qemu_sv130_initial_ram_seed = device_domain('input.transport_projection').qemu_sv130_initial_ram_seed


qemu_ram_argument = device_domain('memory.transport_projection').qemu_ram_argument


qemu_memory_profile = device_domain('memory.transport_projection').qemu_memory_profile


qemu_ram_reserved_property = device_domain('memory.transport_projection').qemu_ram_reserved_property


qemu_native_nand_profile = device_domain('storage.transport_projection').qemu_native_nand_profile


qemu_uis_idle_observer_addresses = device_domain('rex.transport_projection').qemu_uis_idle_observer_addresses


qemu_rex_idle_candidate_observer_address = device_domain('rex.transport_projection').qemu_rex_idle_candidate_observer_address


qemu_upper_nor_enabled = device_domain('storage.transport_projection').qemu_upper_nor_enabled


qemu_raw_nand_main_profile = device_domain('storage.transport_projection').qemu_raw_nand_main_profile


qemu_audio_irq_property = device_domain('audio.transport_projection').qemu_audio_irq_property


qemu_ma3_gpio_irq_property = device_domain('audio.transport_projection').qemu_ma3_gpio_irq_property


qemu_audio_packet_property = device_domain('audio.transport_projection').qemu_audio_packet_property


qemu_virtual_cell_property = device_domain('baseband.transport_projection').qemu_virtual_cell_property


qemu_ma5_readback_property = device_domain('audio.transport_projection').qemu_ma5_readback_property


qemu_ma5_temporary_auto_property = device_domain('audio.transport_projection').qemu_ma5_temporary_auto_property


qemu_ma5_gpio_irq_property = device_domain('audio.transport_projection').qemu_ma5_gpio_irq_property


qemu_audio_sites = device_domain('audio.transport_projection').qemu_audio_sites


qemu_mapped_scan_gate_property = device_domain('input.transport_projection').qemu_mapped_scan_gate_property


qemu_halfword_matrix_property = device_domain('input.transport_projection').qemu_halfword_matrix_property


qemu_distributed_sideband_producer = device_domain('input.transport_projection').qemu_distributed_sideband_producer


qemu_distributed_matrix_property = device_domain('input.transport_projection').qemu_distributed_matrix_property


qemu_seven_row_matrix_property = device_domain('input.transport_projection').qemu_seven_row_matrix_property


qemu_halfword_status_property = device_domain('input.transport_projection').qemu_halfword_status_property


from msm5xxx_emulator.detection.contracts import boot_storage_profile as _boot_storage_profile


qemu_boot_keysense_property = device_domain('input.transport_projection').qemu_boot_keysense_property


qemu_boot_contact_property = device_domain('external_bus.transport_projection').qemu_boot_contact_property


qemu_spi_nv_properties = device_domain('storage.transport_projection').qemu_spi_nv_properties


qemu_basic_row0_property = device_domain('rex.transport_projection').qemu_basic_row0_property


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


qemu_loaded_source_matches = _loaded_source_matches


_source_class_limit = _firmware_source_class_limit


qemu_amd_bank_profile = device_domain('storage.transport_projection').qemu_amd_bank_profile


qemu_row734_property = device_domain('input.transport_projection').qemu_row734_property


qemu_protected_nor_properties = device_domain('storage.transport_projection').qemu_protected_nor_properties


def qemu_uart_console_property(
        profile: object, image_size: int) -> tuple[str | None, str | None]:
    return device_domain("uart_console").qemu_uart_console_property(profile, image_size)


def qemu_loaded_uart_console_property(
        profile: dict, original: bytes, loaded: bytes, config: object,
        *, ram_claimed: bool = False,
        nor_overlay: tuple[int, int] | None = None,
) -> tuple[str | None, str | None]:
    return device_domain("uart_console").qemu_loaded_uart_console_property(
        profile, original, loaded, config, ram_claimed=ram_claimed,
        nor_overlay=nor_overlay)


def qemu_sbi_raw_input_property(
        config: object, profile: object) -> tuple[str | None, str | None]:
    return device_domain('sbi').qemu_sbi_raw_input_property(config, profile)


def qemu_uart2_tx_property(original: bytes, loaded: bytes, config: object,
                           *, claimed: bool = False) -> str | None:
    uart2_tx_property = device_domain('uart2.rules').uart2_tx_property
    return uart2_tx_property(original, loaded, config, claimed=claimed)


def qemu_sbi_property(config: object) -> tuple[str | None, str | None]:
    return device_domain('sbi').bootstrap_property(config)


def qemu_sbi_repeat_property(image: bytes, config: object) -> str | None:
    return device_domain('sbi').repeat_property(image, config)


qemu_board_revision_property = device_domain('boot.transport_projection').qemu_board_revision_property


adjacent_amd_x16_flash_ids = device_domain('storage.transport_projection').adjacent_amd_x16_flash_ids


qemu_dmd5100_property = device_domain('dmd.selection').qemu_dmd5100_property


def qemu_dmd5000_property(original: bytes, loaded: bytes, config: object, **options):
    return device_domain('dmd').qemu_dual_property(
        original, loaded, config,
        uart_windows=device_domain('uart_console').resource_windows(
            getattr(config, 'uart_console', None)), **options)


def qemu_dmd_5500_property(image: bytes, config: object, immutable_limit=None):
    return device_domain('dmd').qemu_5500_property(image, config, immutable_limit)


matrix_input_command = device_domain('input.transport_projection').matrix_input_command


sideband_input_command = device_domain('input.transport_projection').sideband_input_command


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


def detector_firmware_image(image: bytes, image_offset: int, *,
                            supplied: ImageView | None = None) -> bytes:
    """Match the canonical detector's header and sparse-gap normalization."""
    if not 0 <= image_offset < len(image):
        raise ValueError("image offset outside firmware")
    normalized, gap = restore_sparse_nor_gap(image[image_offset:])
    if supplied is not None:
        bind_facts(normalized, supplied.normalized(
            image_offset, size=len(normalized), gap=gap))
    return normalized


select_primary_x16_nor_profile = device_domain('storage.transport_projection').select_primary_x16_nor_profile


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


qemu_pause_timer_profile = device_domain('boot.transport_projection').qemu_pause_timer_profile


legacy_dmd_loader_patch = device_domain('boot.transport_projection').legacy_dmd_loader_patch


ma2_silent_boot_loader_patch = device_domain('boot.transport_projection').ma2_silent_boot_loader_patch


c80_rex_irq_profile = device_domain('rex.transport_projection').c80_rex_irq_profile


_legacy_620_rex_irq_profile = device_domain('rex.transport_projection')._legacy_620_rex_irq_profile


read_consume_rex_irq_profile = device_domain('rex.transport_projection').read_consume_rex_irq_profile


w1c_rex_irq_profile = device_domain('rex.transport_projection').w1c_rex_irq_profile


qemu_stack_w1c_property = device_domain('rex.transport_projection').qemu_stack_w1c_property


qemu_legacy_nv_nor_profile = device_domain('storage.transport_projection').qemu_legacy_nv_nor_profile

_input_event_projection = device_domain('input.event_projection')


class Transport:
    _matrix_input_position = _input_event_projection._matrix_input_position
    _sideband_input_producer = _input_event_projection._sideband_input_producer

    @with_fact_scope
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
                 experimental_ma5_pcm_output: bool = False,
                 launcher=None) -> None:
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
        self._network_monitor = None
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
            firmware_image, self.config.image_offset,
            supplied=getattr(loaded_firmware, 'image_view', None)
        )
        from ..devices.storage.descriptor_state import load_truncated_nor_state
        original_flash_size = self.config.flash_size
        truncated_bank_profile = truncated_legacy_state = None
        extent_plan = device_domain('storage.descriptor_plan').early_plan(detector_image, self.config)
        if extent_plan.capabilities:
            extent_options = dict(extent_plan.capabilities[0].parameters)
            extent, profile = extent_options['extent'], extent_options['profile']
            state = load_truncated_nor_state(detector_image, original_flash_size, profile, Path(self.config.flash_state))
            if state is not None:
                self.config.flash_size = extent
                missing = extent - len(detector_image)
                self.config.dump_status = f"partial NOR; padded 0x{missing:X} erased bytes"
                self.config.detection_notes.append(
                    f"source-linked NOR extent 0x{extent:X}; 0x{missing:X} unprovided bytes are erased")
                truncated_bank_profile, truncated_legacy_state = profile, state
        self.boot_format_nor_profile = find_boot_format_nor(
            detector_image, self.config.ram_base, self.config.ram_size)
        find_row734_input_profile = device_domain('input.row734').find_row734_input_profile
        find_protected_nor_profile = device_domain('storage.protected_nor').find_protected_nor_profile
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
        (controller,) = device_domain('rex.selection').select_controller(self, detector_image, experimental_c80, source_limit)
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
        self.input_send_started_ns = 0
        self.input_send_completed_ns = 0
        self.input_send_duration_ns = 0
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
        self.audio_native_ma3_pcm = False
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
                if (os.name == "posix"
                        and getattr(launcher, "supports_pass_fds", True)):
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
        secondary_gpio_property = device_domain('display.secondary_gpio_raster').loaded_property(
            detector_image, self.decoder.image, self.config, self.decoder._lcd_secondary_panel is not None)
        if secondary_gpio_property is not None:
            from msm5xxx_emulator.devices.display.secondary_gpio_raster import SecondaryGpioRaster
            self.decoder._lcd_secondary_panel = SecondaryGpioRaster()
            self.decoder._lcd_secondary_reason = "copied-gpio-raster-awaiting-complete-frame"
            machine += ',' + secondary_gpio_property
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
        adc_properties = device_domain('sbi').adc_properties(self.config)
        if adc_properties:
            machine += ',' + adc_properties
        # Keep the established property slot while admission waits for the
        # final persistent/loader bytes below.
        sbi_slot = len(machine)
        ready_property, ready_reject, ready_owner = qemu_runtime_ready_poll_property(
            detector_image, self.config)
        if ready_owner == "indexed-lcd":
            self.config.detection_notes.append(
                "QEMU closed indexed LCD bridge status enabled; "
                "source-PC and selector bound, synchronous display writes"
            )
        elif ready_owner == "arm-tx":
            self.config.detection_notes.append(
                "QEMU source-closed ARM UART TX-empty pulse enabled; "
                "existing Thumb consumer retained, no inbound RX data"
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
        uart_deferred = device_domain('uart_console').requires_loaded_source(
            getattr(self.config, 'uart_console', None))
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
        find_legacy_six_row_keypad = device_domain('input.legacy_keypad').find_legacy_six_row_keypad
        legacy_keypad = find_legacy_six_row_keypad(detector_image)
        if revision_property is None and revision_reject is None:
            revision_property = qemu_legacy_board_revision_property(
                detector_image, self.config.flash_size, legacy_keypad)
            if revision_property is not None:
                self.config.detection_notes.append("source-qualified board revision 0x60")
        if revision_property is not None:
            machine += f",{revision_property}"
        elif revision_reject is not None:
            self.config.detection_notes.append(
                f"QEMU board-revision bridge rejected: {revision_reject}; "
                "native fallback retained"
            )
        (machine, legacy_keypad, board_status, seven_row_status, status_property,) = device_domain('input.machine').select_inputs(self, detector_image, legacy_keypad, machine, experimental_distributed, experimental_halfword, experimental_low5, experimental_ma5_irq, experimental_status_level, temporary)
        audio = self.config.audio_transport
        audio_family = audio.get("family") if audio is not None else None
        audio_grammar = audio.get("grammar") if audio is not None else None
        tone_generator = getattr(self.config, "tone_generator", None)
        if (isinstance(tone_generator, dict) and
                tone_generator.get("static_status") == "accepted"):
            machine += ",tone=on"
            if os.environ.get("MSM5XXX_TONE_LOG") == "1":
                machine += ",tone-log=on"
            self.config.detection_notes.append(
                "QEMU register-level two-channel tone block enabled from static firmware evidence")
            if not audio_pcm:
                machine += ",audio-pcm=off"
                self.audio_stream_status = "native"
            elif audio_listener is not None or audio_qemu_socket is not None:
                machine += ",audio-stream-chardev=audio"
                self.audio_stream_enabled = True
                self.audio_stream_status = "pending"
            else:
                desktop_audio_driver = (
                    "coreaudio" if sys.platform == "darwin" else
                    "dsound" if sys.platform == "win32" else "alsa"
                )
                machine += ",audiodev=msm5xxx"
                self.audio_native = True
        ma3_indexed_ram_profile = device_domain('audio.selection').indexed_ram_profile(audio, self.config)
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
                ma5_auto_irq = device_domain('audio.selection').automatic_irq(detector_image)
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
        else:
            audio_selection = device_domain('audio.selection').boot_transport_selection(
                detector_image, audio, self.config,
                ma3_indexed_ram_profile=ma3_indexed_ram_profile,
                upper_nor_present=upper_nor_present,
                experimental_audio_refill=experimental_audio_refill)
            for audio_property in audio_selection['properties']:
                machine += ',' + audio_property
            self.config.detection_notes.extend(audio_selection['notes'])
            if audio_selection['ma3_native']:
                self.audio_native = True
                self.audio_native_ma3_pcm = True
            if audio_selection['stream']:
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
        machine, boot_property = device_domain('input.machine').project_boot_keys(self, machine, detector_image)
        machine = device_domain('rex.selection').project_controller(self, machine, detector_image)
        (amd_profile, amd_reject, direct_protocol_conflict, find_sharp_intel_profile, intel_profile, intel_reject, mapped_primary_profile, mapped_primary_reject, primary_profile, primary_regions, probe_profile, probe_reject, profile_reject, sharp_intel,) = device_domain('storage.selection').select_primary(self, detector_image)
        (record_profile, catalog_profile,) = device_domain('storage.selection').select_record(self, detector_image, primary_profile, intel_profile, amd_profile, profile_reject, probe_reject, intel_reject, amd_reject, mapped_primary_reject)
        primary_seed = bytes(self.decoder.flash.data)
        if truncated_bank_profile is not None:
            legacy_seed, primary_imported = truncated_legacy_state
            primary_seed = legacy_seed + primary_seed[original_flash_size:]
        else:
            primary_seed, primary_imported = load_legacy_nor_state(primary_seed, (legacy_primary_state,))
        bank_plan = device_domain('storage.descriptor_plan').bank_plan(
            detector_image, primary_seed, self.config,
            claimed=(primary_profile is not None or intel_profile is not None or amd_profile is not None
                     or mapped_primary_profile is not None or profile_reject is not None or direct_protocol_conflict),
            profile=truncated_bank_profile)
        if bank_plan.capabilities:
            primary_profile = dict(bank_plan.capabilities[0].parameters)['profile']
        eeprom_profile, eeprom_reject = eeprom_gpio_profile(detector_image, self.config)
        ma2_patch = ma2_silent_boot_loader_patch(
            primary_seed, self.config,
            primary_profile[0] if primary_profile is not None else None,
        )
        dmd5100_property, dmd5100_reject = qemu_dmd5100_property(
            detector_image, primary_seed, self.config,
            immutable_limit=primary_profile[0] if primary_profile is not None else None,
            input_profile=self.matrix_input_profile,
            eeprom_window=device_domain('eeprom').eeprom_gpio_window(eeprom_profile),
            allow_read_760=device_domain('input.machine').single_boot_contact(self.config),
            layout_claimed=ma2_patch is not None or any(value is not None for value in (
                ram_reserved, primary_profile, record_profile, mapped_primary_profile,
                upper_x16_profile, intel_profile, amd_profile,
                self.config.upper_flash_address, self.config.secondary_flash_address,
                self.config.native_nand_profile, self.config.nand_image)),
        )
        if dmd5100_property is None:
            dmd5100_property, dual_reject = qemu_dmd5000_property(
                detector_image, primary_seed, self.config,
                immutable_limit=(primary_profile[0] if primary_profile is not None else
                                 sharp_intel["geometry"][0] if sharp_intel is not None else None),
                input_profile=self.matrix_input_profile,
                eeprom_window=device_domain('eeprom').eeprom_gpio_window(eeprom_profile),
                layout_claimed=ma2_patch is not None or any(value is not None for value in (
                    ram_reserved, primary_profile, record_profile, mapped_primary_profile,
                    upper_x16_profile, intel_profile if sharp_intel is None else None, amd_profile,
                    self.config.upper_flash_address, self.config.secondary_flash_address,
                    self.config.native_nand_profile, self.config.nand_image)),
            )
            if dual_reject is not None:
                dmd5100_reject = dual_reject
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
        sbi_fragment, sbi_notes = device_domain('sbi').runtime_fragment(
            detector_image, primary_seed, self.config)
        self.config.detection_notes.extend(sbi_notes)
        machine = machine[:sbi_slot] + sbi_fragment + machine[sbi_slot:]
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
        external_image = source_prefix(detector_image, self.config.flash_size)
        external_property, external_reject = qemu_external_bus_property(
            self.config.external_bus, external_image,
            self.config.ram_base, self.config.ram_size,
            primary_seed[:len(external_image)],
            ((self.config.ram_bootstrap_profile['reserved_base'],
              self.config.ram_bootstrap_profile['reserved_size'])
             if ram_reserved is not None else None),
        )
        if external_property is not None:
            machine += "," + external_property
        elif external_reject is not None:
            for channel in (lcd_listener, input_listener, gdb_listener,
                            audio_listener, audio_host_socket, audio_qemu_socket):
                if channel is not None:
                    channel.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise ValueError(f"QEMU external bus plan rejected: {external_reject}")
        watchdog_property, watchdog_reject = device_domain('watchdog.rules').loaded_property(
            primary_seed, self.config, self.boot_format_nor_profile)
        if watchdog_property is not None:
            machine += f",{watchdog_property}"
        elif watchdog_reject is not None:
            self.config.detection_notes.append(
                f"QEMU watchdog rejected: {watchdog_reject}")
        if len(primary_seed) != self.config.flash_size:
            raise ValueError("primary seed size does not match flash size")
        if not qemu_legacy_keypad_source_matches(
                primary_seed[:len(detector_image)], legacy_keypad):
            for channel in (lcd_listener, input_listener, gdb_listener,
                            audio_listener, audio_host_socket, audio_qemu_socket):
                if channel is not None:
                    channel.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise ValueError("loaded keypad source changed")
        if not device_domain('rex.selection').loaded_controller_matches(
                self, primary_seed, source_limit, controller):
            for channel in (lcd_listener, input_listener, gdb_listener,
                            audio_listener, audio_host_socket, audio_qemu_socket):
                if channel is not None:
                    channel.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise ValueError("loaded REX NOR veneer/copy source route changed")
        sharp_intel, intel_profile = device_domain('storage.selection').loaded_primary(
            self, primary_seed, len(detector_image), sharp_intel, intel_profile)
        device_domain('input.machine').validate_loaded_status(primary_seed, board_status, seven_row_status)
        try:
            machine = device_domain('rex.selection').revalidate_loaded_stack(
                self, machine, detector_image, primary_seed)
        except ValueError:
            for channel in (lcd_listener, input_listener, gdb_listener,
                            audio_listener, audio_host_socket, audio_qemu_socket):
                if channel is not None:
                    channel.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise
        if revision_property is None and revision_reject is None:
            revision_domain = device_domain('boot.revision_plan')
            revision_plan = revision_domain.machine_plan(
                detector_image, primary_seed, self.config)
            cached_revision = revision_domain.project(revision_plan)
            if cached_revision is not None:
                machine += ',' + cached_revision
                self.config.detection_notes.append(
                    'source-linked cached halfword revision register enabled')
        bootstrap_plan = device_domain('storage.boot_nand').machine_plan(
            detector_image, firmware_image, self.config)
        bootstrap_binding = device_domain('storage.boot_nand_projection').project(bootstrap_plan)
        if bootstrap_binding is not None:
            machine += bootstrap_binding.machine
            self.config.detection_notes.append(
                "source-linked high-vector NAND bootstrap and private split-page media enabled")
        signal_domain = device_domain('external_bus.signal_memory_plan')
        signal_plan = signal_domain.machine_plan(
            detector_image, firmware_image if bootstrap_binding is not None else primary_seed,
            self.config, bootstrap_plan=bootstrap_plan)
        signal_property = signal_domain.project(signal_plan)
        if signal_property is not None:
            machine += ',' + signal_property
            self.config.detection_notes.append(
                'source-linked upload-table memory apertures enabled')
        from ..devices.display.source_plan import apply_source_plan
        display_plan = device_domain("display.source_writers").machine_plan(
            detector_image, firmware_image if bootstrap_binding is not None else primary_seed,
            self.config)
        apply_source_plan(self.decoder, display_plan)
        machine += device_domain('display.source_writers').machine_properties(display_plan)
        gpio_lcd_property = device_domain('display.binding').bind_loaded_sources(
            self.decoder, detector_image, primary_seed, allowed_patch=dmd_patch,
            ram_claimed=any(value is not None for value in (
                ram_reserved, primary_profile, record_profile, mapped_primary_profile,
                upper_x16_profile, intel_profile, amd_profile,
                self.config.upper_flash_address, self.config.secondary_flash_address,
                self.config.native_nand_profile, self.config.nand_image)))
        if gpio_lcd_property is not None:
            machine += "," + gpio_lcd_property
        machine, boot_property = device_domain('input.machine').project_loaded_contact(self, machine, boot_property, detector_image, primary_seed, status_property, experimental_halfword, experimental_low5, experimental_status_level, eeprom_profile, ram_reserved, primary_profile, record_profile, mapped_primary_profile, upper_x16_profile, intel_profile, amd_profile)
        machine = device_domain('display.binding').project_legacy_panel(
            self.decoder, machine, detector_image, primary_seed,
            ram_reserved=ram_reserved, claimed=direct_protocol_conflict or any(
                value is not None for value in (
                    primary_profile, record_profile, mapped_primary_profile,
                    upper_x16_profile, intel_profile, amd_profile,
                    self.config.upper_flash_address, self.config.secondary_flash_address,
                    self.config.native_nand_profile, self.config.nand_image)))
        uart2_tx_property = qemu_uart2_tx_property(
            detector_image, primary_seed, self.config,
            claimed=ram_reserved is not None)
        if uart2_tx_property is not None:
            machine += "," + uart2_tx_property
        machine = device_domain('uart_console.selection').project_loaded_console(self, machine, detector_image, primary_seed, uart_property, uart_deferred, ram_reserved, mapped_primary_profile, upper_x16_profile, intel_profile, sharp_intel, amd_profile)
        if ram_reserved is not None:
            try:
                device_domain('memory.transport_projection').validate_loaded_reserved(
                    primary_seed, self.config, initial_state['sp'], ram_reserved,
                    (primary_profile, record_profile, mapped_primary_profile, intel_profile, amd_profile))
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
        (record_profile, amd_profile, legacy_nv_profile, legacy_nv_properties, native_ram_size,) = device_domain('storage.selection').select_overlay(self, detector_image, primary_seed, direct_protocol_conflict, upper_nor_present, profile_reject, primary_profile, probe_profile, record_profile, mapped_primary_profile, intel_profile, amd_profile, catalog_profile, ram_reserved, upper_x16_profile, dmd5100_property)
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
        if self.boot_format_nor_profile is not None:
            # CFI02's independent region properties survive the machine's
            # scalar capacity setup. Both AMD 8MiB devices share this geometry.
            for index, (count, length) in enumerate(self.boot_format_nor_profile["erase_regions"]):
                for prop, value in (("num-blocks", count), ("sector-length", length)):
                    storage_args.extend(("-global",
                        f"driver=cfi.pflash02,property={prop}{index},value={value}"))
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
            machine += device_domain('storage.native_projection').primary_fragment(base, size, sector_size, id0, id1, primary_regions)
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
            machine += device_domain('storage.native_projection').record_fragment(self, base, size, sector_size)
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
            machine += device_domain('storage.native_projection').mapped_fragment(base, size, sector_size)
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
                seed = primary_seed[base:base + size] if sharp_intel is not None else b""
                intel_state.write_bytes(seed + b"\xff" * (size - len(seed)))
            fragment, loader_exclude = device_domain('storage.native_projection').intel_fragment(base, size, sector_size, id0, id1, sharp_intel, loader_exclude)
            machine += fragment
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
            machine += device_domain('storage.native_projection').legacy_fragment(legacy_nv_profile, legacy_nv_properties)
            base, size, sector_size, id0, id1, options = amd_profile
            amd_state = ((state_dir / "amd-x16.raw")
                         if state_dir is not None else
                         (temporary / "amd-x16.raw"))
            if amd_state.exists():
                if amd_state.stat().st_size != size:
                    raise ValueError("persistent AMD x16 NOR size mismatch")
            else:
                amd_state.write_bytes(b"\xff" * size)
            machine += device_domain('storage.native_projection').amd_fragment(base, size, sector_size, id0, id1, options, legacy_nv_properties)
            storage_args.extend((
                "-drive",
                f"file={amd_state},if=pflash,format=raw,unit={pflash_unit}",
            ))
            pflash_unit += 1
            self.config.detection_notes.append(
                "direct AMD x16 NOR selected from unique "
                "probe/caller/ordered-descriptor linkage"
            )
        (secondary, secondary_base, secondary_size, catalog_secondary, legacy_nv_secondary, adjacent_amd, embedded_secondary, secondary_ids, loader_exclude,) = device_domain('storage.selection').select_secondary(self, detector_image, catalog_profile, primary_profile, legacy_nv_profile, loader_exclude)
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
                    adjacent_matches = device_domain('storage.selection').secondary_extension_matches(
                        detector_image, self.config.flash_size, secondary_base, len(secondary_seed), secondary_ids)
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
                            and adjacent_matches):
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
            machine += device_domain('storage.native_projection').secondary_fragment(self, legacy_nv_properties, legacy_nv_secondary, secondary_base, secondary_size, secondary_ids)
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
            machine += device_domain('storage.native_projection').upper_fragment(8)
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
            machine += device_domain('storage.native_projection').upper_fragment(16)
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
            secondary_domain = device_domain('storage.secondary_protected_plan')
            secondary_plan = secondary_domain.machine_plan(
                detector_image, primary_seed, self.config,
                claimed=bool(storage_args) or upper_nor_present
                or secondary_base is not None or bool(secondary_ids))
            secondary_binding = secondary_domain.project(secondary_plan)
            if secondary_binding is not None:
                from ..devices.storage.secondary_media import prepare_secondary_media
                storage_args.extend(prepare_secondary_media(
                    secondary_binding, temporary, source_image=primary_seed))
                machine += secondary_binding.machine
                self.config.detection_notes.append(
                    'source-linked secondary protected NOR with erased private media enabled'
                    if getattr(secondary_binding, 'source_offset', None) is None else
                    'source-linked secondary protected NOR initialized from supplied '
                    f'image offset 0x{secondary_binding.source_offset:x} in private media')
        except Exception:
            for channel in (lcd_listener, input_listener, gdb_listener,
                            audio_listener, audio_host_socket, audio_qemu_socket):
                if channel is not None:
                    channel.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise
        (middle_nand_ready, native_nand, raw_nand_profile,) = device_domain('storage.selection').select_nand(self, detector_image, eeprom_profile, primary_seed, upper_nor_present)
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
            machine += device_domain('storage.native_projection').raw_nand_fragment(data, address, command, data_size, page_size, pages_per_block, bus_width, middle_nand_ready)
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
            capacity = device_domain('eeprom').eeprom_gpio_capacity(eeprom_profile)
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
            machine += ',' + device_domain('eeprom').eeprom_gpio_property(eeprom_profile)
            storage_args.extend((
                "-drive", f"file={eeprom_state},if=mtd,format=raw,unit=0",
            ))
        try:
            machine = device_domain('input.machine').project_row734(self, machine, detector_image, boot_property, status_property, experimental_halfword, experimental_low5, experimental_status_level, eeprom_profile)
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
        if sharp_intel is not None:
            sharp_status, sharp_status_reject = qemu_sharp_board_status_property(
                detector_image, primary_seed, self.config,
                claimed=(board_status is not None or
                         self.matrix_input_profile is not None or
                         self.decoder.direct_input_profile is not None or
                         boot_property is not None or status_property is not None or
                         eeprom_profile is not None or spi_property is not None or
                         experimental_status_level is not None),
            )
            if sharp_status is not None:
                machine += "," + sharp_status
                self.config.detection_notes.append(
                    "QEMU source-bound board status input enabled"
                )
            elif sharp_status_reject is not None:
                self.config.detection_notes.append(
                    f"QEMU Sharp board status rejected: {sharp_status_reject}"
                )
        self.stderr = tempfile.TemporaryFile(mode="w+t")
        try:
            bootstrap_loader_args = None
            if bootstrap_binding is not None:
                from ..devices.storage.boot_media import prepare_boot_media
                bootstrap_loader_args, bootstrap_drive_args = prepare_boot_media(
                    bootstrap_binding, firmware, temporary, source_image=firmware_image)
                storage_args.extend(bootstrap_drive_args)
            nand_monitor_args = []
            if native_nand is not None:
                if self.config.firmware_sha256 != loaded_firmware.source_sha256:
                    raise ValueError("timed NAND firmware identity mismatch")
                nand_monitor_args = self._prepare_native_nand(
                    native_nand, temporary, state_dir, legacy_primary_state,
                    firmware, legacy_secondary_state, legacy_upper_state,
                )
                machine += device_domain('storage.native_projection').nand_fragment(native_nand)
                storage_args.extend((
                    "-drive", f"file={self._native_nand_working},if=none,format=raw,"
                    "id=msm5xxx-small-page-nand,cache=writeback",
                ))
            network_monitor_args = []
            if self.virtual_cell_status == "configured":
                from .network_control import NetworkMonitor
                self._network_monitor = NetworkMonitor()
                network_monitor_args = self._network_monitor.arguments()
            popen_options = (
                {"pass_fds": (audio_qemu_socket.fileno(),)}
                if audio_qemu_socket is not None else {}
            )
            self.process = launch_qemu(
                [
                    *qemu_prefix, str(qemu), "-M", machine, "-cpu",
                    bootstrap_binding.cpu if bootstrap_binding is not None else "ti925t",
                    "-m", qemu_ram_argument(native_ram_size),
                    *(bootstrap_loader_args if bootstrap_binding is not None else (
                        *raw_loader_arguments(
                            loader, self.config.ram_size, temporary, loader_size,
                            loader_exclude,
                        ),
                        *getattr(self, "ram_seed_loader_args", ()),
                    )),
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
                    *nand_monitor_args, *network_monitor_args,
                    "-nographic", "-monitor", "none", "-serial", "none",
                    "-S", "-gdb", "chardev:gdb",
                    "-icount", f"shift={icount_shift},align=on,sleep=on",
                    "-no-shutdown",
                ],
                launcher=launcher,
                stdout=subprocess.DEVNULL,
                stderr=self.stderr,
                text=True,
                **popen_options,
            )
            if audio_qemu_socket is not None:
                audio_qemu_socket.close()
                audio_qemu_socket = None
        except Exception:
            if self._network_monitor is not None:
                self._network_monitor.close()
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
            if self._network_monitor is not None:
                self._network_monitor.connect()
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
        if (getattr(self, "audio_native_ma5_pcm", False)
                or getattr(self, "audio_native_ma3_pcm", False)):
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
                    or getattr(self, "audio_native_ma5_pcm", False) is True
                    or getattr(self, "audio_native_ma3_pcm", False) is True)
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
        elif (status == AUDIO_STATUS_REJECTED and order == dropped == detail == 0
              and getattr(self, "audio_native_ma3_pcm", False)):
            self._reject_audio_stream("qemu-ma3-pcm-output-stopped")
        elif status == AUDIO_STATUS_NATIVE and order == dropped == detail == 0:
            self.audio_native = True
            self.audio_stream_status = "native"
        else:
            self._reject_audio_stream("qemu-audio-status-shape")

    def _replay_records(self, records: memoryview) -> None:
        """Replay a complete batch without allocating a bytes object per LCD write.

        Keep non-LCD handling in the single-record dispatcher: audio and status
        records are infrequent and retain their existing validation boundaries.
        The caller releases the view before resizing its receive buffer.
        """
        decoder = self.decoder
        offset = 0
        for kind, size, address, value, _tail in _LCD_RECORD.iter_unpack(records):
            if kind == LCD_WRITE:
                decoder._lcd_write(decoder.uc, 0, address, size, value, None)
            else:
                self._replay_record(bytes(records[offset:offset + RECORD_SIZE]))
            offset += RECORD_SIZE

    def _replay_record(self, record: bytes | bytearray) -> None:
        if record[0] == LCD_WRITE:
            _kind, size, address, value, _tail = _LCD_RECORD.unpack_from(record)
            self.decoder._lcd_write(
                self.decoder.uc, 0, address, size, value, None,
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

    def _replay_batch(self, pending: bytearray, complete: int) -> None:
        # Bound continuous decoder ownership of the GIL even without audio.
        # A single record is atomic; never discard/reorder LCD state writes.
        deadline = time.monotonic_ns() + 2_000_000
        step = 256 * RECORD_SIZE
        for offset in range(0, complete, step):
            with memoryview(pending)[offset:min(offset + step, complete)] as records:
                self._replay_records(records)
            if (offset + step < complete
                    and time.monotonic_ns() >= deadline):
                time.sleep(0)
                deadline = time.monotonic_ns() + 2_000_000
        del pending[:complete]
        if complete:
            # Also hand off after short bursts, including input ACK bursts.
            time.sleep(0)

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
                    self._replay_batch(pending, complete)
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



    def can_set_fold(self) -> bool:
        profile = self.config.board_status_input
        if (getattr(self, "_sd840_status_source_closed", False)
                or getattr(self, "_kp2100_status_source_closed", False)):
            # The default is source-proven; its edge IRQ is not modeled yet.
            return False
        if (getattr(self.config, "sd810_gpio_profile", None) == (0x03000720, 1, 1) and profile is not None
                and (profile.address, profile.mask) == (0x03000720, 1)):
            # The UI name is inferred: the source proves the logical status
            # produces open/closed events and gates keys, not the sensor type.
            if not getattr(self, "_sd810_fold_source_closed", False):
                return False
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
        self.input_send_started_ns = time.monotonic_ns()
        try:
            self.input_socket.sendall(packet)
        except OSError as error:
            self.decoder.input_error = f"QEMU input transport failed: {error}"
            return False
        finally:
            self.input_send_completed_ns = time.monotonic_ns()
            self.input_send_duration_ns = (
                self.input_send_completed_ns - self.input_send_started_ns
            )
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

    def update_network_time(self, timestamp=None, refresh=False):
        if self._network_monitor is None or self.process.poll() is not None:
            raise RuntimeError("virtual network is not running")
        self._network_monitor.update(timestamp, refresh)

    def close(self) -> None:
        if self._network_monitor is not None:
            self._network_monitor.close()
            self._network_monitor = None
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
