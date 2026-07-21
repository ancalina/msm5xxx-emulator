"""GenericMSMEmulator lifecycle methods."""
from __future__ import annotations

from collections import Counter
from collections import deque
from .config import FirmwareConfig
from .constants import FRAMEBUFFER_FORMATS
from .constants import MAX_NAND_BACKING_SIZE
from .constants import MAX_NAND_DATA_SIZE
from .constants import MAX_RAM_SIZE
from .constants import NAND_MMIO_RANGES
from .constants import PAGE
from .constants import POLL_OBSERVATION_STEPS
from .constants import STABLE_MSM_MMIO
from .constants import UNMAPPED_ACCESS_HISTORY_LIMIT
from .errors import HostBackendFault
from ..detection.boot import BUSY_DELAY_SIGNATURE
from ..detection.boot import BUSY_DELAY_SIGNATURES
from ..detection.boot import DELAY_SIGNATURE
from ..detection.boot import absent_optional_ram_probe_addresses
from ..detection.boot import busy_delay_addresses
from ..detection.display import detect_lcd_width_hint
from ..detection.firmware import ADDRESS_SPACE
from ..detection.firmware import MAX_FLASH_SIZE
from ..detection.input import detect_input_profile
from ..detection.memory_layout import aligned
from ..detection.memory_layout import interval_gaps
from ..detection.memory_layout import restore_sparse_nor_gap
from ..detection.storage import flash_id_for_size
from ..detection.storage import fujitsu_x16_flash_ids
from ..detection.storage import qualcomm_efs_seed
from ..devices.storage.nor import NORFlash
from pathlib import Path
from ..state_io import exclusive_path_lock
from ..state_io import lock_path
from unicorn import UC_ARCH_ARM
from unicorn import UC_HOOK_BLOCK
from unicorn import UC_HOOK_CODE
from unicorn import UC_HOOK_MEM_READ
from unicorn import UC_HOOK_MEM_UNMAPPED
from unicorn import UC_HOOK_MEM_WRITE
from unicorn import UC_MEM_FETCH_UNMAPPED
from unicorn import UC_MEM_READ_UNMAPPED
from unicorn import UC_MEM_WRITE_UNMAPPED
from unicorn import UC_MODE_ARM
from unicorn import UC_PROT_ALL
from unicorn import Uc
from unicorn import UcError
from unicorn.arm_const import UC_ARM_REG_CPSR
from unicorn.arm_const import UC_ARM_REG_SP
from unicorn.arm_const import UC_CPU_ARM_TI925T
import json
import struct
import threading
import logging

LOGGER = logging.getLogger("msm5xxx")

try:
    from e170_gm_audio import ApproximateSmafPlayer
except ImportError:
    ApproximateSmafPlayer = None


class LifecycleMixin:
    def __init__(self, config: FirmwareConfig) -> None:
        self.config = config
        LOGGER.info("emulator init config=%s",
                    json.dumps(config.diagnostic_config(), ensure_ascii=False,
                               sort_keys=True))
        flash_end, ram_end, secondary_base = self._validate_config(config)
        eeprom_enabled, eeprom_state_path = self._prepare_state_paths(
            config, secondary_base
        )
        self._validate_nand_geometry(config)
        available, ram_seed = self._load_primary_image(config, secondary_base)
        self._init_nor_eeprom_state(
            config, secondary_base, eeprom_enabled, eeprom_state_path,
            available, ram_end,
        )
        self._validate_register_layout(
            config, secondary_base, available, flash_end, ram_end
        )
        self._create_cpu_and_map_memory(
            config, secondary_base, ram_end, ram_seed
        )
        self._init_runtime_state(ram_seed)
        self._init_display_capture_state(config)
        self._init_nand_state(config)
        self._init_display_protocol_state(config)
        self._init_unmapped_state()
        self._init_input_state(config)
        self._init_nor_probe_state()
        self._init_audio_state()
        self._install_remaining_hooks(config, secondary_base, eeprom_enabled)

    def _validate_config(
            self, config: FirmwareConfig) -> tuple[int, int, int | None]:
        if config.image_kind != "firmware":
            raise ValueError(
                "input has no ARM exception vector table; it appears to be "
                "EFS/data rather than executable firmware"
            )
        if not 32 <= config.width <= 1024 or not 32 <= config.height <= 1024:
            raise ValueError("screen dimensions must be in 32..1024")
        if config.chipset not in (
                "MSM5000", "MSM5100", "MSM5105", "MSM5500", "MSM5xxx"):
            raise ValueError(f"unsupported chipset: {config.chipset}")
        if not 0 <= config.load_address < ADDRESS_SPACE:
            raise ValueError("flash load address outside 32-bit address space")
        if not 0 < config.flash_size <= MAX_FLASH_SIZE:
            raise ValueError("flash size must be in 1..64 MiB")
        flash_end = config.load_address + config.flash_size
        if flash_end > ADDRESS_SPACE:
            raise ValueError("flash range outside 32-bit address space")
        if not 0 < config.ram_base < ADDRESS_SPACE:
            raise ValueError("RAM base must be a positive 32-bit address")
        if not 0 < config.ram_size <= MAX_RAM_SIZE:
            raise ValueError("RAM size must be in 1..128 MiB")
        ram_end = config.ram_base + config.ram_size
        if ram_end > ADDRESS_SPACE:
            raise ValueError("RAM range outside 32-bit address space")
        if max(config.load_address, config.ram_base) < min(flash_end, ram_end):
            raise ValueError("primary flash overlaps configured RAM")
        if config.linker is not None:
            layout = config.linker
            if not (config.ram_base <= layout.data_target
                    <= layout.data_target + layout.data_size == layout.bss_target
                    < layout.bss_target + layout.bss_size <= ram_end):
                raise ValueError("linker data/BSS range outside configured RAM")
        configured = ((config.load_address, flash_end, "primary flash"),
                      (config.ram_base, ram_end, "RAM"))
        for start, end, label in configured:
            if max(start, 0x02000000) < min(end, 0x02801000):
                raise ValueError(f"{label} overlaps fixed LCD MMIO")
            if max(start, 0x02C00000) < min(end, 0x02C01000):
                raise ValueError(f"{label} overlaps fixed alternate LCD MMIO")
            if max(start, 0x03000000) < min(end, 0x04000000):
                raise ValueError(f"{label} overlaps fixed MSM MMIO/internal RAM")
        if config.nand_enabled:
            for start, end, label in configured:
                if any(max(start, port_start) < min(end, port_end)
                       for port_start, port_end in NAND_MMIO_RANGES):
                    raise ValueError(f"{label} overlaps fixed NAND MMIO")
        if not 0 <= config.entry < config.flash_size:
            raise ValueError("entry offset outside primary flash")
        if config.framebuffer_address is not None:
            if config.framebuffer_format not in FRAMEBUFFER_FORMATS:
                raise ValueError(f"unsupported framebuffer format: {config.framebuffer_format}")
            if config.framebuffer_stride < config.width * 2:
                raise ValueError("framebuffer stride is smaller than one RGB565 row")
            framebuffer_end = (config.framebuffer_address
                               + config.framebuffer_stride * config.height)
            if (config.framebuffer_address < config.ram_base
                    or framebuffer_end > ram_end):
                raise ValueError("framebuffer range outside configured RAM")
        elif (config.framebuffer_flush_address is not None
              or config.framebuffer_rect_flush_address is not None):
            raise ValueError("framebuffer trigger configured without framebuffer address")
        if not config.flash_state:
            raise ValueError("primary flash state path is empty")
        secondary_base = config.secondary_flash_address
        if secondary_base == 0:
            secondary_base = None
        if secondary_base is not None and not config.secondary_flash_state:
            raise ValueError("secondary flash state path is empty")
        return flash_end, ram_end, secondary_base

    def _prepare_state_paths(
            self, config: FirmwareConfig,
            secondary_base: int | None) -> tuple[bool, Path]:
        def resolved_path(filename: str) -> Path:
            return Path(filename).expanduser().resolve()

        config.flash_state = str(resolved_path(config.flash_state))
        if secondary_base is not None:
            config.secondary_flash_state = str(resolved_path(
                config.secondary_flash_state
            ))
        eeprom_enabled = (
            config.eeprom_geometry_address is not None
            and (config.eeprom_read_address is not None
                 or config.eeprom_write_address is not None)
        )
        eeprom_state_path = resolved_path(config.flash_state + ".eeprom.bin")
        persistent_outputs = [
            ("primary flash state", resolved_path(config.flash_state)),
        ]
        if secondary_base is not None:
            persistent_outputs.append((
                "secondary flash state",
                resolved_path(config.secondary_flash_state),
            ))
        if eeprom_enabled:
            persistent_outputs.append(("EEPROM state", eeprom_state_path))
        if config.nand_enabled:
            persistent_outputs.extend((
                ("NAND state", resolved_path(config.flash_state + ".nand.bin")),
                ("NAND metadata", resolved_path(config.flash_state + ".nand.json")),
            ))
        write_targets: list[tuple[str, Path]] = []
        for label, state_path in persistent_outputs:
            write_targets.extend((
                (label, state_path),
                (f"{label} temporary",
                 state_path.with_suffix(state_path.suffix + ".tmp")),
            ))
        state_locks = [("primary state lock", lock_path(config.flash_state))]
        if secondary_base is not None:
            state_locks.append((
                "secondary state lock", lock_path(config.secondary_flash_state)
            ))
        if eeprom_enabled:
            state_locks.append(("EEPROM state lock", lock_path(eeprom_state_path)))
        write_targets.extend(state_locks)
        protected_inputs = [("firmware", resolved_path(config.path))]
        if secondary_base is not None and config.secondary_flash_image:
            protected_inputs.append((
                "secondary flash image",
                resolved_path(config.secondary_flash_image),
            ))
        if config.nand_enabled and config.nand_image:
            protected_inputs.append(("NAND image", resolved_path(config.nand_image)))
        for index, (label, path) in enumerate(write_targets):
            for other_label, other_path in [*write_targets[:index], *protected_inputs]:
                if path == other_path:
                    raise ValueError(f"{label} path collides with {other_label}")
        return eeprom_enabled, eeprom_state_path

    def _validate_nand_geometry(self, config: FirmwareConfig) -> None:
        if config.nand_bus_width not in (1, 2):
            raise ValueError("NAND bus width must be 1 or 2 bytes")
        if not 0 < config.nand_data_size <= MAX_NAND_DATA_SIZE:
            raise ValueError("NAND data size must be in 1..128 MiB")
        if not 256 <= config.nand_page_size <= 0x4000:
            raise ValueError("NAND page size must be in 256..16384 bytes")
        if not 0 < config.nand_spare_size <= 0x1000:
            raise ValueError("NAND spare size must be in 1..4096 bytes")
        if not 0 < config.nand_pages_per_block <= 0x1000:
            raise ValueError("NAND pages per block must be in 1..4096")
        if config.nand_data_size % config.nand_page_size:
            raise ValueError("NAND data size must be a whole number of pages")

    def _load_primary_image(
            self, config: FirmwareConfig,
            secondary_base: int | None) -> tuple[bytes, bytes]:
        raw = Path(config.path).read_bytes()
        if not 0 <= config.image_offset < len(raw):
            raise ValueError("image offset outside firmware")
        available, _sparse_gap = restore_sparse_nor_gap(
            raw[config.image_offset:]
        )
        if config.secondary_flash_image_offset is not None:
            start = config.secondary_flash_image_offset
            end = start + config.secondary_flash_size
            if secondary_base is None:
                raise ValueError("internal secondary image has no secondary flash")
            if config.secondary_flash_image:
                raise ValueError("internal and external secondary images conflict")
            if not 0 <= start < end <= len(available):
                raise ValueError("internal secondary image range outside firmware")
        # Partial dumps are padded as erased NOR.  The inferred capacity is
        # independently bounded above, so a large omitted tail is safe here.
        if (config.ram_image_size < 0 or config.ram_image_offset < 0
                or config.ram_image_size > config.ram_size
                or (config.ram_image_size
                    and config.ram_image_offset + config.ram_image_size > len(available))):
            raise ValueError("RAM seed range outside firmware")
        ram_seed = (available[config.ram_image_offset:
                              config.ram_image_offset + config.ram_image_size]
                    if config.ram_image_size else b"")
        self.image = (available[:config.flash_size]
                      + b"\xff" * max(0, config.flash_size - len(available)))
        # Bootstrap inference must distinguish actual supplied NOR bytes from
        # the erased padding that lets a partial dump model its physical chip.
        # A structural early copy may not promote a padded tail into firmware.
        self.primary_rom_end = (config.load_address
                                + min(len(available), config.flash_size))
        return available, ram_seed

    def _init_nor_eeprom_state(
            self, config: FirmwareConfig, secondary_base: int | None,
            eeprom_enabled: bool, eeprom_state_path: Path, available: bytes,
            ram_end: int) -> None:
        self.original_image = bytes(self.image)
        self.flash = NORFlash(self.image, Path(config.flash_state))
        self.image = bytes(self.flash.data)
        self.secondary_flash: NORFlash | None = None
        self.secondary_base: int | None = secondary_base
        self._lazy_secondary_attempted: set[int] = set()
        if secondary_base is not None:
            secondary_end = secondary_base + config.secondary_flash_size
            image_end = config.load_address + len(self.image)
            overlaps_image = (max(secondary_base, config.load_address)
                              < min(secondary_end, image_end))
            overlaps_ram = max(secondary_base, config.ram_base) < min(secondary_end, ram_end)
            overlaps_nand = (config.nand_enabled
                             and any(max(secondary_base, port_start)
                                     < min(secondary_end, port_end)
                                     for port_start, port_end in NAND_MMIO_RANGES))
            overlaps_fixed = (
                max(secondary_base, 0x02000000) < min(secondary_end, 0x02801000)
                or max(secondary_base, 0x02C00000) < min(secondary_end, 0x02C01000)
                or max(secondary_base, 0x03000000) < min(secondary_end, 0x04000000)
            )
            if (not 0 < config.secondary_flash_size <= MAX_FLASH_SIZE
                    or secondary_base < 0
                    or secondary_end > ADDRESS_SPACE or overlaps_image or overlaps_ram
                    or overlaps_nand or overlaps_fixed):
                raise ValueError(f"invalid secondary flash: 0x{secondary_base:X}")
            if config.secondary_flash_image:
                seed = Path(config.secondary_flash_image).read_bytes()
                if len(seed) > config.secondary_flash_size:
                    raise ValueError("secondary flash image is larger than configured size")
                seed += b"\xff" * (config.secondary_flash_size - len(seed))
            elif config.secondary_flash_image_offset is not None:
                start = config.secondary_flash_image_offset
                seed = available[start:start + config.secondary_flash_size]
            elif b"\x0b$USER_DIRS\0" in available:
                seed = qualcomm_efs_seed(
                    config.secondary_flash_size, config.chipset
                )
            else:
                seed = b"\xff" * config.secondary_flash_size
            self.secondary_flash = NORFlash(seed, Path(config.secondary_flash_state))
        self.eeprom_enabled = eeprom_enabled
        self.eeprom_state_path = eeprom_state_path
        self.eeprom_data = bytearray()
        self.eeprom_original = b""
        self.eeprom_loaded = b""
        self.eeprom_operations: list[tuple[int, bytes]] = []
        self.eeprom_capacity = 0
        self.eeprom_loaded_from_state = False
        self.eeprom_error: str | None = None

    def _validate_register_layout(
            self, config: FirmwareConfig, secondary_base: int | None,
            available: bytes, flash_end: int, ram_end: int) -> None:
        storage_ranges = [
            (config.load_address, flash_end, "primary flash"),
            (config.ram_base, ram_end, "RAM"),
        ]
        if secondary_base is not None:
            storage_ranges.append((
                secondary_base, secondary_base + config.secondary_flash_size,
                "secondary flash",
            ))
        register_ranges = []
        if config.key_register is not None:
            register_ranges.append((config.key_register, config.key_register + 4,
                                    "key register"))
        if config.board_revision_register is not None:
            register_ranges.append((
                config.board_revision_register,
                config.board_revision_register + 4,
                "board revision register",
            ))
        if config.board_status_input is not None:
            register_ranges.append((
                config.board_status_input.address,
                config.board_status_input.address + 1,
                "board status input",
            ))
        register_reserved = [
            (0x02000000, 0x02801000, "LCD MMIO"),
            (0x02C00000, 0x02C01000, "alternate LCD MMIO"),
            (0x03800000, 0x03A00000, "internal RAM"),
            *((address, address + len(value), "stable MSM MMIO")
              for address, value in STABLE_MSM_MMIO),
            *((overlay.target, overlay.target + overlay.size, "executable overlay")
              for overlay in config.overlays),
        ]
        if config.nand_enabled:
            register_reserved.extend(
                (start, end, "NAND MMIO") for start, end in NAND_MMIO_RANGES
            )
        for index, (start, end, label) in enumerate(register_ranges):
            if not 0 <= start < end <= ADDRESS_SPACE:
                raise ValueError(f"{label} outside 32-bit address space")
            conflicts = [*storage_ranges, *register_reserved,
                         *register_ranges[:index]]
            for other_start, other_end, other_label in conflicts:
                if max(start, other_start) < min(end, other_end):
                    # SCH-E470 partial dumps reference code in the upper half
                    # of a 16 MiB NOR while also decoding the board-revision
                    # latch at 0x00DFFFDC.  The physical board uses that small
                    # MMIO aperture as a hole in the NOR window.  Accept the
                    # aperture only when it lies beyond the bytes actually
                    # supplied by the dump; never hide real firmware bytes.
                    supplied_end = (config.load_address
                                    + min(len(available), config.flash_size))
                    if (label == "board revision register"
                            and other_label == "primary flash"
                            and start >= supplied_end):
                        continue
                    raise ValueError(f"{label} overlaps {other_label}")

    def _create_cpu_and_map_memory(
            self, config: FirmwareConfig, secondary_base: int | None,
            ram_end: int, ram_seed: bytes) -> None:
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_TI925T)
        # Map actual devices and storage, rather than one contiguous 80 MiB
        # arena.  Besides catching bad pointers, this avoids large-map issues
        # seen in the Windows Unicorn backend.
        ranges = [
            (config.load_address, len(self.image)),
            (config.ram_base, config.ram_size),
            (0x02000000, PAGE),       # LCD command/data bus
            (0x02800000, PAGE),       # alternate/indexed LCD bus
            (0x02C00000, PAGE),       # later parallel LCD command/data bus
            (0x03000000, 0x01000000), # MSM MMIO and internal RAM overlays
            # Some incomplete board dumps retain an all-ones optional-device
            # pointer.  On the physical 32-bit bus this lands on open bus,
            # rather than becoming a host pointer or crashing Unicorn.
            (0xFFFFF000, PAGE),
            *((address, len(value)) for address, value in STABLE_MSM_MMIO),
        ]
        if config.key_register is not None:
            ranges.append((config.key_register, 4))
        if config.nand_enabled:
            ranges.extend((start, end - start) for start, end in NAND_MMIO_RANGES)
        if secondary_base is not None:
            ranges.append((secondary_base, config.secondary_flash_size))
        if config.board_revision_register is not None:
            ranges.append((config.board_revision_register, 4))
        mapped_ranges: list[tuple[int, int]] = []
        for start, length in ranges:
            if not 0 <= start < ADDRESS_SPACE or start + length > ADDRESS_SPACE:
                raise ValueError(f"mapping outside 32-bit address space: 0x{start:X}")
            left = start & -PAGE
            right = aligned(start + length)
            if left < right:
                mapped_ranges.append((left, right))
        merged: list[list[int]] = []
        for left, right in sorted(mapped_ranges):
            if merged and left <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], right)
            else:
                merged.append([left, right])
        for left, right in merged:
            self.uc.mem_map(left, right - left, UC_PROT_ALL)
        self.uc.mem_write(config.load_address, self.image)
        self.uc.mem_write(0xFFFFF000, b"\xff" * PAGE)
        if secondary_base is not None and self.secondary_flash is not None:
            self.uc.mem_write(secondary_base, bytes(self.secondary_flash.data))
        if ram_seed:
            self.uc.mem_write(config.ram_base, ram_seed)
        self.flash.ids = self._detect_primary_flash_ids()
        if self.secondary_flash is not None:
            secondary_ids = fujitsu_x16_flash_ids(
                self.original_image, config.secondary_flash_write_address,
                config.load_address, int(secondary_base)
            )
            if secondary_ids is not None:
                self.secondary_flash.ids = secondary_ids
            elif config.flash_id_value is not None:
                self.secondary_flash.ids = (config.flash_id_value & 0xFFFF,
                                            config.flash_id_value >> 16 & 0xFFFF)
        if config.key_register is not None:
            self.uc.mem_write(config.key_register,
                              struct.pack("<I", 0xFFFFFFFF if config.key_active_low else 0))
        for address, value in STABLE_MSM_MMIO:
            self.uc.mem_write(address, value)
            self.uc.hook_add(UC_HOOK_MEM_READ, self._stable_mmio_read,
                             begin=address, end=address + len(value) - 1,
                             user_data=(address, value))
        if (config.board_revision_register is not None
                and config.board_revision_value is not None):
            self.uc.mem_write(config.board_revision_register,
                              struct.pack("<I", config.board_revision_value & 0xFFFFFFFF))
        self._refresh_board_status_input(self.uc)
        self.uc.reg_write(UC_ARM_REG_CPSR, 0xD3)
        stack = ram_end - 4
        if config.linker:
            candidate = (aligned(config.linker.bss_target + config.linker.bss_size
                                 + 0x100000) - 4)
            if config.ram_base <= candidate < ram_end:
                stack = candidate
        self.uc.reg_write(UC_ARM_REG_SP, stack)

    def _init_runtime_state(self, ram_seed: bytes) -> None:
        self.instructions = 0
        self.reset_entries = 0
        self.fast_boot_used = False
        self.fault: str | None = None
        self._host_backend_fault: HostBackendFault | None = None
        self._logged_fault: str | None = None
        self.tail: deque[int] = deque(maxlen=64)
        self.hot: Counter[int] = Counter()
        self.mmio_reads: Counter[tuple[int, int, int]] = Counter()
        self.mmio_read_totals: Counter[tuple[int, int, int]] = Counter()
        self.poll_escapes: list[dict[str, int]] = []
        self._poll_escape_keys: set[tuple[int, int, int, int, int]] = set()
        self._poll_candidate_chunks: Counter[tuple[int, int, int]] = Counter()
        self._poll_window_remaining = POLL_OBSERVATION_STEPS
        self.ready_bits: dict[tuple[int, int], tuple[int, int]] = {}
        self.zero_fetches = 0
        self.rex_idle_entries = 0
        self.rex_ticks = 0
        self.rex_elapsed_ms = 0
        self.rex_next_instruction = 0
        self._rex_tick_return_address: int | None = None
        self._rex_tick_context: tuple[tuple[int, int], ...] | None = None
        self._rex_irq_pending = [0, 0]
        self.rex_irq_deliveries = 0
        self.board_adc_reads = 0
        self._board_adc_reader_channel: int | None = None
        self.flash_id_reads = 0
        self.fast_crc16_calls = 0
        self.fast_dmd_downloads = 0
        self.ram_seed_size = len(ram_seed)
        self.secondary_flash_reads = 0
        self.secondary_flash_writes = 0
        self.legacy_efs_page_reads = 0
        self.eeprom_reads = 0
        self.eeprom_read_bytes = 0
        self.eeprom_writes = 0
        self.eeprom_write_bytes = 0
        self.fast_memory_clears = 0
        self.fast_memory_copies = 0
        self.fast_register_ramps = 0
        self.fast_arm_memory_copies = 0
        # A few BSPs construct the initial runtime image with a literal
        # ROM->SDRAM copy, a contiguous BSS clear, then one IRAM overlay copy
        # instead of an ordinary linker table. These bounds are a one-shot
        # lease for that exact bootstrap chain; they never authorize later
        # runtime work buffers.
        self._bootstrap_data_end: int | None = None
        self._bootstrap_rom_end: int | None = None
        self._bootstrap_bss_end: int | None = None
        self._bootstrap_bss_complete = False
        self._bootstrap_iram_end: int | None = None
        # The structural Thumb clear/copy HLE and the older generic
        # scatter-load escape are individually safe, but they describe
        # mutually exclusive bootstrap phases.  Once real RAM-init work has
        # been completed by the former, do not later return through the
        # latter's guessed LR.
        self.hot_loop_hle_used = False

    def _init_display_capture_state(self, config: FirmwareConfig) -> None:
        # The emulation worker can identify a new LCD geometry while Tk is
        # rendering the previous immutable frame.  Publish width/height/frame
        # as one snapshot so the GUI never hands Pillow mismatched byte counts.
        self._display_lock = threading.Lock()
        self.framebuffer = bytearray(config.width * config.height * 3)
        self.display_frame = bytes(self.framebuffer)
        self.frame_sequence = 0
        self.firmware_frame_sequence = 0
        self.lcd_writes = 0
        self.lcd_port_writes: Counter[tuple[int, int]] = Counter()
        # Some boards expose a pixel FIFO at a board-specific LCD aperture
        # instead of the command/data pair used by the Samsung BSPs.  Keep a
        # bounded rolling capture for such ports and promote it only after a
        # complete RGB565-sized scanout has actually been observed.
        self._lcd_raw_streams: dict[tuple[int, int], deque[int]] = {}
        self._lcd_raw_counts: Counter[tuple[int, int]] = Counter()
        self._lcd_raw_frames: Counter[tuple[int, int]] = Counter()
        self._lcd_raw_port: tuple[int, int] | None = None
        self._lcd_raw_segment_streams: dict[tuple[int, int], deque[int]] = {}
        self._lcd_raw_segment_counts: Counter[tuple[int, int]] = Counter()
        self._lcd_recent_commands: deque[int] = deque(maxlen=8)
        # Hold only the exact byte-command/low-byte-word page candidate
        # until two adjacent rows prove it.  This sidecar never decodes pixels.
        self._lcd_lowbyte_page_stage = ""
        self._lcd_lowbyte_page_page = -1
        self._lcd_lowbyte_page_last = -1
        self._lcd_lowbyte_page_high = -1
        self._lcd_lowbyte_page_rows = 0
        self._lcd_lowbyte_page_words: list[int] = []
        # A byte-wide 0x028+2 transport occurs on one otherwise unknown board.
        # It is promoted only after its complete controller setup fingerprint
        # and one exact 96x64 RGB565 payload have both been observed.
        self._lcd_byte_rgb565_commands = bytearray()
        self._lcd_byte_rgb565_payload: bytearray | None = None
        # LG-LX5350 uses a byte-wide four-register window followed by
        # big-endian RGB565 bytes through +0x10/+0x11.  Keep it separate from
        # command/data transports until header and whole rectangle agree.
        self._lcd_window_rgb565_header: list[int] = []
        self._lcd_window_rgb565_window: tuple[int, int, int, int] | None = None
        self._lcd_window_rgb565_pixels: list[int] = []
        self._lcd_window_rgb565_high: int | None = None
        # One selector/data board uses packed register/argument words.  Its
        # mode register selects either paired RGB666 or one-word RGB565.
        self._lcd_selector_registers: dict[int, int] = {}
        self._lcd_selector_words: list[int] = []
        self._lcd_selector_expected = 0
        self._lcd_selector_window: tuple[int, int, int, int] | None = None
        self._lcd_selector_format: str | None = None
        # An early 12-bit controller addresses one horizontal run with the
        # exact 0x03=x, 0x05=y, 0x0B=pixels command sequence.
        self._lcd_bgr444_command: int | None = None
        self._lcd_bgr444_axis_state = 0
        self._lcd_bgr444_cursor = [0, 0]
        self._lcd_bgr444_qualified = False
        self._lcd_bgr444_dirty = False
        self._lcd_bgr444_streamed_pixels = 0
        self._lcd_bgr444_run_origin: tuple[int, int] | None = None
        self._lcd_bgr444_run_words: list[int] = []
        self._lcd_bgr444_runs: list[tuple[int, int, tuple[int, ...]]] = []
        self._lcd_protocol = "unknown"
        self._lcd_frame_protocol = "none"
        if config.framebuffer_address is not None:
            self._render_framebuffer_region(
                0, 0, config.width - 1, config.height - 1,
                firmware_originated=False,
            )

    def _init_nand_state(self, config: FirmwareConfig) -> None:
        self.nand_commands: list[int] = []
        self.nand_image = bytearray()
        self.nand_raw_page_size = config.nand_page_size + config.nand_spare_size
        self.nand_page_count = config.nand_data_size // config.nand_page_size
        nand_backing_size = self.nand_page_count * self.nand_raw_page_size
        if nand_backing_size > MAX_NAND_BACKING_SIZE:
            raise ValueError("NAND raw backing exceeds 256 MiB safety limit")
        if config.nand_enabled:
            if config.nand_image:
                supplied = Path(config.nand_image).read_bytes()
                self.nand_image = self._normalise_nand(supplied, nand_backing_size,
                                                       "NAND image")
            else:
                self.nand_image = bytearray(b"\xff" * nand_backing_size)
        self.nand_original = bytes(self.nand_image)
        self.nand_state_path = Path(config.flash_state + ".nand.bin")
        self.nand_metadata_path = Path(config.flash_state + ".nand.json")
        self.nand_recovered_seed = False
        self.nand_needs_rewrite = False
        if config.nand_enabled:
            with exclusive_path_lock(config.flash_state):
                self.nand_recovered_seed = self.nand_state_path.is_file()
                if self.nand_recovered_seed:
                    self._validate_nand_metadata()
                    saved = self.nand_state_path.read_bytes()
                    saved_nand = self._normalise_nand(
                        saved, len(self.nand_image), "NAND state"
                    )
                    self.nand_image[:] = saved_nand
                    self.nand_needs_rewrite = (
                        len(saved) != len(self.nand_image)
                        or not self.nand_metadata_path.is_file()
                    )
        self.nand_loaded = bytes(self.nand_image)
        self.nand_operations: list[tuple[str, int, bytes | int]] = []
        self.nand_mode = "idle"
        self.nand_address: list[int] = []
        self.nand_cursor = 0
        self.nand_reads = 0
        self.nand_writes = 0
        self.nand_bad_block_probes = 0
        self.nand_program = bytearray()
        self.nand_spare_latched = False

    def _init_display_protocol_state(self, config: FirmwareConfig) -> None:
        self._lg_pixels: list[int] = []
        self._lcd_mode = 0
        self._lcd_command = 0
        self._lcd_args: list[int] = []
        self._lcd_x = [0, config.width - 1]
        self._lcd_y = [0, config.height - 1]
        self._lcd_cursor = [0, 0]
        self._lcd_expected = 0
        self._lcd_streamed = 0
        self._lcd_direct_cursor = [0, 0]
        self._lcd_direct_window = [config.width, config.height]
        self._lcd_direct_origin = [0, 0]
        self._lcd_direct_calibrated = [False, False]
        self._lcd_gram_cursor = [0, 0]
        self._lcd_gram_addressed = False
        self._lcd_gram_dirty = False
        self._lcd_packed_21_state = 0
        self._lcd_data_byte_latch: dict[int, int] = {}
        # An older 0x028 board uses the direct 0x75/0x15/0x5C setup while
        # sharing the aperture with page-LCD traffic.  Hold only that exact
        # short grammar until it proves itself; all other traffic stays on
        # the existing parallel/page path.
        self._lcd_028_direct_probe: list[tuple[int, int, int]] = []
        # Some byte-wide controllers send complete 128-pixel RGB565 rows as
        # 0/base-command/+2-high/+2-low packets.  Hold only this exact
        # grammar; a mismatch is replayed through the established decoders.
        self._lcd_byte_020_row_probe: list[tuple[int, int, int]] = []
        self._lcd_byte_020_row_events: list[tuple[int, int, int]] = []
        self._lcd_byte_020_row_stage = ""
        self._lcd_byte_020_row_y = -1
        self._lcd_byte_020_row_words: list[int] = []
        self._lcd_byte_raster_stage = ""
        self._lcd_byte_raster_row = 0
        self._lcd_byte_raster_pixels = bytearray()
        # The E370-class +8/+C controller packs two RGB332 pixels into one
        # data word.  Keep it wholly separate from the ordinary 0x020/+4
        # command state: unrelated LCD traffic must not turn register 0x22
        # into a generic GRAM transfer halfway through a packed frame.
        self._lcd_packed_command = 0
        self._lcd_packed_window_order: list[int] = []
        self._lcd_packed_registers: dict[int, int] = {}
        self._lcd_packed_qualified = False
        self._lcd_packed_window = [0, 0, -1, -1]
        self._lcd_packed_cursor = [0, 0]
        self._lcd_packed_expected_words = 0
        self._lcd_packed_streamed_words = 0
        # Some earlier MSM5000 boards use a byte-wide, page-addressed
        # monochrome controller on the 0x02000000/+4 or 0x02800000/+4
        # aperture.  It is not RGB565: B0..BF select 8-pixel pages and the
        # 10..1F/00..0F pair selects a byte column.  Keep its state separate
        # from the direct RGB controllers until two complete adjacent page
        # rows prove the transport; that prevents an incidental B0 register
        # write on a colour panel from changing its renderer.
        self._lcd_page_current = -1
        self._lcd_page_port: int | None = None
        self._lcd_page_column_high: int | None = None
        self._lcd_page_column_ready = False
        self._lcd_page_column = 0
        self._lcd_page_start_column = 0
        self._lcd_page_data_count = 0
        self._lcd_page_row_bytes = 0
        self._lcd_page_width = 0
        self._lcd_page_height = 0
        self._lcd_page_bits_per_pixel = 1
        self._lcd_page_width_hint = detect_lcd_width_hint(self.image)
        self._lcd_page_geometry_rendered = False
        self._lcd_page_candidate_rows = 0
        self._lcd_page_last_finished = -1
        self._lcd_page_qualified = False
        self._lcd_page_seen: set[int] = set()
        self._lcd_page_ram = bytearray(16 * 256)
        self._lcd_index = 0
        self._lcd_indexed_dirty = False

    def _init_unmapped_state(self) -> None:
        self.dynamic_pages: set[int] = set()
        self.dynamic_page_first_accesses: deque[dict[str, int | str]] = deque(
            maxlen=UNMAPPED_ACCESS_HISTORY_LIMIT
        )
        self.last_unmapped: dict[str, int | str] | None = None
        self.unmapped_accesses: deque[dict[str, int | str]] = deque(
            maxlen=UNMAPPED_ACCESS_HISTORY_LIMIT
        )
        self._chunk_unmapped: dict[str, int | str] | None = None
        self._lcd_mmio_extended_mapped = False

    def _init_input_state(self, config: FirmwareConfig) -> None:
        self.held_keys: set[int] = set()
        self.key_baselines: dict[int, int] = {}
        self.key_press_read_epochs: dict[int, int] = {}
        self.key_read_epoch = 0
        self.key_register_reads = 0
        self.key_register_read_pcs: Counter[int] = Counter()
        self.input_profile = detect_input_profile(self.image, config.load_address)
        self.input_error = ""
        self.input_events = 0
        self.firmware_key_events = 0
        if self.input_profile is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._input_entry_observed,
                             begin=self.input_profile[1], end=self.input_profile[1])

    def _init_nor_probe_state(self) -> None:
        self._flash_restore: dict[int, bytes] = {}
        # T720 and Motorola MSM510x firmware directly issue Intel's ID
        # sequence (0x90, halfword reads at +0/+2, then 0xFF).  The mapped
        # bytes are not proof of the physical device, so observe completed
        # probes only; never alter NOR responses from this telemetry.
        self._parallel_nor_direct_probe: dict[str, int] | None = None
        self.primary_parallel_nor_direct_id_probes: list[dict[str, int]] = []

    def _init_audio_state(self) -> None:
        self.audio_player = ApproximateSmafPlayer() if ApproximateSmafPlayer is not None else None
        self.audio_play_requests = 0
        self.audio_last_size = 0
        self.ma2_silent_boot_calls = 0
        self.audio_discovered_address: int | None = None
        self._audio_probe_hook: int | None = None

    def _install_remaining_hooks(
            self, config: FirmwareConfig, secondary_base: int | None,
            eeprom_enabled: bool) -> None:
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._unmapped)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read, begin=0x03000000, end=0x03FFFFFF)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read, begin=0x02800000, end=0x02800FFF)
        self.uc.hook_add(UC_HOOK_MEM_READ, self._read, begin=0x02C00000, end=0x02C00FFF)
        flash_end = config.load_address + len(self.image)
        open_bus_exclusions = [
            *NAND_MMIO_RANGES,
            (0x02000000, 0x02801000),  # LCD buses and indexed registers
            (0x02C00000, 0x02C01000),
            (0x03000000, 0x04000000),  # MSM MMIO plus internal RAM
            *((address, address + len(value))
              for address, value in STABLE_MSM_MMIO),
        ]
        if config.key_register is not None:
            open_bus_exclusions.append((config.key_register,
                                        config.key_register + 4))
        if config.board_revision_register is not None:
            open_bus_exclusions.append((config.board_revision_register,
                                        config.board_revision_register + 4))
        if secondary_base is not None:
            open_bus_exclusions.append((
                secondary_base, secondary_base + config.secondary_flash_size
            ))
        for left, right in interval_gaps(
                flash_end, config.ram_base, open_bus_exclusions):
            self.uc.hook_add(UC_HOOK_MEM_READ, self._open_bus_read,
                             begin=left, end=right - 1)
        # The old MSMs commonly expose one 8 MiB SDRAM bank.  A permissive
        # backing arena must not make a physically absent second bank writable.
        absent_start = config.ram_base + config.ram_size
        if absent_start < 0x02000000:
            for left, right in interval_gaps(
                    absent_start, 0x02000000, open_bus_exclusions):
                self.uc.hook_add(UC_HOOK_MEM_READ, self._open_bus_read,
                                 begin=left, end=right - 1)
        if (config.board_revision_register is not None
                and config.board_revision_value is not None):
            self.uc.hook_add(UC_HOOK_MEM_READ, self._board_revision_read,
                             begin=config.board_revision_register,
                             end=config.board_revision_register + 3)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._lcd_write,
                         begin=0x02000000, end=0x02800FFF)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._lcd_write,
                         begin=0x02C00000, end=0x02C00FFF)
        if config.framebuffer_flush_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._framebuffer_rows,
                             begin=config.framebuffer_flush_address,
                             end=config.framebuffer_flush_address)
        if config.framebuffer_rect_flush_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._framebuffer_rect,
                             begin=config.framebuffer_rect_flush_address,
                             end=config.framebuffer_rect_flush_address)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._flash_write,
                         begin=config.load_address,
                         end=config.load_address + len(self.image) - 1,
                         user_data=(config.load_address, self.flash))
        self.uc.hook_add(UC_HOOK_MEM_READ, self._flash_read,
                         begin=config.load_address,
                         end=config.load_address + len(self.image) - 1,
                         user_data=(config.load_address, self.flash))
        if secondary_base is not None and self.secondary_flash is not None:
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._flash_write,
                             begin=secondary_base,
                             end=secondary_base + config.secondary_flash_size - 1,
                             user_data=(secondary_base, self.secondary_flash))
            self.uc.hook_add(UC_HOOK_MEM_READ, self._flash_read,
                             begin=secondary_base,
                             end=secondary_base + config.secondary_flash_size - 1,
                             user_data=(secondary_base, self.secondary_flash))
            if config.secondary_flash_read_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._secondary_flash_read_fast,
                                 begin=config.secondary_flash_read_address,
                                 end=config.secondary_flash_read_address)
            if config.secondary_flash_write_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._secondary_flash_write_fast,
                                 begin=config.secondary_flash_write_address,
                                 end=config.secondary_flash_write_address)
        if eeprom_enabled:
            if config.eeprom_read_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._eeprom_read_fast,
                                 begin=config.eeprom_read_address,
                                 end=config.eeprom_read_address)
            if config.eeprom_write_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._eeprom_write_fast,
                                 begin=config.eeprom_write_address,
                                 end=config.eeprom_write_address)
        if config.legacy_efs_page_read_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._legacy_efs_page_read,
                             begin=config.legacy_efs_page_read_address,
                             end=config.legacy_efs_page_read_address)
        if config.nand_enabled:
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._nand_command,
                             begin=0x01A00000, end=0x01A00000)
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._nand_address_write,
                             begin=0x01900000, end=0x01900000)
            self.uc.hook_add(UC_HOOK_MEM_READ, self._nand_data_read,
                             begin=0x01800000, end=0x01800003)
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._nand_data_write,
                             begin=0x01800000, end=0x01800003)
        if config.audio_play_address:
            self.uc.hook_add(UC_HOOK_CODE, self._audio_play,
                             begin=config.audio_play_address,
                             end=config.audio_play_address)
        if config.ma2_silent_boot_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._ma2_silent_boot,
                             begin=config.ma2_silent_boot_address,
                             end=config.ma2_silent_boot_address)
        if config.fast_boot_address and config.linker is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_boot_hook,
                             begin=config.fast_boot_address,
                             end=config.fast_boot_address)
        if config.nand_enabled:
            if config.nand_bad_block_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._nand_bad_block,
                                 begin=config.nand_bad_block_address,
                                 end=config.nand_bad_block_address)
            if config.nand_read_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._nand_read_fast,
                                 begin=config.nand_read_address,
                                 end=config.nand_read_address)
            if config.nand_write_address is not None:
                self.uc.hook_add(UC_HOOK_CODE, self._nand_write_fast,
                                 begin=config.nand_write_address,
                                 end=config.nand_write_address)
        if config.delay_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._return_if_thumb_signature,
                             begin=config.delay_address, end=config.delay_address,
                             user_data=DELAY_SIGNATURE)
        for address in busy_delay_addresses(self.original_image,
                                            config.load_address,
                                            config.busy_delay_address):
            offset = address - config.load_address
            signature = next((candidate for candidate in BUSY_DELAY_SIGNATURES
                              if self.original_image[
                                  offset:offset + len(candidate)] == candidate),
                             BUSY_DELAY_SIGNATURE)
            self.uc.hook_add(UC_HOOK_CODE, self._return_busy_delay,
                             begin=address, end=address,
                             user_data=signature)
        for address in absent_optional_ram_probe_addresses(
                self.original_image, config.load_address,
                config.ram_base, config.ram_size):
            self.uc.hook_add(UC_HOOK_CODE, self._absent_optional_ram_probe,
                             begin=address, end=address)
        if config.rex_idle_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._rex_tick,
                             begin=config.rex_idle_address, end=config.rex_idle_address)
        if (config.rex_irq_wrapper_address is not None
                and config.rex_irq_status_address is not None):
            self.uc.hook_add(
                UC_HOOK_MEM_WRITE, self._rex_irq_status_write,
                begin=config.rex_irq_status_address,
                end=config.rex_irq_status_address + 7,
            )
            self.uc.hook_add(
                UC_HOOK_MEM_READ, self._rex_irq_status_read,
                begin=config.rex_irq_status_address,
                end=config.rex_irq_status_address + 7,
            )
        if config.board_adc_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._board_adc,
                             begin=config.board_adc_address, end=config.board_adc_address)
        if config.board_adc_reader_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._board_adc_reader_entry,
                             begin=config.board_adc_reader_address,
                             end=config.board_adc_reader_address)
        if config.flash_id_address is not None and config.flash_id_value is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._flash_id,
                             begin=config.flash_id_address, end=config.flash_id_address)
        if config.crc16_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._crc16_fast,
                             begin=config.crc16_address, end=config.crc16_address)
        if config.dmd_download_address is not None:
            self.uc.hook_add(UC_HOOK_CODE, self._dmd_download_fast,
                             begin=config.dmd_download_address,
                             end=config.dmd_download_address)
        for address in config.memory_clear_addresses:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_memory_clear,
                             begin=address, end=address)
        for address in config.memory_copy_addresses:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_memory_copy,
                             begin=address, end=address)
        for address in config.register_ramp_addresses:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_register_ramp,
                             begin=address, end=address)
        for address in config.arm_memory_copy_addresses:
            self.uc.hook_add(UC_HOOK_CODE, self._fast_arm_memory_copy,
                             begin=address, end=address)
        # GUI execution uses small run() chunks.  Keep this observer for the
        # session instead of repeatedly creating and deleting a Unicorn block
        # hook; long Windows sessions otherwise churn the backend hook list.
        self._trace_hook = self.uc.hook_add(UC_HOOK_BLOCK, self._trace)

    def close(self) -> None:
        LOGGER.info("emulator close begin model=%s instructions=%d fault=%r",
                    self.config.model, self.instructions, self.fault)
        try:
            if self._host_backend_fault is None:
                self.save_flash()
                self._save_eeprom()
                self._save_nand()
            else:
                # A host backend failure can interrupt a Python device hook at
                # an unknown point.  Keep the last durable state instead of
                # mixing a partial chunk into the next boot.
                LOGGER.warning("emulator state persistence skipped after host backend fault "
                               "model=%s", self.config.model)
        finally:
            if self.audio_player is not None:
                self.audio_player.close()
        LOGGER.info("emulator close complete model=%s", self.config.model)
