"""GUI-free QEMU MSM5xxx transport shared by desktop and Android."""
from __future__ import annotations

import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import tempfile
import threading

from gdb_remote import Remote
from msm5xxx_emulator.core import FirmwareConfig, GenericMSMEmulator
from msm5xxx_emulator.core.constants import STABLE_MSM_MMIO
from msm5xxx_emulator.detection import detect
from msm5xxx_emulator.detection.arm import (
    thumb_bl_target,
    thumb_literal_value,
)
from msm5xxx_emulator.detection.boot import (
    DMD_DOWNLOAD_SIGNATURE,
    find_ma2_silent_boot_wait,
)
from msm5xxx_emulator.detection.storage import (
    EEPROM_24LCXX_READ_SIGNATURE,
    EEPROM_24LCXX_X430_READ_PREFIX,
    EEPROM_24LCXX_X430_WRITE_PREFIX,
    eeprom_24lcxx_write_at,
    fujitsu_x16_flash_ids,
    find_embedded_fujitsu_x16_nor,
    find_primary_fsd_amd_x16_nor,
)
from msm5xxx_emulator.detection.upper_nor import (
    UPPER_FLASH_ADDRESS,
    UPPER_FLASH_SIZE,
)
from msm5xxx_emulator.devices.storage.nor import NORFlash
from msm5xxx_emulator.state_io import atomic_write_text, exclusive_path_lock
from unicorn import arm_const


RECORD_SIZE = 16
LCD_WRITE = 1
TELEMETRY = 2
DEVICE_TELEMETRY = 3
INPUT_TELEMETRY = 4
AUDIO_WRITE = 5
AUDIO_STATUS = 6
AUDIO_STATUS_OVERFLOW = 1
AUDIO_STATUS_RESET = 2
HOST_INPUT = 0x80
REGISTER_NAMES = tuple(f"r{index}" for index in range(13)) + (
    "sp", "lr", "pc", "cpsr",
)
PAUSE_TIMER_ADDRESS = 0x04800020
PERSISTENT_STATE_FILES = (
    "primary-writable.raw", "secondary.raw", "upper.raw", "eeprom.raw",
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


def qemu_upper_nor_enabled(config: object) -> bool:
    """Accept only the detector's closed fixed upper-NOR range."""
    address = getattr(config, "upper_flash_address", None)
    size = int(getattr(config, "upper_flash_size", 0))
    if address is None and size == 0:
        return False
    if address != UPPER_FLASH_ADDRESS or size != UPPER_FLASH_SIZE:
        raise ValueError("QEMU cannot represent the detected upper NOR")
    return True


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
    """Encode only the detector-closed, explicitly enabled C80 route."""
    if not enabled:
        return None
    candidate = getattr(config, "rex_static_controller_candidate", None)
    required = {
        "signature": "static-c80-controller-callback-v1",
        "controller_class":
            "legacy-c80-index1e-delta5-controller-candidate-v1",
        "accepted": True,
        "active": False,
        "vector": 0x18,
        "mask": 0x0200,
        "callback_delta": 5,
        "callback_validation_size": 68,
    }
    if (not isinstance(candidate, dict)
            or any(candidate.get(key) != value
                   for key, value in required.items())):
        return None
    integer_fields = (
        "vector_target", "status", "enable", "wrapper_file_offset",
        "handler_slot", "handler_file_offset", "handler_validation_size",
        "callback_slot", "callback_file_offset", "wrapper_validation_size",
    )
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
            or int(candidate["vector_target"]) != ram_base
            or status != 0x03000C80 or enable != status + 0x14
            or tuple(candidate.get("status_banks", ()))
               != (status, status + 4)
            or tuple(candidate.get("clear_banks", ()))
               != (status, status + 4)
            or tuple(candidate.get("controller_write_banks", ()))
               != (enable, enable + 4)
            or tuple(candidate.get("controller_aperture", ()))
               != (status, enable + 6)
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
        status, enable, 0x0200, 5_000_000,
        ram_base, wrapper, handler_slot, handler, handler_size,
        callback_slot, callback,
    )
    return ":".join(f"{value:x}" for value in values)


def read_consume_rex_irq_profile(config: object, enabled: bool) -> str | None:
    """Encode an explicitly enabled, detector-closed read-consume route."""
    if not enabled:
        return None
    candidate = getattr(config, "rex_static_controller_candidate", None)
    classes = {
        "legacy-msm5000-620-two-bank-read-consume-v1": 12,
        "legacy-msm5000-620-two-bank-read-consume-group10-v1": 10,
    }
    required = {
        "signature": "static-msm5000-620-controller-callback-v1",
        "accepted": True,
        "active": False,
        "promotion": "experimental-only",
        "vector": 0x18,
        "mask": 0x0200,
        "callback_delta": 5,
        "callback_validation_size": 68,
        "pending_read_semantics": "consume-on-read",
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
            or tuple(candidate.get("mask_set_banks", ()))
               != (status, status + 4)
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
                 qemu_prefix: tuple[str, ...] = ()) -> None:
        self.config = config if config is not None else detect(firmware)
        state_dir = qemu_state_directory(state_dir, self.config)
        self.temporary = tempfile.TemporaryDirectory(prefix="msm5xxx-qemu-gui-")
        temporary = Path(self.temporary.name)
        if state_dir is not None:
            state_dir.mkdir(parents=True, exist_ok=True)
        firmware_image = firmware.read_bytes()
        self.rex_c80_profile = c80_rex_irq_profile(
            self.config, experimental_c80
        )
        self.rex_read_consume_profile = read_consume_rex_irq_profile(
            self.config, experimental_c80
        )
        self.config.rex_static_controller_experimental = (
            self.rex_c80_profile is not None
            or self.rex_read_consume_profile is not None
        )
        upper_nor_enabled = qemu_upper_nor_enabled(self.config)
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
        self.audio_stream_enabled = False
        self.audio_stream_seen = False
        self.audio_stream_order = 0
        self.audio_stream_status = "disabled"
        self.audio_stream_reject_reason: str | None = None
        self.audio_stream_dropped = 0
        self.matrix_input_profile: dict[str, object] | None = None
        self.matrix_input_sideband_producer: dict[str, object] | None = None
        self.matrix_held: dict[int, tuple[int, int, int]] = {}
        self.sideband_held: set[int] = set()
        self.state_imports: list[str] = []
        self.config.flash_state = str(temporary / "primary.flash.json")
        self.config.secondary_flash_state = str(temporary / "secondary.flash.json")
        if upper_nor_enabled:
            self.config.upper_flash_state = str(temporary / "upper.flash.json")
        self.decoder = GenericMSMEmulator(self.config)
        if self.config.load_address != 0:
            raise ValueError("QEMU PoC requires NOR=0")
        memory_profile = qemu_memory_profile(
            self.config, unicorn_state(self.decoder)
        )

        lcd_listener = loopback_listener()
        input_listener = None
        try:
            input_listener = loopback_listener()
            gdb_listener = loopback_listener()
        except Exception:
            lcd_listener.close()
            if input_listener is not None:
                input_listener.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise
        lcd_host, lcd_port = lcd_listener.getsockname()
        input_host, input_port = input_listener.getsockname()
        gdb_host, gdb_port = gdb_listener.getsockname()
        eligible = (
            self.config.chipset == "MSM5000"
            and self.config.board_adc_reader_address is not None
        )
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
        if eligible:
            machine += ",sbi=on"
        if (self.config.ready_poll is not None
                and len(self.config.ready_poll["entries"]) == 1):
            profile = self.config.ready_poll
            machine += (
                f",ready-poll={int(profile['status_address']):x}:"
                f"{int(profile['mask']):x}:"
                f"{int(profile['pulse_address']):x}:"
                f"{int(profile['entries'][0]):x}"
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
        if (audio is not None
                and audio.get("static_status") == "accepted"
                and audio.get("family") == "ma2"
                and self.config.ma2_silent_boot_address is not None):
            machine += (
                f",audio-aperture={int(audio['base']):x}:"
                f"{int(audio['data_offset']):x}"
            )
            self.audio_stream_enabled = True
            self.audio_stream_status = "pending"
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
        primary_profile = find_primary_fsd_amd_x16_nor(
            firmware_image[:self.config.flash_size],
            self.config.flash_id_address, self.config.flash_size,
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
            storage_args.extend((
                "-drive",
                f"file={primary_state},if=pflash,format=raw,unit=0",
            ))
            loader_size = base
            pflash_unit = 1
            self.config.detection_notes.append(
                "primary x16 NOR writable tail selected from unique "
                "fsd_amd descriptor/writer/ID linkage"
            )
        secondary = self.decoder.secondary_flash
        secondary_base = self.config.secondary_flash_address
        secondary_size = self.config.secondary_flash_size
        embedded_secondary = None
        if secondary_base is None and primary_profile is None:
            embedded_secondary = find_embedded_fujitsu_x16_nor(
                firmware_image, self.config.flash_size,
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
                firmware_image,
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
                firmware_image, self.config.secondary_flash_write_address,
                self.config.load_address, int(secondary_base or 0),
            )
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
                    raise ValueError("persistent secondary NOR size mismatch")
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
        eeprom_profile, eeprom_reject = eeprom_gpio_profile(
            firmware_image, self.config
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
            self.process = subprocess.Popen(
                [
                    *qemu_prefix, str(qemu), "-M", machine, "-cpu", "ti925t",
                    "-m", f"{self.config.ram_size // (1024 * 1024)}M",
                    *raw_loader_arguments(
                        loader, self.config.ram_size, temporary, loader_size,
                        loader_exclude,
                    ),
                    *storage_args,
                    "-chardev",
                    f"socket,id=lcd,host={lcd_host},port={lcd_port},"
                    "server=off,nodelay=on",
                    "-chardev",
                    f"socket,id=input,host={input_host},port={input_port},"
                    "server=off,nodelay=on",
                    "-chardev",
                    f"socket,id=gdb,host={gdb_host},port={gdb_port},"
                    "server=off,nodelay=on",
                    "-nographic", "-monitor", "none", "-serial", "none",
                    "-S", "-gdb", "chardev:gdb",
                    "-icount", "shift=6,align=on,sleep=on",
                    "-no-reboot", "-no-shutdown",
                ],
                stdout=subprocess.DEVNULL,
                stderr=self.stderr,
                text=True,
            )
        except Exception:
            lcd_listener.close()
            input_listener.close()
            gdb_listener.close()
            self.stderr.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise
        try:
            try:
                self.lcd_socket = self._accept_qemu(lcd_listener)
                self.input_socket = self._accept_qemu(input_listener)
                gdb_socket = self._accept_qemu(gdb_listener)
            finally:
                lcd_listener.close()
                input_listener.close()
                gdb_listener.close()
            self.lcd_socket.settimeout(0.2)
            self.input_socket.settimeout(0.2)
            self.input_socket.setsockopt(
                socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
            )
            with gdb_socket:
                gdb_socket.settimeout(10)
                remote = Remote(gdb_socket)
                remote.command("qSupported:qXfer:features:read+")
                if remote.command("D") != "OK":
                    raise RuntimeError("QEMU GDB detach failed")
        except Exception:
            lcd_listener.close()
            input_listener.close()
            gdb_listener.close()
            if hasattr(self, "lcd_socket"):
                self.lcd_socket.close()
            if hasattr(self, "input_socket"):
                self.input_socket.close()
            self._terminate_process()
            self.stderr.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise

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
        try:
            self.lcd_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.input_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._terminate_process()

    def _reject_audio_stream(self, reason: str, dropped: int = 0) -> None:
        first_rejection = self.audio_stream_status != "rejected"
        if first_rejection:
            self.audio_stream_status = "rejected"
            self.audio_stream_reject_reason = reason
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
        self.audio_stream_status = "active"

    def _replay_audio_status(self, record: bytes | bytearray) -> None:
        status = record[1]
        order, dropped, reserved = struct.unpack_from("<III", record, 4)
        if (not self.audio_stream_enabled or record[2:4] != b"\0\0"
                or reserved != 0):
            self._reject_audio_stream("qemu-audio-status-shape")
        elif status == AUDIO_STATUS_OVERFLOW and dropped:
            self.audio_stream_order = order
            self._reject_audio_stream("qemu-audio-overflow", dropped)
        elif status == AUDIO_STATUS_RESET and order == dropped == 0:
            self._reject_audio_stream("qemu-audio-reset")
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
            if (self.audio_stream_enabled
                    and self.audio_stream_status != "rejected"):
                self.decoder._flush_audio_transport_renderer()
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

    def replay(self, stop: threading.Event) -> None:
        input_pending = bytearray()
        lcd_pending = bytearray()
        streams = (
            (self.input_socket, input_pending),
            (self.lcd_socket, lcd_pending),
        )
        while not stop.is_set() and self.process.poll() is None:
            try:
                readable, _, _ = select.select(
                    (self.input_socket, self.lcd_socket), (), (), 0.2
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
                        channel = "input" if stream is self.input_socket else "LCD"
                        self.decoder.input_error = (
                            f"QEMU {channel} channel closed"
                        )
                        self._terminate_process()
                    return
                pending.extend(chunk)
                complete = len(pending) // RECORD_SIZE * RECORD_SIZE
                for offset in range(0, complete, RECORD_SIZE):
                    self._replay_record(
                        pending[offset:offset + RECORD_SIZE]
                    )
                del pending[:complete]

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
        self.lcd_socket.close()
        self.input_socket.close()
        self._terminate_process()
        self.stderr.close()
        self.decoder.close()
        self.temporary.cleanup()
