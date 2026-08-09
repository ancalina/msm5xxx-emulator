#!/usr/bin/env python3
"""Run the QEMU PoC while the unchanged emulator GUI decodes LCD writes."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import queue
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk


ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "src"))

from gdb_remote import Remote  # noqa: E402
from msm5xxx_emulator.core import GenericMSMEmulator  # noqa: E402
from msm5xxx_emulator.core.constants import STABLE_MSM_MMIO  # noqa: E402
from msm5xxx_emulator.detection import detect  # noqa: E402
from msm5xxx_emulator.detection.storage import (  # noqa: E402
    EEPROM_24LCXX_READ_SIGNATURE,
    eeprom_24lcxx_write_at,
    fujitsu_x16_flash_ids,
    find_primary_fsd_amd_x16_nor,
)
from msm5xxx_emulator.devices.storage.nor import NORFlash  # noqa: E402
from msm5xxx_emulator.gui.app import Window  # noqa: E402
from msm5xxx_emulator.gui.locale import display_model_name  # noqa: E402
from unicorn import arm_const  # noqa: E402


RECORD_SIZE = 16
LCD_WRITE = 1
TELEMETRY = 2
DEVICE_TELEMETRY = 3
INPUT_TELEMETRY = 4
HOST_INPUT = 0x80
REGISTER_NAMES = tuple(f"r{index}" for index in range(13)) + (
    "sp", "lr", "pc", "cpsr",
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
                         size: int | None = None) -> list[str]:
    """Split raw NOR only around QEMU loader's machine-RAM size limit."""
    data = image.read_bytes()
    if size is not None:
        if not 0 <= size <= len(data):
            raise ValueError("raw loader size is outside the image")
        data = data[:size]
    parts = [(image, 0)]
    if len(data) != image.stat().st_size or len(data) > max_size:
        parts = []
        for offset in range(0, len(data), max_size):
            part = temporary / f"primary-{offset:08x}.raw"
            part.write_bytes(data[offset:offset + max_size])
            parts.append((part, offset))
    return [argument for part, offset in parts for argument in (
        "-device", f"loader,file={part},addr=0x{offset:x},force-raw=on",
    )]


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


def eeprom_gpio_profile(image: bytes, config: object) -> tuple[int, int] | None:
    """Return the exact common 24LCxx GPIO aperture and static capacity."""
    read = getattr(config, "eeprom_read_address", None)
    write = getattr(config, "eeprom_write_address", None)
    geometry = getattr(config, "eeprom_geometry_address", None)
    load = getattr(config, "load_address", 0)
    if not all(isinstance(value, int) for value in (read, write, geometry)):
        return None
    read -= load
    write -= load
    if (image[read:read + len(EEPROM_24LCXX_READ_SIGNATURE)]
            != EEPROM_24LCXX_READ_SIGNATURE
            or not eeprom_24lcxx_write_at(image, write)):
        return None
    gpio = struct.pack("<II", 0x03000660, 0x03000670)
    if (not all(value in image[write:write + 0x700]
                for value in (gpio[:4], gpio[4:]))
            or not all(value in image[read:read + 0x700]
                       for value in (gpio[:4], gpio[4:]))):
        return None
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
            return 0x03000660, 0x8000
    return None


class Transport:
    def __init__(self, qemu: Path, firmware: Path,
                 state_dir: Path | None = None,
                 experimental_c80: bool = False) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="msm5xxx-qemu-gui-")
        temporary = Path(self.temporary.name)
        if state_dir is not None:
            state_dir.mkdir(parents=True, exist_ok=True)
        self.config = detect(firmware)
        firmware_image = firmware.read_bytes()
        self.rex_c80_profile = c80_rex_irq_profile(
            self.config, experimental_c80
        )
        self.config.rex_static_controller_experimental = (
            self.rex_c80_profile is not None
        )
        legacy_primary_state = Path(self.config.flash_state)
        legacy_secondary_state = Path(self.config.secondary_flash_state)
        legacy_eeprom_state = Path(str(self.config.flash_state) + ".eeprom.bin")
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
        self.matrix_input_profile: dict[str, object] | None = None
        self.matrix_input_sideband_producer: dict[str, object] | None = None
        self.matrix_held: dict[int, tuple[int, int, int]] = {}
        self.sideband_held: set[int] = set()
        self.state_imports: list[str] = []
        self.config.flash_state = str(temporary / "primary.flash.json")
        self.config.secondary_flash_state = str(temporary / "secondary.flash.json")
        if self.config.upper_flash_state:
            self.config.upper_flash_state = str(temporary / "upper.flash.json")
        self.decoder = GenericMSMEmulator(self.config)
        if self.config.load_address != 0:
            raise ValueError("QEMU PoC requires NOR=0")
        memory_profile = qemu_memory_profile(
            self.config, unicorn_state(self.decoder)
        )

        lcd_path = temporary / "lcd.sock"
        gdb_path = temporary / "gdb.sock"
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(lcd_path))
        listener.listen(1)
        eligible = (
            self.config.chipset == "MSM5000"
            and self.config.board_adc_reader_address is not None
        )
        machine = (
            "msm5xxx-poc,lcd-trace-chardev=lcd,"
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
        primary_seed, primary_imported = load_legacy_nor_state(
            bytes(self.decoder.flash.data), (legacy_primary_state,)
        )
        loader = firmware
        loader_size = None
        if primary_imported:
            loader = temporary / "primary.raw"
            loader.write_bytes(primary_seed)
            self.state_imports.append("primary-nor-json")
        storage_args: list[str] = []
        pflash_unit = 0
        primary_profile = find_primary_fsd_amd_x16_nor(
            firmware_image[:self.config.flash_size],
            self.config.flash_id_address, self.config.flash_size,
        )
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
        secondary_ids = fujitsu_x16_flash_ids(
            firmware_image, self.config.secondary_flash_write_address,
            self.config.load_address, int(secondary_base or 0),
        )
        if secondary_base is not None and secondary_ids:
            if loader == firmware:
                loader = temporary / "primary.raw"
                loader.write_bytes(primary_seed)
            secondary_state = ((state_dir / "secondary.raw")
                               if state_dir is not None else
                               (temporary / "secondary.raw"))
            secondary_seed = (
                bytes(secondary.data) if secondary is not None else
                b"\xff" * self.config.secondary_flash_size
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
        eeprom_profile = eeprom_gpio_profile(firmware_image, self.config)
        if eeprom_profile is not None:
            gpio_base, capacity = eeprom_profile
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
                f",eeprom-24lcxx-gpio={gpio_base:x}:8:8:c:1:1c:"
                f"{capacity:x}"
            )
            storage_args.extend((
                "-drive", f"file={eeprom_state},if=mtd,format=raw,unit=0",
            ))
        self.stderr = tempfile.TemporaryFile(mode="w+t")
        try:
            self.process = subprocess.Popen(
                [
                    str(qemu), "-M", machine, "-cpu", "ti925t",
                    "-m", f"{self.config.ram_size // (1024 * 1024)}M",
                    *raw_loader_arguments(
                        loader, self.config.ram_size, temporary, loader_size
                    ),
                    *storage_args,
                    "-chardev", f"socket,id=lcd,path={lcd_path},server=off",
                    "-nographic", "-monitor", "none", "-serial", "none",
                    "-S", "-gdb", f"unix:{gdb_path},server=on,wait=off",
                    "-icount", "shift=6,align=on,sleep=on",
                    "-no-reboot", "-no-shutdown",
                ],
                stdout=subprocess.DEVNULL,
                stderr=self.stderr,
                text=True,
            )
        except Exception:
            listener.close()
            self.stderr.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise
        try:
            listener.settimeout(5)
            try:
                self.lcd_socket, _ = listener.accept()
            finally:
                listener.close()
            self.lcd_socket.settimeout(0.2)
            deadline = time.monotonic() + 5
            while not gdb_path.exists():
                if self.process.poll() is not None:
                    raise RuntimeError(self._stderr_text() or
                                       "QEMU exited during startup")
                if time.monotonic() >= deadline:
                    raise TimeoutError("QEMU GDB socket did not appear")
                time.sleep(0.02)
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(10)
                sock.connect(str(gdb_path))
                remote = Remote(sock)
                remote.command("qSupported:qXfer:features:read+")
                if remote.command("D") != "OK":
                    raise RuntimeError("QEMU GDB detach failed")
        except Exception:
            listener.close()
            if hasattr(self, "lcd_socket"):
                self.lcd_socket.close()
            self._terminate_process()
            self.stderr.close()
            self.decoder.close()
            self.temporary.cleanup()
            raise

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

    def replay(self, stop: threading.Event) -> None:
        pending = bytearray()
        while not stop.is_set() and self.process.poll() is None:
            try:
                chunk = self.lcd_socket.recv(65536)
            except TimeoutError:
                continue
            except OSError:
                if stop.is_set() or self.process.poll() is not None:
                    break
                raise
            if not chunk:
                break
            pending.extend(chunk)
            complete = len(pending) // RECORD_SIZE * RECORD_SIZE
            for offset in range(0, complete, RECORD_SIZE):
                record = pending[offset:offset + RECORD_SIZE]
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
                    self.ready_responses = int.from_bytes(
                        record[12:16], "little"
                    )
                elif record[0] == INPUT_TELEMETRY:
                    matrix = int.from_bytes(record[4:8], "little")
                    self.input_pressed = bool(record[1])
                    self.input_row = matrix & 0xff
                    self.input_sense = matrix >> 8 & 0xff
                    self.input_rejections = matrix >> 16
                    self.input_host_events = int.from_bytes(
                        record[8:12], "little"
                    )
                    self.input_active_reads = int.from_bytes(
                        record[12:16], "little"
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
            self.lcd_socket.sendall(packet)
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
        self._terminate_process()
        self.stderr.close()
        self.decoder.close()
        self.temporary.cleanup()


class LiveWindow(Window):
    def __init__(self, root: tk.Tk, firmware: Path,
                 transport: Transport) -> None:
        self.transport = transport
        super().__init__(root, firmware)
        self.emulator = transport.decoder
        config = transport.config
        self.model.set(display_model_name(
            config.model, config.verified_model, self.ui_language
        ))
        self.device_details.set(
            f"QEMU TCG · {config.chipset} · {config.width}×{config.height}"
        )
        self.status.set("QEMU TCG real-time LCD transport")
        self.settings_button.configure(state="disabled")
        self.worker = threading.Thread(
            target=transport.replay, args=(self.stop,), daemon=False
        )
        self.worker.start()
        self.root.after(100, self._refresh_qemu_metrics)
        self.root.after(5, self._forward_qemu_keys)

    def _restart(self) -> None:
        pass

    def _key_supported(self, bit: int,
                       event_code: int | None = None) -> bool:
        return self.transport.can_set_key(bit, event_code)

    def _forward_qemu_keys(self) -> None:
        if self.closing:
            return
        while True:
            try:
                command = self.commands.get_nowait()
            except queue.Empty:
                break
            if len(command) in (2, 3) and isinstance(command[0], int):
                event_code = int(command[2]) if len(command) == 3 else None
                self.transport.set_key(
                    int(command[0]), bool(command[1]), event_code
                )
            elif command[0] == "framebuffer-format" and len(command) == 2:
                self.transport.decoder.set_framebuffer_format(str(command[1]))
        self.root.after(5, self._forward_qemu_keys)

    def _refresh_qemu_metrics(self) -> None:
        if self.closing:
            return
        emulator = self.transport.decoder
        width, height, _frame = emulator.display_snapshot()
        self.device_details.set(
            f"QEMU TCG · {emulator.config.chipset} · {width}×{height}"
        )
        self.metric_values["run"].set(f"{self.transport.instructions:,}")
        self.metric_values["pc"].set(f"0x{self.transport.pc:08X}")
        self.metric_values["lcd"].set(f"{emulator.lcd_writes:,}")
        self.metric_values["frame"].set(str(emulator.frame_sequence))
        self.root.after(100, self._refresh_qemu_metrics)

    def _close(self) -> None:
        if not self.closing:
            self.stop.set()
            if self.worker is not None and self.worker.is_alive():
                self.worker.join(1)
            self.transport.close()
        super()._close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware", type=Path)
    parser.add_argument("--qemu", required=True, type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--experimental-c80-controller", action="store_true")
    args = parser.parse_args()
    transport = Transport(
        args.qemu.resolve(), args.firmware.resolve(),
        args.state_dir.resolve() if args.state_dir is not None else None,
        args.experimental_c80_controller,
    )
    root = tk.Tk()
    window = LiveWindow(root, args.firmware.resolve(), transport)
    try:
        root.mainloop()
    finally:
        window._close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
