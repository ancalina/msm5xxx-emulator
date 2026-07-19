#!/usr/bin/env python3
"""Run staged, evidence-producing boot probes against representative firmware."""
from __future__ import annotations

import argparse
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
import tempfile

from PIL import Image

from ..core.emulator import GenericMSMEmulator, detect


def integer(value: str) -> int:
    return int(value.replace("_", ""), 0)


def parse_checkpoints(value: str) -> list[int]:
    points = sorted(set(integer(item) for item in value.split(",") if item.strip()))
    if not points or points[0] <= 0:
        raise argparse.ArgumentTypeError("checkpoints must be positive")
    return points


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("firmware", nargs="+", type=Path)
    result.add_argument(
        "--checkpoints", type=parse_checkpoints,
        default=parse_checkpoints("100000,500000,1000000,5000000,20000000"),
        help="comma-separated cumulative instruction counts",
    )
    result.add_argument(
        "--chunk-steps", type=integer, default=25_000,
        help="timeline sampling cadence (0 records checkpoints only)",
    )
    result.add_argument("--output-dir", type=Path, default=Path("boot-probe"))
    result.add_argument(
        "--state-dir", type=Path,
        help="preserve NOR/NAND state here for a later warm-boot probe",
    )
    result.add_argument("--json", type=Path)
    return result


def boot_phase(state: dict[str, object], nonblack: int) -> str:
    if state["fault"]:
        return "fault"
    firmware_frames = int(state.get(
        "firmware_frame_sequence", state["frame_sequence"]
    ))
    display = firmware_frames > 0 and nonblack > 0
    preseed = int(state["frame_sequence"]) > 0 and nonblack > 0 and not display
    scheduler = int(state["rex_ticks"]) > 0
    secondary_telemetry = state.get("secondary_flash_telemetry")
    secondary_operations = (
        sum(int(secondary_telemetry.get(name, 0))
            for name in ("reads", "programs", "erases"))
        if isinstance(secondary_telemetry, dict) else 0
    )
    storage = (int(state["secondary_flash_reads"])
               + int(state["secondary_flash_writes"])
               + int(state.get("secondary_flash_changed_pages", 0))
               + secondary_operations
               + int(state["nand_reads"]) + int(state["nand_writes"])) > 0
    if display and scheduler and storage:
        return "runtime+display+storage"
    if display and scheduler:
        return "runtime+display"
    if display:
        return "visible-frame"
    if state.get("control_sink") is not None and not scheduler:
        return "control-sink"
    if preseed:
        return "preseed-frame"
    if int(state["lcd_writes"]) > 0:
        return "display-traffic"
    if scheduler:
        return "scheduler-active"
    return "early-boot"


def boot_event(state: dict[str, object], nonblack: int, frame_hash: str,
               reset_hash: str, previous_hash: str,
               saw_splash: bool) -> tuple[str, bool]:
    """Classify only time-ordered display evidence, never image contents."""
    if state["fault"]:
        return "fault", saw_splash
    firmware_frames = int(state.get(
        "firmware_frame_sequence", state["frame_sequence"]
    ))
    if saw_splash and firmware_frames and frame_hash != previous_hash:
        return "post-splash-changing", True
    if firmware_frames and nonblack and not saw_splash:
        if frame_hash != reset_hash:
            return "boot-splash", True
        return "firmware-visible-unchanged", False
    if saw_splash:
        return "post-splash-stable", True
    if state.get("control_sink") is not None and not int(state["rex_ticks"]):
        return "control-sink", False
    if int(state["lcd_writes"]):
        return "display-traffic", False
    return "early-boot", False


def visible_pixels(frame: bytes) -> int:
    return sum(any(frame[offset:offset + 3])
               for offset in range(0, len(frame), 3))


def firmware_visible_frame(state: dict[str, object], nonblack: int) -> bool:
    return bool(state["firmware_frame_sequence"] and nonblack)


def changed_pixels(previous: bytes, current: bytes) -> int | None:
    if len(previous) != len(current):
        return None
    return sum(previous[offset:offset + 3] != current[offset:offset + 3]
               for offset in range(0, len(current), 3))


def probe(path: Path, checkpoints: list[int], output_dir: Path,
          chunk_steps: int = 0, state_dir: Path | None = None) -> dict[str, object]:
    config = detect(path)
    result: dict[str, object] = {
        "file": str(path),
        "model": config.model,
        "chipset": config.chipset,
        "chipset_confidence": config.chipset_confidence,
        "image_kind": config.image_kind,
        "dump_status": config.dump_status,
        "image_offset": config.image_offset,
        "load_address": config.load_address,
        "flash_size": config.flash_size,
        "ram_base": config.ram_base,
        "ram_size": config.ram_size,
        "rex_idle_address": config.rex_idle_address,
        "rex_tick_address": config.rex_tick_address,
        "secondary_flash_address": config.secondary_flash_address,
        "detection_notes": config.detection_notes,
        "timeline": [],
        "checkpoints": [],
    }
    if config.image_kind != "firmware" or config.chipset == "MSM6050":
        result["status"] = "rejected"
        return result
    output_dir.mkdir(parents=True, exist_ok=True)
    state_context = (
        tempfile.TemporaryDirectory(prefix="msm5xxx-boot-probe-")
        if state_dir is None else nullcontext(str(state_dir.resolve()))
    )
    with state_context as selected_state_dir:
        state_root = Path(selected_state_dir)
        state_root.mkdir(parents=True, exist_ok=True)
        if state_dir is None:
            config.flash_state = str(state_root / "flash.json")
            config.secondary_flash_state = str(state_root / "secondary.json")
        else:
            config.flash_state = str(state_root / Path(config.flash_state).name)
            config.secondary_flash_state = str(
                state_root / Path(config.secondary_flash_state).name
            )
        result["state_mode"] = "ephemeral" if state_dir is None else "persistent"
        result["flash_state"] = config.flash_state
        result["secondary_flash_state"] = config.secondary_flash_state
        emulator = GenericMSMEmulator(config)
        previous = 0
        try:
            baseline = emulator.run(0)
            initial_width, initial_height, initial_frame = emulator.display_snapshot()
            initial_hash = hashlib.sha256(initial_frame).hexdigest()
            initial_nonblack = visible_pixels(initial_frame)
            result["initial_display"] = {
                "frame_sequence": baseline["frame_sequence"],
                "firmware_frame_sequence": baseline["firmware_frame_sequence"],
                "display_width": initial_width,
                "display_height": initial_height,
                "nonblack_pixels": initial_nonblack,
                "frame_sha256": initial_hash,
            }
            previous_state = baseline
            previous_timeline_frame = initial_frame
            previous_timeline_hash = initial_hash
            saw_splash = False
            for target in checkpoints:
                remaining = target - previous
                state: dict[str, object] = {}
                while remaining:
                    chunk = min(remaining, chunk_steps) if chunk_steps else remaining
                    state = emulator.run(chunk)
                    remaining -= chunk
                    width, height, timeline_frame = emulator.display_snapshot()
                    timeline_hash = hashlib.sha256(timeline_frame).hexdigest()
                    timeline_nonblack = visible_pixels(timeline_frame)
                    event, saw_splash = boot_event(
                        state, timeline_nonblack, timeline_hash, initial_hash,
                        previous_timeline_hash, saw_splash,
                    )

                    def delta(name: str) -> int:
                        return (int(state.get(name, 0))
                                - int(previous_state.get(name, 0)))

                    def flash_delta(device: str, name: str) -> int:
                        current = state.get(device)
                        prior = previous_state.get(device)
                        current_value = (current.get(name, 0)
                                         if isinstance(current, dict) else 0)
                        prior_value = (prior.get(name, 0)
                                       if isinstance(prior, dict) else 0)
                        return int(current_value) - int(prior_value)

                    result["timeline"].append({
                        "executed_instructions": state["instructions"],
                        "event": event,
                        "pc": state["pc"],
                        "fault": state["fault"],
                        "control_sink": state.get("control_sink"),
                        "display_width": width,
                        "display_height": height,
                        "frame_sequence": state["frame_sequence"],
                        "frame_publishes_delta": delta("frame_sequence"),
                        "firmware_frame_sequence": state[
                            "firmware_frame_sequence"
                        ],
                        "firmware_frame_publishes_delta": delta(
                            "firmware_frame_sequence"
                        ),
                        "frame_sha256": timeline_hash,
                        "frame_changed_pixels": changed_pixels(
                            previous_timeline_frame, timeline_frame
                        ),
                        "nonblack_pixels": timeline_nonblack,
                        "lcd_writes_delta": delta("lcd_writes"),
                        "rex_idle_entries_delta": delta("rex_idle_entries"),
                        "rex_ticks_delta": delta("rex_ticks"),
                        "secondary_flash_reads_delta": delta(
                            "secondary_flash_reads"
                        ),
                        "secondary_flash_writes_delta": delta(
                            "secondary_flash_writes"
                        ),
                        "secondary_flash_changed_pages_delta": delta(
                            "secondary_flash_changed_pages"
                        ),
                        "secondary_nor_reads_delta": flash_delta(
                            "secondary_flash_telemetry", "reads"
                        ),
                        "secondary_nor_programs_delta": flash_delta(
                            "secondary_flash_telemetry", "programs"
                        ),
                        "secondary_nor_program_bytes_delta": flash_delta(
                            "secondary_flash_telemetry", "program_bytes"
                        ),
                        "secondary_nor_erases_delta": flash_delta(
                            "secondary_flash_telemetry", "erases"
                        ),
                        "secondary_nor_erase_bytes_delta": flash_delta(
                            "secondary_flash_telemetry", "erase_bytes"
                        ),
                        "nand_reads_delta": delta("nand_reads"),
                        "nand_writes_delta": delta("nand_writes"),
                    })
                    previous_state = state
                    previous_timeline_frame = timeline_frame
                    previous_timeline_hash = timeline_hash
                    if state["fault"]:
                        break
                previous = target
                _width, _height, frame = emulator.display_snapshot()
                frame_hash = hashlib.sha256(frame).hexdigest()
                nonblack = visible_pixels(frame)
                top_hot = [
                    {"pc": f"0x{pc:08X}", "blocks": count}
                    for pc, count in emulator.hot.most_common(5)
                ]
                top_mmio = [
                    {"pc": f"0x{pc:08X}", "address": f"0x{address:08X}",
                     "size": size, "reads": count}
                    for (pc, address, size), count
                    in emulator.mmio_reads.most_common(5)
                ]
                cumulative_mmio = [
                    {"pc": f"0x{pc:08X}", "address": f"0x{address:08X}",
                     "size": size, "reads": count}
                    for (pc, address, size), count
                    in emulator.mmio_read_totals.most_common(20)
                ]
                screenshot = None
                if firmware_visible_frame(state, nonblack):
                    safe_model = "".join(
                        character if character.isalnum() or character in "-_"
                        else "_" for character in config.model
                    )
                    target_path = output_dir / f"{safe_model}-{target}.png"
                    Image.frombytes("RGB", (config.width, config.height), frame).save(
                        target_path
                    )
                    screenshot = str(target_path)
                checkpoint = {
                    "target_instructions": target,
                    "executed_instructions": state["instructions"],
                    "phase": boot_phase(state, nonblack),
                    "pc": state["pc"],
                    "lr": state["lr"],
                    "registers": state["registers"],
                    "fault": state["fault"],
                    "fault_context": state.get("fault_context"),
                    "frame_sequence": state["frame_sequence"],
                    "firmware_frame_sequence": state["firmware_frame_sequence"],
                    "display_width": config.width,
                    "display_height": config.height,
                    "nonblack_pixels": nonblack,
                    "frame_sha256": frame_hash,
                    "screenshot": screenshot,
                    "lcd_writes": state["lcd_writes"],
                    "lcd_protocol": state["lcd_protocol"],
                    "lcd_frame_protocol": state["lcd_frame_protocol"],
                    "lcd_port_writes": state["lcd_port_writes"],
                    "fast_register_ramps": state["fast_register_ramps"],
                    "primary_flash_ids": state["primary_flash_ids"],
                    "primary_flash_telemetry": state[
                        "primary_flash_telemetry"
                    ],
                    "rex_idle_entries": state["rex_idle_entries"],
                    "rex_ticks": state["rex_ticks"],
                    "rex_elapsed_ms": state["rex_elapsed_ms"],
                    "input_mode": state["input_mode"],
                    "input_events": state["input_events"],
                    "firmware_key_events": state["firmware_key_events"],
                    "secondary_flash_reads": state["secondary_flash_reads"],
                    "secondary_flash_writes": state["secondary_flash_writes"],
                    "secondary_flash_changed_pages": state[
                        "secondary_flash_changed_pages"
                    ],
                    "secondary_flash_telemetry": state[
                        "secondary_flash_telemetry"
                    ],
                    "eeprom_capacity": state["eeprom_capacity"],
                    "eeprom_reads": state["eeprom_reads"],
                    "eeprom_read_bytes": state["eeprom_read_bytes"],
                    "eeprom_writes": state["eeprom_writes"],
                    "eeprom_write_bytes": state["eeprom_write_bytes"],
                    "eeprom_changed_bytes": state["eeprom_changed_bytes"],
                    "eeprom_loaded_from_state": state[
                        "eeprom_loaded_from_state"
                    ],
                    "eeprom_error": state["eeprom_error"],
                    "secondary_flash_address": state["config"].get(
                        "secondary_flash_address"
                    ),
                    "nand_reads": state["nand_reads"],
                    "nand_writes": state["nand_writes"],
                    "nand_commands": state["nand_commands"],
                    "poll_escapes": state["poll_escapes"],
                    "control_sink": state.get("control_sink"),
                    "last_unmapped": state["last_unmapped"],
                    "unmapped_accesses": state.get("unmapped_accesses", []),
                    "top_hot_blocks": top_hot,
                    "top_mmio_reads": top_mmio,
                    "cumulative_mmio_reads": cumulative_mmio,
                    "tail": state["tail"],
                }
                result["checkpoints"].append(checkpoint)
                if state["fault"]:
                    break
        finally:
            emulator.close()
        result["secondary_flash_address"] = config.secondary_flash_address
        result["secondary_flash_state"] = config.secondary_flash_state
    result["status"] = (
        "fault" if result["checkpoints"][-1]["fault"] else "budget-exhausted"
    )
    return result


def main() -> int:
    args = parser().parse_args()
    if args.chunk_steps < 0:
        raise SystemExit("chunk steps must be non-negative")
    results = [probe(path, args.checkpoints, args.output_dir, args.chunk_steps,
                     args.state_dir)
               for path in args.firmware]
    report = {"checkpoints": args.checkpoints, "chunk_steps": args.chunk_steps,
              "results": results}
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.json:
        args.json.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 1 if any(item["status"] == "fault" for item in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
