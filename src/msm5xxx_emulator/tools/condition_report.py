#!/usr/bin/env python3
"""Extract and group firmware-required boot conditions from a dump corpus."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

from ..detection.firmware import detect
from ..detection.input import detect_input_profile


FIRMWARE_SUFFIXES = (".bin", ".rom", ".dump")


def integer(value: str) -> int:
    return int(value.replace("_", ""), 0)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("path", type=Path, help="firmware file or directory")
    result.add_argument("--json", type=Path)
    return result


def paths(source: Path) -> list[Path]:
    if source.is_file():
        return [source]
    return sorted(item for item in source.iterdir()
                  if item.is_file() and item.suffix.lower() in FIRMWARE_SUFFIXES)


def profile(path: Path) -> dict[str, object]:
    config = detect(path)
    image = path.read_bytes()
    primary = image[
        config.image_offset:config.image_offset + min(config.flash_size, len(image))
    ]
    input_profile = detect_input_profile(primary, config.load_address)
    target_counts = Counter(item.target for item in config.overlays)
    reused_targets = {
        f"0x{target:08X}": count
        for target, count in sorted(target_counts.items()) if count > 1
    }
    requirements: list[str] = []
    if config.image_offset:
        requirements.append("strip-dump-header")
    if config.linker is not None:
        requirements.append("scatter-load-data-bss")
    if config.overlays:
        requirements.append("copy-executable-overlay")
    if reused_targets:
        requirements.append("track-runtime-overlay-bank")
    if config.runtime_overlays:
        requirements.append("inspect-runtime-overlay-sdram-source")
    if config.missing_overlays:
        requirements.append("missing-overlay-bytes")
    if "padded" in config.dump_status:
        requirements.append("pad-erased-nor-tail")
    if config.secondary_flash_address not in (None, 0):
        requirements.append("secondary-nor")
    if config.nand_enabled:
        requirements.append("raw-nand")
    if config.framebuffer_address is not None:
        requirements.append("ram-framebuffer")
    else:
        requirements.append("lcd-controller-bus")
    if config.memory_clear_addresses:
        requirements.append("large-bss-clear")
    if config.memory_copy_addresses or config.arm_memory_copy_addresses:
        requirements.append("large-memory-copy")
    if config.register_ramp_addresses:
        requirements.append("repeated-mmio-ramp")
    if config.rex_idle_address is not None or config.rex_tick_address is not None:
        requirements.append("rex-scheduler-timer")
    if input_profile is not None:
        requirements.append("keypad-producer-task")

    return {
        "file": str(path),
        "model": config.model,
        "chipset": config.chipset,
        "confidence": config.chipset_confidence,
        "accepted_firmware": (config.image_kind == "firmware"
                              and config.chipset != "MSM6050"),
        "image_kind": config.image_kind,
        "dump_status": config.dump_status,
        "image_offset": config.image_offset,
        "load_address": config.load_address,
        "flash_size": config.flash_size,
        "ram_base": config.ram_base,
        "ram_size": config.ram_size,
        "linker": config.linker is not None,
        "overlay_count": len(config.overlays),
        "missing_overlay_count": len(config.missing_overlays),
        "reused_overlay_targets": reused_targets,
        "runtime_overlay_dependencies": len(config.runtime_overlays),
        "nand_enabled": config.nand_enabled,
        "secondary_nor": config.secondary_flash_address not in (None, 0),
        "framebuffer": config.framebuffer_address is not None,
        "input_profile": input_profile[0] if input_profile else None,
        "memory_clear_loops": len(config.memory_clear_addresses),
        "memory_copy_loops": (len(config.memory_copy_addresses)
                              + len(config.arm_memory_copy_addresses)),
        "register_ramps": len(config.register_ramp_addresses),
        "requirements": requirements,
        "notes": config.detection_notes,
    }


def main() -> int:
    args = parser().parse_args()
    records: list[dict[str, object]] = []
    errors: list[dict[str, str]] = []
    for path in paths(args.path):
        try:
            records.append(profile(path))
        except Exception as error:  # one malformed dump must not hide the corpus
            errors.append({"file": str(path), "error": str(error)})

    accepted = [item for item in records if item["accepted_firmware"]]
    requirements = Counter(
        requirement
        for item in accepted for requirement in item["requirements"]
    )
    chipsets = Counter(str(item["chipset"]) for item in accepted)
    signatures: dict[tuple[object, ...], list[str]] = defaultdict(list)
    for item in accepted:
        key = (
            item["chipset"], item["flash_size"], item["ram_base"],
            item["ram_size"], item["linker"], item["nand_enabled"],
            item["secondary_nor"], item["framebuffer"],
            bool(item["reused_overlay_targets"]),
        )
        signatures[key].append(str(item["model"]))
    groups = [
        {
            "count": len(models),
            "chipset": key[0],
            "flash_size": key[1],
            "ram_base": key[2],
            "ram_size": key[3],
            "linker": key[4],
            "nand": key[5],
            "secondary_nor": key[6],
            "framebuffer": key[7],
            "runtime_overlay_banks": key[8],
            "models": models,
        }
        for key, models in sorted(signatures.items(), key=lambda item: -len(item[1]))
    ]
    report = {
        "summary": {
            "files": len(records) + len(errors),
            "detected": len(records),
            "accepted_firmware": len(accepted),
            "errors": len(errors),
            "chipsets": dict(sorted(chipsets.items())),
            "required_conditions": dict(requirements.most_common()),
            "condition_groups": len(groups),
        },
        "groups": groups,
        "firmwares": records,
        "errors": errors,
    }
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.json:
        args.json.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
