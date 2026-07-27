#!/usr/bin/env python3
"""Extract and group firmware-required boot conditions from a dump corpus."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
import hashlib
import json
from pathlib import Path
import sys

from ..detection.firmware import detect
from ..detection.firmware_image import load_firmware_image
from ..detection.input import detect_input_profile


FIRMWARE_SUFFIXES = (
    ".bin", ".rom", ".dump", ".b16", ".bin_", ".ful", ".hex", ".hxb",
)


def integer(value: str) -> int:
    return int(value.replace("_", ""), 0)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("path", nargs="?", type=Path,
                        help="firmware file or directory")
    result.add_argument("--merge", nargs="+", type=Path, metavar="REPORT",
                        help="merge a complete set of shard JSON reports")
    result.add_argument("--workers", type=int, default=1)
    result.add_argument("--shard-count", type=int, default=1)
    result.add_argument("--shard-index", type=int, default=0)
    result.add_argument("--json", type=Path)
    return result


def paths(source: Path) -> list[Path]:
    if source.is_file():
        return [source]
    return sorted(item for item in source.rglob("*")
                  if item.is_file() and item.suffix.lower() in FIRMWARE_SUFFIXES)


def profile(path: Path) -> dict[str, object]:
    config = detect(path)
    image = load_firmware_image(path).image
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
    if config.upper_flash_address is not None:
        requirements.append("upper-nor")
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
        "sha256": config.firmware_sha256,
        "bytes": config.file_size,
        "model": config.model,
        "verified_model": config.verified_model,
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
        "upper_nor": config.upper_flash_address is not None,
        "framebuffer": config.framebuffer_address is not None,
        "input_profile": input_profile[0] if input_profile else None,
        "memory_clear_loops": len(config.memory_clear_addresses),
        "memory_copy_loops": (len(config.memory_copy_addresses)
                              + len(config.arm_memory_copy_addresses)),
        "register_ramps": len(config.register_ramp_addresses),
        "requirements": requirements,
        "notes": config.detection_notes,
        "detector": config.diagnostic_config(),
    }


def _inspect(
        path: Path
) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    try:
        return profile(path), None
    except Exception as error:  # one malformed dump must not hide the corpus
        return None, {
            "file": str(path), "error": str(error),
            "error_type": type(error).__name__,
            "bytes": path.stat().st_size,
        }


def _relative(path: Path, source: Path) -> str:
    return (path.name if source.is_file()
            else path.relative_to(source).as_posix())


def _inventory_digest(inventory: list[tuple[str, int]]) -> str:
    encoded = json.dumps(
        inventory, ensure_ascii=False, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _inventory_sha256(source: Path, candidates: list[Path]) -> str:
    inventory = [
        (_relative(path, source), path.stat().st_size) for path in candidates
    ]
    return _inventory_digest(inventory)


def _detector_digest(record: dict[str, object]) -> str:
    detector = dict(record["detector"])
    detector.pop("model", None)
    detector.pop("verified_model", None)
    firmware = dict(detector.get("firmware", {}))
    firmware.pop("basename", None)
    detector["firmware"] = firmware
    encoded = json.dumps(
        detector, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _exact_sha256_groups(
        records: list[dict[str, object]]
) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for record in records:
        grouped[str(record["sha256"])].append(record)
    result: list[dict[str, object]] = []
    for sha256, members in sorted(grouped.items()):
        sizes = {int(member["bytes"]) for member in members}
        if len(sizes) != 1:
            raise ValueError(f"same SHA-256 has conflicting sizes: {sha256}")
        paths = sorted(str(member["file"]) for member in members)
        detector_variants = {_detector_digest(member) for member in members}
        result.append({
            "sha256": sha256,
            "bytes": sizes.pop(),
            "paths": paths,
            "path_count": len(paths),
            "canonical_path": paths[0],
            "merge_basis": "exact-raw-sha256",
            "models_observed": sorted({
                str(member["model"]) for member in members
            }),
            "verified_models_observed": sorted({
                str(member["verified_model"]) for member in members
                if member["verified_model"] is not None
            }),
            "detector_path_variance": len(detector_variants) > 1,
            "detector_variants": len(detector_variants),
        })
    return result


def build_report(
        records: list[dict[str, object]],
        errors: list[dict[str, object]],
        shard: dict[str, object],
) -> dict[str, object]:
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
    exact_groups = _exact_sha256_groups(records)
    return {
        "schema": 3,
        "shard": shard,
        "summary": {
            "files": len(records) + len(errors),
            "raw_files": len(records) + len(errors),
            "detected": len(records),
            "unique_exact_sha256": len(exact_groups),
            "duplicate_raw_files": sum(
                int(group["path_count"]) - 1 for group in exact_groups
            ),
            "detector_path_variance_groups": sum(
                bool(group["detector_path_variance"]) for group in exact_groups
            ),
            "accepted_firmware": len(accepted),
            "errors": len(errors),
            "chipsets": dict(sorted(chipsets.items())),
            "required_conditions": dict(requirements.most_common()),
            "condition_groups": len(groups),
        },
        "groups": groups,
        "exact_sha256_groups": exact_groups,
        "firmwares": records,
        "errors": errors,
    }


def scan_report(source: Path, workers: int = 1, shard_count: int = 1,
                shard_index: int = 0) -> dict[str, object]:
    all_paths = paths(source)
    inventory_sha256 = _inventory_sha256(source, all_paths)
    selected = [path for index, path in enumerate(all_paths)
                if index % shard_count == shard_index]
    executor: ProcessPoolExecutor | None = None
    if workers == 1:
        inspected = map(_inspect, selected)
    else:
        executor = ProcessPoolExecutor(max_workers=workers)
        inspected = executor.map(_inspect, selected)
    records: list[dict[str, object]] = []
    errors: list[dict[str, object]] = []
    try:
        for index, (record, error) in enumerate(inspected, 1):
            relative = _relative(selected[index - 1], source)
            if record is not None:
                record["file"] = relative
                records.append(record)
            elif error is not None:
                error["file"] = relative
                errors.append(error)
            if index % 10 == 0 or index == len(selected):
                print(f"{index}/{len(selected)}", file=sys.stderr, flush=True)
    finally:
        if executor is not None:
            executor.shutdown()
    return build_report(records, errors, {
        "count": shard_count, "index": shard_index,
        "source_files": len(all_paths), "selected_files": len(selected),
        "complete": shard_count == 1, "inventory_sha256": inventory_sha256,
    })


def merge_reports(reports: list[dict[str, object]]) -> dict[str, object]:
    if not reports or any(report.get("schema") != 3 for report in reports):
        raise ValueError("all merge inputs must use condition report schema 3")
    shards = [report["shard"] for report in reports]
    counts = {int(shard["count"]) for shard in shards}
    source_counts = {int(shard["source_files"]) for shard in shards}
    inventories = {str(shard["inventory_sha256"]) for shard in shards}
    if len(counts) != 1 or len(source_counts) != 1 or len(inventories) != 1:
        raise ValueError("shard count/source inventory mismatch")
    count = counts.pop()
    indexes = [int(shard["index"]) for shard in shards]
    if sorted(indexes) != list(range(count)):
        raise ValueError("merge requires each shard index exactly once")
    records = [record for report in reports for record in report["firmwares"]]
    errors = [error for report in reports for error in report["errors"]]
    files = [str(item["file"]) for item in (*records, *errors)]
    if len(files) != len(set(files)):
        raise ValueError("duplicate raw path across shard reports")
    source_files = source_counts.pop()
    if len(files) != source_files:
        raise ValueError(
            f"incomplete shard set: expected {source_files}, got {len(files)}"
        )
    inventory = sorted(
        (str(item["file"]), int(item["bytes"])) for item in (*records, *errors)
    )
    inventory_sha256 = inventories.pop()
    if _inventory_digest(inventory) != inventory_sha256:
        raise ValueError("merged rows do not match source inventory")
    expected = {
        index: {path for position, (path, _size) in enumerate(inventory)
                if position % count == index}
        for index in range(count)
    }
    for report in reports:
        index = int(report["shard"]["index"])
        actual = {str(item["file"])
                  for item in (*report["firmwares"], *report["errors"])}
        if actual != expected[index]:
            raise ValueError(f"shard {index} path assignment mismatch")
    records.sort(key=lambda item: str(item["file"]).lower())
    errors.sort(key=lambda item: str(item["file"]).lower())
    return build_report(records, errors, {
        "count": count, "index": None, "source_files": source_files,
        "selected_files": len(files), "complete": True, "merged": True,
        "inventory_sha256": inventory_sha256,
    })


def main() -> int:
    args = parser().parse_args()
    if bool(args.path) == bool(args.merge):
        raise SystemExit("provide exactly one path or --merge reports")
    if not 1 <= args.workers <= 32:
        raise SystemExit("--workers must be in 1..32")
    if args.shard_count < 1 or not 0 <= args.shard_index < args.shard_count:
        raise SystemExit("--shard-index must be in 0..--shard-count-1")
    try:
        if args.merge:
            reports = [
                json.loads(path.read_text(encoding="utf-8")) for path in args.merge
            ]
            report = merge_reports(reports)
        else:
            report = scan_report(
                args.path, args.workers, args.shard_count, args.shard_index
            )
    except ValueError as error:
        raise SystemExit(str(error)) from error
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
