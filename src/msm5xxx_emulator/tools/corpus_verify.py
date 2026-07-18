#!/usr/bin/env python3
"""Isolated batch detector/smoke runner for MSM firmware collections."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("directory", type=Path)
    result.add_argument("--steps", type=lambda value: int(value, 0), default=100_000)
    result.add_argument("--chunk-steps", type=lambda value: int(value, 0), default=0,
                        help="execute each firmware in fixed chunks (matches GUI pacing)")
    result.add_argument("--until-visible", action="store_true",
                        help=("treat --steps as a visual-boot budget and stop "
                              "per firmware after its first non-black frame"))
    result.add_argument("--workers", type=int, default=4)
    result.add_argument("--json", type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    if not args.directory.is_dir():
        raise SystemExit(f"not a directory: {args.directory}")
    if args.steps < 0 or args.chunk_steps < 0 or not 1 <= args.workers <= 32:
        raise SystemExit("steps/chunk steps must be non-negative; workers must be in 1..32")
    source_root = Path(__file__).resolve().parents[2]
    files = sorted(path for path in args.directory.rglob("*") if path.is_file()
                   and path.suffix.lower() in (".bin", ".rom", ".dump"))
    environment = dict(os.environ)
    # Keep the runner importable when it is launched from a source checkout,
    # but do not discard an explicit dependency path supplied by a test or
    # portable installation (for example a local Unicorn wheel directory).
    inherited_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = os.pathsep.join(
        item for item in (str(source_root), inherited_pythonpath) if item
    )

    def invoke(path: Path) -> dict[str, object]:
        detect_command = [sys.executable, "-m", "msm5xxx_emulator.cli", str(path),
                          "--detect-only"]
        detected = subprocess.run(
            detect_command, capture_output=True, text=True, env=environment,
            timeout=60,
        )
        if detected.returncode:
            return {"file": str(path), "status": "detect-error",
                    "error": detected.stderr.strip().splitlines()[-1]}
        config = json.loads(detected.stdout)
        result: dict[str, object] = {
            "file": str(path), "status": "detected", "config": config,
        }
        if (config["image_kind"] != "firmware"
                or config["chipset"] not in ("MSM5000", "MSM5100", "MSM5500",
                                              "MSM5xxx")
                or args.steps == 0):
            result["status"] = "rejected" if args.steps else "detected"
            return result
        run_command = [sys.executable, "-m", "msm5xxx_emulator.cli", str(path),
                       "--steps", str(args.steps), "--display-metrics"]
        if args.chunk_steps:
            run_command.extend(("--chunk-steps", str(args.chunk_steps)))
        if args.until_visible:
            run_command.append("--until-visible")
        run = subprocess.run(
            run_command, capture_output=True, text=True, env=environment,
            timeout=max(60, args.steps // 20_000),
        )
        if run.returncode:
            result.update(status="process-error",
                          error=run.stderr.strip().splitlines()[-1])
            return result
        state = json.loads(run.stdout)
        result.update(
            status="fault" if state["fault"] else "ok",
            fault=state["fault"], fault_context=state.get("fault_context"),
            pc=state["pc"],
            instructions=state.get("instructions"),
            lcd_writes=state["lcd_writes"], frame=state["frame_sequence"],
            firmware_frame=state.get("firmware_frame_sequence",
                                     state["frame_sequence"]),
            lcd_protocol=state.get("lcd_protocol"),
            lcd_frame_protocol=state.get("lcd_frame_protocol"),
            lcd_port_writes=state.get("lcd_port_writes", []),
            width=state.get("display_width"), height=state.get("display_height"),
            visible_pixels=state.get("visible_pixels", 0),
            visual_booted=state.get("visual_booted"),
            secondary_flash_reads=state.get("secondary_flash_reads", 0),
            secondary_flash_writes=state.get("secondary_flash_writes", 0),
            secondary_flash_changed_pages=state.get(
                "secondary_flash_changed_pages", 0
            ),
            secondary_flash_telemetry=state.get("secondary_flash_telemetry"),
            nand_reads=state.get("nand_reads", 0),
            nand_writes=state.get("nand_writes", 0),
            rex_idle_entries=state.get("rex_idle_entries", 0),
            rex_ticks=state.get("rex_ticks", 0),
            hot_loop_hle_used=state.get("hot_loop_hle_used", False),
        )
        return result

    rows: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="msm5xxx-corpus-verify-") as state_dir:
        environment["MSM5XXX_STATE_DIR"] = state_dir
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(invoke, path) for path in files]
            for index, future in enumerate(as_completed(futures), 1):
                rows.append(future.result())
                if index % 10 == 0 or index == len(files):
                    print(f"{index}/{len(files)}", file=sys.stderr, flush=True)
    rows.sort(key=lambda row: str(row["file"]).lower())
    summary = Counter(str(row["status"]) for row in rows)
    completed = [row for row in rows if row.get("status") in ("ok", "fault")]
    screen = {
        "lcd_traffic": sum(int(row.get("lcd_writes", 0)) > 0 for row in completed),
        "frames": sum(int(row.get("firmware_frame", 0)) > 0 for row in completed),
        "visible_frames": sum(
            int(row.get("firmware_frame", 0)) > 0
            and int(row.get("visible_pixels", 0)) > 0
            for row in completed
        ),
    }
    rex = {
        "idle_signatures": sum(
            row.get("config", {}).get("rex_idle_address") is not None
            for row in completed
        ),
        "idle_callsites_reached": sum(
            int(row.get("rex_idle_entries", 0)) > 0 for row in completed
        ),
        "tick_hle_active": sum(
            int(row.get("rex_ticks", 0)) > 0 for row in completed
        ),
    }
    report = {"files": len(rows), "steps": args.steps,
              "chunk_steps": args.chunk_steps, "until_visible": args.until_visible,
              "summary": dict(summary),
              "screen": screen, "rex": rex, "results": rows}
    output = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.json:
        args.json.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    print("summary:", dict(summary), file=sys.stderr)
    return 1 if summary["detect-error"] or summary["process-error"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
