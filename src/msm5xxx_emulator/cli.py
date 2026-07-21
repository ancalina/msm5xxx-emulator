#!/usr/bin/env python3
"""Generic Qualcomm MSM5XXX firmware bring-up runner."""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from .core.constants import BUILD_CODENAME, FRAMEBUFFER_FORMATS
from .core.emulator import GenericMSMEmulator
from .core.errors import HostBackendFault
from .detection.firmware import detect


LOGGER = logging.getLogger("msm5xxx")


def integer(value: str) -> int:
    return int(value, 0)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("firmware", type=Path)
    result.add_argument("--detect-only", action="store_true")
    result.add_argument("--steps", type=integer, default=2_000_000)
    result.add_argument("--chunk-steps", type=integer, default=0,
                        help="run in GUI-sized chunks (0 = one continuous run)")
    result.add_argument("--until-visible", action="store_true",
                        help=("treat --steps as a visual-boot budget and stop "
                              "after the first non-black display frame"))
    result.add_argument("--display-metrics", action="store_true",
                        help="include immutable frame geometry/visible-pixel metrics")
    result.add_argument("--model")
    result.add_argument(
        "--chipset",
        choices=("MSM5000", "MSM5100", "MSM5105", "MSM5500", "MSM5xxx"),
    )
    result.add_argument("--width", type=integer)
    result.add_argument("--height", type=integer)
    result.add_argument("--framebuffer-address", type=integer)
    result.add_argument("--framebuffer-stride", type=integer)
    result.add_argument("--framebuffer-format", choices=FRAMEBUFFER_FORMATS)
    result.add_argument("--framebuffer-flush-address", type=integer)
    result.add_argument("--framebuffer-rect-flush-address", type=integer)
    result.add_argument("--board-revision")
    result.add_argument("--board-revision-register", type=integer)
    result.add_argument("--board-revision-value", type=integer)
    result.add_argument("--image-offset", type=integer)
    result.add_argument("--load-address", type=integer)
    result.add_argument("--flash-size", type=integer)
    result.add_argument("--secondary-flash-address", type=integer)
    result.add_argument("--secondary-flash-size", type=integer)
    result.add_argument("--secondary-flash-image")
    result.add_argument("--secondary-flash-state")
    result.add_argument("--secondary-flash-read-address", type=integer)
    result.add_argument("--secondary-flash-write-address", type=integer)
    result.add_argument("--legacy-efs-page-read-address", type=integer)
    result.add_argument("--eeprom-read-address", type=integer)
    result.add_argument("--eeprom-write-address", type=integer)
    result.add_argument("--eeprom-geometry-address", type=integer)
    result.add_argument("--ram-base", type=integer)
    result.add_argument("--ram-size", type=integer)
    result.add_argument("--ram-image-offset", type=integer)
    result.add_argument("--ram-image-size", type=integer)
    result.add_argument("--entry", type=integer)
    result.add_argument("--key-register", type=integer)
    result.add_argument("--key-active-high", dest="key_active_low", action="store_false")
    result.add_argument("--audio-play-address", type=integer)
    result.add_argument("--fast-boot-address", type=integer)
    result.add_argument("--delay-address", type=integer)
    result.add_argument("--busy-delay-address", type=integer)
    result.add_argument("--flash-state")
    result.add_argument("--nand-enabled", action=argparse.BooleanOptionalAction)
    result.add_argument("--nand-image")
    result.add_argument("--nand-data-size", type=integer)
    result.add_argument("--nand-page-size", type=integer)
    result.add_argument("--nand-spare-size", type=integer)
    result.add_argument("--nand-pages-per-block", type=integer)
    result.add_argument("--nand-bus-width", type=integer)
    result.add_argument("--nand-bad-block-address", type=integer)
    result.add_argument("--nand-read-address", type=integer)
    result.add_argument("--nand-write-address", type=integer)
    result.add_argument("--rex-idle-address", type=integer)
    result.add_argument("--rex-tick-address", type=integer)
    result.add_argument("--rex-irq-wrapper-address", type=integer)
    result.add_argument("--rex-tick-ms", type=integer)
    result.add_argument("--board-adc-address", type=integer)
    result.add_argument("--board-adc-value", type=integer)
    result.add_argument("--flash-id-address", type=integer)
    result.add_argument("--flash-id-value", type=integer)
    result.add_argument("--crc16-address", type=integer)
    result.add_argument("--dmd-download-address", type=integer)
    result.add_argument("--primary-flash-probe-address", type=integer)
    result.set_defaults(key_active_low=None)
    result.add_argument("--json", type=Path)
    return result


def main() -> int:
    from .diagnostics.runtime_log import install_runtime_logging, record_diagnostic

    session_log = install_runtime_logging("cli")
    args = parser().parse_args()
    config = detect(args.firmware, args)
    LOGGER.info("CLI request firmware=%s detect_only=%s steps=%d log=%s build=%s",
                json.dumps(config.firmware_identity(), sort_keys=True),
                args.detect_only, args.steps, session_log.name, BUILD_CODENAME)
    LOGGER.info("detected model=%s chipset=%s image_offset=0x%X load=0x%X "
                "flash=0x%X screen=%dx%d board_revision=%s",
                config.model, config.chipset, config.image_offset,
                config.load_address, config.flash_size, config.width,
                config.height, config.board_revision)
    if args.detect_only:
        state = config.to_dict()
    else:
        emulator = GenericMSMEmulator(config)
        try:
            if args.steps < 0 or args.chunk_steps < 0:
                raise ValueError("steps and chunk steps must be non-negative")
            remaining = args.steps
            state: dict[str, object] = {}
            visible_pixels = 0
            while remaining:
                # A visual boot probe must sample immutable GUI-equivalent
                # frames.  Do not let a long single Unicorn run hide the
                # first panel update behind the full instruction budget.
                chunk_size = args.chunk_steps or (25_000 if args.until_visible else remaining)
                chunk = min(remaining, chunk_size)
                state = emulator.run(chunk)
                remaining -= chunk
                if args.until_visible:
                    _width, _height, frame = emulator.display_snapshot()
                    visible_pixels = sum(
                        any(frame[offset:offset + 3])
                        for offset in range(0, len(frame), 3)
                    )
                    if state["firmware_frame_sequence"] and visible_pixels:
                        state["visual_booted"] = True
                        break
                if state["fault"]:
                    break
            if not state:
                state = emulator.run(0)
            if args.display_metrics or args.until_visible:
                width, height, frame = emulator.display_snapshot()
                state.update({
                    "display_width": width,
                    "display_height": height,
                    "visible_pixels": (visible_pixels or sum(
                        any(frame[offset:offset + 3])
                        for offset in range(0, len(frame), 3)
                    )),
                })
                if args.until_visible:
                    state["visual_booted"] = bool(
                        state["firmware_frame_sequence"]
                        and state["visible_pixels"]
                    )
        except HostBackendFault as error:
            payload = {
                **error.diagnostic,
                "firmware": config.firmware_identity(),
                "model": config.model,
                "chipset": config.chipset,
            }
            artifact = record_diagnostic("host_backend_fault", payload)
            LOGGER.error("CLI host backend fault model=%s diagnostic=%s",
                         config.model,
                         artifact.name if artifact is not None else "unavailable")
            return 1
        finally:
            emulator.close()
    output = json.dumps(state, ensure_ascii=False, indent=2)
    if args.json:
        args.json.write_text(output + "\n", encoding="utf-8")
        LOGGER.info("JSON result saved file=%s", args.json.name)
    LOGGER.info("CLI complete model=%s fault=%r", config.model,
                state.get("fault") if isinstance(state, dict) else None)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
