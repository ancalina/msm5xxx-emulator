#!/usr/bin/env python3
from pathlib import Path
import logging
import sys
import tempfile

from ..core.emulator import GenericMSMEmulator, detect
from ..diagnostics.runtime_log import install_runtime_logging


LOGGER = logging.getLogger("verify")


KNOWN_STEPS = {
    "SCH-E100": 5_000_000,
    "SCH-E110": 3_000_000,
    "SCH-E135": 1_000_000,
    "SCH-E170": 10_000_000,
    "SCH-E370": 5_000_000,
    "KTFT-X3500": 1_000_000,
    "SCH-X150": 3_000_000,
    "SCH-X350": 3_000_000,
    "SCH-X800": 1_000_000,
    "LG-KP8500": 5_000_000,
    "LG-SD810": 20_000_000,
    "LG-SV130": 5_000_000,
    "LP2400": 5_000_000,
    "SPH-E3330": 2_000_000,
}
VISUAL_ONLY_STEPS = {
    # The supplied image reaches a complete boot splash just before its
    # missing next-stage device/ROM path; assert the real panel transfer
    # without claiming its keypad task booted.
    "VK100-dump": 275_000,
}
VERIFY_CHUNK_STEPS = 25_000


def run_like_gui(emulator: GenericMSMEmulator, steps: int) -> dict[str, object]:
    """Keep raw FIFO/controller timing identical to the GUI worker."""
    state: dict[str, object] = {}
    remaining = steps
    while remaining:
        state = emulator.run(min(remaining, VERIFY_CHUNK_STEPS))
        remaining -= min(remaining, VERIFY_CHUNK_STEPS)
        if state["fault"]:
            break
    return state if state else emulator.run(0)


def main() -> int:
    session_log = install_runtime_logging("verify")
    if len(sys.argv) == 1:
        print(f"usage: {Path(sys.argv[0]).name} firmware.bin [...]", file=sys.stderr)
        return 2
    for argument in sys.argv[1:]:
        path = Path(argument)
        LOGGER.info("verify begin firmware=%s log=%s", path, session_log)
        config = detect(path)
        with tempfile.TemporaryDirectory() as directory:
            config.flash_state = str(Path(directory) / "flash.json")
            config.secondary_flash_state = str(Path(directory) / "secondary-flash.json")
            emulator = GenericMSMEmulator(config)
            try:
                state = run_like_gui(
                    emulator, KNOWN_STEPS.get(
                        config.model, VISUAL_ONLY_STEPS.get(config.model, 1_000_000)
                    )
                )
                if state["fault"]:
                    raise RuntimeError(f"{path.name}: {state['fault']}")
                _width, _height, frame = emulator.display_snapshot()
                nonblack = sum(
                    any(frame[offset:offset + 3])
                    for offset in range(0, len(frame), 3)
                )
                if config.model in KNOWN_STEPS or config.model in VISUAL_ONLY_STEPS:
                    if not state["firmware_frame_sequence"] or not nonblack:
                        raise RuntimeError(
                            f"{path.name}: booted without a visible frame"
                        )
                if config.model in KNOWN_STEPS and config.key_register is not None:
                    key = (2 if emulator.input_profile
                           and emulator.input_profile[0] == "lg-decoded" else 0)
                    before_press = int.from_bytes(emulator.uc.mem_read(
                        config.key_register, 4), "little")
                    emulator.set_key(key, True)
                    emulator.set_key(key, True)
                    mask = 1 << key
                    expected = (before_press & ~mask if config.key_active_low
                                else before_press | mask)
                    if int.from_bytes(emulator.uc.mem_read(
                            config.key_register, 4), "little") != expected:
                        raise RuntimeError(f"{path.name}: key press state was not written")
                    pressed = emulator.run(250_000)
                    before_release = int.from_bytes(emulator.uc.mem_read(
                        config.key_register, 4), "little")
                    emulator.set_key(key, False)
                    emulator.set_key(key, False)
                    expected = before_release & ~mask | before_press & mask
                    if int.from_bytes(emulator.uc.mem_read(
                            config.key_register, 4), "little") != expected:
                        raise RuntimeError(f"{path.name}: key release state was not written")
                    released = emulator.run(250_000)
                    if pressed["fault"] or released["fault"] or emulator.held_keys:
                        raise RuntimeError(f"{path.name}: input transition failed")
                    if released["input_mode"] != "candidate-register":
                        raise RuntimeError(f"{path.name}: unexpected input mode")
            finally:
                emulator.close()
        suffix = ("BOOT+DISPLAY OK; input=not-detected"
                  if config.model in KNOWN_STEPS else
                  "DISPLAY OK; supplied dump stops after splash"
                  if config.model in VISUAL_ONLY_STEPS else "UNKNOWN: metrics only")
        print(f"{path.name}: {config.model} {config.chipset} {state['pc']} "
              f"frame={state['frame_sequence']} nonblack={nonblack} {suffix}")
        LOGGER.info("verify complete firmware=%s model=%s pc=%s frame=%s "
                    "nonblack=%d fault=%r", path, config.model, state["pc"],
                    state["frame_sequence"], nonblack, state["fault"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
