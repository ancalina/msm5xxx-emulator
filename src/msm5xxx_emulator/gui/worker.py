from __future__ import annotations

import hashlib
import logging
from pathlib import Path
import queue
import threading
import time

from ..probe.boot import visible_pixels
from ..core.emulator import GenericMSMEmulator
from ..core.errors import HostBackendFault
from ..diagnostics.runtime_log import record_exception

from .controls import detect_profile
from .locale import display_model_name
from .repro import (create_repro_bundle, finish_repro_bundle,
                    firmware_telemetry)
from .telemetry import (
    TELEMETRY_SCREENSHOT_CADENCE, TELEMETRY_SCREENSHOT_CAP, _counter,
    _frame_metrics, _mapping, emit_telemetry, hydrate_host_checkpoint,
    runtime_telemetry, save_telemetry_frame, telemetry_artifact_due,
    telemetry_transition,
)


LOGGER = logging.getLogger("gui")


class WorkerMixin:
    def _restart(self) -> None:
        self.generation += 1
        generation = self.generation
        self.stop.set()
        for callback in self.pending_key_releases.values():
            self.root.after_cancel(callback)
        self.pending_key_releases.clear()
        self.keyboard_bits.clear()
        self.keyboard_sources.clear()
        self.commands = queue.SimpleQueue()
        self.held.clear()
        self.emulator = None
        self._render_cache = None
        self.status.set(self._text("restarting"))
        self._start_when_stopped(generation)

    def _start_when_stopped(self, generation: int) -> None:
        if self.closing or generation != self.generation:
            return
        if self.worker is not None and self.worker.is_alive():
            self.root.after(25, self._start_when_stopped, generation)
            return
        self._show_save_errors()
        self.stop = threading.Event()
        stop = self.stop
        commands = self.commands
        firmware = self.firmware
        overrides = dict(self.overrides)
        self.worker = threading.Thread(
            target=self._run,
            args=(generation, stop, commands, firmware, overrides),
            daemon=False,
        )
        self.worker.start()

    def _run(self, generation: int, stop: threading.Event,
             commands: queue.SimpleQueue[tuple[object, ...]], firmware: Path,
             overrides: dict[str, object]) -> None:
        emulator: GenericMSMEmulator | None = None
        config = None
        captures = 0
        terminal = False
        try:
            config, overrides = detect_profile(firmware, overrides)
            worker_boot = {
                "generation": generation,
                "firmware": firmware_telemetry(config),
                "model": config.model,
                "verified_model": config.verified_model,
                "chipset": config.chipset,
                "chipset_confidence": config.chipset_confidence,
                "screen": {"width": config.width, "height": config.height},
                "dump_status": config.dump_status,
            }
            emit_telemetry("firmware_identity", worker_boot)
            emulator = GenericMSMEmulator(config)
            if generation == self.generation:
                self.emulator = emulator
            self.states.put((generation, {
                "_profile_overrides": overrides,
                "model": display_model_name(
                    config.model, config.verified_model, self.ui_language
                ),
                "device_details": (
                    f"{config.chipset} / {config.chipset_confidence}  ·  "
                    f"{config.width}×{config.height}  ·  {config.dump_status}"
                ),
            }))
            last_publish = 0.0
            _width, _height, initial_frame = emulator.display_snapshot()
            reset_hash = hashlib.sha256(initial_frame).hexdigest()
            previous_frame_hash = reset_hash
            previous_frame = initial_frame
            previous_nonblack = visible_pixels(initial_frame)
            saw_splash = False
            last_phase: str | None = None
            last_event: str | None = None
            last_telemetry_instructions = 0
            last_screenshot_instructions = 0
            while not stop.is_set():
                while True:
                    try:
                        command = commands.get_nowait()
                    except queue.Empty:
                        break
                    if len(command) == 2 and isinstance(command[0], int):
                        bit, pressed = command
                        emulator.set_key(bit, bool(pressed))
                    elif command[0] == "framebuffer-format" and len(command) == 2:
                        framebuffer_format = str(command[1])
                        emulator.set_framebuffer_format(framebuffer_format)
                        LOGGER.info("live framebuffer format=%s generation=%d",
                                    framebuffer_format, generation)
                state = emulator.run(25_000)
                frame_width, frame_height, frame = emulator.display_snapshot()
                frame_hash, nonblack = _frame_metrics(
                    frame, previous_frame, previous_frame_hash, previous_nonblack
                )
                phase, event, saw_splash, telemetry_due = telemetry_transition(
                    state, nonblack, frame_hash, reset_hash, previous_frame_hash,
                    saw_splash, last_phase, last_event, last_telemetry_instructions,
                )
                terminal = bool(state.get("fault"))
                instructions = _counter(state, "instructions")
                transitioned = phase != last_phase or event != last_event
                periodic_screenshot_due = instructions >= (
                    last_screenshot_instructions + TELEMETRY_SCREENSHOT_CADENCE
                )
                artifact_due = telemetry_artifact_due(
                    transitioned=transitioned, terminal=terminal,
                    instructions=instructions,
                    last_screenshot_instructions=last_screenshot_instructions,
                )
                if telemetry_due:
                    screenshot = None
                    # Reserve one capture for a terminal fault after noisy animation.
                    if (artifact_due and captures < TELEMETRY_SCREENSHOT_CAP
                            and (terminal or captures < TELEMETRY_SCREENSHOT_CAP - 1)):
                        captures += 1
                        screenshot = save_telemetry_frame(
                            config, generation=generation, instructions=instructions,
                            phase=phase, capture=captures,
                            width=frame_width, height=frame_height, frame=frame,
                        )
                    if screenshot is not None or periodic_screenshot_due:
                        last_screenshot_instructions = instructions
                    telemetry = runtime_telemetry(
                        config, state, generation=generation, phase=phase, event=event,
                        width=frame_width, height=frame_height, frame=frame,
                        nonblack=nonblack, screenshot=screenshot,
                        frame_hash=frame_hash,
                    )
                    emit_telemetry(
                        "terminal_state" if terminal else "runtime_checkpoint",
                        telemetry,
                        persist=artifact_due,
                    )
                    last_phase, last_event = phase, event
                    last_telemetry_instructions = instructions
                previous_frame_hash = frame_hash
                previous_frame = frame
                previous_nonblack = nonblack
                now = time.monotonic()
                if state["fault"] or now - last_publish >= 0.1:
                    self.states.put((generation, state))
                    last_publish = now
                if state["fault"]:
                    terminal = True
                    LOGGER.error("worker emulation stopped generation=%d fault=%s",
                                 generation, state["fault"])
                    break
        except HostBackendFault as error:
            terminal = True
            diagnostic = getattr(error, "diagnostic", {})
            state = dict(diagnostic) if isinstance(diagnostic, dict) else {}
            # Host error must not be mistaken for a guest Unicorn fault.
            state.pop("fault", None)
            state = hydrate_host_checkpoint(state)
            registers = _mapping(state, "registers")
            state.setdefault("pc", registers.get("pc"))
            state.setdefault("lr", registers.get("lr"))
            screenshot = None
            if emulator is not None and config is not None:
                try:
                    frame_width, frame_height, frame = emulator.display_snapshot()
                    if captures < TELEMETRY_SCREENSHOT_CAP:
                        captures += 1
                        screenshot = save_telemetry_frame(
                            config, generation=generation,
                            instructions=_counter(state, "instructions"),
                            phase="host-backend-fault", capture=captures,
                            width=frame_width, height=frame_height, frame=frame,
                        )
                    telemetry = runtime_telemetry(
                        config, state, generation=generation,
                        phase="host-backend-fault", event="host-backend-fault",
                        width=frame_width, height=frame_height, frame=frame,
                        nonblack=visible_pixels(frame), screenshot=screenshot,
                    )
                except (OSError, RuntimeError, ValueError) as snapshot_error:
                    LOGGER.warning("host fault snapshot failed generation=%d error=%s",
                                   generation, type(snapshot_error).__name__)
                    telemetry = runtime_telemetry(
                        config, state, generation=generation,
                        phase="host-backend-fault", event="host-backend-fault",
                        width=config.width, height=config.height, frame=b"",
                        nonblack=0,
                    )
            else:
                telemetry = {"generation": generation}
            telemetry["host_backend_fault"] = str(error)
            telemetry["host_checkpoint"] = state
            emit_telemetry("host_backend_fault", telemetry)
            LOGGER.error("worker host backend stopped generation=%d firmware=%s error=%s",
                         generation, (Path(config.path).name if config is not None
                                      else "unknown"), error)
            ui_state = {
                name: state[name] for name in (
                    "instructions", "pc", "lr", "lcd_writes", "frame_sequence",
                    "audio_play_requests", "audio_backend", "audio_error", "input_error",
                ) if name in state
            }
            ui_state["host_backend_fault"] = str(error)
            self.states.put((generation, ui_state))
        except Exception as error:
            terminal = emulator is not None
            record_exception(f"GUI worker generation {generation}", error)
            self.states.put((generation, {"fault": str(error)}))
        finally:
            if emulator is not None:
                repro_bundle = (create_repro_bundle(config, emulator, overrides, generation)
                                if terminal and config is not None else None)
                try:
                    emulator.close()
                except Exception as error:
                    record_exception(f"GUI save generation {generation}", error)
                    self.save_errors.put(str(error))
                    self.states.put((generation, {
                        "fault": f"{self._text('save_failed')}: {error}"
                    }))
                finally:
                    if repro_bundle is not None and config is not None:
                        finish_repro_bundle(
                            repro_bundle, config, emulator, overrides, generation
                        )
