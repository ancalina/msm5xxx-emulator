from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from PIL import Image

from ..probe.boot import boot_event, boot_phase, visible_pixels
from ..diagnostics.runtime_log import record_diagnostic

LOGGER = logging.getLogger("gui")
from .repro import (_diagnostic_directory, _diagnostic_session_token,
                    _safe_log_name, firmware_telemetry)


TELEMETRY_INSTRUCTION_CADENCE = 1_000_000


TELEMETRY_SCREENSHOT_CADENCE = 5_000_000


TELEMETRY_SCREENSHOT_CAP = 32


TELEMETRY_POLL_ESCAPE_CAP = 8


TELEMETRY_MATRIX_REJECTION_CAP = 8


TELEMETRY_MATRIX_REASON_CAP = 4


TELEMETRY_MATRIX_SIDEBAND_CAP = 4


def _frame_metrics(frame: bytes, previous_frame: bytes, previous_hash: str,
                   previous_nonblack: int) -> tuple[str, int]:
    """Reuse metrics when a publish returns the same immutable frame contents."""
    if frame is previous_frame or frame == previous_frame:
        return previous_hash, previous_nonblack
    return hashlib.sha256(frame).hexdigest(), visible_pixels(frame)


def _counter(state: dict[str, object], name: str) -> int:
    value = state.get(name, 0)
    return value if isinstance(value, int) else 0


def _nonnegative_counter(state: dict[str, object], name: str) -> int:
    value = state.get(name, 0)
    return value if type(value) is int and value >= 0 else 0


def _mapping(state: dict[str, object], name: str) -> dict[str, object]:
    value = state.get(name)
    return dict(value) if isinstance(value, dict) else {}


def _matrix_label(value: object) -> str | None:
    """Keep detector labels bounded and independent of local paths."""
    if (not isinstance(value, str) or len(value) > 128
            or "/" in value or "\\" in value):
        return None
    return value


def _matrix_rejections(state: dict[str, object]) -> tuple[int, list[list[str]]]:
    """Keep only bounded detector reject reasons, never candidate addresses."""
    raw_rejections = state.get("direct_matrix_rejections")
    if not isinstance(raw_rejections, list):
        return 0, []
    rejections: list[list[str]] = []
    for raw_rejection in raw_rejections[:TELEMETRY_MATRIX_REJECTION_CAP]:
        if not isinstance(raw_rejection, dict):
            continue
        raw_reasons = raw_rejection.get("reasons")
        if not isinstance(raw_reasons, list):
            continue
        reasons = [label for reason in raw_reasons[:TELEMETRY_MATRIX_REASON_CAP]
                   if (label := _matrix_label(reason)) is not None]
        if reasons:
            rejections.append(reasons)
    return len(raw_rejections), rejections


def _matrix_sideband_producers(
        state: dict[str, object]
) -> tuple[int, list[dict[str, object]]]:
    raw_producers = state.get("direct_matrix_sideband_producers")
    if not isinstance(raw_producers, list):
        return 0, []
    producers: list[dict[str, object]] = []
    for raw in raw_producers[:TELEMETRY_MATRIX_SIDEBAND_CAP]:
        if not isinstance(raw, dict):
            continue
        event = raw.get("event")
        register = raw.get("register")
        mask = raw.get("mask")
        grammar = _matrix_label(raw.get("grammar"))
        evidence = _matrix_label(raw.get("evidence"))
        polarity = _matrix_label(raw.get("polarity"))
        semantic_status = _matrix_label(raw.get("semantic_status"))
        if (type(event) is not int or not 0 <= event <= 0xFF
                or type(register) is not int or not 0 <= register <= 0xFFFFFFFF
                or type(mask) is not int or not 0 < mask <= 0xFFFFFFFF
                or None in (grammar, evidence, polarity, semantic_status)):
            continue
        producers.append({
            "grammar": grammar,
            "evidence": evidence,
            "semantic_status": semantic_status,
            "event": f"0x{event:02X}",
            "register": f"0x{register:08X}",
            "mask": f"0x{mask:X}",
            "polarity": polarity,
        })
    return len(raw_producers), producers


def _matrix_input_telemetry(state: dict[str, object]) -> dict[str, object]:
    """Return detector status plus aggregate scanner-to-task progress."""
    rejection_count, rejections = _matrix_rejections(state)
    sideband_count, sideband_producers = _matrix_sideband_producers(state)
    raw_sideband_rejections = state.get("direct_matrix_sideband_rejections")
    sideband_rejections = [label for reason in (
        raw_sideband_rejections[:TELEMETRY_MATRIX_REASON_CAP]
        if isinstance(raw_sideband_rejections, list) else []
    ) if (label := _matrix_label(reason)) is not None]
    return {
        "profile": _matrix_label(state.get("input_profile")),
        "mode": _matrix_label(state.get("input_mode")),
        "error": _matrix_label(state.get("input_error")),
        "input_events": _nonnegative_counter(state, "input_events"),
        "firmware_key_events": _nonnegative_counter(
            state, "firmware_key_events"
        ),
        "register_reads": _nonnegative_counter(
            state, "input_register_reads"
        ),
        "detection": _matrix_label(state.get("direct_matrix_detection")),
        "family": _matrix_label(state.get("direct_matrix_family")),
        "evidence": _matrix_label(state.get("direct_matrix_evidence")),
        "consumer_evidence": _matrix_label(
            state.get("direct_matrix_consumer_evidence")
        ),
        "grammar_fingerprint": _matrix_label(
            state.get("direct_matrix_grammar_fingerprint")
        ),
        "rejection_count": rejection_count,
        "rejections": rejections,
        "sideband_producer_count": sideband_count,
        "sideband_producers": sideband_producers,
        "sideband_detection": _matrix_label(
            state.get("direct_matrix_sideband_detection")
        ),
        "sideband_rejections": sideband_rejections,
        "transport": _matrix_label(state.get("input_transport")),
        "scans": _nonnegative_counter(state, "direct_matrix_scans"),
        "active_reads": _nonnegative_counter(
            state, "direct_matrix_active_reads"
        ),
        "call_edges": _nonnegative_counter(
            state, "direct_matrix_sink_events"
        ),
        "raw_enqueues": _nonnegative_counter(
            state, "direct_matrix_raw_enqueue_events"
        ),
        "dequeues": _nonnegative_counter(
            state, "direct_matrix_dequeue_events"
        ),
        "task_consumers": _nonnegative_counter(
            state, "direct_matrix_task_consumer_events"
        ),
        "mapped_keys": _nonnegative_counter(
            state, "direct_matrix_mapped_keys"
        ),
    }


def _host_hle_telemetry(state: dict[str, object]) -> dict[str, object]:
    """Return bounded, path-safe provenance for emulator-side accelerators."""
    events: list[dict[str, object]] = []
    total = 0
    raw_events = state.get("poll_escapes")
    if isinstance(raw_events, list):
        for raw_event in raw_events:
            if not isinstance(raw_event, dict):
                continue
            pc = raw_event.get("pc")
            address = raw_event.get("address")
            value = raw_event.get("value")
            bit = raw_event.get("bit")
            ready = raw_event.get("state")
            if (type(pc) is not int or not 0 <= pc <= 0xFFFFFFFF
                    or type(address) is not int or not 0 <= address <= 0xFFFFFFFF
                    or type(value) is not int or not 0 <= value <= 0xFFFFFFFF
                    or type(bit) is not int or not 0 <= bit < 32
                    or type(ready) is not int or ready not in (0, 1)):
                continue
            total += 1
            if len(events) < TELEMETRY_POLL_ESCAPE_CAP:
                events.append({
                    "pc": f"0x{pc:08X}", "address": f"0x{address:08X}",
                    "value": f"0x{value:08X}", "bit": bit, "state": ready,
                })
    return {
        "fast_boot_used": state.get("fast_boot_used") is True,
        "fast_memory_clears": _nonnegative_counter(state, "fast_memory_clears"),
        "fast_memory_copies": _nonnegative_counter(state, "fast_memory_copies"),
        "fast_register_ramps": _nonnegative_counter(state, "fast_register_ramps"),
        "fast_arm_memory_copies": _nonnegative_counter(state, "fast_arm_memory_copies"),
        "hot_loop_hle_used": state.get("hot_loop_hle_used") is True,
        "fast_crc16_calls": _nonnegative_counter(state, "fast_crc16_calls"),
        "fast_dmd_downloads": _nonnegative_counter(state, "fast_dmd_downloads"),
        "ma2_silent_boot_calls": _nonnegative_counter(state, "ma2_silent_boot_calls"),
        "poll_escape_count": total,
        "poll_escapes": events,
    }


def _phase_state(state: dict[str, object]) -> dict[str, object]:
    """Supply boot-probe's small evidence vocabulary, even on host faults."""
    return {
        "fault": state.get("fault"),
        "frame_sequence": _counter(state, "frame_sequence"),
        "firmware_frame_sequence": _counter(state, "firmware_frame_sequence"),
        "rex_ticks": _counter(state, "rex_ticks"),
        "secondary_flash_reads": _counter(state, "secondary_flash_reads"),
        "secondary_flash_writes": _counter(state, "secondary_flash_writes"),
        "secondary_flash_changed_pages": _counter(
            state, "secondary_flash_changed_pages"
        ),
        "secondary_flash_telemetry": _mapping(state, "secondary_flash_telemetry"),
        "upper_flash_telemetry": _mapping(state, "upper_flash_telemetry"),
        "nand_reads": _counter(state, "nand_reads"),
        "nand_writes": _counter(state, "nand_writes"),
        "lcd_writes": _counter(state, "lcd_writes"),
        "control_sink": state.get("control_sink"),
    }


def telemetry_transition(state: dict[str, object], nonblack: int, frame_hash: str,
                         reset_hash: str, previous_hash: str, saw_splash: bool,
                         last_phase: str | None, last_event: str | None,
                         last_instructions: int) -> tuple[str, str, bool, bool]:
    """Return phase/event and whether this state merits one diagnostic line."""
    phase_state = _phase_state(state)
    phase = boot_phase(phase_state, nonblack)
    event, saw_splash = boot_event(
        phase_state, nonblack, frame_hash, reset_hash, previous_hash, saw_splash,
    )
    due = _counter(state, "instructions") >= (
        last_instructions + TELEMETRY_INSTRUCTION_CADENCE
    )
    emit = (phase != last_phase or event != last_event
            or bool(state.get("fault")) or due)
    return phase, event, saw_splash, emit


def telemetry_artifact_due(*, transitioned: bool, terminal: bool,
                            instructions: int,
                            last_screenshot_instructions: int) -> bool:
    """Keep 1M checkpoints in the session log without writing artifact files."""
    return (transitioned or terminal or instructions >= (
        last_screenshot_instructions + TELEMETRY_SCREENSHOT_CADENCE
    ))


def runtime_telemetry(config: object, state: dict[str, object], *, generation: int,
                      phase: str, event: str, width: int, height: int,
                      frame: bytes, nonblack: int,
                      screenshot: str | None = None,
                      frame_hash: str | None = None) -> dict[str, object]:
    """Keep periodic GUI evidence compact and free of local firmware paths."""
    registers = _mapping(state, "registers")
    payload: dict[str, object] = {
        "generation": generation,
        "firmware": firmware_telemetry(config),
        "model": config.model,  # type: ignore[attr-defined]
        "verified_model": getattr(config, "verified_model", None),
        "chipset": config.chipset,  # type: ignore[attr-defined]
        "dump_status": config.dump_status,  # type: ignore[attr-defined]
        "instructions": _counter(state, "instructions"),
        "pc": state.get("pc", registers.get("pc")),
        "lr": state.get("lr", registers.get("lr")),
        "cpsr": registers.get("cpsr"),
        "phase": phase,
        "event": event,
        "frame": {
            "width": width,
            "height": height,
            "sha256": (frame_hash if frame_hash is not None
                       else hashlib.sha256(frame).hexdigest()),
            "nonblack_pixels": nonblack,
            "sequence": _counter(state, "frame_sequence"),
            "firmware_sequence": _counter(state, "firmware_frame_sequence"),
        },
        "lcd": {
            "writes": _counter(state, "lcd_writes"),
            "protocol": state.get("lcd_protocol"),
            "frame_protocol": state.get("lcd_frame_protocol"),
            "selector": _mapping(state, "lcd_selector"),
            "geometry_source": getattr(
                config, "display_geometry_source", "external-config"
            ),
        },
        "rex": {
            "idle_entries": _counter(state, "rex_idle_entries"),
            "ticks": _counter(state, "rex_ticks"),
            "elapsed_ms": _counter(state, "rex_elapsed_ms"),
            "irq_deliveries": _counter(state, "rex_irq_deliveries"),
            "controller": _mapping(state, "rex_controller"),
        },
        "board": {
            "adc_reads": _counter(state, "board_adc_reads"),
            "adc_channels": state.get("board_adc_channels", []),
        },
        "dc0_transport": _mapping(state, "dc0_transport"),
        "nor": {
            "primary": _mapping(state, "primary_flash_telemetry"),
            "primary_parallel_nor_direct_id_probes": state.get(
                "primary_parallel_nor_direct_id_probes", []
            ),
            "secondary_reads": _counter(state, "secondary_flash_reads"),
            "secondary_writes": _counter(state, "secondary_flash_writes"),
            "secondary_changed_pages": _counter(
                state, "secondary_flash_changed_pages"
            ),
            "secondary": _mapping(state, "secondary_flash_telemetry"),
            "upper": _mapping(state, "upper_flash_telemetry"),
        },
        "eeprom": {
            "capacity": _counter(state, "eeprom_capacity"),
            "reads": _counter(state, "eeprom_reads"),
            "read_bytes": _counter(state, "eeprom_read_bytes"),
            "writes": _counter(state, "eeprom_writes"),
            "write_bytes": _counter(state, "eeprom_write_bytes"),
            "changed_bytes": _counter(state, "eeprom_changed_bytes"),
            "loaded_from_state": bool(state.get("eeprom_loaded_from_state")),
            "error": state.get("eeprom_error"),
        },
        "nand": {
            "reads": _counter(state, "nand_reads"),
            "writes": _counter(state, "nand_writes"),
            "bad_block_probes": _counter(state, "nand_bad_block_probes"),
        },
        "input": _matrix_input_telemetry(state),
        "host_hle": _host_hle_telemetry(state),
        "control_sink": state.get("control_sink"),
        "last_unmapped": _mapping(state, "last_unmapped"),
        "unmapped_accesses": state.get("unmapped_accesses", []),
        "dynamic_page_first_accesses": state.get("dynamic_page_first_accesses", []),
        "fault": state.get("fault"),
        "fault_context": _mapping(state, "fault_context"),
    }
    if screenshot is not None:
        payload["screenshot"] = screenshot
    return payload


def hydrate_host_checkpoint(state: dict[str, object]) -> dict[str, object]:
    """Promote pre-call checkpoint counters into outer host-fault telemetry."""
    hydrated = dict(state)
    counters = _mapping(hydrated, "counters")
    display = _mapping(hydrated, "display")
    storage = _mapping(counters, "storage")

    def promote(target: str, source: dict[str, object], name: str = "") -> None:
        value = source.get(name or target)
        if isinstance(value, int) and (not isinstance(hydrated.get(target), int)
                                       or hydrated.get(target) == 0):
            hydrated[target] = value

    for name in (
            "lcd_writes", "rex_idle_entries", "rex_ticks", "rex_elapsed_ms",
            "rex_irq_deliveries", "board_adc_reads"):
        promote(name, counters)
    if (not isinstance(hydrated.get("board_adc_channels"), list)
            and isinstance(counters.get("board_adc_channels"), list)):
        hydrated["board_adc_channels"] = counters["board_adc_channels"]
    for name in ("frame_sequence", "firmware_frame_sequence"):
        promote(name, display)
    for target, source in (
            ("eeprom_reads", "eeprom_reads"),
            ("eeprom_writes", "eeprom_writes"),
            ("eeprom_changed_bytes", "eeprom_changed_bytes"),
            ("secondary_flash_reads", "secondary_nor_reads"),
            ("secondary_flash_writes", "secondary_nor_writes"),
            ("secondary_flash_changed_pages", "secondary_nor_changed_pages"),
            ("nand_reads", "nand_reads"),
            ("nand_writes", "nand_writes"),
    ):
        promote(target, storage, source)
    return hydrated


def save_telemetry_frame(config: object, *, generation: int,
                         instructions: int, phase: str, capture: int,
                         width: int, height: int, frame: bytes) -> str | None:
    """Save one immutable display snapshot beside current session log."""
    try:
        directory = _diagnostic_directory()
        directory.mkdir(parents=True, exist_ok=True)
        stem = (
            f"frame-{_diagnostic_session_token()}"
            f"-{_safe_log_name(Path(config.path).stem)}"  # type: ignore[attr-defined]
            f"-g{generation}-i{instructions}-c{capture:02d}"
            f"-{_safe_log_name(phase)}"
        )
        image = Image.frombytes("RGB", (width, height), frame)
        for suffix in range(10_000):
            target = directory / (
                f"{stem}.png" if suffix == 0 else f"{stem}-{suffix}.png"
            )
            try:
                with target.open("xb") as output:
                    image.save(output, format="PNG")
                return target.name
            except FileExistsError:
                continue
            except (OSError, RuntimeError, ValueError):
                try:
                    target.unlink()
                except OSError:
                    pass
                raise
        raise OSError("diagnostic screenshot filename space exhausted")
    except (OSError, RuntimeError, ValueError) as error:
        LOGGER.warning("diagnostic screenshot failed generation=%d firmware=%s error=%s",
                       generation, Path(config.path).name, type(error).__name__)  # type: ignore[attr-defined]
        return None


def _compact_telemetry(payload: dict[str, object]) -> dict[str, object]:
    """Keep one-million-instruction session lines useful but small."""
    return {
        name: payload[name] for name in (
            "generation", "firmware", "model", "chipset", "dump_status",
            "instructions", "pc", "lr", "cpsr", "phase", "event", "frame",
            "lcd", "rex", "dc0_transport", "nor", "eeprom", "nand",
            "control_sink",
            "input",
            "host_hle", "last_unmapped", "unmapped_accesses",
            "dynamic_page_first_accesses", "fault",
        ) if name in payload
    }


def emit_telemetry(kind: str, payload: dict[str, object], *, persist: bool = True) -> None:
    session_payload = payload if persist else _compact_telemetry(payload)
    LOGGER.info("telemetry kind=%s payload=%s", kind,
                json.dumps(session_payload, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":")))
    if persist:
        record_diagnostic(kind, payload)
