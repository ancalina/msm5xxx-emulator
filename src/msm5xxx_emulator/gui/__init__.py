"""Tk GUI and diagnostic helpers."""

from .app import Window, main
from .controls import (METRIC_TEXT, can_apply_live_framebuffer_format,
                       settings_apply_mode)
from .display_view import frame_repaint_needed
from .locale import (display_model_name, normalize_ui_language,
                     resolve_ui_language, runtime_status_text,
                     system_ui_language)
from .repro import create_repro_bundle, finish_repro_bundle
from .telemetry import (
    TELEMETRY_INSTRUCTION_CADENCE, TELEMETRY_POLL_ESCAPE_CAP,
    TELEMETRY_SCREENSHOT_CADENCE, _compact_telemetry, _frame_metrics,
    hydrate_host_checkpoint, runtime_telemetry, save_telemetry_frame,
    telemetry_artifact_due, telemetry_transition,
)

__all__ = (
    "METRIC_TEXT", "TELEMETRY_INSTRUCTION_CADENCE",
    "TELEMETRY_POLL_ESCAPE_CAP", "TELEMETRY_SCREENSHOT_CADENCE", "Window",
    "_compact_telemetry", "_frame_metrics", "can_apply_live_framebuffer_format",
    "create_repro_bundle", "display_model_name", "finish_repro_bundle",
    "frame_repaint_needed", "hydrate_host_checkpoint", "main",
    "normalize_ui_language", "resolve_ui_language", "runtime_status_text",
    "runtime_telemetry", "save_telemetry_frame", "settings_apply_mode",
    "system_ui_language", "telemetry_artifact_due", "telemetry_transition",
)
