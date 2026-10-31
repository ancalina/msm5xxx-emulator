"""Shared Tk interface for the QEMU desktop application."""

from .app import Window, main
from .controls import (METRIC_TEXT, can_apply_live_framebuffer_format,
                       settings_apply_mode)
from .display_view import frame_repaint_needed
from .locale import (display_model_name, normalize_ui_language,
                     resolve_ui_language, runtime_status_text,
                     system_ui_language)

__all__ = (
    "METRIC_TEXT", "Window", "can_apply_live_framebuffer_format",
    "display_model_name", "frame_repaint_needed", "main",
    "normalize_ui_language", "resolve_ui_language", "runtime_status_text",
    "settings_apply_mode", "system_ui_language",
)
