"""Desktop interface and platform-independent settings helpers.

The public desktop objects are loaded on demand so settings parsing is also
available on platforms without Tk.
"""
from importlib import import_module

_EXPORTS = {
    "Window": "app", "main": "app",
    "METRIC_TEXT": "controls", "can_apply_live_framebuffer_format": "controls",
    "settings_apply_mode": "controls", "frame_repaint_needed": "display_view",
    "display_model_name": "locale", "normalize_ui_language": "locale",
    "resolve_ui_language": "locale", "runtime_status_text": "locale",
    "system_ui_language": "locale",
}
__all__ = tuple(_EXPORTS)


def __getattr__(name):
    if name not in _EXPORTS:
        raise AttributeError(name)
    return getattr(import_module(f"{__name__}.{_EXPORTS[name]}"), name)
