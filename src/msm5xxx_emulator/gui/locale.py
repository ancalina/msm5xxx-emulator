from __future__ import annotations

import locale
import os


UI_LANGUAGE_CHOICES = ("auto", "ko", "en")


from importlib.resources import files
import json

UI_TEXT = {
    language: json.loads(files(__package__).joinpath("locales", language + ".json").read_text(encoding="utf-8"))
    for language in ("ko", "en")
}


def display_model_name(model: str | None, verified_model: str | None, language: str,
                       filename_stem: str = "") -> str:
    """Show detector candidate while marking unverified identity explicitly."""
    if verified_model:
        return verified_model
    if model is None:
        label = UI_TEXT[language]["unknown_label"]
        return f"{label} ({filename_stem})"
    suffix = UI_TEXT[language]["unverified"]
    return f"{model} ({suffix})"


def normalize_ui_language(value: object) -> str:
    return value if isinstance(value, str) and value in UI_LANGUAGE_CHOICES else "auto"


def system_ui_language(locale_name: str | None = None) -> str:
    if locale_name is None:
        locale_name = os.environ.get("LC_ALL") or next(
            (os.environ[name] for name in ("LC_MESSAGES", "LANGUAGE", "LANG")
             if os.environ.get(name)), None
        )
    if locale_name is None:
        try:
            category = getattr(locale, "LC_MESSAGES", locale.LC_CTYPE)
            locale_name = locale.getlocale(category)[0] or locale.getlocale()[0]
        except ValueError:
            locale_name = None
    normalized = (locale_name or "").lower()
    return "ko" if normalized.startswith("ko") or "korean" in normalized else "en"


def resolve_ui_language(preference: object, locale_name: str | None = None) -> str:
    preference = normalize_ui_language(preference)
    return system_ui_language(locale_name) if preference == "auto" else preference


def runtime_status_text(latest: dict[str, object], ui_language: str) -> str:
    parts = [
        f"{UI_TEXT[ui_language]['run_label']} {latest['instructions']:,}",
        f"{UI_TEXT[ui_language]['metric_pc_label']} {latest.get('pc', '?')}",
        f"{UI_TEXT[ui_language]['metric_lcd_label']} {int(latest.get('lcd_writes', 0)):,}",
        f"{UI_TEXT[ui_language]['metric_frame_label']} {latest.get('frame_sequence', 0)}",
    ]
    audio_requests = int(latest.get("audio_play_requests", 0))
    audio_backend = str(latest.get("audio_backend", ""))
    if audio_requests:
        parts.append(f"{UI_TEXT[ui_language]['audio_label']} {audio_requests}")
    elif audio_backend in ("disabled", "render-only"):
        parts.append(UI_TEXT[ui_language]["audio_unavailable"])
    if latest.get("audio_error"):
        parts.append(f"{UI_TEXT[ui_language]['audio_error']}: {latest['audio_error']}")
    return "\n".join(parts)


def runtime_notice_text(latest: dict[str, object], ui_language: str) -> str:
    """Return only exceptional or optional runtime notices below metrics."""
    parts: list[str] = []
    audio_requests = int(latest.get("audio_play_requests", 0))
    audio_backend = str(latest.get("audio_backend", ""))
    if audio_requests:
        parts.append(f"{UI_TEXT[ui_language]['audio_label']} {audio_requests}")
    elif audio_backend in ("disabled", "render-only"):
        parts.append(UI_TEXT[ui_language]["audio_unavailable"])
    if latest.get("audio_error"):
        parts.append(f"{UI_TEXT[ui_language]['audio_error']}: "
                     f"{latest['audio_error']}")
    return "\n".join(parts)
