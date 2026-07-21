from __future__ import annotations

import locale
import os


UI_LANGUAGE_CHOICES = ("auto", "ko", "en")


UI_TEXT = {
    "ko": {
        "window_title": "MSM5XXX Emulator",
        "ready": "준비",
        "detecting": "자동 탐지 중",
        "unknown_model": "모델 미확인",
        "settings": "설정",
        "capture": "캡처",
        "restarting": "재부팅 중",
        "boot_settings": "부팅 설정",
        "ui_language": "UI 언어",
        "choose_file": "파일 선택…",
        "choose_firmware": "펌웨어 파일 선택",
        "apply": "적용 (필요 시 재부팅)",
        "save_failed": "저장 실패",
        "settings_error": "설정 오류",
        "settings_save_error": "설정 저장 오류",
    },
    "en": {
        "window_title": "MSM5XXX Emulator",
        "ready": "Ready",
        "detecting": "Detecting automatically",
        "unknown_model": "Unknown model",
        "settings": "Settings",
        "capture": "Capture",
        "restarting": "Restarting",
        "boot_settings": "Boot Settings",
        "ui_language": "UI Language",
        "choose_file": "Choose File…",
        "choose_firmware": "Choose Firmware",
        "apply": "Apply (restart if needed)",
        "save_failed": "Save Failed",
        "settings_error": "Settings Error",
        "settings_save_error": "Settings Save Error",
    },
}


def display_model_name(model: str, verified_model: str | None, language: str) -> str:
    """Show detector candidate while marking unverified identity explicitly."""
    if verified_model:
        return verified_model
    suffix = "미확인" if language == "ko" else "unverified"
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
    english = ui_language == "en"
    parts = [
        f"{'Run' if english else '실행'} {latest['instructions']:,}",
        f"PC {latest.get('pc', '?')}",
        f"LCD {int(latest.get('lcd_writes', 0)):,}",
        f"frame {latest.get('frame_sequence', 0)}",
    ]
    audio_requests = int(latest.get("audio_play_requests", 0))
    audio_backend = str(latest.get("audio_backend", ""))
    if audio_requests:
        parts.append(f"{'Audio' if english else '오디오'} {audio_requests}")
    elif audio_backend in ("disabled", "render-only"):
        parts.append("Audio unavailable" if english else "오디오 재생기 없음")
    if latest.get("audio_error"):
        parts.append(f"{'Audio error' if english else '오디오 오류'}: {latest['audio_error']}")
    if latest.get("input_error"):
        parts.append(f"{'Input error' if english else '입력 오류'}: {latest['input_error']}")
    return "\n".join(parts)


def runtime_notice_text(latest: dict[str, object], ui_language: str) -> str:
    """Return only exceptional or optional runtime notices below metrics."""
    english = ui_language == "en"
    parts: list[str] = []
    audio_requests = int(latest.get("audio_play_requests", 0))
    audio_backend = str(latest.get("audio_backend", ""))
    if audio_requests:
        parts.append(f"{'Audio' if english else '오디오'} {audio_requests}")
    elif audio_backend in ("disabled", "render-only"):
        parts.append("Audio unavailable" if english else "오디오 재생기 없음")
    if latest.get("audio_error"):
        parts.append(f"{'Audio error' if english else '오디오 오류'}: "
                     f"{latest['audio_error']}")
    if latest.get("input_error"):
        parts.append(f"{'Input error' if english else '입력 오류'}: "
                     f"{latest['input_error']}")
    return "\n".join(parts)
