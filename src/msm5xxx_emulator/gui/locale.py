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
        "more": "더보기",
        "done_editing": "편집 완료",
        "virtual_network_menu": "가상 통신망",
        "start": "실행", "stop_emulator": "에뮬 종료", "reboot_emulator": "에뮬 재부팅",
        "choose_firmware_menu": "펌웨어 선택…", "edit_input": "키 입력 편집",
        "time": "시간", "host_time": "호스트 시간", "set_time": "지정 시간…",
        "key_prompt": "이 버튼에 보낼 키 값을 입력하세요 (비우면 기본값)",
        "additional_display": "보조 화면", "display_position": "보조 화면 위치",
        "display_left": "왼쪽", "display_right": "오른쪽",
        "persistent_state": "기기 상태 저장",
        "reboot": "재부팅",
        "capture": "캡처",
        "virtual_network": "가상 통신망 (통화 미지원)",
        "virtual_network_active": "가상 통신망",
        "virtual_network_unavailable": "가상 통신망 미지원",
        "network_host_time": "통신망 시간에 PC 시계 사용",
        "network_start_time": "통신망 시작 시간 (비우면 사용 안 함)",
        "network_time_error": "시간을 YYYY-MM-DD HH:MM 형식으로 입력하세요",
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
        "more": "More",
        "done_editing": "Done editing",
        "virtual_network_menu": "Virtual network",
        "start": "Start", "stop_emulator": "Stop emulator", "reboot_emulator": "Reboot emulator",
        "choose_firmware_menu": "Choose firmware…", "edit_input": "Edit key input",
        "time": "Time", "host_time": "Host time", "set_time": "Set time…",
        "key_prompt": "Key value for this button (blank = default)",
        "additional_display": "Additional display", "display_position": "Additional display position",
        "display_left": "Left", "display_right": "Right",
        "persistent_state": "Persistent device state",
        "reboot": "Reboot",
        "capture": "Capture",
        "virtual_network": "Virtual network (calls unavailable)",
        "virtual_network_active": "Virtual network",
        "virtual_network_unavailable": "Virtual network unavailable",
        "network_host_time": "Use PC clock for network time",
        "network_start_time": "Network start time (blank = off)",
        "network_time_error": "Enter a valid time in YYYY-MM-DD HH:MM format",
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


def display_model_name(model: str | None, verified_model: str | None, language: str,
                       filename_stem: str = "") -> str:
    """Show detector candidate while marking unverified identity explicitly."""
    if verified_model:
        return verified_model
    if model is None:
        label = "알 수 없음" if language == "ko" else "Unknown"
        return f"{label} ({filename_stem})"
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
    return "\n".join(parts)
