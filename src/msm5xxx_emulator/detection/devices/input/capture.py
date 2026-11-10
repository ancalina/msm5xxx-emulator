"""Input-domain capture helpers used by plan layout discovery."""
from __future__ import annotations

from msm5xxx_emulator.detection.devices.input.boot_keysense import find_boot_keysense_release
from msm5xxx_emulator.detection.devices.input.boot_rules import detect_guest_owned_status_72c
from msm5xxx_emulator.detection.devices.input.rules import find_board_status_input
from msm5xxx_emulator.detection.devices.input.sd810 import sd810_gpio_board_status_profile

def capture_boot_key(layout) -> tuple[dict | None, str | None]:
    """Capture reset-linked boot-key evidence when the firmware loads at zero."""
    profile = None
    reason = None
    if layout.requested_load_address == 0:
        profile, reason = find_boot_keysense_release(layout.primary_image)
        if (profile is not None and profile.get("signature") == "arm-thumb-single-boot-contact-v1" and layout.chipset not in ("MSM5100", "MSM5105")):
            profile, reason = None, "predicate-not-closed"
    return profile, reason

def note_boot_key(layout, profile: dict | None, reason: str | None) -> None:
    """Append the original boot-key capture notes to a layout."""
    if profile is not None:
        if profile.get("signature") == "arm-thumb-single-boot-contact-v1":
            layout.detection_notes.append("reset-linked released boot contact detected; only its single source read is eligible")
        else:
            layout.detection_notes.append("reset-linked released-key predicate detected; only its three source reads are eligible, " "not active key mapping")
    elif reason not in (None, "predicate-not-closed"):
        layout.detection_notes.append(f"boot key release not applied: {reason}; native fallback")

def capture_status(layout):
    """Capture guest-owned status and board GPIO input evidence, preserving notes."""
    guest_owned_status_72c, status_72c_note = detect_guest_owned_status_72c(layout.primary_image)
    if status_72c_note is not None:
        layout.detection_notes.append(status_72c_note)
    sd810_profile = sd810_gpio_board_status_profile(layout.primary_image)
    source_info: dict = {}
    board_status_input = find_board_status_input(layout.primary_image, layout.detection_notes, sd810_profile=sd810_profile, source_info=source_info,)
    if board_status_input is not None and not source_info.get("native_default", False):
        layout.detection_notes.append("Thumb byte-status mask/branch/debounce shape detected board-status input")
        if board_status_input.mask == 0x04:
            layout.detection_notes.append("experimental offset-byte status profile: asserted default; "
                "physical fold polarity and runtime switch response unverified")
    return guest_owned_status_72c, sd810_profile, board_status_input

from .boot_rules import detect_guest_owned_status_72c
from .rules import find_board_status_input
from .sd810 import sd810_gpio_board_status_profile
