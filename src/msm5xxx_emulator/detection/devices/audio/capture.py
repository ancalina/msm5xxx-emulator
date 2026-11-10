"""Audio capture selection and layout-facing evidence notes."""
from __future__ import annotations

from msm5xxx_emulator.detection.devices.audio.boot_rules import (AUDIO_PLAY_SIGNATURE, find_ma2_silent_boot_wait,)
from msm5xxx_emulator.detection.devices.audio.rules import find_audio_transport
from msm5xxx_emulator.detection.devices.audio.tone import tone_admission

def capture_address(layout, direct_signature):
    return direct_signature("audio_play_address", AUDIO_PLAY_SIGNATURE)

def capture_transport(layout, mapped_runtime):
    audio_transport = find_audio_transport(layout.primary_image)
    tone_generator = tone_admission(layout.primary_image, audio_transport)
    if tone_generator["static_status"] == "accepted":
        layout.detection_notes.append("MSM5000 two-channel tone generator detected")
        audio_transport = {**audio_transport, "tone_generator": tone_generator}
    if audio_transport["static_status"] == "accepted":
        audio_transport = { **audio_transport, "sites": { kind:[runtime for position in positions if (runtime := mapped_runtime(position)) is not None] for kind,
            positions in audio_transport["sites"].items() }, "block_write_offsets":[runtime for position in audio_transport["block_write_offsets"] if (runtime
            := mapped_runtime(position)) is not None], }
        if audio_transport["family"] != "ma3":
            layout.detection_notes.append(
                f"Yamaha {audio_transport['family'].upper()} "
                f"{audio_transport['grammar']} audio transport detected"
            )
    elif audio_transport["static_status"] == "rejected":
        reason = ("protocol-unsupported" if audio_transport["family"] == "ma3" else audio_transport["reject_reason"])
        layout.detection_notes.append(f"Yamaha audio transport rejected: {reason}")
    elif (audio_transport["static_status"] == "candidate" and audio_transport.get("structural_evidence", {}).get ("transport_class") not in ("alternate-reset-readback-v1",
        "alternate-direct-reset-readback-v1")):
        layout.detection_notes.append("Yamaha MA5 structural readback candidate; runtime timing and " "device mapping unverified; native fallback retained")
    return audio_transport

def capture_ma2(layout, runtime_position):
    ma2_wait = find_ma2_silent_boot_wait(layout.primary_image)
    ma2_silent_boot_address = (runtime_position("ma2_silent_boot_address", ma2_wait) if ma2_wait is not None else None)
    if ma2_silent_boot_address is not None:
        layout.detection_notes.append("Yamaha MA2 silent boot stub detected; status-wait calls return " "success without device emulation")
    return ma2_silent_boot_address
