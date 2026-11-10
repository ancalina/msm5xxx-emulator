"""Closed boot-time instruction evidence owned by this domain."""
from __future__ import annotations
import re
import struct
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.signatures import find_all

AUDIO_PLAY_SIGNATURE = bytes.fromhex("ffb5071c0e1c27490868400838d38868002835db002f33db042f31da002e2fd0c"
    "c207843441824342078012828d1e51d1d35281cfff76afa039b0120002b00d1")
MA2_COMMAND_BUS_SIGNATURE = bytes.fromhex("4121c90468700870")
MA2_REGISTER_READ_SIGNATURE = bytes.fromhex("80b504494127ff0448703870")
MA2_STATUS_WAIT_SIGNATURE = bytes.fromhex("f8b500220f1c0092041c00237d22154d")
MA2_INIT_SIGNATURE = bytes.fromhex("90b5b2b06846c822")
MA2_RESET_AFTER_BL_SIGNATURE = bytes.fromhex("1d4902230a781c4d1a430a7009782971")

def find_ma2_silent_boot_wait(image: bytes) -> int | None:
    """Find the uniquely cross-checked MA2 status-wait entry."""
    if b"Ma2main.c\0" not in image or b"Ma2lib.c\0" not in image:
        return None
    commands = find_all(image, MA2_COMMAND_BUS_SIGNATURE)
    reads = find_all(image, MA2_REGISTER_READ_SIGNATURE)
    waits = find_all(image, MA2_STATUS_WAIT_SIGNATURE)
    inits = find_all(image, MA2_INIT_SIGNATURE)
    if not all(len(matches) == 1 for matches in (commands, reads, waits, inits)):
        return None
    command, read, wait, init = commands[0], reads[0], waits[0], inits[0]
    reset = command - 0xA4
    if (any(position & 1 for position in (command, read, wait, init)) or read != command + 0x78 or init != command + 0x9CC or reset < 0 or reset + 0x90 > len(image)
        or image[command + 0xC:command + 0x12] != bytes.fromhex("4120c0048770") or image[read + 0x10:read + 0x14] != bytes.fromhex("b87880bd") or image[reset:reset
        + 2] != b"\xb0\xb5" or image[reset + 6:reset + 6 + len(MA2_RESET_AFTER_BL_SIGNATURE)] != MA2_RESET_AFTER_BL_SIGNATURE or struct.unpack_from("<I", image,
        reset + 0x80)[0] != 0x03000680 or struct.unpack_from("<I", image, reset + 0x88)[0] != 0x03000670 or facts_for(image).thumb_call_target(init + 0x10) !=
        command + 0x824 or facts_for(image).thumb_call_target(init + 0x16) != command + 0x838 or facts_for(image).thumb_call_target(init + 0x48) != command +
        0x90):
        return None
    fixed_wait_chunks = ((0x1A, bytes.fromhex("0026f64315e0")), (0x24, bytes.fromhex("384003d0281c")), (0x2E, bytes.fromhex("09e00d480078002807d0281c")), (0x3E,
        bytes.fromhex("0a4900200870301cf8bd")), (0x50, bytes.fromhex("2040e5d0281c")), (0x5A, bytes.fromhex("0020f3e70000")),)
    if (wait + 0x60 > len(image) or any(image[wait + offset:wait + offset + len(expected)] != expected for offset, expected in fixed_wait_chunks) or facts_for(image).thumb_call_target(wait
        + 0x20) != command + 0xC2 or facts_for(image).thumb_call_target(wait + 0x4C) != command + 0xF2):
        return None
    return wait
