"""Closed SC GPIO-to-parent route used with the indexed MA3 transport."""
from __future__ import annotations

import struct

from .arm import thumb_bl_target
from .audio import find_ma3_indexed_candidate
from .rex import find_rex_static_controller_callback_candidate


_IRQ_FIELDS = (
    0x17, 0x1D, 0x0100B914, 0x0129E278, 0x0100B584,
    0x00161F69, 0x00161BFC, 0x0009BB71, 0x2000,
    0x03000C84, 0x03000C98,
)
_COPY = (0x0066AC3C, 0x01000000, 0x00029538)


def _u32s(image: bytes, offset: int, count: int) -> tuple[int, ...] | None:
    if offset < 0 or offset + count * 4 > len(image):
        return None
    return struct.unpack_from("<" + "I" * count, image, offset)


def _u16s(image: bytes, offset: int, count: int) -> tuple[int, ...] | None:
    if offset < 0 or offset + count * 2 > len(image):
        return None
    return struct.unpack_from("<" + "H" * count, image, offset)


def _thumb_pushes(image: bytes, offset: int, registers: int,
                  *, link_register: bool = True) -> bool:
    """Decode a Thumb PUSH mask instead of matching copied instruction bytes."""
    word = _u16s(image, offset, 1)
    if word is None:
        return False
    opcode = word[0]
    return (opcode & 0xFE00 == 0xB400
            and opcode & 0xFF == registers
            and bool(opcode & 0x100) == link_register)


def _thumb_pops(image: bytes, offset: int, registers: int,
                *, program_counter: bool = False) -> bool:
    word = _u16s(image, offset, 1)
    return (word is not None and word[0] & 0xFE00 == 0xBC00
            and word[0] & 0xFF == registers
            and bool(word[0] & 0x100) == program_counter)


def _thumb_bx(image: bytes, offset: int, register: int) -> bool:
    word = _u16s(image, offset, 1)
    return (word is not None and word[0] & 0xFF87 == 0x4700
            and word[0] >> 3 & 0xF == register)


def _thumb_ldr_literal(image: bytes, offset: int, register: int) -> bool:
    word = _u16s(image, offset, 1)
    return (word is not None and word[0] & 0xF800 == 0x4800
            and word[0] >> 8 & 7 == register)


def _thumb_movs_imm(image: bytes, offset: int, register: int,
                    immediate: int) -> bool:
    word = _u16s(image, offset, 1)
    return (word is not None and word[0] & 0xF800 == 0x2000
            and word[0] >> 8 & 7 == register
            and word[0] & 0xFF == immediate)


def _thumb_adds_low(image: bytes, offset: int, destination: int,
                    source: int) -> bool:
    word = _u16s(image, offset, 1)
    return (word is not None and word[0] & 0xF800 == 0x1800
            and word[0] >> 6 & 7 == 0
            and word[0] >> 3 & 7 == source
            and word[0] & 7 == destination)


def _thumb_ldr_halfword_imm(image: bytes, offset: int, destination: int,
                            base: int, byte_offset: int) -> bool:
    word = _u16s(image, offset, 1)
    return (word is not None and word[0] & 0xF800 == 0x8800
            and word[0] >> 3 & 7 == base
            and word[0] & 7 == destination
            and (word[0] >> 6 & 0x1F) * 2 == byte_offset)


def _thumb_sub_sp(image: bytes, offset: int, byte_count: int) -> bool:
    word = _u16s(image, offset, 1)
    return (word is not None and word[0] & 0xFF80 == 0xB080
            and (word[0] & 0x7F) * 4 == byte_count)


def find_ma3_gpio_irq_candidate(image: bytes) -> dict[str, object]:
    """Prove the one linked GPIO23 route associated with SC indexed MA3.

    Static admission is deliberately exact: the audio verifier/reader/FIFO
    chain, reset copy metadata, copied parent/GPIO tables, registration edges,
    and dispatcher entry shapes must all match the same image. Runtime RAM
    validation remains the native device's responsibility.
    """
    rejected: dict[str, object] = {
        "status": "rejected", "profile": "ma3-sc-gpio23-v1",
        "reject_reason": "audio-profile-unmatched",
    }
    audio = find_ma3_indexed_candidate(image)
    if audio.get("static_status") != "accepted":
        return rejected

    # The image's closed reset-to-RAM copy route must cover both descriptor
    # tables at the exact source offsets validated below.
    rex = find_rex_static_controller_callback_candidate(
        image, ram_base=0x01000000, ram_size=0x00800000)
    if (not isinstance(rex, dict) or rex.get("accepted") is not True
            or (rex.get("vector_copy_source"), rex.get("vector_target"),
                rex.get("vector_copy_size")) != _COPY
            or rex.get("handler_file_offset") != 0x00161BFC):
        rejected["reject_reason"] = "vector-copy-unmatched"
        return rejected

    # These are source addresses under the closed reset copy. The row gives
    # the parent status/enable pair and mask; the GPIO rows bind bank 1 to the
    # second register tuple. The timer descriptor is a distinct neighbouring
    # row and is not accepted as the MA3 parent route.
    parent_row = _u32s(image, 0x0066AC3C + 0x0000B584 + 29 * 0x1C, 7)
    gpio_rows = _u32s(image, 0x0066AC3C + 0x0000B914, 12)
    if parent_row != (
            0x03000C84, 0x03000C98, 0x2000, 0x0100B57A,
            0x0100B580, 0x00161B95, 0):
        rejected["reject_reason"] = "parent-row-unmatched"
        return rejected
    if gpio_rows != (
            0x03000C88, 0x03000CA4, 0x03000CB0, 0x0300074C,
            0xFFFF0000, 0, 0x03000C8C, 0x03000CA8, 0x03000CB4,
            0x03000750, 0xFFFF0000, 0):
        rejected["reject_reason"] = "gpio-table-unmatched"
        return rejected

    # Decode function-entry instructions and call edges to close registration
    # to the dispatchers. Keep the native live-RAM and callback-slot checks.
    decoded_shapes = (
        _thumb_pushes(image, 0x00161BFC, 0xF0)
        and _thumb_sub_sp(image, 0x00161BFE, 0x18)
        and thumb_bl_target(image, 0x00161C00) == 0x000B7F4C
        and _thumb_pushes(image, 0x00161F68, 0xB0)
        and _thumb_ldr_halfword_imm(image, 0x00161F6C, 0, 4, 8)
        and _thumb_pushes(image, 0x00161E1C, 0xF0)
        and _thumb_adds_low(image, 0x00161E1E, 4, 0)
        and _thumb_adds_low(image, 0x00161E20, 7, 1)
        and thumb_bl_target(image, 0x00161E22) == 0x001D3B3C
        and _thumb_pushes(image, 0x00162030, 0xF0)
        and _thumb_adds_low(image, 0x00162032, 7, 0)
        and _thumb_adds_low(image, 0x00162034, 5, 1)
        and _thumb_adds_low(image, 0x00162036, 4, 2)
        and _thumb_pushes(image, 0x0016210C, 0xF0)
        and _thumb_movs_imm(image, 0x0016210E, 7, 0)
        and thumb_bl_target(image, 0x00162110) == 0x001D3B3C
        and _thumb_pushes(image, 0x0009BB70, 0)
        and thumb_bl_target(image, 0x0009BB72) == 0x0009BB98
        and thumb_bl_target(image, 0x0009BB76) == 0x0008B010
        and thumb_bl_target(image, 0x0009BB7A) == 0x0009BB82
        and _thumb_pops(image, 0x0009BB7E, 0x08)
        and _thumb_bx(image, 0x0009BB80, 3)
    )
    if not decoded_shapes:
        rejected["reject_reason"] = "dispatcher-shape-unmatched"
        return rejected
    if (thumb_bl_target(image, 0x001621AA) != 0x00161E1C
            or thumb_bl_target(image, 0x0009BB8A) != 0x00162030
            or thumb_bl_target(image, 0x0009BBA0) != 0x00162030):
        rejected["reject_reason"] = "registration-linkage-unmatched"
        return rejected

    # GPIO 23 is the bank-1 0x80 bit. The callback table itself lives in the
    # cleared RAM region; its base and the callback pointer are fixed by the
    # linked setup/callback code and checked again after relocation natively.
    pointer_evidence = (
        _u32s(image, 0x00161D94, 2) == (0x0100B584, 0x0129E264)
        and _u32s(image, 0x00162024, 2) == (0x0100B914, 0x0129E278)
        and _u32s(image, 0x001620AC, 3)
        == (0x0129E278, 0x0100B914, 0x00161F65)
        and _u32s(image, 0x001621C0, 4)
        == (0x0100B914, 0x0129E278, 0x00161F65, 0x00161F69)
        and _thumb_bx(image, 0x0009BB90, 3)
        and _u32s(image, 0x0009BB94, 1) == (0x9BB71,)
        and _thumb_movs_imm(image, 0x0009BB82, 1, 0)
        and _thumb_movs_imm(image, 0x0009BB84, 0, 23)
        and _thumb_pushes(image, 0x0009BB86, 0)
        and _thumb_ldr_literal(image, 0x0009BB88, 2)
    )
    if not pointer_evidence:
        rejected["reject_reason"] = "registration-data-unmatched"
        return rejected
    return {
        "status": "candidate", "profile": "ma3-sc-gpio23-v1",
        "reject_reason": None, "fields": list(_IRQ_FIELDS),
        "vector_copy": list(_COPY), "audio_profile": "ma3-indexed-v1",
        "parent_descriptor_source": 0x0066AC3C + 0x0000B584 + 29 * 0x1C,
        "gpio_table_source": 0x0066AC3C + 0x0000B914,
        "gpio_pin": 23, "gpio_bank": 1, "gpio_mask": 0x80,
        "registration_sites": [0x001621AA, 0x0009BB8A],
    }


__all__ = ("find_ma3_gpio_irq_candidate",)
