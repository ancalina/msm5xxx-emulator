"""A boot power guard whose input bit must not be overwritten by GPIO stores."""
from __future__ import annotations

from ..core.config import BoardStatusInput
from .arm import thumb_literal_value


def find_cold_power_guard(image: bytes) -> BoardStatusInput | None:
    # GPIO+0xc bit4 selects the boot path. GPIO+0 bit2 admits either path.
    # The other path additionally tests the external 0x04800020 bit0 input.
    # The physical switch name is not established by this instruction shape.
    shape = bytes.fromhex(
        "b0b40020134901220a7000220a70114fbc89102323402024002b08d1"
        "3888c00814d2bc813a80012008700a70fce73d88eb080bd2094b1b88"
        "5b0807d2bc813a8001230b700a700130ff28fad3b0bc7047"
    )
    at = 0
    found = 0
    while (at := image.find(shape, at)) >= 0:
        if not at & 1 and (
            thumb_literal_value(image, at + 4, 1) == 0x03001080
            and thumb_literal_value(image, at + 14, 7) == 0x03000720
            and thumb_literal_value(image, at + 52, 3) == 0x04800020
        ):
            found += 1
        at += 2
    # Require the two matching guard copies to agree on this external pin.
    return BoardStatusInput(0x03000720, 4, 4) if found == 2 else None
