"""Bounded callee identities for the ARM-clock byte input scanner."""
from __future__ import annotations

import hashlib
import struct

from .arm import thumb_bl_target, thumb_literal_value

# Code and literal values are checked together. Unlike the scanner profile,
# these primitive bodies keep their BL encodings and validate resolved targets.
_CALLEES = {
    'irq_lock': (0x1c,
        '05bb1a2e651a889ae08f19e98607f956161b40424ed99b20b412b687a6667f10',
        (),
        ()),
    'irq_unlock': (0x1c,
        'd961305ca13c6c8a3d2a5bd54d508f2977a58483bff33d6de0ae24fa06c4fe82',
        (),
        ()),
    'scanner_aux_display_message': (0x34,
        'ee169f11b23836e27e7230c62cf779218f40cb0db35ac766613c724be8b2f15e',
        ((0x0, 0), (0xa, 0), (0x2c, 1)),
        ((0xc, 0x13e5c), (0x20, 0x7f184), (0x2e, 0x72c30))),
    'scanner_aux_time': (0x56,
        'a23cdb75bb13cd75db6fe47d806ac5a3acf1d04f16b44e80349227d61dc34367',
        ((0x6, 3), (0x3a, 0), (0x3c, 1), (0x46, 1)),
        ((0x2, 0xd4ec), (0x12, 0x4b604), (0x20, 0x4b604))),
    'event_cancel_timer': (0xc,
        '1d08586655874f8eaf44dae6fab6758d95cbc785e6edee4fa45b695bc33c83ca',
        ((0x2, 0),),
        ((0x4, 0xd460),)),
    'assert_helper': (0x14,
        '1399a37e1e52cff3e7b86cadff1516c77a3dd785ab14ed846e38d02685fd8e1c',
        ((0x0, 2),),
        ((0xc, 0x72ad0),)),
    'rex_set_sigs': (0x40,
        '52cad9ee56ddd3a346c6d2afc0e0c32fcac2ce3590272aa7a7ab7680cdef41f9',
        ((0x1c, 1),),
        ((0x6, 0x1b7448), (0x2c, 0x1b73b0), (0x34, 0x1b7464))),
    'power_delay': (0x22,
        '3921634dec250327182255473313b51b6eb73fe0fec357873c057c4c14e8d0f5',
        ((0x0, 1),),
        ()),
    'rex_clr_sigs': (0x22,
        '4c08d51112a9ac5332db4b8552d0e6c8f3de684ce0fe639768601ba478c9a6e0',
        (),
        ((0x6, 0x1b7448), (0x16, 0x1b7464))),
    'clock_remove': (0x42,
        '0f8411bdc6cd36dd8ee20d11c52f5633a5d39b0a140199c5a571d1ab40bc86c4',
        ((0x2a, 1),),
        ((0x4, 0x1b7448), (0x38, 0x1b7464))),
    'clock_insert': (0x5a,
        'aa43ca47a6130a3d01aab14fb11be0805800442179f8e0f2603ca1da85334662',
        ((0xc, 0), (0x3c, 0)),
        ((0x4, 0x1b7448), (0x50, 0x1b7464))),
    'clock_subobject_initializer': (0x6,
        '8fb5ab71b040bed6249e97e544b9d2c6233732ad711f66220d03432a884c3f50',
        (),
        ()),
}


def callee_at(image: bytes, start: int, name: str) -> bool:
    length, digest, literals, calls = _CALLEES[name]
    alignment_mask = 3 if name in ('irq_lock', 'irq_unlock') else 1
    if start < 0 or start & alignment_mask or start + length > len(image):
        return False
    code = bytearray(image[start:start + length])
    for offset, register in literals:
        value = thumb_literal_value(image, start + offset, register)
        if value is None:
            return False
        code.extend(struct.pack('<I', value))
    return (hashlib.sha256(code).hexdigest() == digest
            and all(0 <= target < len(image)
                    and thumb_bl_target(image, start + offset) == target
                    for offset, target in calls))
