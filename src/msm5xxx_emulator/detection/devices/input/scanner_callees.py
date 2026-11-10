"""Bounded callee identities for the ARM-clock byte input scanner."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import hashlib
import struct

# Code and literal values are checked together. Unlike the scanner profile,
# these primitive bodies keep their BL encodings and validate resolved targets.
_CALLEES = {'irq_lock': (28, '05bb1a2e651a889ae08f19e98607f956161b40424ed99b20b412b687a6667f10', (), ()), 'irq_unlock': (28,
    'd961305ca13c6c8a3d2a5bd54d508f2977a58483bff33d6de0ae24fa06c4fe82', (), ()), 'scanner_aux_display_message': (52,
    'ee169f11b23836e27e7230c62cf779218f40cb0db35ac766613c724be8b2f15e', ((0, 0), (10, 0), (44, 1)), ((12, 81500), (32, 520580), (46, 470064))),
    'scanner_aux_time': (86, 'a23cdb75bb13cd75db6fe47d806ac5a3acf1d04f16b44e80349227d61dc34367', ((6, 3), (58, 0), (60, 1), (70, 1)), ((2, 54508), (18, 308740),
    (32, 308740))), 'event_cancel_timer': (12, '1d08586655874f8eaf44dae6fab6758d95cbc785e6edee4fa45b695bc33c83ca', ((2, 0),), ((4, 54368),)), 'assert_helper': (20,
    '1399a37e1e52cff3e7b86cadff1516c77a3dd785ab14ed846e38d02685fd8e1c', ((0, 2),), ((12, 469712),)), 'rex_set_sigs': (64,
    '52cad9ee56ddd3a346c6d2afc0e0c32fcac2ce3590272aa7a7ab7680cdef41f9', ((28, 1),), ((6, 1799240), (44, 1799088), (52, 1799268))), 'power_delay': (34,
    '3921634dec250327182255473313b51b6eb73fe0fec357873c057c4c14e8d0f5', ((0, 1),), ()), 'rex_clr_sigs': (34,
    '4c08d51112a9ac5332db4b8552d0e6c8f3de684ce0fe639768601ba478c9a6e0', (), ((6, 1799240), (22, 1799268))), 'clock_remove': (66,
    '0f8411bdc6cd36dd8ee20d11c52f5633a5d39b0a140199c5a571d1ab40bc86c4', ((42, 1),), ((4, 1799240), (56, 1799268))), 'clock_insert': (90,
    'aa43ca47a6130a3d01aab14fb11be0805800442179f8e0f2603ca1da85334662', ((12, 0), (60, 0)), ((4, 1799240), (80, 1799268))), 'clock_subobject_initializer': (6,
    '8fb5ab71b040bed6249e97e544b9d2c6233732ad711f66220d03432a884c3f50', (), ())}

def callee_at(image: bytes, start: int, name: str) -> bool:
    length, digest, literals, calls = _CALLEES[name]
    alignment_mask = 3 if name in ('irq_lock', 'irq_unlock') else 1
    if start < 0 or start & alignment_mask or start + length > len(image):
        return False
    code = bytearray(image[start:start + length])
    for offset, register in literals:
        value = facts_for(image).thumb_literal_value(start + offset, register)
        if value is None:
            return False
        code.extend(struct.pack('<I', value))
    return (hashlib.sha256(code).hexdigest() == digest and all(0 <= target < len(image) and facts_for(image).thumb_call_target(start + offset) == target for
        offset, target in calls))
