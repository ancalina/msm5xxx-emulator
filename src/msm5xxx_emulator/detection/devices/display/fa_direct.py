"""Source evidence for the fa direct panel protocol."""
from __future__ import annotations
import struct

_ROW = bytes.fromhex('0a30a0e1babfcae1babfc3e1babfc3e1babfc3e17800a0e3010000eab210d4e0ba1fc3e1011040e20118a0e12118a0e10020a0e10100a0e1000052e3f6ffffcababfc3e1babfc3e1babfc3e1babfc3e1010086e2406bc0e3050056e1e7ffffda')
_WINDOW = bytes.fromhex('f0472de90150a0e10040a0e19100a0e38110a0e30370a0e10260a0e1150d00eb0110a0e33b00a0e3120d00eb3c001fe58087a0e30000d0e544911fe505a0a0e3000050e350001f050000d005000050030900001a560b00ebac241fe5bc10d2e1401e81e3bc10c2e1bc10d2e1002092e5b010c2e1000050e3500b000bf70c00ebb8a7c8e1ba9fc8e1fa0fa0e3f60c00ebf20c00eb1600a0e3b807c8e1060484e1ba0fc8e1ed0c00eb1700a0e3b807c8e1070485e1ba0fc8e1e80c00eb2100a0e3b807c8e1050484e0400bc0e3ba0fc8e1')
_CALLER = bytes.fromhex('0530a0e17f20a0e30610a0e10000a0e3dcfeffeb000457e580a7a0e3a0941fe500b0a0e3')
_HEIGHT = bytes.fromhex('010086e2406bc0e3a00056e3420000aa050056e1e5ffffda3f0000ea')
_CONTROL_INIT = bytes.fromhex('0760a0e38057a0e3b867c5e10470a0e3ba7fc5e1020e00eb0d80a0e3b887c5e1ff0f86e2ba0fc5e1fd0d00eb0e90a0e3b897c5e180029fe5ba0fc5e10a00a0e1fa0d00ebf60d00eb01a0a0e3b8a7c5e1430f86e2ba0fc5e1f10d00eb0200a0e3b807c5e1700ea0e3ba0fc5e1ec0d00eb0500a0e3b807c5e140029fe5ba0fc5e1e70d00eb0600a0e3b807c5e100b0a0e3babfc5e1e20d00eb0b00a0e3b807c5e1400ca0e3ba0fc5e1dd0d00eb0c00a0e3b807c5e1baafc5e1d90d00eb0300a0e3b807c5e19400a0e3ba0fc5e1d40d00ebb877c5e1babfc5e1e4019fe5d30d00ebcf0d00ebb897c5e1d8019fe5ba0fc5e1cb0d00ebb887c5e1cc019fe5ba0fc5e1c70d00eb2100a0e3b807c5e1babfc5e1c30d00eb3000a0e3b807c5e10570a0e1bf5f86e2ba5fc7e1bd0d00eb3100a0e3b807c7e1ba5fc7e1b90d00eb3200a0e3b807c7e1ba5fc7e1b50d00eb3300a0e3b807c7e1ba5fc7e1b10d00eb3400a0e3b807c7e1f48f80e2ba8fc7e1ac0d00eb3500a0e3b807c7e1ba8fc7e1a80d00eb3600a0e3b807c7e1ba8fc7e1a40d00eb3780a0e3b887c7e1ba5fc7e1a00d00eb0f00a0e3b807c7e1babfc7e19c0d00eb1100a0e3b807c7e1babfc7e1980d00eb1400a0e3b807c7e19f5ca0e3ba5fc7e1930d00eb1500a0e3b807c7e1babfc7e18f0d00eb1600a0e3b807c7e17f0ca0e3ba0fc7e18a0d00eb1700a0e3b807c7e1ba5fc7e1860d00eb3a00a0e3b807c7e1b8009fe5ba0fc7e1810d00eb3b00a0e3b807c7e1a00e89e2ba0fc7e17c0d00ebb867c7e12550a0e3ba5fc7e17d0ea0e37a0d00eb760d00ebb867c7e1ba5fc7e1730d00ebb867c7e12700a0e3ba0fc7e16f0d00ebb867c7e1ba8fc7e18010a0e39100a0e3')
_CONTROL_STANDBY = bytes.fromhex('0700a0e38077a0e3b807c7e10400a0e3ba0fc7e1340d00eb0300a0e3b807c7e10200a0e3ba0fc7e1')
_CONTROL_VALUES = bytes.fromhex('b80b0000204e00001d16000030100000409c00001d36000013040000031f0000')

def _branch_target(image: bytes, at: int) -> int | None:
    if not 0 <= at <= len(image)-4:
        return None
    word = struct.unpack_from('<I', image, at)[0]
    if word >> 24 != 0xEB:
        return None
    displacement = word & 0xFFFFFF
    if displacement & 0x800000:
        displacement -= 0x1000000
    return at + 8 + displacement*4

def find_fa_direct_port(image: bytes) -> tuple[int | None, str]:
    witnesses = []
    start = 0
    while (at := image.find(_ROW, start)) >= 0:
        start = at + 1
        helper, caller = at - 0x750, at - 0x2D8
        if at % 4 or at < 0xB14:
            continue
        if (image[helper:helper+len(_WINDOW)] != _WINDOW or image[caller:caller+len(_CALLER)] != _CALLER or image[at-0xBC:at-0xBC+len(_HEIGHT)] != _HEIGHT or
            image[helper-0x104:helper-0x100] != bytes.fromhex('30100000') or _branch_target(image, caller+16) != helper or image[at-0xB14:at-0xB14+len(_CONTROL_INIT)]
            != _CONTROL_INIT or image[at-0x7DC:at-0x7DC+len(_CONTROL_STANDBY)] != _CONTROL_STANDBY or image[at-0x860:at-0x860+len(_CONTROL_VALUES)] !=
            _CONTROL_VALUES):
            continue
        witnesses.append(at)
    if len(witnesses) == 1:
        return 0x02000000, 'fa-direct-producer-window-bound'
    return None, 'ambiguous-fa-direct-writers' if witnesses else 'writer-signature-not-found'
