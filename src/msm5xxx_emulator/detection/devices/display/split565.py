"""Source evidence for the split565 panel protocol."""
from __future__ import annotations
import struct

_PRODUCER = bytes.fromhex('b200d4e04027a0e1ba2fc3e1e02d00e20221a0e1f80cc0e3800082e1ba0fc3e1')
_WINDOW_HELPER = bytes.fromhex('f0402de90370a0e10260a0e10150a0e10040a0e1b80c00eb770066e2800f80e3'
    '8067a0e3b807c6e1b30c00ebc00f85e3b807c6e1b00c00eb770064e2400e80e3' 'b807c6e1ac0c00eb500e87e3b807c6e1f040bde81eff2fe1')

def find_split565_port(image: bytes) -> tuple[int | None, str]:
    """Require producer, base register, 120-wide loop and linked window helper."""
    witnesses = []
    start = 0
    while (offset := image.find(_PRODUCER, start)) >= 0:
        start = offset+1
        if offset < 76 or offset % 4:
            continue
        if (image[offset-76:offset-64] != bytes.fromhex('7720a0e30610a0e10000a0e3') or image[offset-52:offset-48] != bytes.fromhex('80a7a0e3') or image[offset-16:offset-12]
            != bytes.fromhex('0a30a0e1') or image[offset-8:offset-4] != bytes.fromhex('7810a0e3') or image[offset+228:offset+260] != _PRODUCER or image[offset+296:offset+300]
            != bytes.fromhex('a00056e3')):
            continue
        call = struct.unpack_from('<I', image, offset-64)[0]
        if call >> 24 != 0xeb:
            continue
        displacement = call & 0xffffff
        if displacement & 0x800000:
            displacement -= 0x1000000
        target = offset-64+8+displacement*4
        helper = image[target:target+len(_WINDOW_HELPER)] if target >= 0 else b''
        if len(helper) != len(_WINDOW_HELPER):
            continue
        valid = True
        for index in range(0, len(helper), 4):
            if index in (20,40,52,68):
                valid &= helper[index+3] == 0xeb
            else:
                valid &= helper[index:index+4] == _WINDOW_HELPER[index:index+4]
        if valid:
            witnesses.append(offset)
    if len(witnesses) == 1:
        return 0x02000000, 'split565-producer-window-bound'
    return None, ('ambiguous-split565-writers' if witnesses else 'writer-signature-not-found')
