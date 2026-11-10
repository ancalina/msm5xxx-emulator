"""Source evidence for the split18 panel protocol."""
from __future__ import annotations

_SPLIT = bytes.fromhex('8700d459240c6c80d759bf07bf0f6f80')
_PORT = bytes.fromhex('0121c9028f033980')
_LOOPS = bytes.fromhex('013101308028ecd30133a02be5d3')
_GLYPH = bytes.fromhex('f0b400011149002743180124104d64061a7807210020161c0e41760802d300266680'
    '01e065800326668001390904090c01300006000e0828eddb013301373f063f0e102f' 'e4dbf0bc7047')
_WINDOW = bytes.fromhex('fcb5041c0025002728010721090201430e1cc11d08310b22120211430191d11ff939'
    '014300912078002827d0f8000121c902014301225206118000991180c11d09231b02' '194311800199118003214902084310801680')

def find_split18_port(image: bytes) -> tuple[int | None, str]:
    """Bind original producer, bus construction, dimensions and window caller."""
    witnesses = []
    start = 0
    while (offset := image.find(_SPLIT, start)) >= 0:
        if (offset % 2 == 0 and offset >= 126 and image[offset-126:offset-118] == _PORT and image[offset+30:offset+44] == _LOOPS):
            witnesses.append(offset)
        start = offset + 1
    start = 0
    while (offset := image.find(_GLYPH, start)) >= 0:
        if (offset % 2 == 0 and image[offset+80:offset+82] == b'\xff\xff' and image[offset+84:offset+84+len(_WINDOW)] == _WINDOW):
            witnesses.append(offset)
        start = offset + 1
    if len(witnesses) == 1:
        return 0x02000000, 'split18-producer-window-bound'
    return None, ('ambiguous-split18-writers' if witnesses else 'writer-signature-not-found')
