"""Source evidence for the packed2 panel protocol."""
from __future__ import annotations
import struct

_HELPER = bytes.fromhex('002201235b0600b51a701870081298709970')
_CONSUMER = bytes.fromhex('315d601c0e4a4900441c305c515a0c4a4000105a01431220fff733ff0137')

def find_packed2_port(image: bytes) -> tuple[int | None, str]:
    """Require the byte writer, its actual LUT consumer and both full bitplanes."""
    matches = []
    offset = image.find(_CONSUMER)
    while offset >= 0:
        helper = offset - 0x17e
        if offset % 2 == 0 and helper >= 0 and image[helper:helper + len(_HELPER)] == _HELPER:
            # Literal loads are part of the consumer; unrelated LUT occurrences cannot qualify.
            pointers = [((offset + delta + 4) & ~3) + immediate * 4 for delta, immediate in ((4, 14), (14, 12))]
            if all(p + 4 <= len(image) for p in pointers):
                addresses = [struct.unpack_from('<I', image, p)[0] for p in pointers]
                valid = True
                for address, plane in zip(addresses, (1, 0)):
                    if address + 512 > len(image):
                        valid = False
                        break
                    words = struct.unpack_from('<256H', image, address)
                    if any(word != sum(((n >> b) & 1) << (2 * b + plane) for b in range(8)) for n, word in enumerate(words)):
                        valid = False
                        break
                if valid:
                    matches.append(offset)
        offset = image.find(_CONSUMER, offset + 1)
    if len(matches) == 1:
        return 0x02000000, 'interleaved-two-plane-byte-writer'
    return None, 'ambiguous-packed2-writer' if matches else 'packed2-writer-not-found'
