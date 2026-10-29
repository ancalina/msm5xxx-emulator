"""Source-bound ARM producer for a descending 96-byte page stream."""
from __future__ import annotations
import re

_BODY = bytes.fromhex(
    '30402de910501fe50040a0e30400a0e1000000ebc00295e5071004e2070080e2'
    '013040e00000a0e3000000eb0020a0e30000d3e5000000eb012082e2600052e3'
    '083083e2f9ffffba010084e2ff4000e2080054e3ecffffba3040bde81eff2fe1')
_DATA_AND_COMMAND = bytes.fromhex('a017a0e30200c1e51eff2fe1a017a0e30000c1e51eff2fe1')
_CALLER = re.compile(rb'.[\x10-\x1f]\x1f\xe5\x14\x00\x94\xe5\xc0\x02\x81\xe5...\xeb', re.S)


def _word(image: bytes, offset: int) -> int:
    return int.from_bytes(image[offset:offset + 4], 'little')


def _branch(image: bytes, offset: int, *, link: bool) -> int | None:
    if offset < 0 or offset + 4 > len(image):
        return None
    word = _word(image, offset)
    if word >> 24 != (0xeb if link else 0xea):
        return None
    displacement = word & 0xffffff
    if displacement & 0x800000:
        displacement -= 1 << 24
    target = offset + 8 + (displacement << 2)
    return target if target % 4 == 0 and 0 <= target <= len(image) - 4 else None


def find_secondary_arm_page(image: bytes) -> tuple[dict | None, str]:
    candidates = []
    start = 0
    while (at := image.find(_BODY[:16], start)) >= 0:
        start = at + 1
        if at % 4 or at < 4 or at + len(_BODY) > len(image):
            continue
        body = image[at:at + len(_BODY)]
        if any(body[i] != value for i, value in enumerate(_BODY)
               if not any(offset <= i < offset + 3 for offset in (0x10, 0x28, 0x34))):
            continue
        page, column, data = (_branch(image, at + offset, link=True)
                              for offset in (0x10, 0x28, 0x34))
        if page is None or column is None or data is None:
            continue
        if image[data:data + len(_DATA_AND_COMMAND)] != _DATA_AND_COMMAND:
            continue
        command = data + 12
        if not (image[page:page + 12] == bytes.fromhex('070050e300f18f90170000ea')
                and page + 0x6c <= len(image)):
            continue
        if any(_branch(image, page + 12 + n * 4, link=False) != page + 44 + n * 8
               for n in range(8)):
            continue
        if any(_word(image, page + 44 + n * 8) != 0xe3a000b7 - n
               or _branch(image, page + 48 + n * 8, link=False) != command
               for n in range(8)):
            continue
        if not (image[column:column + 20] == bytes.fromhex('0020a0e10f00a0e3420200e0100080e204e02de5')
                and _branch(image, column + 20, link=True) == command
                and image[column + 24:column + 32] == bytes.fromhex('0f0002e204e09de4')
                and _branch(image, column + 32, link=False) == command):
            continue
        descriptor = _word(image, at - 4)
        if descriptor % 4 or not 0x01000000 <= descriptor <= 0x01fffd3c:
            continue
        callers = []
        for match in _CALLER.finditer(image):
            pos = match.start()
            if pos % 4 or _branch(image, pos + 12, link=True) != at:
                continue
            # ARM LDR r1,[pc,-imm12] followed by storing the incoming buffer
            # to the same descriptor field consumed by the producer.
            op = _word(image, pos)
            if op & 0xfffff000 != 0xe51f1000:
                continue
            literal = pos + 8 - (op & 0xfff)
            if literal >= 0 and literal + 4 <= len(image) and _word(image, literal) == descriptor:
                callers.append((pos, literal))
        if len(callers) != 1:
            continue
        candidates.append({'class_name': 'arm-descending-page96-v1',
                           'admission': 'temporary-evidence-gated',
                           'command_port': 0x02800000, 'data_port': 0x02800002,
                           'width': 96, 'height': 64, 'access_width': 1,
                           'descriptor': descriptor, 'buffer_field': 0x2c0,
                           'source_intervals': [(at - 4, at + len(_BODY)),
                                                (page, page + 0x6c),
                                                (column, column + 36),
                                                (data, data + len(_DATA_AND_COMMAND)),
                                                (callers[0][0], callers[0][0] + 16),
                                                (callers[0][1], callers[0][1] + 4)]})
    if len(candidates) != 1:
        return None, 'arm-page-producer-missing-or-ambiguous'
    return candidates[0], 'accepted-source-bound-arm-page-candidate'
