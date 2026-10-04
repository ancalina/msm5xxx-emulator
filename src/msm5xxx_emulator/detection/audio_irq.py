"""Static IRQ descriptor candidates; runtime readback is still required."""
from __future__ import annotations

import re
import struct

from .arm import thumb_bl_target, thumb_literal_value
from .rex import _normalized_thumb_sha256

_DISPATCH_PREFIX = bytes.fromhex('f0b51d4f00247879002834d0')
_DISPATCH_BODY = ('a20263109146f42dab950aa24c31cf920ae80d520a6777fe305b893bd976e220',
                  (12, 18, 26, 56, 84, 96, 110, 114))
_REGISTER_BODY = ('e24308607ffafe3b13c06bc3c5059befcad9ae2cf96bb17f3afe01178ee1e1b1',
                  (6, 32, 104))


_CALLBACK_PREFIX = bytes.fromhex('b0b50f4c011c')
_CALLBACK_BODY = ('28667306ba9dbd178a69db7a9bc4bc3d8db9f3d7104501131d9fec901d9cb663', ())
_STATUS_BODY = ('551c2cd1abc431c5f72a160c1560a8b9f12f2c43a32eae1610543386288b8e60',
                (4, 10, 18))
_CALLS = re.compile(rb'(?=.[\xf0-\xf7].[\xf8-\xff])', re.DOTALL)


def _callback_linkage(image: bytes, dispatcher: int) -> dict[str, int] | None:
    state = thumb_literal_value(image, dispatcher + 2, 7)
    table = thumb_literal_value(image, dispatcher + 0x16, 5)
    if (state is None or table is None or state & 1 or table & 3
            or not 0x01000000 <= state <= 0x01fffff8
            or not 0x01000000 <= table <= 0x01fffff0):
        return None
    registrars = set()
    position = 0
    for _ in range(65):
        offset = image.find(_CALLBACK_PREFIX, position)
        if offset < 0:
            break
        position = offset + 1
        if _ == 64:
            return None
        if (not offset & 1 and _normalized_thumb_sha256(image, offset, 0x3e) == _CALLBACK_BODY
                and thumb_literal_value(image, offset + 2, 4) == state
                and thumb_literal_value(image, offset + 0x10, 2) == table):
            registrars.add(offset)
    if len(registrars) != 1:
        return None
    links = set()
    for match in _CALLS.finditer(image):
        call = match.start()
        if call & 1 or call < 2 or thumb_bl_target(image, call) not in registrars:
            continue
        pointer = thumb_literal_value(image, call - 2, 0)
        if pointer is None or not pointer & 1:
            continue
        callback = pointer - 1
        if image[callback:callback + 4] != bytes.fromhex('f0b58ab0'):
            continue
        status = thumb_bl_target(image, callback + 4)
        if status is None or _normalized_thumb_sha256(image, status, 0x20) != _STATUS_BODY:
            continue
        read = thumb_bl_target(image, status + 0xa)
        if (read is not None and 0 <= read <= len(image) - 0x12
                and read == thumb_bl_target(image, status + 0x12)):
            links.add((callback, read + 0x10))
    if len(links) != 1:
        return None
    callback, read = links.pop()
    return {'state_address': state, 'table_address': table,
            'callback_offset': callback, 'data_read_offset': read}


def find_audio_irq_candidate(image: bytes) -> dict[str, object]:
    """Locate a shared callback dispatcher and its initialized descriptor.

    Offsets are file-relative. No electrical route or MA2 status ownership is
    admitted here: the installed handler and callback need live verification.
    """
    candidates = []
    position = 0
    for attempt in range(65):
        entry = image.find(_DISPATCH_PREFIX, position)
        if entry < 0:
            break
        position = entry + 1
        if attempt == 64:
            return {'status': 'rejected', 'reason': 'dispatcher-search-limit'}
        if entry & 1 or _normalized_thumb_sha256(image, entry, 0x78) != _DISPATCH_BODY:
            continue
        thunk = thumb_bl_target(image, entry + 0x38)
        if (thunk is None or not 0 <= thunk <= len(image) - 2
                or image[thunk:thunk + 2] != b'\x00\x47'):
            continue
        literal_position = 0
        for reference in range(65):
            literal = image.find(struct.pack('<I', entry | 1), literal_position)
            if literal < 0:
                break
            literal_position = literal + 1
            if reference == 64:
                return {'status': 'rejected', 'reason': 'registration-search-limit'}
            if literal & 3:
                continue
            for load in range(max(2, literal - 1024), literal, 2):
                if (image[load - 2:load] != b'\x00\xb5'
                        or thumb_literal_value(image, load, 1) != entry | 1
                        or load + 8 > len(image)):
                    continue
                immediate = struct.unpack_from('<H', image, load + 2)[0]
                api = thumb_bl_target(image, load + 4)
                if (immediate & 0xff00 != 0x2000 or api is None
                        or _normalized_thumb_sha256(image, api, 0x6e) != _REGISTER_BODY):
                    continue
                index = immediate & 0xff
                # The matched registrar bounds its descriptor index at 0x1d.
                if index >= 0x1d:
                    continue
                table = thumb_literal_value(image, api + 0x28, 1)
                if table is None or table & 3:
                    continue
                descriptor = table + index * 0x1c
                mappings = []
                for offset in range(0, min(len(image) - 20, 0x20000) + 1, 4):
                    source, target, size, bss, bss_size = struct.unpack_from('<5I', image, offset)
                    if not (0 < size <= 0x800000 and source + size <= len(image)
                            and 0x01000000 <= target < 0x02000000
                            and target + size == bss and 0 < bss_size <= 0x2000000
                            and bss + bss_size <= 0x02000000
                            and target <= descriptor and descriptor + 0x1c <= bss):
                        continue
                    row = source + descriptor - target
                    words = struct.unpack_from('<7I', image, row)
                    status, enable, mask, shadow, second_shadow, _, reserved = words
                    if not (0x03000000 <= status < 0x03001000 and status & 3 == 0
                            and enable == status + 8
                            and 0 < mask <= 0x8000 and mask & (mask - 1) == 0
                            and reserved == 0
                            and all(target <= address <= bss + bss_size - 2
                                    and address & 1 == 0
                                    for address in (shadow, second_shadow))):
                        continue
                    mappings.append({'scatter_offset': offset, 'file_offset': row,
                                     'words': list(words)})
                if len(mappings) != 1:
                    continue
                candidates.append({'dispatcher_offset': entry,
                                   'registration_offset': load - 2,
                                   'registrar_offset': api, 'index': index,
                                   'descriptor_address': descriptor,
                                   **mappings[0]})
    if len(candidates) != 1:
        return {'status': 'rejected', 'reason': 'descriptor-none' if not candidates
                else 'descriptor-ambiguous'}
    linkage = _callback_linkage(image, candidates[0]['dispatcher_offset'])
    return {'status': 'candidate', 'reason': 'live-handler-and-consumer-unverified',
            'profile': 'two-bank-callback-descriptor-v1', **candidates[0],
            **({'callback_linkage': linkage} if linkage is not None else {})}
