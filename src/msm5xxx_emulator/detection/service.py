"""Bounded origination producer and live protocol revision source."""
import hashlib
import re
from .baseband import _literal
from .arm import thumb_bl_target
_PREFIX = bytes.fromhex('f7b583b0d51d2935e87b141c0f1c202801dd01207be06846391c221c')
_SIZE = 1644
_CALLS = [(28, 0), (52, 1), (84, 2), (108, 1), (132, 1), (210, 1), (238, 1), (252, 3), (282, 1), (306, 1), (330, 1), (354, 1), (378, 1), (402, 1), (432, 4), (456, 1), (480, 1), (510, 1), (534, 1), (558, 1), (582, 1), (620, 1), (646, 1), (686, 1), (718, 1), (742, 1), (766, 1), (798, 1), (822, 1), (846, 1), (880, 4), (928, 3), (960, 1), (984, 1), (1014, 4), (1038, 1), (1062, 1), (1086, 1), (1110, 1), (1138, 1), (1172, 1), (1196, 1), (1220, 1), (1250, 1), (1274, 1), (1310, 4), (1340, 1), (1376, 1), (1406, 1), (1438, 1), (1462, 1), (1498, 4), (1528, 1), (1564, 1), (1604, 1)]
_LITERALS = [(146, 6, 1144), (250, 0, 1148), (700, 0, 1144), (910, 5, 1144), (926, 0, 1148), (1624, 3, 1644)]
_CALLEE_PREFIXES = {0: 'f7b581b0fa4e141c30780022', 1: 'f0b555076d0f1f1c08235b1b', 2: 'ffb59a18181c531e1a1c002b', 3: 'ffb581b0039d18781c1c0623', 4: 'ffb59a18181c531e1a1c002b'}
_SHAPE_SHA = 'f0a4767775013c63c156a5e2d4f16fcebb86681c50b3432d9cc1cc89ff24de8c'
_DISPATCHER_PREFIX = bytes.fromhex('80b517780b2f27d201a3db5d5b009f44')
_DISPATCHER_SIZE = 92
_DISPATCHER_CALLS = [28, 34, 40, 46, 52, 58, 64, 70, 76, 82]
_DISPATCHER_SHA = '8db3b718fb4cdda25f2a29ab4b4f81d5b8031c814eeb5e4c6c02e88962a70bd3'

def _dispatcher_for(image, packer):
    matches = []
    for match in re.finditer(re.escape(_DISPATCHER_PREFIX), image):
        entry = match.start()
        if entry & 1 or entry + _DISPATCHER_SIZE > len(image):
            continue
        data = bytearray(image[entry:entry + _DISPATCHER_SIZE])
        valid = True
        for off in _DISPATCHER_CALLS:
            target = thumb_bl_target(image, entry + off)
            if target is None or not 0 <= target < len(image) - 1:
                valid = False
                break
            data[off:off + 4] = bytes(4)
        if not valid or hashlib.sha256(data).hexdigest() != _DISPATCHER_SHA:
            continue
        # Thumb ADD PC uses instruction+4, without literal-load alignment.
        call = entry + 18 + 2 * image[entry + 16 + 4]
        if thumb_bl_target(image, call) == packer:
            matches.append(entry)
    return matches[0] if len(matches) == 1 else None
_CALLEE_BODIES = {1: (128, 'a72ffbe8c35f2c43e97d67f6fdd30ac77d04d0b5bad1fcd6ab6e7df59880c588'), 4: (164, '5c739ad1cbad4a973f2118727a4104463373e82e52f4752d59b1bdce477d2ad5'), 2: (158, '6d3c18e8cdbb6051c29102b9018adf355b30225b3d29fe2bc78425bbd77dd943')}

def _at(image: bytes, entry: int, ram_base: int, ram_size: int):
    if entry & 1 or entry < 0 or entry + _SIZE + 4 > len(image):
        return None
    shape = bytearray(image[entry:entry + _SIZE])
    for offset, group in _CALLS:
        shape[offset:offset + 4] = bytes(4)
    for offset, register, pool in _LITERALS:
        shape[offset] = 0
    for offset in (1144, 1148):
        shape[offset:offset + 4] = bytes(4)
    if hashlib.sha256(shape).hexdigest() != _SHAPE_SHA:
        return None
    targets = {}
    for offset, group in _CALLS:
        target = thumb_bl_target(image, entry + offset)
        prefix = bytes.fromhex(_CALLEE_PREFIXES[group])
        if target is None or target < 0 or target + len(prefix) > len(image):
            return None
        if image[target:target + len(prefix)] != prefix:
            return None
        if targets.setdefault(group, target) != target:
            return None
    if len(set(targets.values())) != len(targets):
        return None
    for group, (length, digest) in _CALLEE_BODIES.items():
        target = targets[group]
        if target + length > len(image) or hashlib.sha256(image[target:target + length]).hexdigest() != digest:
            return None
    values = []
    for offset, register, pool in _LITERALS:
        word = int.from_bytes(image[entry + offset:entry + offset + 2], 'little')
        if (entry + offset + 4 & ~3) + 4 * (word & 255) != entry + pool:
            return None
        value = _literal(image, entry + offset, register, 0)
        if value is None:
            return None
        values.append(value)
    revision, extra = values[:2]
    if values != [revision, extra, revision, revision, extra, 842]:
        return None
    if type(ram_base) is not int or type(ram_size) is not int or ram_size < 13:
        return None
    if not ram_base <= revision <= ram_base + ram_size - 13 or extra != revision + 12:
        return None
    dispatcher = _dispatcher_for(image, entry)
    if dispatcher is None or _literal(image, targets[0] + 4, 6, 0) != revision:
        return None
    header = targets[0]
    word = int.from_bytes(image[header + 4:header + 6], 'little')
    header_pool = (header + 8 & ~3) + 4 * (word & 255)
    code = [(entry, _SIZE + 4), (dispatcher, _DISPATCHER_SIZE), (header, 12), (header_pool, 4)]
    code.extend(((target, max(len(bytes.fromhex(_CALLEE_PREFIXES[group])), _CALLEE_BODIES.get(group, (0, ''))[0])) for group, target in targets.items()))
    code.extend(((thumb_bl_target(image, dispatcher + off), 2) for off in _DISPATCHER_CALLS))
    return {'signature': 'thumb-legacy-origination-service-v1', 'code_dependencies': sorted(set(code)), 'ram_dependencies': [(revision, 1), (extra, 1)], 'entry': entry, 'revision_address': revision, 'extension_length_address': extra, 'header_packer': targets[0], 'dispatcher': dispatcher, 'message_type': 4, 'supported_body_revisions': (2, 3), 'accepted': True, 'reject_reason': None}

def find_origination_service_profile(image: bytes, ram_base: int, ram_size: int) -> dict[str, object]:
    matches = []
    for match in re.finditer(re.escape(_PREFIX), image):
        result = _at(image, match.start(), ram_base, ram_size)
        if result:
            matches.append(result)
    if len(matches) != 1:
        return {'signature': 'thumb-legacy-origination-service-v1', 'accepted': False, 'reject_reason': 'service-packer-ambiguous' if matches else 'service-packer-unmatched', 'matches': len(matches)}
    return matches[0]
