"""Source-bound dual-descriptor DSP upload and readback contract."""
from __future__ import annotations

import struct

from capstone import arm as a
from ...capabilities import Capability, Evidence, ResourceClaim
from ...facts import CodeAddress, facts_for
from ...contracts import BodySpec
from .projection import owner_conflict

_PORTS = (0x0300004C, 0x03000050, 0x0300005C,
          0x03000768, 0x0300076C)
_READ_BASE = 0x03000760
_COUNT = 0x1000
# Preserve the source contract that packs this byte into the returned halfword.
_REVISION_READER = BodySpec.thumb(20, {
    0: 0xB508, 4: 0xAB00, 6: 0x7B00, 8: 0x7058, 10: 0x2000,
    12: 0x7018, 14: 0xA800, 16: 0x8800, 18: 0xBD08,
}, {2: 0})
_CALL_LAYOUTS = (
    (388, (14, 28, 52, 56, 130, 144, 160, 256, 366, 382)),
    (382, (14, 28, 52, 56, 130, 144, 160, 256, 366, 376)),
)
_LITERAL_ROLES = (
    (8, 1, 'completion'), (22, 1, 0x03000050), (40, 3, 'descriptor1'),
    (44, 3, 'descriptor0'), (48, 1, 0x03000040), (68, 0, 0x03000040),
    (70, 3, 'descriptor1'), (100, 0, 0x03000040), (102, 3, 'descriptor0'),
    (134, 1, 0x03000050), (148, 7, _READ_BASE), (172, 3, 'descriptor1'),
    (208, 3, 'descriptor0'), (246, 7, _READ_BASE), (268, 3, 'descriptor1'),
    (284, 7, _READ_BASE), (308, 3, 'descriptor0'), (324, 7, _READ_BASE),
    (350, 7, _READ_BASE), (358, 1, 'completion'),
)
# Native source PCs and the bus operation each instruction must perform.
_EVENTS = (
    (0x01A, 'write', _PORTS[2], 1, 0),
    (0x032, 'write', _PORTS[0], 2, 0),
    *((off, 'write', _PORTS[1], 2, None)
      for off in (0x052, 0x058, 0x072, 0x078)),
    (0x08A, 'write', _PORTS[2], 1, 1),
    (0x098, 'write', _PORTS[3], 1, 0x0E),
    (0x09C, 'write', _PORTS[4], 1, 0),
    (0x0FA, 'write', _PORTS[4], 1, 0),
    (0x160, 'write', _PORTS[3], 1, 0),
    (0x0BC, 'read', _PORTS[3], 2, None),
    (0x0E0, 'read', _PORTS[3], 2, None),
    (0x120, 'read', _PORTS[4], 2, None),
    (0x148, 'read', _PORTS[4], 2, None),
)


def _const(value):
    return (value.value if getattr(value, 'kind', None) == 'const'
            and type(value.value) is int else value if type(value) is int else None)


def _literal(facts, entry, offset, register):
    item = facts.literal(CodeAddress(entry + offset, 'thumb'))
    return item.value if item is not None and item.register == a.ARM_REG_R0 + register else None


def _descriptor_mode_write(facts, function, entry):
    """Keep each descriptor choice separate until its zero mode is written."""
    starts = {CodeAddress(entry + off, 'thumb') for off in (40, 44)}
    endpoint = CodeAddress(entry + 50, 'thumb')
    covered = set()
    for start in starts:
        region = facts.function_region(start, endpoint, budget=16)
        if (not region.complete or region.truncated or region.unresolved
                or not any(item.instruction == endpoint
                           and item.operation == 'write' and item.address == _PORTS[0]
                           and item.width == 2 and item.value == 0
                           for item in region.accesses)):
            return False
        covered.update(region.instructions)
    return not any(target in covered and target not in starts and source not in covered
                   for source, target in function.control_edges)


def _candidate(facts, image, entry):
    if entry <= 0 or entry > 0x02000000 - 0x184 or not facts.view.covers(entry, 382):
        return None
    start = CodeAddress(entry, 'thumb')
    first = facts.decode(start)
    if first is None or first.id != a.ARM_INS_PUSH:
        return None
    function = facts.function(start, budget=512, stop_at_initial_return=True)
    if not function.complete or function.truncated or function.unresolved:
        return None
    access = {item.instruction: item for item in
              (*function.accesses, *function.symbolic_accesses)}
    descriptor = _literal(facts, entry, 44, 3)
    completion = _literal(facts, entry, 8, 1)
    if descriptor is None or completion is None:
        return None
    raw = facts.view.read(descriptor, 16, phase='reset', bank='primary')
    if raw is None:
        return None
    payload0, mode0, count0, payload1, mode1, count1 = struct.unpack('<IHHIHH', raw)
    if mode0 or mode1 or count0 != _COUNT or count1 != _COUNT:
        return None
    call_map = {site.address - entry: target for site, target in function.calls}
    layout = next(((size, offsets) for size, offsets in _CALL_LAYOUTS
                   if set(call_map) == set(offsets)), None)
    if layout is None:
        return None
    size, _ = layout
    literal_roles = (*_LITERAL_ROLES,
                     (374 if size == 382 else 380, 1, 'descriptor_end'))
    for off, reg, role in literal_roles:
        expected = {'completion': completion, 'descriptor0': descriptor,
                    'descriptor1': descriptor + 8,
                    'descriptor_end': descriptor + 16}.get(role, role)
        if _literal(facts, entry, off, reg) != expected:
            return None
    sites = {item.site: dict(item.registers) for item in function.call_sites}
    if (call_map[28] != call_map[56] or call_map[28] != call_map[160]
            or call_map[28] != call_map[256] or call_map[52] != call_map[130]):
        return None
    args = {reg: value for reg, value in sites.get(CodeAddress(entry + 52, 'thumb'), {}).items()
            if value is not None}
    helper = facts.function(call_map[52], budget=96, initial_registers=args,
                            symbolic_registers={}, stop_at_initial_return=True)
    nested = {site.address - call_map[52].address: target
              for site, target in helper.calls}
    if (not helper.complete or helper.truncated or helper.unresolved
            or set(nested) != {10, 38, 42, 62}
            or nested[10] != call_map[14] or nested[42] != call_map[14]
            or nested[38] != call_map[144] or nested[62] != call_map[144]):
        return None
    if not facts.view.covers(entry, size):
        return None
    if descriptor & 3 or payload0 & 1 or payload1 & 1:
        return None
    if any(not facts.view.covers(target.address, 2, phase=target.phase,
                                bank=target.bank)
           for target in call_map.values()):
        return None
    for off, operation, address, width, value in _EVENTS:
        item = access.get(CodeAddress(entry + off, 'thumb'))
        if (item is None or item.operation != operation or _const(item.address) != address
                or item.width != width
                or (value is not None and _const(item.value) != value
                    and not (off == 0x032 and _descriptor_mode_write(facts, function, entry)))):
            return None
    # The code-linked reader used by the board-revision property is a separate
    # byte read from the status register at 0x0300075c.
    reader_call = next((target for site, target in function.calls
                        if site.address == entry + 28), None)
    if reader_call is None:
        return None
    reader_args = {reg: value for reg, value in sites.get(
        CodeAddress(entry + 28, 'thumb'), {}).items() if value is not None}
    reader_fn = facts.function(reader_call, budget=32,
                               initial_registers=reader_args, symbolic_registers={},
                               stop_at_initial_return=True)
    if (not reader_fn.complete or reader_fn.truncated or reader_fn.unresolved
            or not any(item.operation == 'read' and item.address == 0x0300075C
                       and item.width == 1 for item in reader_fn.accesses)):
        return None
    spans = ((entry, entry + size), (descriptor, descriptor + 16),
             (payload0, payload0 + 2 * count0),
             (payload1, payload1 + 2 * count1))
    if any(not 0 <= start < end <= len(image)
           or not facts.view.covers(start, end - start) for start, end in spans):
        return None
    for i, (start, end) in enumerate(spans):
        if any(start < other_end and other_start < end
               for other_start, other_end in spans[i + 1:]):
            return None
    callers = [at for at, target in facts.call_candidates('thumb')
               if target == entry]
    if len(callers) != 1:
        return None
    return {'completion': completion, 'entry': entry,
            'descriptors': (descriptor, descriptor + 8),
            'payloads': (payload0, payload1), 'pairs': count0 // 2}


def find_dmd5000_profile(image: bytes) -> dict | None:
    """Find a unique dual-descriptor source footprint; payload bytes are guest data."""
    if not isinstance(image, bytes):
        return None
    facts = facts_for(image)
    candidates = set()
    for item in facts.literal_references(0x03000050):
        entry = item.instruction.address - 22
        if facts.view.covers(entry, 2):
            candidates.add(entry)
    found = [profile for entry in sorted(candidates)
             if (profile := _candidate(facts, image, entry)) is not None]
    if len(found) != 1:
        return None
    return found[0]


def capability(profile: dict) -> Capability:
    """Return typed ownership for the five native DMD port windows."""
    evidence = Evidence('dmd5000-footprint', profile,
                        tuple(profile['entry'] + event[0] for event in _EVENTS),
                        'instruction')
    value = ':'.join(f'{v:x}' for v in (profile['entry'], profile['descriptors'][0],
        profile['payloads'][0], profile['descriptors'][1], profile['payloads'][1],
        profile['pairs']))
    return Capability(
        'dmd5000_dual', (evidence.name,), (evidence,),
        properties=(('dmd5000-program', value),),
        claims=tuple(ResourceClaim('address', 'dmd5000', port, port + 4,
                                   address_space='physical', phase='runtime')
                     for port in _PORTS),
        parameters=(('profile', tuple(profile[key] for key in
                                      ('entry', 'descriptors', 'payloads', 'pairs'))),))


def qemu_dual_property(original: bytes, loaded: bytes, config: object, *,
                  layout_claimed=False, input_profile=None, eeprom_window=None,
                  immutable_limit=None, uart_windows=()):
    profile = find_dmd5000_profile(original)
    if profile is None:
        return None, None
    fields = ('load_address', 'image_offset', 'entry', 'flash_size', 'ram_base', 'ram_size')
    if (any(type(getattr(config, key, None)) is not int for key in fields)
            or getattr(config, 'image_kind', None) != 'firmware'
            or (config.load_address, config.image_offset, config.entry) != (0, 0, 0)
            or not isinstance(loaded, bytes) or len(loaded) != config.flash_size
            or not 0 < len(original) <= config.flash_size <= 0x02000000
            or loaded[:len(original)] != original
            or find_dmd5000_profile(loaded) != profile
            or not 0 <= config.ram_base <= profile['completion'] <
                   config.ram_base + config.ram_size <= 0x100000000
            or layout_claimed or (immutable_limit is not None and
                (type(immutable_limit) is not int or immutable_limit <= 0
                 or find_dmd5000_profile(loaded[:immutable_limit]) != profile))
            or getattr(config, 'ram_bootstrap_profile', None) is not None
            or getattr(config, 'missing_overlays', None)
            or getattr(config, 'ram_image_size', 0)):
        return None, 'dmd5000-loaded-source-or-memory-owner-unclosed'
    conflict = owner_conflict(config, input_profile, eeprom_window, uart_windows, _PORTS)
    if conflict:
        reason = 'input-owner-conflict' if conflict == 'invalid-window' else conflict
        return None, 'dmd5000-' + reason
    property_pair, = capability(profile).properties
    return '='.join(property_pair), None


def board_revision_property(image: bytes, flash_size: int, keypad: dict | None,
                            *, bus_qualified: bool):
    """Qualify the linked revision reader against an independent bus proof."""
    if keypad is None or not bus_qualified or flash_size <= 0:
        return None
    profile = find_dmd5000_profile(image)
    if profile is None:
        return None
    facts = facts_for(image)
    reader = facts.thumb_call_target(profile['entry'] + 28)
    body = _REVISION_READER.match(facts, reader) if reader is not None else None
    return ('board-revision=300075c:60'
            if body is not None and body.values[2] == 0x03000750 else None)
