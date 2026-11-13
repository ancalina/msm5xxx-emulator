"""Plan a source-backed secondary protected-NOR command aperture."""
from __future__ import annotations

import struct
from dataclasses import dataclass

from capstone import arm as a

from msm5xxx_emulator.detection.capabilities import (
    Capability, Decision, Evidence, ResourceClaim, resolve_proposals,
)
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for, source_prefix
from msm5xxx_emulator.detection.values import SymbolicValue

from . import (protected_nor, secondary_nor_copy, secondary_protected_nor,
               secondary_protected_protocol)
from .secondary_nor_seed import find_secondary_seed
from .secondary_direct_nor import find_secondary_direct_nor


_NAME = 'source-linked-secondary-protected-nor'
_DIRECT_NAME = 'source-linked-direct-secondary-nor'
_PROPERTY_NOR = 'experimental-protected-nor'
_PROPERTY_BANK = 'protected-nor-bank'
_OBJECT_SIZE = 0xD0
_ID_OFFSET = 0xA4
_ID_WIDTH_OFFSET = 0xAC
_BEGIN_OFFSET = 0xB0
_BOUND_OFFSET = 0xB4
_ADDRESS_FLOOR = 0x10000000


@dataclass(frozen=True, slots=True)
class SecondaryProtectedNorBinding:
    machine: str
    raw_size: int
    source_offset: int | None = None
    firmware_size: int | None = None


def _u32(image: bytes, address: int) -> int:
    return struct.unpack_from('<I', image, address)[0]


def _const_int(value):
    if type(value) is int:
        return value
    if isinstance(value, SymbolicValue) and value.kind == 'const':
        return value.value
    return None


def _spans(value):
    """Collect validated end-exclusive image spans from source profiles."""
    result = set()
    if not isinstance(value, (tuple, list)):
        return None
    for item in value:
        if (not isinstance(item, (tuple, list)) or len(item) != 2
                or type(item[0]) is not int or type(item[1]) is not int
                or item[0] < 0 or item[1] <= item[0]):
            return None
        result.add((item[0], item[1]))
    return tuple(sorted(result)) if result else None


def _merge_spans(spans):
    merged = []
    for start, end in sorted(set(spans)):
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _linked_functions(candidate, facts):
    """Recollect complete owned code and literal pools used by the candidate."""
    entries = set()
    lifecycle = candidate.get('lifecycle')
    if not isinstance(lifecycle, dict):
        return None
    for key in ('selector', 'constructor', 'active_object_getter',
                'count_initializer', 'count_getter', 'reset_caller'):
        value = lifecycle.get(key)
        if type(value) is not int or value < 0 or value & 1:
            return None
        entries.add(value)
    methods = candidate.get('methods')
    if not isinstance(methods, dict) or set(methods) != {
            'read', 'program', 'erase', 'poll', 'suspend', 'resume'}:
        return None
    for pointer in methods.values():
        if type(pointer) is not int or pointer < 0 or pointer & 1:
            return None
        entries.add(pointer)
    intervals = candidate.get('protocol_intervals')
    if not isinstance(intervals, dict):
        return None
    for name in ('command_helper', 'program', 'erase', 'poll'):
        interval = intervals.get(name)
        if (not isinstance(interval, (tuple, list)) or len(interval) != 2
                or any(type(value) is not int for value in interval)
                or not 0 <= interval[0] < interval[1]):
            return None
        entries.add(interval[0])
    consumers = candidate.get('sector_prefix_consumer')
    caller = candidate.get('sector_count_caller')
    if not isinstance(consumers, dict) or not isinstance(caller, dict):
        return None
    for profile in (consumers, caller):
        entry = profile.get('entry')
        interval = profile.get('function_interval')
        if (type(entry) is not int or entry < 0 or entry & 1
                or not isinstance(interval, (tuple, list)) or len(interval) != 2
                or any(type(value) is not int for value in interval)
                or not 0 <= interval[0] < interval[1]):
            return None
        entries.add(entry)

    code_spans = set()
    for entry in sorted(entries):
        body = facts.function(CodeAddress(entry, 'thumb'), budget=2048,
                              symbolic_registers={})
        if (not body.complete or body.unresolved or body.truncated
                or not body.instructions):
            return None
        for pc in body.instructions:
            instruction = facts.decode(pc)
            if instruction is None:
                return None
            code_spans.add((pc.address, pc.address + instruction.size))
        code_spans.update((literal.pool, literal.pool + 4)
                          for literal in body.literals)
    for profile in (consumers, caller):
        interval = profile['function_interval']
        code_spans.add(tuple(interval))
    for interval in intervals.values():
        code_spans.add(tuple(interval))
    return _merge_spans(code_spans), entries


def _selector_query(candidate, facts, ram_base: int, ram_end: int):
    """Find one concrete selector cell and one R1 query buffer call argument."""
    lifecycle = candidate['lifecycle']
    selector_entry = lifecycle['selector']
    body = facts.function(CodeAddress(selector_entry, 'thumb'), budget=2048,
                          symbolic_registers={})
    if not body.complete or body.unresolved or body.truncated:
        return None
    consumer = candidate['sector_prefix_consumer']
    global_address = consumer.get('global_address')
    if type(global_address) is not int:
        return None
    cells = set()
    for access in body.symbolic_accesses:
        address = access.address
        if (access.operation == 'read' and access.width == 4
                and isinstance(address, SymbolicValue) and address.kind == 'const'
                and type(address.value) is int
                and ram_base <= address.value <= ram_end - 4
                and address.value != global_address + 8):
            cells.add(address.value)
    if len(cells) != 1:
        return None
    pointers = set()
    for call in body.call_sites:
        if call.target.isa != 'thumb':
            continue
        thunk = facts.decode(call.target)
        if (thunk is None or thunk.id != a.ARM_INS_BX or len(thunk.operands) != 1
                or thunk.operands[0].type != a.ARM_OP_REG
                or thunk.operands[0].reg != a.ARM_REG_R1):
            continue
        registers = dict(call.registers)
        pointer = _const_int(registers.get(a.ARM_REG_R1))
        if (type(pointer) is int and pointer & 1
                and ram_base <= (pointer & ~1) <= ram_end - 20):
            pointers.add(pointer & ~1)
    if len(pointers) != 1:
        return None
    cell, probe = next(iter(cells)), next(iter(pointers))
    if cell >= probe or probe + 20 > ram_end:
        return None
    return cell, probe


def _object_matches(image, candidate):
    obj = candidate.get('selected_object')
    if type(obj) is not int or obj < 0 or obj + _OBJECT_SIZE > len(image):
        return None
    count = _u32(image, obj + 4)
    if not 1 <= count <= 64 or 8 + count * 4 > _BEGIN_OFFSET:
        return None
    sectors = tuple(_u32(image, obj + 8 + 4 * index) for index in range(count))
    begin = _u32(image, obj + _BEGIN_OFFSET) * 2
    bound = _u32(image, obj + _BOUND_OFFSET) * 2
    extent = sum(sectors)
    if (_u32(image, obj + _ID_WIDTH_OFFSET) != 2
            or any(size <= 0 or size & 1 for size in sectors)
            or (candidate.get('address'), candidate.get('size'),
                tuple(candidate.get('sector_sizes', ()))) != (begin, extent, sectors)
            or bound < extent or candidate.get('bus_width') != 2):
        return None
    packed_id = _u32(image, obj + _ID_OFFSET)
    return obj, sectors, packed_id


def _candidate_spans(candidate, functions, copy_profile, probe_source,
                     query_spans=()):
    spans = set(functions[0])
    obj = candidate['selected_object']
    spans.add((obj, obj + _OBJECT_SIZE))
    for start, end in copy_profile['evidence_spans']:
        spans.add((start, end))
    spans.add((probe_source, probe_source + 20))
    spans.update(tuple(span) for span in query_spans)
    return _merge_spans(spans)


def _sources_match(original: bytes, loaded: bytes, spans) -> bool:
    if len(original) != len(loaded):
        return False
    return all(0 <= start < end <= len(original)
               and original[start:end] == loaded[start:end]
               for start, end in spans)


def _seed_source(original, loaded, base, length):
    profile = find_secondary_seed(original, base, length)
    if profile is None:
        return None, ()
    if not isinstance(profile, dict):
        raise ValueError('invalid secondary NOR source proof')
    offset = profile.get('source_offset')
    origins = profile.get('identical_source_offsets')
    spans = profile.get('evidence_spans')
    if (type(offset) is not int or offset < 0 or offset % length
            or profile.get('source_length') != length
            or not isinstance(origins, tuple) or not origins
            or any(type(origin) is not int or origin < 0 or origin % length
                   or origin + length > len(original) for origin in origins)
            or origins != tuple(sorted(set(origins))) or offset != origins[0]
            or not isinstance(spans, tuple) or not spans
            or any(not isinstance(span, tuple) or len(span) != 2
                   or any(type(value) is not int for value in span)
                   or not 0 <= span[0] < span[1] <= len(original)
                   for span in spans)):
        raise ValueError('invalid secondary NOR source range')
    guards = _merge_spans((*spans, *((origin, origin + length) for origin in origins)))
    if not _sources_match(original, loaded, guards):
        raise ValueError('loaded secondary NOR source changed')
    return offset, guards


def _no_other_storage_owner(config) -> bool:
    for name in (
        'missing_overlays', 'ram_bootstrap_profile', 'native_nand_profile',
        'guarded_nand', 'nand_image', 'nand_read_address', 'nand_write_address',
        'nand_bad_block_address', 'secondary_flash_image',
        'secondary_flash_image_offset', 'secondary_flash_address',
        'secondary_flash_read_address', 'secondary_flash_write_address',
        'upper_flash_image', 'upper_flash_address', 'primary_flash_probe_address',
    ):
        value = getattr(config, name, None)
        if value not in (None, False, 0, '', [], ()):
            return False
    return not bool(getattr(config, 'nand_enabled', False))


def _direct_plan(original, loaded):
    """Bind the older direct command driver to the same private NOR model."""
    empty = resolve_proposals(()).plan
    profile = find_secondary_direct_nor(original)
    if (not isinstance(profile, dict)
            or profile.get('signature') != 'direct-secondary-protected-nor-x16-v1'
            or profile.get('identity_queried') is not False):
        return empty
    base, length, sector = (profile.get(key) for key in
                            ('bank_base', 'bank_size', 'sector_size'))
    spans = _spans(profile.get('evidence_spans'))
    if (any(type(value) is not int for value in (base, length, sector))
            or base < _ADDRESS_FLOOR or length not in (0x400000, 0x800000)
            or base % length or base + length > 0x100000000
            or sector != 0x10000 or spans is None
            or not _sources_match(original, loaded, spans)):
        return empty
    try:
        seed_offset, seed_spans = _seed_source(original, loaded, base, length)
    except ValueError:
        return empty
    spans = _merge_spans((*spans, *seed_spans))
    locations = tuple(start for start, _ in spans)
    # This driver reads array bytes after F3; its closed command path never
    # queries an identity register. Leave the unused identity at reset zero.
    evidence = (Evidence('direct-secondary-nor-protocol',
        (base, length, sector, 0), locations, 'linkage'),)
    if seed_offset is not None:
        evidence += (Evidence('secondary-protected-nor-source',
            (seed_offset, length), tuple(sorted({seed_offset,
                *(start for start, _ in seed_spans)})), 'linkage'),)
    capability = Capability(_DIRECT_NAME, tuple(item.name for item in evidence),
        evidence,
        properties=((_PROPERTY_NOR, f'{base:x}:{length:x}:{sector:x}:f4240'),
                    (_PROPERTY_BANK, f'{base:x}:0')),
        claims=(ResourceClaim('address', _DIRECT_NAME, base, base + length,
                              phase='runtime'),),
        parameters=(('bank_base', base), ('bank_length', length),
                    ('sector_size', sector), ('packed_id', 0),
                    ('raw_size', length), ('firmware_size', len(loaded)))
                   + (() if seed_offset is None else (('seed_offset', seed_offset),)))
    return resolve_proposals((Decision('accepted', capability=capability),)).plan


def machine_plan(original: bytes, loaded: bytes, config, *, claimed: bool = False):
    """Select one volatile NOR aperture only for an ordinary, unclaimed image."""
    flash_size = getattr(config, 'flash_size', None)
    if (claimed or not isinstance(original, bytes) or not isinstance(loaded, bytes)
            or getattr(config, 'image_kind', None) != 'firmware'
            or (getattr(config, 'load_address', None),
                getattr(config, 'image_offset', None), getattr(config, 'entry', None))
            != (0, 0, 0)
            or getattr(config, 'file_size', None) != len(original)
            or type(flash_size) is not int or not 0 < flash_size <= len(original)
            or len(loaded) != flash_size
            or not _no_other_storage_owner(config)):
        return resolve_proposals(()).plan
    source_image = source_prefix(original, flash_size)
    ram_base, ram_size = getattr(config, 'ram_base', None), getattr(config, 'ram_size', None)
    if (type(ram_base) is not int or type(ram_size) is not int or ram_base < 0
            or ram_size <= 0 or ram_base + ram_size > 0x100000000):
        return resolve_proposals(()).plan
    candidate = secondary_protected_nor.find_secondary_protected_nor(
        source_image, ram_base, ram_size)
    if candidate is None:
        return _direct_plan(source_image, loaded)
    if (not isinstance(candidate, dict)
            or candidate.get('signature') != 'table-summed-secondary-protected-nor-x16-v1'
            or candidate.get('bus_width') != 2
            or candidate.get('admission') != 'candidate-awaiting-reset-copy'
            or candidate.get('lifecycle') is None
            or candidate.get('unclosed') != ['reset-copy-provenance']):
        return resolve_proposals(()).plan
    object_data = _object_matches(source_image, candidate)
    if object_data is None:
        return resolve_proposals(()).plan
    obj, sectors, packed_id = object_data
    facts = facts_for(source_image)
    functions = _linked_functions(candidate, facts)
    if functions is None:
        return resolve_proposals(()).plan
    selector_query = _selector_query(candidate, facts, ram_base, ram_base + ram_size)
    if selector_query is None:
        return resolve_proposals(()).plan
    selection_cell, probe_ram = selector_query
    required_span = (selection_cell, probe_ram + 20)
    copy_profile = secondary_nor_copy.find_copy_source(
        source_image, ram_base, ram_size, required_span, obj)
    if (not isinstance(copy_profile, dict)
            or copy_profile.get('required_span') != list(required_span)
            or copy_profile.get('expected_object') != obj
            or type(copy_profile.get('copy_source')) is not int):
        return resolve_proposals(()).plan
    copy_source = copy_profile['copy_source']
    copy_writes = copy_profile.get('copy_writes')
    if (not isinstance(copy_writes, (tuple, list)) or not any(
            isinstance(item, (tuple, list)) and len(item) == 3
            and all(type(value) is int for value in item)
            and item[0] <= selection_cell and probe_ram + 20 <= item[0] + item[1]
            and item[2] + selection_cell - item[0] == copy_source
            for item in copy_writes)):
        return resolve_proposals(()).plan
    probe_source = copy_source + probe_ram - selection_cell
    if (probe_source < 0 or probe_source + 20 > len(source_image)
            or not protected_nor._code(source_image, probe_source, 'probe')):
        return resolve_proposals(()).plan
    if not secondary_protected_protocol.packed_identity_is_read(candidate, facts, obj):
        return resolve_proposals(()).plan
    query_spans = ()
    aperture = secondary_protected_protocol.bank_window(candidate, facts, sectors)
    if aperture is None:
        query_proof = secondary_protected_protocol.selector_query_address(
            candidate, facts, probe_ram | 1, with_spans=True)
        if (not isinstance(query_proof, tuple) or len(query_proof) != 2
                or query_proof[0] != candidate.get('address')
                or not isinstance(query_proof[1], tuple)):
            return resolve_proposals(()).plan
        query_spans = query_proof[1]
        aperture = secondary_protected_protocol.bank_window(
            candidate, facts, sectors, query_pointer=probe_ram | 1)
    if aperture is None:
        return resolve_proposals(()).plan
    bank_base, bank_length, sector_size = aperture
    if (not bank_base <= candidate['address']
            or candidate['address'] + candidate['size'] > bank_base + bank_length):
        return resolve_proposals(()).plan
    spans = _candidate_spans(candidate, functions, copy_profile, probe_source,
                             query_spans)
    try:
        seed_offset, seed_spans = _seed_source(source_image, loaded, bank_base, bank_length)
    except ValueError:
        return resolve_proposals(()).plan
    spans = _merge_spans((*spans, *seed_spans))
    if not _sources_match(source_image, loaded, spans):
        return resolve_proposals(()).plan
    locations = tuple(start for start, _ in spans)
    evidence = (
        Evidence('secondary-protected-nor-layout',
                 (bank_base, bank_length, sector_size, packed_id), locations, 'linkage'),
        Evidence('secondary-protected-nor-copy',
                 (selection_cell, probe_ram, probe_source, obj), locations, 'linkage'),
    )
    if seed_offset is not None:
        evidence += (Evidence('secondary-protected-nor-source',
            (seed_offset, bank_length), tuple(sorted({seed_offset,
                *(start for start, _ in seed_spans)})), 'linkage'),)
    nor_value = f'{bank_base:x}:{bank_length:x}:{sector_size:x}:f4240'
    bank_value = f'{bank_base:x}:{packed_id:x}'
    capability = Capability(
        _NAME, tuple(item.name for item in evidence), evidence,
        properties=((_PROPERTY_NOR, nor_value), (_PROPERTY_BANK, bank_value)),
        claims=(ResourceClaim('address', _NAME, bank_base,
                              bank_base + bank_length, phase='runtime'),),
        parameters=(('bank_base', bank_base), ('bank_length', bank_length),
                    ('sector_size', sector_size), ('packed_id', packed_id),
                    ('raw_size', bank_length), ('firmware_size', len(loaded)))
                   + (() if seed_offset is None else (('seed_offset', seed_offset),)),
    )
    return resolve_proposals((Decision('accepted', capability=capability),)).plan


def project(plan) -> SecondaryProtectedNorBinding | None:
    """Serialize an admitted volatile bank without querying source bytes."""
    choices = [capability for capability in plan.capabilities
               if capability.name in (_NAME, _DIRECT_NAME)]
    if not choices:
        return None
    if len(choices) != 1:
        raise ValueError('ambiguous secondary protected-NOR plan')
    capability = choices[0]
    direct = capability.name == _DIRECT_NAME
    parameters = dict(capability.parameters)
    seeded = 'seed_offset' in parameters
    seed_offset = parameters.pop('seed_offset', None)
    if set(parameters) != {'bank_base', 'bank_length', 'sector_size', 'packed_id',
                           'raw_size', 'firmware_size'}:
        raise ValueError('invalid secondary protected-NOR parameters')
    base, length, sector, packed_id, raw_size, firmware_size = (
        parameters[key] for key in ('bank_base', 'bank_length', 'sector_size',
                                    'packed_id', 'raw_size', 'firmware_size'))
    if any(type(value) is not int for value in
           (base, length, sector, packed_id, raw_size, firmware_size)):
        raise ValueError('invalid secondary protected-NOR parameter types')
    nor_value = f'{base:x}:{length:x}:{sector:x}:f4240'
    bank_value = f'{base:x}:{packed_id:x}'
    expected_claim = ResourceClaim('address', capability.name, base, base + length,
                                   phase='runtime')
    expected_evidence = {'direct-secondary-nor-protocol':
                         (base, length, sector, 0)} if direct else {
        'secondary-protected-nor-layout': (base, length, sector, packed_id),
        'secondary-protected-nor-copy': None,
    }
    if seeded:
        expected_evidence['secondary-protected-nor-source'] = (seed_offset, length)
    values = {item.name: item.value for item in capability.evidence}
    if (base < _ADDRESS_FLOOR or length not in (0x400000, 0x800000)
            or base % length or base + length > 0x100000000
            or sector != 0x10000
            or not 0 <= packed_id <= 0xFFFFFFFF
            or direct and packed_id != 0
            or not 0 < firmware_size <= 0x100000000
            or raw_size != length
            or seeded and (type(seed_offset) is not int or seed_offset < 0
                           or seed_offset % length
                           or seed_offset + length > firmware_size)
            or capability.properties != ((_PROPERTY_NOR, nor_value),
                                         (_PROPERTY_BANK, bank_value))
            or capability.claims != (expected_claim,)
            or capability.required_evidence != tuple(expected_evidence)
            or set(values) != set(expected_evidence)
            or any(values.get(name) != value for name, value in
                   expected_evidence.items() if value is not None)
            or not direct and (
                not isinstance(values.get('secondary-protected-nor-copy'), tuple)
                or len(values['secondary-protected-nor-copy']) != 4)
            or seeded and (values.get('secondary-protected-nor-source')
                           != expected_evidence['secondary-protected-nor-source']
                           or not any(item.name == 'secondary-protected-nor-source'
                                      and seed_offset in item.locations
                                      for item in capability.evidence))
            or any(not item.locations for item in capability.evidence)):
        raise ValueError('unsupported secondary protected-NOR plan contract')
    machine = f',{_PROPERTY_NOR}={nor_value},{_PROPERTY_BANK}={bank_value}'
    return SecondaryProtectedNorBinding(machine, raw_size, seed_offset,
                                       firmware_size if seeded else None)
