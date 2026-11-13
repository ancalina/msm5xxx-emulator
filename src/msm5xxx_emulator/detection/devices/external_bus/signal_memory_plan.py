"""Source-guarded projection of firmware upload apertures to machine memory."""
from __future__ import annotations

from msm5xxx_emulator.detection.capabilities import (
    Capability, Decision, Evidence, MachinePlan, ResourceClaim, resolve_proposals,
)
from .signal_memory import find_signal_memory
from .observations.windows import detect_external_cs0a

REQUIRES = {
    'project_bootstrap': ('storage.boot_nand_projection', 'project'),
}


_CAPABILITY = 'source-signal-memory'
_PAGE = 0x1000
_MAX_RANGE = 0x100000
_ADDRESS_LIMIT = 1 << 32


def _config_supported(config):
    return (
        getattr(config, 'image_kind', None) == 'firmware'
        and getattr(config, 'load_address', None) == 0
        and getattr(config, 'image_offset', None) == 0
        and getattr(config, 'entry', None) == 0
        and type(getattr(config, 'flash_size', None)) is int
        and config.flash_size > 0
    )


def _ram_supported(config, *, word_bootstrap):
    base, size = getattr(config, 'ram_base', None), getattr(config, 'ram_size', None)
    if type(base) is not int or type(size) is not int or size <= 0:
        return False
    if word_bootstrap:
        return base == 0x01000000 and size in (0x00800000, 0x01000000)
    return 0x10000000 <= base < base + size <= 0x20000000


def _word_bootstrap(plan):
    if not isinstance(plan, MachinePlan):
        return None
    candidates = [item for item in plan.capabilities
                  if item.name == 'high-linked-nand-bootstrap'
                  and dict(item.parameters).get('word_interface') is True
                  and ('bootstrap-nand-word-interface', 1) in item.properties]
    if len(candidates) != 1:
        return None
    capability = candidates[0]
    params = dict(capability.parameters)
    if (params.get('cpu') != 'arm926,reset-hivecs=on'
            or type(params.get('main_size')) is not int
            or params['main_size'] not in (0x04000000, 0x08000000)
            or type(params.get('raw_size')) is not int
            or type(params.get('high_code_size')) is not int
            or params['high_code_size'] != 0x2000
            or not capability.claims):
        return None
    try:
        if project_bootstrap(plan) is None:
            return None
    except (TypeError, ValueError):
        return None
    occupied = []
    for claim in capability.claims:
        if claim.kind == 'address':
            occupied.append((claim.start, claim.end))
    return tuple(occupied) if occupied else None


def _ordinary_storage_clear(config):
    names = ('missing_overlays', 'ram_bootstrap_profile', 'native_nand_profile',
             'nand_image', 'nand_enabled', 'secondary_flash_image',
             'secondary_flash_address', 'upper_flash_image', 'upper_flash_address')
    return not any(getattr(config, name, None) for name in names)


def _source_spans(profile):
    evidence = profile.get('evidence')
    if not isinstance(evidence, (tuple, list)) or not evidence:
        return None
    spans = []
    for item in evidence:
        if not isinstance(item, dict):
            return None
        for span in (item.get('span'), *item.get('extra_spans', ())):
            if (not isinstance(span, (tuple, list)) or len(span) != 2
                    or type(span[0]) is not int or type(span[1]) is not int
                    or span[0] < 0 or span[1] <= 0):
                return None
            spans.append((span[0], span[1]))
    return tuple(sorted(set(spans))) if spans else None


def _ordinary_reset_gate(image):
    profile, _ = detect_external_cs0a(image)
    if not isinstance(profile, dict):
        return None
    sites = profile.get('sites')
    if not isinstance(sites, (list, tuple)):
        return None
    reset_writes = set()
    for site in sites:
        if (isinstance(site, dict) and site.get('kind') == 'literal-access'
                and site.get('operation') == 'write'
                and isinstance(site.get('span'), (list, tuple))
                and isinstance(site.get('extra_spans'), (list, tuple))):
            reset_writes.add(site.get('address'))
    if not {0x0A0000A0, 0x0A0000B0} <= reset_writes:
        return None
    spans = _source_spans({'evidence': [site for site in sites
        if isinstance(site, dict) and site.get('kind') == 'literal-access'
        and site.get('operation') == 'write'
        and site.get('address') in (0x0A0000A0, 0x0A0000B0)]})
    return spans


def _normalize_ranges(ranges):
    if not isinstance(ranges, (list, tuple)) or not ranges:
        return None
    result = []
    for item in ranges:
        if not isinstance(item, dict):
            return None
        base, length = item.get('base'), item.get('length')
        if (type(base) is not int or type(length) is not int or base <= 0
                or length <= 0 or base % _PAGE or length % _PAGE
                or length > _MAX_RANGE or base + length > _ADDRESS_LIMIT):
            return None
        result.append((base, base + length))
    result.sort()
    if (len(result) > 8
            or any(left[1] > right[0] for left, right in zip(result, result[1:]))):
        return None
    return tuple(result)


def _subtract(ranges, occupied):
    remaining = []
    for start, end in ranges:
        pieces = [(start, end)]
        for cut_start, cut_end in occupied:
            next_pieces = []
            for lo, hi in pieces:
                if cut_end <= lo or hi <= cut_start:
                    next_pieces.append((lo, hi))
                    continue
                if lo < cut_start:
                    next_pieces.append((lo, cut_start))
                if cut_end < hi:
                    next_pieces.append((cut_end, hi))
            pieces = next_pieces
        remaining.extend(pieces)
    remaining.sort()
    if (not 1 <= len(remaining) <= 8
            or any(lo % _PAGE or (hi - lo) % _PAGE or hi - lo > _MAX_RANGE
                   for lo, hi in remaining)
            or any(left[1] > right[0]
                   for left, right in zip(remaining, remaining[1:]))):
        return None
    return tuple(remaining)


def _format(ranges):
    return ':'.join(f'{base:x}:{end - base:x}' for base, end in ranges)


def machine_plan(original: bytes, loaded: bytes, config,
                 bootstrap_plan: MachinePlan | None = None) -> MachinePlan:
    """Plan only code-proven, uploaded memory ranges outside existing claims."""
    if (not isinstance(original, bytes) or not isinstance(loaded, bytes)
            or len(original) != len(loaded) or not _config_supported(config)):
        return resolve_proposals(()).plan

    occupied = _word_bootstrap(bootstrap_plan)
    if not _ram_supported(config, word_bootstrap=occupied is not None):
        return resolve_proposals(()).plan
    if occupied is None:
        reset_spans = _ordinary_reset_gate(original)
        if reset_spans is None or not _ordinary_storage_clear(config):
            return resolve_proposals(()).plan
        source_kind = 'reset-chip-select-initializer'
    else:
        reset_spans = ()
        source_kind = 'word-bootstrap-claims'

    code_limit = min(len(original), config.flash_size)
    profile = find_signal_memory(original, code_limit=code_limit)
    if not isinstance(profile, dict) or profile.get('version') != 1:
        return resolve_proposals(()).plan
    ranges = _normalize_ranges(profile.get('ranges'))
    spans = _source_spans(profile)
    if ranges is None or spans is None:
        return resolve_proposals(()).plan
    spans = tuple(sorted(set((*spans, *reset_spans))))
    if any(start + length > len(original) or original[start:start + length] != loaded[start:start + length]
           for start, length in spans):
        return resolve_proposals(()).plan
    if occupied is not None:
        ranges = _subtract(ranges, occupied)
        if ranges is None:
            return resolve_proposals(()).plan

    locations = tuple(sorted({start for start, _ in spans}))
    evidence = Evidence(_CAPABILITY, (source_kind, ranges, spans), locations, 'linkage')
    claims = tuple(ResourceClaim('address', _CAPABILITY, start, end)
                   for start, end in ranges)
    capability = Capability(_CAPABILITY, (_CAPABILITY,), (evidence,),
        properties=(('signal-memory', _format(ranges)),), claims=claims,
        parameters=(('ranges', ranges), ('source_kind', source_kind)))
    return resolve_proposals((Decision('accepted', capability=capability),)).plan


def project(plan: MachinePlan) -> str | None:
    """Validate the typed signal-memory capability and render its machine property."""
    choices = [item for item in plan.capabilities if item.name == _CAPABILITY]
    if not choices:
        return None
    if len(choices) != 1:
        raise ValueError('ambiguous signal-memory plan')
    capability = choices[0]
    parameters = dict(capability.parameters)
    ranges = parameters.get('ranges')
    source_kind = parameters.get('source_kind')
    if source_kind not in ('reset-chip-select-initializer', 'word-bootstrap-claims'):
        raise ValueError('unsupported signal-memory source')
    normalized = _normalize_ranges(
        [{'base': pair[0], 'length': pair[1] - pair[0]}
         for pair in ranges] if isinstance(ranges, (tuple, list))
        and all(isinstance(pair, (tuple, list)) and len(pair) == 2
                and type(pair[0]) is int and type(pair[1]) is int
                for pair in ranges) else None)
    expected_claims = (() if normalized is None else tuple(
        ResourceClaim('address', _CAPABILITY, lo, hi) for lo, hi in normalized))
    expected_value = None if normalized is None else _format(normalized)
    evidence_value = capability.evidence[0].value if capability.evidence else None
    evidence_spans = (evidence_value[2] if isinstance(evidence_value, tuple)
                      and len(evidence_value) == 3 else None)
    spans_valid = (isinstance(evidence_spans, tuple)
        and all(isinstance(span, tuple) and len(span) == 2
                and type(span[0]) is int and type(span[1]) is int
                and span[0] >= 0 and span[1] > 0 for span in evidence_spans)
        and tuple(sorted(set(evidence_spans))) == evidence_spans)
    if (normalized is None or len(normalized) > 8
            or set(parameters) != {'ranges', 'source_kind'}
            or capability.properties != (('signal-memory', expected_value),)
            or capability.claims != expected_claims
            or capability.required_evidence != (_CAPABILITY,)
            or len(capability.evidence) != 1
            or capability.evidence[0].name != _CAPABILITY
            or not capability.evidence[0].locations
            or not spans_valid
            or evidence_value[:2] != (source_kind, normalized)
            or capability.evidence[0].locations != tuple(sorted({span[0]
                                                                  for span in evidence_spans}))
            or plan.properties != capability.properties
            or plan.claims != capability.claims):
        raise ValueError('invalid signal-memory plan')
    return f'signal-memory={expected_value}'
