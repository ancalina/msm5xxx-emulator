"""Source-bound machine ownership for the cached revision register."""
from __future__ import annotations

from msm5xxx_emulator.detection.capabilities import (
    Capability, Decision, Evidence, ResourceClaim, resolve_proposals,
)

REQUIRES = {
    'find_cached_revision': ('boot.revision_reader', 'find_cached_revision'),
    'detect_external_cs0a': ('external_bus.observations', 'detect_external_cs0a'),
}

_REGISTER = 0x0300075c
_RAW = 0x20f5
_NORMALIZED = 0xf025
_THRESHOLD = 0xf051
_NAME = 'cached-revision-register'
_PROPERTY = 'board-revision'
_VALUE = '300075c:20f5'


def _spans(evidence):
    result = []
    if not isinstance(evidence, (tuple, list)) or not evidence:
        return None
    for item in evidence:
        if not isinstance(item, dict):
            return None
        extra = item.get('extra_spans', ())
        if not isinstance(extra, (tuple, list)):
            return None
        for span in (item.get('span'), *extra):
            if (not isinstance(span, (tuple, list)) or len(span) != 2
                    or type(span[0]) is not int or type(span[1]) is not int
                    or span[0] < 0 or span[1] <= 0):
                return None
            result.append((span[0], span[1]))
    return tuple(dict.fromkeys(result)) if result else None


def _cs0a_sources(profile):
    if not isinstance(profile, dict) or not isinstance(profile.get('sites'), list):
        return None
    required = {0x0a0000a0, 0x0a0000b0}
    found = {address: [] for address in required}
    for site in profile['sites']:
        if (not isinstance(site, dict) or site.get('kind') != 'literal-access'
                or site.get('operation') != 'write'
                or site.get('address') not in required):
            continue
        spans = _spans((site,))
        if spans is None or not site.get('extra_spans'):
            continue
        found[site['address']].extend(spans)
    if any(not spans for spans in found.values()):
        return None
    addresses = tuple(sorted(found))
    spans = tuple(dict.fromkeys(span for values in found.values() for span in values))
    return addresses, spans


def _sources_match(original, loaded, spans):
    limit = min(len(original), len(loaded))
    return all(start + size <= limit
               and original[start:start + size] == loaded[start:start + size]
               for start, size in spans)


def machine_plan(original: bytes, loaded: bytes, config):
    """Plan a read-only revision value only for a linked ordinary ROM image."""
    if (not isinstance(original, bytes) or not isinstance(loaded, bytes)
            or getattr(config, 'image_kind', None) != 'firmware'
            or (getattr(config, 'load_address', None),
                getattr(config, 'image_offset', None),
                getattr(config, 'entry', None)) != (0, 0, 0)
            or getattr(config, 'file_size', len(original)) != len(original)
            or getattr(config, 'board_revision_register', None) is not None
            or getattr(config, 'board_revision_value', None) is not None
            # The GPIO PMIC serial contract owns the whole MSM GPIO block natively.
            or ((getattr(config, 'external_bus', None) or {}).get('machine_properties') or {}).get(
                'experimental-contract-gpio-pmic-serial')
            or any(getattr(config, name, None) for name in (
                'missing_overlays', 'ram_bootstrap_profile', 'native_nand_profile',
                'nand_image', 'secondary_flash_image', 'secondary_flash_address',
                'upper_flash_image', 'upper_flash_address'))):
        return resolve_proposals(()).plan

    revision = find_cached_revision(original)
    if (not isinstance(revision, dict)
            or (revision.get('register'), revision.get('raw_value'),
                revision.get('revision'), revision.get('threshold'))
            != (_REGISTER, _RAW, _NORMALIZED, _THRESHOLD)):
        return resolve_proposals(()).plan
    revision_spans = _spans(revision.get('evidence'))
    if revision_spans is None or not _sources_match(original, loaded, revision_spans):
        return resolve_proposals(()).plan

    cs0a, _ = detect_external_cs0a(original)
    cs0a_proof = _cs0a_sources(cs0a)
    if cs0a_proof is None:
        return resolve_proposals(()).plan
    cs0a_addresses, cs0a_spans = cs0a_proof
    if not _sources_match(original, loaded, cs0a_spans):
        return resolve_proposals(()).plan

    reader_locations = tuple(sorted({span[0] for span in revision_spans}))
    cs0a_locations = tuple(sorted({span[0] for span in cs0a_spans}))
    evidence = (
        Evidence('cached-revision-read', (_REGISTER, _RAW, _NORMALIZED),
                 reader_locations, 'linkage'),
        Evidence('revision-feature-gate', _THRESHOLD,
                 reader_locations, 'linkage'),
        Evidence('external-cs0a-reset-topology', cs0a_addresses,
                 cs0a_locations, 'linkage'),
    )
    capability = Capability(
        _NAME,
        tuple(item.name for item in evidence),
        evidence,
        properties=((_PROPERTY, _VALUE),),
        claims=(ResourceClaim('address', _NAME, _REGISTER, _REGISTER + 2,
                              phase='runtime', semantics='read-only'),),
        parameters=(('register', _REGISTER), ('raw_value', _RAW),
                    ('revision', _NORMALIZED), ('readonly', True)),
    )
    return resolve_proposals((Decision('accepted', capability=capability),)).plan


def project(plan) -> str | None:
    """Serialize only the validated cached-revision plan contract."""
    choices = [capability for capability in plan.capabilities
               if capability.name == _NAME]
    if not choices:
        return None
    if len(choices) != 1:
        raise ValueError('ambiguous cached-revision plan')
    capability = choices[0]
    params = dict(capability.parameters)
    claims = capability.claims
    evidence = {item.name: item for item in capability.evidence}
    expected_claim = ResourceClaim('address', _NAME, _REGISTER, _REGISTER + 2,
                                   phase='runtime', semantics='read-only')
    if (capability.properties != ((_PROPERTY, _VALUE),)
            or params != {'register': _REGISTER, 'raw_value': _RAW,
                          'revision': _NORMALIZED, 'readonly': True}
            or claims != (expected_claim,)
            or set(capability.required_evidence)
            != {'cached-revision-read', 'revision-feature-gate',
                'external-cs0a-reset-topology'}
            or set(evidence) != set(capability.required_evidence)
            or any(not item.locations for item in evidence.values())
            or evidence['cached-revision-read'].value != (_REGISTER, _RAW, _NORMALIZED)
            or evidence['revision-feature-gate'].value != _THRESHOLD
            or evidence['external-cs0a-reset-topology'].value
            != (0x0a0000a0, 0x0a0000b0)):
        raise ValueError('unsupported cached-revision plan')
    return f'board-revision={_REGISTER:x}:{_RAW:x}'
