"""Admit the source-linked periodic A80 interrupt controller."""
from msm5xxx_emulator.detection.capabilities import (
    Capability, Decision, Evidence, ResourceClaim, resolve_proposals,
)
from .a80_timer import find_a80_timer

_NAME = 'source-a80-periodic-controller'
_PARAMETERS = {
    'status': 0x03000A80, 'enable': 0x03000A94,
    'upper_status': 0x03000A84, 'upper_enable': 0x03000A98,
    'arm': 0x030007A0, 'arm_value': 2, 'mask': 0x200,
    'period_ns': 5_000_000,
    'clock_control': 0x030007AC, 'clock_mask': 0x33,
    'clock_value': 3, 'reload0': 0x030007B0,
    'reload1': 0x030007B4, 'reload_value': 0x80,
}
_PROPERTIES = (('legacy-a80-timer', True),)
_CLAIMS = (
    ResourceClaim('address', _NAME, 0x03000A80, 0x03000AA0, phase='runtime'),
    ResourceClaim('address', _NAME, 0x030007A0, 0x030007B8, phase='runtime'),
)


def machine_plan(original, loaded, config):
    empty = resolve_proposals(()).plan
    if (not isinstance(original, bytes) or not isinstance(loaded, bytes)
            or len(original) != len(loaded)
            or getattr(config, 'file_size', None) != len(original)
            or getattr(config, 'rex_irq_mask', 0)
            or getattr(config, 'rex_basic_irq_profile', None) is not None
            or any(getattr(config, key, None) is not None for key in (
                'rex_irq_status_address', 'rex_irq_enable_address',
                'rex_irq_arm_address'))):
        return empty
    profile = find_a80_timer(original, config)
    if (not isinstance(profile, dict) or profile.get('parameters') != _PARAMETERS
            or any(type(value) is not int for value in profile['parameters'].values())):
        return empty
    spans = profile.get('evidence_spans')
    if not isinstance(spans, (tuple, list)) or not spans:
        return empty
    locations = []
    for span in spans:
        if (not isinstance(span, (tuple, list)) or len(span) != 2
                or any(type(value) is not int for value in span)):
            return empty
        start, size = span
        if (not 0 <= start < start + size <= len(original)
                or original[start:start + size] != loaded[start:start + size]):
            return empty
        locations.append(start)
    evidence = Evidence(_NAME, tuple(sorted(_PARAMETERS.items())),
                        tuple(sorted(set(locations))), 'linkage')
    capability = Capability(_NAME, (evidence.name,), (evidence,),
        properties=_PROPERTIES, claims=_CLAIMS,
        parameters=tuple(sorted(_PARAMETERS.items())) + (('raw_size', len(original)),))
    return resolve_proposals((Decision('accepted', capability=capability),)).plan


def machine_properties(plan):
    capabilities = [item for item in plan.capabilities if item.name == _NAME]
    if len(capabilities) != 1:
        return ''
    capability = capabilities[0]
    parameters = dict(capability.parameters)
    raw_size = parameters.pop('raw_size', None)
    if (parameters != _PARAMETERS or any(type(value) is not int for value in parameters.values())
            or type(raw_size) is not int or raw_size <= 0
            or capability.properties != _PROPERTIES or capability.claims != _CLAIMS):
        return ''
    return ',legacy-a80-timer=on'
