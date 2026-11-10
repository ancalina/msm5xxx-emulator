"""SBI capability requirements, resource ownership and native projection."""
from types import SimpleNamespace
from ...facts import source_prefix
from ...capabilities import (Capability, CapabilityPredicate, CapabilityRegistry, Decision, Evidence, ResourceClaim)
from .protocol import BASE, APERTURE, compatibility_events
from .bootstrap import find_bootstraps, bootstrap_layout_at

def bootstrap_property(config, *, original=None, loaded=None):
    """Project the SBI contract, binding actual loader bytes when supplied."""
    from .raw import (bootstrap_profile_matches, qemu_sbi_raw_input_property, qemu_sbi_raw_input_property_for_images,)
    profile = getattr(config, 'sbi_bootstrap_profile', None)
    bind_source = original is not None or loaded is not None
    images = ()
    if bind_source:
        size = getattr(config, 'flash_size', None)
        if (type(size) is not int or size <= 0 or not isinstance(original, bytes) or not isinstance(loaded, bytes)):
            return None, 'sbi-source-unavailable'
        images = (source_prefix(original, size), source_prefix(loaded, size))
    legacy = (getattr(config, 'chipset', None) == 'MSM5000' and getattr(config, 'board_adc_reader_address', None) is not None)
    legacy_reject = None
    if legacy:
        if not bind_source:
            return 'sbi=on', None
        from .adc import board_adc_reader_at
        entry = config.board_adc_reader_address
        if (type(entry) is int and entry >= 0 and not entry & 1 and all(board_adc_reader_at(image, entry) for image in images)):
            return 'sbi=on', None
        legacy_reject = 'sbi-adc-source-unclosed'
    if profile is None:
        return None, legacy_reject
    if not isinstance(profile, dict):
        return None, 'malformed-profile'
    if (profile.get('signature') != 'thumb-sbi-bootstrap-only-v1' or profile.get('admission') != 'temporary-evidence-gated' or profile.get('accepted') is not
        True):
        return None, 'unsupported-contract'
    bootstrap, validation = compatibility_events()
    if (type(profile.get('base_address')) is not int or profile['base_address'] != BASE or profile.get('bootstrap') != bootstrap or profile.get('validation') !=
        validation):
        return None, 'malformed-contract'
    for actual, expected in zip(profile['bootstrap'] + profile['validation'], bootstrap + validation):
        if any(type(value) is not type(wanted) for value, wanted in zip(actual, expected)):
            return None, 'malformed-contract'
    entries = profile.get('entries')
    if (not isinstance(entries, list) or not entries or any(type(entry) is not int or entry < 0 or entry & 1 for entry in entries) or len(set(entries)) != len(entries)):
        return None, 'malformed-entries'
    if bind_source and not all(bootstrap_profile_matches(image, profile) for image in images):
        return None, 'sbi-bootstrap-source-unclosed'
    if bind_source:
        raw, reason = qemu_sbi_raw_input_property_for_images(config, profile.get('raw_input'), profile, images, getattr(config, 'ram_base', 0), getattr(config,
            'ram_size', 0))
    else:
        raw, reason = qemu_sbi_raw_input_property(config, profile.get('raw_input'))
    return ('sbi=on,' + raw, None) if raw else ('sbi=on,sbi-bootstrap-only=on', reason)

def repeat_property(image, config, *, selected=None):
    """Bind a repeated bootstrap to its proved byte-write site and ARM stage."""
    size = getattr(config, 'flash_size', None)
    if (type(getattr(config, 'load_address', None)) is not int or config.load_address != 0 or type(size) is not int or not 0 < size <= 0x02000000 or (selected
        if selected is not None else bootstrap_property(config)[0]) != 'sbi=on,sbi-bootstrap-only=on'):
        return None
    profile = getattr(config, 'sbi_bootstrap_profile', None)
    entries = profile.get('entries') if isinstance(profile, dict) else None
    if not isinstance(entries, list) or len(entries) != 1:
        return None
    entry = entries[0]
    source = source_prefix(image, size)
    if (bootstrap_layout_at(source, entry) != 'thumb-sbi-bootstrap-direct-literal-v1' or len(find_bootstraps(source, 'arm')) != 1):
        return None
    return f'{entry + 4:x}'

def _runtime_selection(original, loaded, config):
    """Resolve SBI properties after persistent state and loader seeds settle."""
    selected, reason = bootstrap_property(config, original=original, loaded=loaded)
    if selected is None:
        return None, reason, None
    first = repeat_property(original, config, selected=selected)
    repeat = first if first == repeat_property(loaded, config, selected=selected) else None
    return selected, reason, repeat

def _sbi_decision(context):
    selected, reason, repeat = _runtime_selection(context.original, context.loaded, context.config)
    if selected is None:
        return Decision('missing', reason=reason)
    profile = getattr(context.config, 'sbi_bootstrap_profile', None)
    legacy = selected == 'sbi=on'
    entries = ((context.config.board_adc_reader_address,) if legacy else tuple(profile['entries']))
    evidence = [Evidence('sbi-source-protocol', ('adc-reader' if legacy else 'bootstrap', BASE), entries)]
    properties = [tuple(field.split('=', 1)) for field in selected.split(',')]
    if 'sbi-raw-input-profile' in dict(properties):
        raw = profile['raw_input']
        evidence.append(Evidence('sbi-raw-data-path', (raw['read_pc'], raw['source_selector'], raw['selector_value']), (raw['entry'], raw['read_pc']), 'linkage'))
    if repeat is not None:
        properties.append(('sbi-bootstrap-repeat', repeat))
        evidence.append(Evidence('sbi-repeated-bootstrap', repeat, (int(repeat, 16),)))
    capability = Capability('sbi', tuple(item.name for item in evidence), tuple(evidence), properties=tuple(properties), claims=(ResourceClaim('address', 'sbi',
        *APERTURE),))
    return Decision('accepted', capability=capability, reason=reason)

_SBI_REGISTRY = CapabilityRegistry()
_SBI_REGISTRY.register(CapabilityPredicate('sbi', (), _sbi_decision))

def sbi_plan(original, loaded, config):
    """Resolve source-bound SBI mode, parameters and native aperture ownership."""
    return _SBI_REGISTRY.resolve(SimpleNamespace(original=original, loaded=loaded, config=config))

def runtime_properties(original, loaded, config):
    resolution = sbi_plan(original, loaded, config)
    properties = dict(resolution.plan.properties)
    reason = resolution.decisions[0].reason
    repeat = properties.pop('sbi-bootstrap-repeat', None)
    selected = ','.join(f'{name}={value}' for name, value in properties.items()) or None
    return selected, reason, repeat

def adc_properties(config):
    values = []
    value = config.board_adc_value
    if type(value) is int and 0 <= value <= 0xff:
        values.append(f'board-adc-value={value}')
    profile = config.dc0_board_adc_profile
    raw = profile.get('response_raw') if isinstance(profile, dict) and profile.get('accepted') is True else value
    if type(raw) is int and 0 <= raw <= 0xff:
        values.append(f'dc0-board-adc-value={raw}')
    return ','.join(values)

def runtime_fragment(original, loaded, config):
    selected, reason, repeat = runtime_properties(original, loaded, config)
    fragment = ',' + selected if selected is not None else ''
    notes = []
    if selected is not None and repeat is not None:
        fragment += f',sbi-bootstrap-repeat={repeat}'
        notes.append('QEMU source-closed repeated SBI bootstrap enabled at its write PC; ' 'full revalidation required, later general SBI transfers unqualified')
    if reason is not None:
        fallback = 'bootstrap-only retained' if selected else 'native fallback retained'
        notes.append(f'QEMU SBI bridge rejected: {reason}; {fallback}')
    return fragment, tuple(notes)
