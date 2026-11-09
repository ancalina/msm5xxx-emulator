"""Descriptor contact evidence, captured GPIO parameters and projection."""
from types import SimpleNamespace
from ...capabilities import (Capability, CapabilityPredicate, CapabilityRegistry,
                             Decision, Evidence, ResourceClaim)
from .rules import indirect_scanner_at
from .clock import periodic_caller


def _entries(image):
    cursor = 0
    while (cursor := image.find(b'\x40\x6a\x00\x88', cursor)) >= 0:
        entry = cursor - 4
        cursor += 2
        if entry >= 0 and not entry & 1:
            yield entry


def find_inputs(image, notes=None):
    found = set()
    for entry in _entries(image):
        profile, reason = indirect_scanner_at(image, entry)
        if profile is not None:
            found.add(profile)
        elif reason and notes is not None:
            notes.append(f'board-status scanner rejected at {entry:#x}: {reason}')
    return tuple(sorted(found, key=lambda p: (p.address, p.mask, p.default)))


def property_value(profile):
    return f'board-status-input={profile.address:x}:{profile.mask:x}:{profile.default:x}'


def matrix_status_matches(image, owner, gates, read_site):
    if owner is None:
        return True
    entry = gates.get('status_entry')
    if type(entry) is not int or entry + 6 != read_site:
        return False
    proven, _ = indirect_scanner_at(image, entry)
    return proven is not None and owner == proven


def _contact_decision(context):
    owner = getattr(context.config, 'board_status_input', None)
    if owner is None:
        return Decision('missing')
    for cursor in _entries(context.image):
        proven, _ = indirect_scanner_at(context.image, cursor)
        if proven == owner:
            evidence = Evidence('contact-source-gate', (owner.address, owner.mask, owner.default),
                                (cursor, cursor + 6), 'linkage')
            return Capability('descriptor-display-contact', (evidence.name,), (evidence,),
                              properties=(('board-status-input', property_value(owner).split('=', 1)[1]),),
                              claims=(ResourceClaim('gpio', 'board-contact', owner.address,
                                                    owner.address + 2, mask=owner.mask),))
    return Decision('missing', reason='contact-source-unclosed')


_CONTACT_RULES = CapabilityRegistry()
_CONTACT_RULES.register(CapabilityPredicate('descriptor-display-contact', (), _contact_decision))


def machine_plan(image, config):
    return _CONTACT_RULES.resolve(SimpleNamespace(image=image, config=config))
