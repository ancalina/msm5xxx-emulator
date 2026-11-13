"""Compose independently proven peripherals around a word NAND controller."""
from __future__ import annotations

from msm5xxx_emulator.detection.capabilities import (
    Capability, Decision, Evidence, resolve_proposals,
)
from msm5xxx_emulator.detection.facts import facts_for
from .boot_nand_word_windows import find_word_windows
from .boot_nand_projection import word_claims

REQUIRES = {
    'find_signal_memory': ('external_bus.signal_memory', 'find_signal_memory'),
    'find_indexed20': ('display.indexed20_writer', 'find_indexed20'),
    'find_bridge20': ('external_bus.bridge20', 'find_bridge20'),
}


def _empty():
    return resolve_proposals(()).plan


def _windows(profile, original):
    if profile.get('selection_kind') == 'fixed-row':
        return {'windows': profile.get('control_windows', []),
                'evidence': profile.get('control_evidence', [])}
    source, size = profile['stage_source'], profile['stage_size']
    stage = facts_for(original[source:source + size])
    vectors = stage.vectors()
    if not vectors:
        return None
    reset = stage.function(vectors[0][1], budget=2048)
    upload = find_signal_memory(original, code_limit=0x1000000)
    windows = find_word_windows(original, source, size, reset, upload)
    if not windows or not profile.get('control_windows') or not profile.get('control_evidence'):
        return None
    return {'windows': [*windows['windows'], *profile['control_windows']],
            'evidence': [*windows['evidence'], *profile['control_evidence']]}


def _ranges(windows):
    if not isinstance(windows, (list, tuple)) or len(windows) > 32:
        return None
    ranges = []
    for window in windows:
        if not isinstance(window, dict):
            return None
        base, length = window.get('base'), window.get('length')
        if (type(base) is not int or type(length) is not int
                or base <= 0 or length <= 0 or length > 0x100000
                or (base | length) & 0xfff or base + length > 0x100000000):
            return None
        if any(start <= base and base + length <= end for start, end in
               ((0x64000000, 0x64001000), (0x80000000, 0x80010000))):
            continue
        reserved = ((0, 0x04000000), (0xffff0000, 0x100000000),
                    (0x64000000, 0x64001000), (0x80000000, 0x80010000),
                    (0x20000000, 0x20000008), (0x20040000, 0x20040020),
                    (0x20080000, 0x20080020))
        if any(base < end and start < base + length for start, end in reserved):
            return None
        ranges.append((base, base + length))
    merged = []
    for start, end in sorted(set(ranges)):
        if merged and start < merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    if len(merged) > 16 or any(end - start > 0x100000 for start, end in merged):
        return None
    return tuple(merged)


def _spans(profiles, original, loaded):
    spans = set()
    for profile in profiles:
        evidence = profile.get('evidence')
        if not isinstance(evidence, (tuple, list)):
            return None
        for item in evidence:
            if not isinstance(item, dict):
                return None
            for span in (item.get('span'), *item.get('extra_spans', ())):
                if (not isinstance(span, (tuple, list)) or len(span) != 2
                        or any(type(value) is not int for value in span)):
                    return None
                start, length = span
                if (not 0 <= start < start + length <= min(len(original), len(loaded))
                        or original[start:start + length] != loaded[start:start + length]):
                    return None
                spans.add((start, length))
    return tuple(sorted(spans)) if spans else None


def machine_plan(original, loaded, config, profile):
    """Keep controller geometry separate from optional board and LCD claims."""
    size = getattr(config, 'file_size', 0)
    main = profile.get('main_size')
    identity = profile.get('identity_status')
    if (type(main) is not int or main not in (0x04000000, 0x08000000)
            or size != len(original) or size != main + main // 32
            or type(identity) is not int or not 0 < identity <= 0x7fffffff
            or identity & 0x7fff):
        return _empty()
    windows = _windows(profile, original)
    if not isinstance(windows, dict):
        return _empty()
    ranges = _ranges(windows.get('windows'))
    if ranges is None or ranges and not windows.get('evidence'):
        return _empty()
    panel = find_indexed20(original, profile)
    bridge = find_bridge20(original) if panel else None
    if panel and not panel.get('evidence'):
        return _empty()
    if bridge and not bridge.get('evidence'):
        return _empty()
    data_port = panel.get('data_port') if panel else 0
    lcd_identity = bridge.get('controller_id') if bridge else 0
    if panel and (panel.get('command_port') != 0x20000000
                  or data_port not in (0x20040000, 0x20080000)):
        return _empty()
    if (type(lcd_identity) is not int
            or (lcd_identity != 0x7068 if bridge else lcd_identity != 0)
            or lcd_identity not in (0, 0x7068)
            or lcd_identity and not panel):
        return _empty()
    peripherals = (1 if panel else 0) | (2 if profile.get('uart_evidence') else 0)
    if (profile.get('input_address'), profile.get('input_value')) == (0x48000050, 31):
        peripherals |= 4
    profiles = [profile, windows]
    if peripherals & 2:
        profiles.append({'evidence': profile['uart_evidence']})
    if panel:
        profiles.append(panel)
    if bridge:
        profiles.append(bridge)
    spans = _spans(profiles, original, loaded)
    if spans is None:
        return _empty()
    parameters = (('cpu', 'arm926,reset-hivecs=on'), ('high_code_size', 0x2000),
                  ('raw_size', size), ('main_size', main), ('word_interface', True),
                  ('identity_status', identity), ('peripherals', peripherals),
                  ('lcd_data_port', data_port),
                  ('lcd_identity', lcd_identity),
                  ('control_windows', ranges))
    properties = (('bootstrap-nand-main-size', main),
                  ('bootstrap-nand-word-interface', 1),
                  ('bootstrap-nand-id-status', identity),
                  ('bootstrap-nand-word-peripherals', peripherals))
    if panel:
        properties += (('bootstrap-nand-lcd-data-port', data_port),)
        if lcd_identity:
            properties += (('bootstrap-nand-lcd-id', lcd_identity),)
    if ranges:
        value = ':'.join(f'{value:x}' for start, end in ranges
                         for value in (start, end - start))
        properties += (('bootstrap-nand-control-windows', value),)
    evidence = Evidence('high-linked-nand-bootstrap',
        (main, identity, peripherals, lcd_identity,
         profile['stage_source'], profile['stage_size']),
        tuple(start for start, _ in spans), 'linkage')
    capability = Capability('high-linked-nand-bootstrap', (evidence.name,), (evidence,),
        properties=properties, parameters=parameters,
        claims=word_claims(ranges, peripherals, data_port))
    return resolve_proposals((Decision('accepted', capability=capability),)).plan
