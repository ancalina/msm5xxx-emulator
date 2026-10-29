"""Temporary source-bound SBI raw-byte consumer, without physical sensor claims."""
from __future__ import annotations

import struct

from .arm import thumb_bl_target, thumb_literal_value
from .input import (SBI_BOOTSTRAP, SBI_BOOTSTRAP_VALIDATION,
                    _sbi_bootstrap_layout_at, _sbi_literals_match, _sbi_words_match)
from .ready_poll import _THUMB_BL

_RAW = bytes.fromhex(
    'b0b50406240e0000000005042d0c000000002a200000000000003878802318433870'
    '38789f2318403870402c04d138784023184338700de0602c04d13878602318433870'
    '06e0002c04d13878202318433870ffe739780a200000000000000000000000003878'
    '8023db431840387039780a2000000000000000000b20000000000000000000008089'
    '07063f0e002d01d100000000002c05d1000000680078002800d0ffe7381cb0bd')
_RAW_CALLS = (6, 0x0E, 0x14, 0x58, 0x5C, 0x60, 0x72, 0x76, 0x7C, 0x80, 0x90)
_RAW_LITERALS = (0x18, 0x84, 0x98)
_FILTER = bytes.fromhex(
    'f0b582b082b00006000e00900d062d0e1106090e019182b000270020019000240021'
    '00910026e91f03390591e91d03310491032e30da03e0701c0606360ef8e702980000'
    '0000002d1ad00399884217db0599814209da0499814206dd20180404240c781c0706'
    '3f0e09e0009908180104090c0091019801300006000e01900ae0002d08d103998842'
    '05db20180404240c781c07063f0ecfe70198032807db00990198000000000006000e'
    '06b0f0bd002f02d1281c06b0f9e7211c381c000000000006000e06b0f1e7')
_FILTER_CALLS = (0x42, 0xA2, 0xBC)
_IRQ_SAVE = bytes.fromhex('7847000001e08ee300000fe1801080e301f021e1800000e21eff2fe1')
_IRQ_RESTORE = bytes.fromhex('7847000001e08ee300000fe18010c0e301f021e1800000e21eff2fe1')


def _shape(image: bytes, at: int, pattern: bytes, calls: tuple[int, ...],
           literals: tuple[int, ...] = ()) -> dict[int, int] | None:
    if at < 0 or at & 1 or at + len(pattern) > len(image):
        return None
    holes = {offset + byte for offset in calls for byte in range(4)}
    holes.update(offset + byte for offset in literals for byte in range(2))
    if any(image[at + i] != value for i, value in enumerate(pattern) if i not in holes):
        return None
    targets = {}
    for offset in calls:
        target = thumb_bl_target(image, at + offset)
        if target is None or target & 1 or not 0 <= target <= len(image) - 2:
            return None
        targets[offset] = target
    return targets


def _poll(image: bytes, at: int, kind: str) -> tuple[int, int] | None:
    words = {0: 0xB590, 2: 0x2732, 6: 0x8820}
    if kind == 'read-full':
        words.update({8: 0x2302, 0x0A: 0x4018, 0x0C: 0xD109,
                      0x16: 0x1C38, 0x18: 0x3F01, 0x1A: 0x2800,
                      0x1C: 0xD100, 0x1E: 0xE000, 0x20: 0xE7F1, 0x22: 0xBD90})
        offsets, length = (0x0E, 0x12), 0x24
    else:
        words.update({0x0C: 0x2804 if kind == 'busy' else 0x2801,
                      0x0E: 0xD109, 0x18: 0x1C38, 0x1A: 0x3F01,
                      0x1C: 0x2800, 0x1E: 0xD100, 0x20: 0xE000,
                      0x22: 0xE7F0, 0x24: 0xBD90})
        words.update({8: 0x2304, 0x0A: 0x4018} if kind == 'busy'
                     else {8: 0x07C0, 0x0A: 0x0FC0})
        offsets, length = (0x10, 0x14), 0x26
    if (not _sbi_words_match(image, at, words)
            or not _sbi_literals_match(image, at, ((4, 4, 0x03000780),))):
        return None
    targets = [thumb_bl_target(image, at + offset) for offset in offsets]
    if (targets[0] is None or targets[0] != targets[1]
            or targets[0] & 1
            or not _sbi_words_match(image, targets[0], {0: 0x46F7})):
        return None
    return targets[0], length


def _bus_helpers(image: bytes, calls: dict[int, int]) -> list[tuple[int, int]] | None:
    specs = (
        (0x14, {0:0x0680,2:0x0E80,4:0x2321,6:0x019B,8:0x4318,
                0x0C:0x8088,0x0E:0x46F7}, 0x0A, 1, 0x10),
        (0x58, {0:0x0600,2:0x0E00,4:0x0609,6:0x0E09,8:0x0700,
                0x0A:0x0F00,0x0C:0x0200,0x0E:0x4308,0x12:0x8188,
                0x14:0x46F7}, 0x10, 1, 0x16),
        (0x5C, {0:0x2100,4:0x7401,6:0x2101,8:0x7401,0x0A:0x46F7}, 2, 0, 0x0C),
        (0x7C, {0:0x0400,2:0x0C00,4:0x0640,6:0x0E40,8:0x0200,
                0x0A:0x2301,0x0C:0x03DB,0x0E:0x4318,0x12:0x8188,
                0x14:0x46F7}, 0x10, 1, 0x16),
    )
    intervals = []
    for key, words, literal, register, length in specs:
        at = calls[key]
        if (not _sbi_words_match(image, at, words)
                or not _sbi_literals_match(image, at, ((literal, register, 0x03000780),))):
            return None
        intervals.append((at, at + length))
    if calls[0x58] != calls[0x72] or calls[0x60] != calls[0x76]:
        return None
    delays = []
    for key, kind in ((0x0E, 'busy'), (0x60, 'write-empty'), (0x80, 'read-full')):
        result = _poll(image, calls[key], kind)
        if result is None:
            return None
        delay, length = result
        delays.append(delay)
        intervals.append((calls[key], calls[key] + length))
    if len(set(delays)) != 1:
        return None
    for key, pattern in ((6, _IRQ_SAVE), (0x90, _IRQ_RESTORE)):
        if image[calls[key]:calls[key] + len(pattern)] != pattern:
            return None
        intervals.append((calls[key], calls[key] + len(pattern)))
    intervals.append((delays[0], delays[0] + 2))
    return intervals


def _clock_pair(image: bytes, calls: dict[int, int]) -> tuple[int, int] | None:
    """Bind the exact reprogramming pair to the already closed control/IRQ helpers."""
    at = calls[0x14] - 0x44
    words = {4:0x214A,8:0x7039,0x0C:0x7021,0x0E:0x2800,0x10:0xD101,
             0x1A:0x1C01,0x1C:0x20CA,0x1E:0x7038,0x20:0x7020,
             0x22:0x2900,0x24:0xD101,0x2A:0xBD90}
    if (not _sbi_words_match(image, at, words)
            or not _sbi_literals_match(image, at, ((0x0A, 4, 0x03000780),))
            or any(thumb_bl_target(image, at + offset) != calls[target]
                   for offset, target in ((0,6),(0x12,0x90),(0x16,6),(0x26,0x90)))):
        return None
    shadow = thumb_literal_value(image, at + 6, 7)
    return (at, shadow) if shadow is not None else None


def find_sbi_raw_input_profile(image: bytes, bootstrap_profile: dict | None,
                               ram_base: int, ram_size: int) -> tuple[dict | None, str]:
    """Close one raw getter, three-sample consumer and byte cache, never a sensor identity."""
    if bootstrap_profile is None:
        return None, 'bootstrap-prerequisite-missing'
    if not isinstance(bootstrap_profile, dict):
        return None, 'malformed-bootstrap-prerequisite'
    entries = bootstrap_profile.get('entries')
    if (bootstrap_profile.get('signature') != 'thumb-sbi-bootstrap-only-v1'
            or bootstrap_profile.get('admission') != 'temporary-evidence-gated'
            or bootstrap_profile.get('accepted') is not True
            or bootstrap_profile.get('base_address') != 0x03000780
            or bootstrap_profile.get('bootstrap') != SBI_BOOTSTRAP
            or bootstrap_profile.get('validation') != SBI_BOOTSTRAP_VALIDATION
            or not isinstance(entries, list) or len(entries) != 1
            or type(entries[0]) is not int or entries[0] & 1
            or not 0 <= entries[0] <= len(image) - 2):
        return None, 'bootstrap-prerequisite-unclosed'
    if (any(type(value) is not int for row in bootstrap_profile['bootstrap'] for value in row)
            or any(type(value) is not type(expected)
                   for row, template in zip(bootstrap_profile['validation'], SBI_BOOTSTRAP_VALIDATION)
                   for value, expected in zip(row, template))):
        return None, 'malformed-bootstrap-prerequisite'
    layout = _sbi_bootstrap_layout_at(image, entries[0])
    if layout is None or layout != bootstrap_profile.get('layout'):
        return None, 'bootstrap-prerequisite-unclosed'
    if (type(ram_base) is not int or type(ram_size) is not int or ram_base < 0
            or ram_size <= 0 or ram_base + ram_size > 0x100000000):
        return None, 'invalid-ram-window'
    def in_ram(at: int | None, size: int = 1) -> bool:
        return at is not None and ram_base <= at and at + size <= ram_base + ram_size

    getters = []
    cursor = 0
    while (at := image.find(_RAW[:6], cursor)) >= 0:
        cursor = at + 1
        calls = _shape(image, at, _RAW, _RAW_CALLS, _RAW_LITERALS)
        if calls is None:
            continue
        shadow = thumb_literal_value(image, at + 0x18, 7)
        flag = thumb_literal_value(image, at + 0x98, 0)
        if (not in_ram(shadow) or not in_ram(flag, 4) or flag & 3
                or not _sbi_literals_match(image, at, ((0x84, 0, 0x03000780),))):
            continue
        intervals = _bus_helpers(image, calls)
        clock = _clock_pair(image, calls)
        if (intervals is not None and clock is not None and in_ram(clock[1])
                and clock[1] != shadow and not flag <= clock[1] < flag + 4):
            getters.append((at, calls, shadow, flag, intervals, *clock))
    if not getters:
        return None, 'raw-getter-not-closed'
    if len(getters) != 1:
        return None, 'ambiguous-raw-getters'
    raw, calls, shadow, flag, intervals, clock_entry, clock_shadow = getters[0]
    links = [(m.start(), thumb_bl_target(image, m.start()))
             for m in _THUMB_BL.finditer(image) if not m.start() & 1]
    consumers = []
    for callsite, target in links:
        if target != raw:
            continue
        filt = callsite - 0x42
        filter_calls = _shape(image, filt, _FILTER, _FILTER_CALLS)
        if (filter_calls is None or filter_calls[0x42] != raw
                or filter_calls[0xA2] != filter_calls[0xBC]):
            continue
        for cache_call, cache_target in links:
            if cache_target != filt:
                continue
            cache = cache_call - 0x0A
            if not _sbi_words_match(image, cache, {0:0xB580,4:0x7839,0x0E:0x7038,0x10:0xBD80}):
                continue
            parameter = struct.unpack_from('<H', image, cache + 6)[0]
            selector = struct.unpack_from('<H', image, cache + 8)[0]
            cache_address = thumb_literal_value(image, cache + 2, 7)
            if (parameter & 0xFF00 != 0x2200 or selector & 0xFF00 != 0x2000
                    or not in_ram(cache_address) or cache_address in (shadow, clock_shadow)
                    or any(flag <= address < flag + 4 for address in (shadow, cache_address))):
                continue
            source_selector = selector & 255
            selected = {0:0x20, 0x40:0x40, 0x60:0x60}.get(source_selector)
            if selected is not None:
                consumers.append((filt, filter_calls, cache, cache_address,
                                  source_selector, selected, parameter & 255))
    if not consumers:
        return None, 'raw-consumer-not-closed'
    if len(consumers) != 1:
        return None, 'ambiguous-raw-consumers'
    filt, filter_calls, cache, cache_address, source_selector, selected, parameter = consumers[0]
    call_links = [dict(call_pc=raw + off, target=target) for off, target in calls.items()]
    call_links += [dict(call_pc=filt + off, target=target) for off, target in filter_calls.items()]
    call_links.append(dict(call_pc=cache + 0x0A, target=filt))
    call_links += [dict(call_pc=clock_entry + offset, target=calls[target])
                   for offset, target in ((0,6),(0x12,0x90),(0x16,6),(0x26,0x90))]
    return dict(signature='thumb-sbi-raw-sample-086a-v1', admission='temporary-evidence-gated',
                accepted=True, policy='configured-virtual-raw-byte-uncalibrated',
                base_address=0x03000780, control=0x086A, request_prefix=0x0A80,
                read_command=0x8B00, selector_mask=0x60, selector_value=selected,
                source_selector=source_selector, read_pc=raw + 0x86, entry=raw, entries=[raw],
                clock_values=[0x4A,0xCA], clock_entry=clock_entry,
                clock_write_pcs=[clock_entry + 0x0C,clock_entry + 0x20],
                clock_shadow=clock_shadow,
                request_shadow=shadow, cache_address=cache_address, cache_entry=cache,
                filter_entry=filt, filter_parameter=parameter, call_links=call_links,
                code_intervals=[(raw,raw + len(_RAW)),(filt,filt + len(_FILTER)),
                                (cache,cache + 0x12),(clock_entry,clock_entry + 0x2C),*intervals]), 'accepted'
