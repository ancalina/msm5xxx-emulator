"""Plan source-linked display writers and their loaded-image ownership."""
from types import SimpleNamespace
from ...capabilities import Capability, CapabilityPredicate, CapabilityRegistry, Evidence, ResourceClaim
from .b0_page_writer import (has_paired_page_writer, has_byte_paired_page_writer,
    has_separate_mono_page_writer, has_offset_mono_page_writer)
from .binary_window_writer import has_binary_window_writer
from .packed_window2_writer import has_packed_window2_writer
from .reverse565_writer import find_reverse565_writer
from .row565_writer import has_row565_writer
from .source_cursor_writer import find_source_packed_cursor
from .source_packed12_writer import find_source_packed12


def _decision(ctx):
    original, loaded, cfg = ctx.original, ctx.loaded, ctx.config
    if not isinstance(original, bytes) or not isinstance(loaded, bytes):
        return None
    packed2 = has_packed_window2_writer(original)
    layout = (getattr(cfg, 'image_kind', None) == 'firmware'
              and (getattr(cfg, 'load_address', None), getattr(cfg, 'image_offset', None),
                   getattr(cfg, 'entry', None)) == (0, 0, 0)
              and not getattr(cfg, 'missing_overlays', None)
              and getattr(cfg, 'ram_bootstrap_profile', None) is None)
    cursor = bool(layout and len(original) >= 0x10000 and len(loaded) >= 0x10000
                  and original[:0x10000] == loaded[:0x10000]
                  and find_source_packed_cursor(original) is not None)
    page = None
    if layout and len(original) >= 0x80000 and len(loaded) >= 0x80000 and original[:0x80000] == loaded[:0x80000]:
        for name, finder in (('paired', has_paired_page_writer), ('byte-paired', has_byte_paired_page_writer),
                             ('mono', has_separate_mono_page_writer), ('offset-mono', has_offset_mono_page_writer),
                             ('row565', has_row565_writer), ('binary', has_binary_window_writer)):
            if finder(original):
                page = name
                break
        if page is None:
            reverse = find_reverse565_writer(original)
            if reverse is not None and reverse == find_reverse565_writer(loaded):
                _, source, length, thunk, color, _ = reverse
                end = max(source + length, thunk + 12, color + 0x100)
                if original[:end] == loaded[:end]:
                    page = 'reverse565'
            if page is None:
                packed = find_source_packed12(original)
                if packed is not None and packed == find_source_packed12(loaded):
                    _, source, length, init, writer, _ = packed
                    end = max(source + length, init + 0x48, writer + 0xb0)
                    if original[:end] == loaded[:end]:
                        page = 'packed12'
        dimensions = {'paired': (128, 128), 'byte-paired': (120, 128), 'mono': (128, 64),
                      'offset-mono': (128, 64), 'row565': (128, 160), 'binary': (120, 143),
                      'reverse565': (120, 133), 'packed12': (128, 128)}
        if page and getattr(cfg, 'display_geometry_source', 'external-config') != 'auto-default' and (cfg.width, cfg.height) != dimensions[page]:
            page = None
    if not (packed2 or cursor or page):
        return None
    evidence = Evidence('display-writer', (packed2, cursor, page), (0, min(len(original), 0x80000)), 'linkage')
    ports = {
        'paired': ((0x02000000, 2), (0x02000002, 2)),
        'byte-paired': ((0x02000000, 1), (0x02000002, 1)),
        'mono': ((0x02000000, 1), (0x02200002, 1)),
        'offset-mono': ((0x02000000, 1), (0x02000002, 1)),
        'row565': ((0x02000000, 1), (0x02000002, 1)),
        'binary': ((0x02000004, 1), (0x02000006, 1)),
        'reverse565': ((0x02000000, 1), (0x02000004, 1)),
        'packed12': ((0x02000040, 1), (0x02000042, 1)),
    }
    selected = list(ports.get(page, ()))
    if packed2:
        selected.extend(((0x02000000, 1), (0x02000004, 1)))
    if cursor:
        selected.extend(((0x02000000, 2), (0x02000002, 2)))
    ranges = []
    for address, width in sorted(selected):
        end = address + width
        if ranges and address <= ranges[-1][1]:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end))
        else:
            ranges.append((address, end))
    return Capability('source-display-writer', (evidence.name,), (evidence,),
        parameters=(('packed2', packed2), ('cursor', cursor), ('page', page)),
        claims=tuple(ResourceClaim('address', 'source-display-writer', start, end)
                     for start, end in ranges))

_RULES = CapabilityRegistry()
_RULES.register(CapabilityPredicate('source-display-writer', (), _decision))

def machine_plan(original, loaded, config):
    return _RULES.resolve(SimpleNamespace(original=original, loaded=loaded, config=config)).plan
