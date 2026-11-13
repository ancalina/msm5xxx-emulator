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
from .window51_writer import find_window51
from .window43_writer import find_window43
from .dcs_window_writer import find_dcs_window
from .indexed28_writer import find_indexed28
from .indexed20_writer import find_indexed20
from .indexed44_writer import find_indexed44
from .indexed1c_writer import find_indexed1c_profile


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
    window51 = None
    indexed28 = None
    indexed44 = None
    indexed1c = None
    if (layout and len(original) >= 0x10000 and len(loaded) >= 0x10000
            and original[:0x10000] == loaded[:0x10000]):
        window51 = find_window51(original)
        dcs = find_dcs_window(original)
        if window51 is not None and dcs is not None:
            window51 = None
        elif dcs is not None:
            window51 = dcs
        elif window51 is None:
            window51 = find_window43(original)
        if window51 is not None:
            spans = [span for item in window51['evidence']
                     for span in (item['span'], *item.get('extra_spans', ()))]
            if any(not 0 <= start < start + length <= min(len(original), len(loaded))
                   or original[start:start + length] != loaded[start:start + length]
                   for start, length in spans):
                window51 = None
        if (window51 is not None
                and getattr(cfg, 'display_geometry_source', 'external-config') != 'auto-default'
                and (cfg.width, cfg.height) != (window51['width'], window51['height'])):
            window51 = None
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
    if layout and len(original) >= 0x14000 and len(loaded) >= 0x14000:
        indexed28 = find_indexed28(original) or find_indexed20(original)
        if indexed28 is not None:
            spans = [span for item in indexed28['evidence']
                     for span in (item['span'], *item.get('extra_spans', ()))]
            if (any(not 0 <= start < start + length <= min(len(original), len(loaded))
                    or original[start:start + length] != loaded[start:start + length]
                    for start, length in spans)
                    or getattr(cfg, 'display_geometry_source', 'external-config') != 'auto-default'
                    and (cfg.width, cfg.height) != (indexed28['width'], indexed28['height'])):
                indexed28 = None
        if indexed28 is not None:
            page, window51, packed2, cursor = None, None, False, False
        else:
            indexed1c = find_indexed1c_profile(original)
            if indexed1c is not None:
                spans = [span for item in indexed1c['evidence']
                         for span in (item['span'], *item.get('extra_spans', ()))]
                if (indexed1c['command_port'] != 0x1c000000
                        or indexed1c['data_port'] != 0x1c000004
                        or not spans
                        or any(not 0 <= start < start + length <= min(len(original), len(loaded))
                            or original[start:start + length] != loaded[start:start + length]
                            for start, length in spans)
                        or getattr(cfg, 'display_geometry_source', 'external-config') != 'auto-default'
                        and (cfg.width, cfg.height) != (indexed1c['width'], indexed1c['height'])):
                    indexed1c = None
                if indexed1c is not None:
                    page, window51, packed2, cursor = None, None, False, False
    ram_base, ram_size = getattr(cfg, 'ram_base', None), getattr(cfg, 'ram_size', None)
    if (layout and indexed1c is None and type(ram_base) is int and type(ram_size) is int
            and 0x10000000 <= ram_base < ram_base + ram_size <= 0x20000000):
        indexed44 = find_indexed44(original)
        if indexed44 is not None:
            spans = [span for item in indexed44['evidence']
                     for span in (item['span'], *item.get('extra_spans', ()))]
            if (not spans or indexed44['command_port'] != 0x18000000
                    or indexed44['data_port'] != 0x18000010
                    or any(not 0 <= start < start + length <= min(len(original), len(loaded))
                        or original[start:start + length] != loaded[start:start + length]
                        for start, length in spans)
                    or getattr(cfg, 'display_geometry_source', 'external-config') != 'auto-default'
                    and (cfg.width, cfg.height) != (indexed44['width'], indexed44['height'])):
                indexed44 = None
        if indexed44 is not None:
            indexed28, indexed1c, page, window51, packed2, cursor = None, None, None, None, False, False
    if page:
        window51 = None
    if not (packed2 or cursor or page or window51 or indexed28 or indexed44 or indexed1c):
        return None
    selected = (packed2, cursor, page)
    if indexed28 is not None:
        selected += (('indexed28', indexed28['width'], indexed28['height']),)
    if window51 is not None:
        selected += ((window51['protocol'], window51['width'], window51['height'], window51['x_origin'], window51['y_origin']),)
    if indexed44 is not None:
        selected += (('indexed44', indexed44['width'], indexed44['height'],
                      indexed44['x_origin'], indexed44['y_origin']),)
    if indexed1c is not None:
        selected += (('indexed1c', indexed1c['width'], indexed1c['height']),)
    locations = (tuple(sorted({span[0] for item in indexed44['evidence']
                  for span in (item['span'], *item.get('extra_spans', ()))}))
                 if indexed44 is not None else
                 tuple(sorted({span[0] for item in indexed1c['evidence']
                   for span in (item['span'], *item.get('extra_spans', ()))}))
                 if indexed1c is not None else (0, min(len(original), 0x80000)))
    evidence = Evidence('display-writer', selected, locations, 'linkage')
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
    if indexed28 is not None:
        selected.extend(((indexed28['command_port'], 2),
                         (indexed28['data_port'],
                          32 if indexed28['command_port'] == 0x20000000 else 2)))
    if indexed44 is not None:
        selected.extend(((indexed44['command_port'], 2), (indexed44['data_port'], 2)))
    if indexed1c is not None:
        # The native adapter normalizes the physical 1C command/data pair to
        # the canonical observer aperture consumed by the runtime model.
        selected.extend(((0x02000000, 2), (0x02000004, 2)))
    if window51 is not None:
        selected.extend(((0x02000000, 2), (0x02000002, 2)))
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
    parameters = (('packed2', packed2), ('cursor', cursor), ('page', page))
    properties = ()
    if indexed44 is not None:
        parameters += (('indexed44', tuple(indexed44[key] for key in (
            'width', 'height', 'x_origin', 'y_origin', 'command_port', 'data_port'))),)
        properties = (('external-lcd-18', True), ('external-lcd-18-register-offset',
                       indexed44['data_port'] - indexed44['command_port']))
    if indexed28 is not None:
        geometry = (indexed28['width'], indexed28['height'])
        if indexed28['command_port'] != 0x28000000:
            geometry += (indexed28['command_port'], indexed28['data_port'],
                         indexed28['x_origin'], indexed28['y_origin'], 32)
        parameters += (('indexed28', geometry),)
    if indexed1c is not None:
        parameters += (('indexed1c', (indexed1c['width'], indexed1c['height'])),)
    if window51 is not None:
        key = 'dcs_window' if window51['protocol'] == 'dcs' else 'window51'
        parameters += ((key, (window51['width'], window51['height'], window51['x_origin'], window51['y_origin'])),)
    return Capability('source-display-writer', (evidence.name,), (evidence,),
        parameters=parameters, properties=properties,
        claims=tuple(ResourceClaim('address', 'source-display-writer', start, end,
                         shared_resource=('indexed44-stream' if indexed44 is not None else
                             'indexed1c-stream' if indexed1c is not None else
                             'indexed28-stream' if indexed28 is not None else None),
                         semantics='native-write-observer' if indexed28 is not None or indexed44 is not None or indexed1c is not None else None)
                     for start, end in ranges))

_RULES = CapabilityRegistry()
_RULES.register(CapabilityPredicate('source-display-writer', (), _decision))

def machine_plan(original, loaded, config):
    return _RULES.resolve(SimpleNamespace(original=original, loaded=loaded, config=config)).plan


def machine_properties(plan):
    """Serialize the native indexed-register view from an admitted plan."""
    choices = [item for item in plan.capabilities if item.name == 'source-display-writer']
    if not choices:
        return ''
    if len(choices) != 1:
        raise ValueError('ambiguous source display plan')
    choice = choices[0]
    panel = dict(choice.parameters).get('indexed44')
    if panel is None:
        if choice.properties:
            raise ValueError('unsupported source display properties')
        return ''
    if (len(panel) != 6 or any(type(value) is not int for value in panel)
            or not 1 < panel[0] <= 256 or not 1 < panel[1] <= 256
            or not 0 <= panel[2] <= 256 - panel[0]
            or not 0 <= panel[3] <= 256 - panel[1]
            or panel[4:] != (0x18000000, 0x18000010)
            or choice.claims != tuple(ResourceClaim('address', 'source-display-writer',
                port, port + 2, shared_resource='indexed44-stream',
                semantics='native-write-observer') for port in panel[4:])
            or choice.properties != (('external-lcd-18', True),
                                      ('external-lcd-18-register-offset', 16))):
        raise ValueError('unsupported indexed display contract')
    return ',external-lcd-18=on,external-lcd-18-register-offset=16'
