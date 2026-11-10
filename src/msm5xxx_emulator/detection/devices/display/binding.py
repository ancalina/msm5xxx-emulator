"""Source, loader and ownership admission for display consumers."""
from __future__ import annotations
from . import (boot_page, bytepair565, copied_window, gpio_serial, legacy_lcd, mux_page, rgb565_boot)

_RULES = { 'mux': ((mux_page, 'find_mux_page_profile'), 'source-external-bit4-mono96-page-v1', ('width', 'height', 'clear_pages', 'clear_row_bytes',
    'command_port', 'data_port', 'mode_port', 'mode_mask', 'access_width'), (96, 64, 10, 96, 0x02000000, 0x02000000, 0x02800000, 0x10, 1),
    'source-mux-contract-unverified', 'source-candidate-awaiting-ten-page-clear'), 'gpio': ((gpio_serial, 'find_gpio_serial_profile'),
    'source-gpio660-serial89-v1', ('width', 'height', 'access_width', 'port'), (89, 64, 2, 0x03000660), 'source-gpio-contract-unverified',
    'source-candidate-awaiting-complete-raster'), 'rgb565': ((rgb565_boot, 'find_rgb565_boot_profile'), 'source-arm-packed-rgb565-boot120-v1', ('width',
    'height', 'pixel_port', 'command_port', 'access_width'), (120, 133, 0x02000000, 0x02000002, 2), 'source-rgb565-boot-contract-unverified',
    'source-candidate-awaiting-complete-blit'), 'bytepair565': ((bytepair565, 'find_bytepair565_profile'), 'source-halfword-bytepair565-104-v1', ('width',
    'height', 'pixel_port', 'command_port', 'access_width'), (104, 80, 0x02400000, 0x02000000, 2), 'source-rgb565-boot-contract-unverified',
    'source-candidate-awaiting-complete-blit'), }

def _layout_failures(original, loaded, cfg, ram_claimed, *, chipset=True, canonical=True, ram_fields=True, owners=True, extent=True):
    failures = []
    if chipset and getattr(cfg, 'chipset', None) not in ('MSM5100', 'MSM5105'):
        failures.append('chipset')
    if getattr(cfg, 'image_kind', None) != 'firmware':
        failures.append('image-kind')
    keys = ('load_address', 'image_offset', 'entry', 'flash_size')
    if ram_fields:
        keys += ('ram_base', 'ram_size')
    if any(type(getattr(cfg, key, None)) is not int for key in keys):
        failures.append('layout-fields')
    else:
        if (cfg.load_address, cfg.image_offset, cfg.entry) != (0, 0, 0):
            failures.append('load-layout')
        if (not isinstance(original, bytes) or not isinstance(loaded, bytes) or cfg.flash_size <= 0 or extent and cfg.flash_size > 0xffffffff or len(loaded) !=
            cfg.flash_size):
            failures.append('image-size')
        elif canonical and loaded != original[:cfg.flash_size].ljust(cfg.flash_size, b'\xff'):
            failures.append('loaded-image')
    if owners:
        if ram_claimed:
            failures.append('memory-claimed')
        if getattr(cfg, 'missing_overlays', None):
            failures.append('missing-overlays')
        if getattr(cfg, 'ram_bootstrap_profile', None) is not None:
            failures.append('ram-bootstrap')
    return failures

def _geometry(cfg, width, height):
    return ((cfg.width, cfg.height) == (width, height) or getattr(cfg, 'display_geometry_source', 'external-config') == 'auto-default')

def _source_spans(profile):
    return profile['code_intervals'] + profile['literal_intervals'] + profile['data_intervals']

def _ranges(profile, original, loaded, cfg, iram_end=None):
    spans = _source_spans(profile)
    return (all(0 <= a < b <= min(len(original), len(loaded)) for a, b in spans) and all(cfg.ram_base <= a < b <= cfg.ram_base + cfg.ram_size for a, b in
        profile['ram_intervals']) and (iram_end is None or all(0x03800000 <= a < b <= iram_end for a, b in profile['iram_intervals'])))

def _canonical_patch(original, loaded, cfg, allowed_patch):
    canonical = original[:cfg.flash_size].ljust(cfg.flash_size, b'\xff')
    span = None
    if allowed_patch is not None:
        if (not isinstance(allowed_patch, tuple) or len(allowed_patch) != 2 or type(allowed_patch[0]) is not int or not isinstance(allowed_patch[1], bytes) or
            not allowed_patch[1] or not 0 <= allowed_patch[0] <= len(canonical) - len(allowed_patch[1])):
            return False, None, 'source-layout-unverified'
        off, payload = allowed_patch
        span = (off, off + len(payload))
        canonical = canonical[:off] + payload + canonical[off + len(payload):]
    return loaded == canonical, span, 'source-loaded-image-mismatch'

def bind_source(kind, original, loaded, cfg, *, ram_claimed=False, allowed_patch=None):
    """Return a captured protocol only after its loader and ownership checks."""
    failures = _layout_failures(original, loaded, cfg, ram_claimed, canonical=kind != 'rgb565')
    if failures:
        reason = 'source-layout-unverified'
        if kind == 'boot_page':
            reason += ': ' + ', '.join(failures)
            cfg.detection_notes.append('Boot page rejected: ' + reason)
        return None, reason
    patch_span = None
    if kind == 'rgb565':
        matched, patch_span, reason = _canonical_patch(original, loaded, cfg, allowed_patch)
        if not matched:
            return None, reason
    if kind == 'boot_page':
        finder = boot_page.find_boot_page_profile
        profile, reason = finder(original)
        if profile is None:
            return None, reason
        byte = (profile.get('signature') == 'source-byte-boot-page128-v1' and profile.get('access_width') == 1 and (profile.get('clear_pages'), profile.get('planes'))
            == (8, 1) and profile.get('publish_after_clear_if_enabled') is True)
        halfword = (profile.get('signature') == 'source-halfword-boot-page128-v1' and profile.get('access_width') == 2 and (profile.get('clear_pages'), profile.get('planes'))
            in ((9, 1), (16, 2)) and profile.get('publish_after_clear_if_enabled', False) is False)
        if (not (halfword or byte) or profile.get('admission') != 'temporary-evidence-gated' or type(profile.get('access_width')) is not int or tuple(profile.get(k)
            for k in ('width', 'command_port', 'data_port')) != (128, 0x02000000, 0x02000002) or profile.get('height') != profile['clear_pages'] * 8):
            return None, 'source-boot-page-contract-unverified'
        success = 'source-candidate-awaiting-complete-clear'
    else:
        provider, signature, fields, values, rejection, success = _RULES[kind]
        finder = getattr(*provider)
        profile, reason = finder(original)
        if profile is None:
            return None, reason
        if (profile.get('signature') != signature or profile.get('admission') != 'temporary-evidence-gated' or tuple(profile.get(k) for k in fields) != values):
            return None, rejection
    if patch_span and any(max(a, patch_span[0]) < min(b, patch_span[1]) for a, b in _source_spans(profile)):
        return None, 'source-patch-overlap'
    if kind == 'gpio':
        pcs = profile.get('capture_pcs', ())
        if (not 0 < len(pcs) <= 64 or len(pcs) != len(set(pcs)) or any(type(pc) is not int or pc & 1 or not 0 <= pc < len(original) for pc in pcs)):
            return None, 'source-memory-owner-unverified'
    # Mux checks geometry before ranges; retain its first-rejection contract.
    if kind == 'mux' and not _geometry(cfg, profile['width'], profile['height']):
        return None, 'source-geometry-owner-conflict'
    iram_end = 0x03a00000 if kind == 'mux' else 0x03810000 if kind in ('rgb565', 'bytepair565') else None
    if not _ranges(profile, original, loaded, cfg, iram_end):
        return None, 'source-memory-owner-unverified'
    if not _geometry(cfg, profile['width'], profile['height']):
        return None, 'source-geometry-owner-conflict'
    if (kind != 'mux' or loaded is not original) and finder(loaded)[0] != profile:
        return None, 'source-loaded-owner-mismatch'
    return profile, success

def gpio_property(profile):
    return 'experimental-gpio660-lcd=' + ':'.join(f'{pc:x}' for pc in profile['capture_pcs'])

def bind_window(original, loaded, cfg, *, ram_claimed=False):
    if (_layout_failures(original, loaded, cfg, False, chipset=False, canonical=False, owners=False) or len(original) < len(loaded)):
        return None, 'source-layout-unverified'
    profile, reason = copied_window.find_copied_window_profile(original)
    if profile is None:
        return None, reason
    if (profile.get('writer_layout') == 'arm-loop-count-tail-rom-content-v1' and getattr(cfg, 'chipset', None) not in ('MSM5100', 'MSM5105')):
        return None, 'source-writer-chipset-scope-unclosed'
    if ram_claimed or getattr(cfg, 'ram_bootstrap_profile', None) is not None or getattr(cfg, 'missing_overlays', None):
        return None, 'source-memory-owner-unclosed'
    if not _geometry(cfg, 128, 128):
        return None, 'source-geometry-owner-conflict'
    for field, begin, end in (('ram_intervals', cfg.ram_base, cfg.ram_base + cfg.ram_size), ('iram_intervals', 0x03800000, 0x03a00000)):
        spans = profile.get(field)
        if (not isinstance(spans, (list, tuple)) or not spans or any(not isinstance(span, (list, tuple)) or len(span) != 2 or any(type(v) is not int for v in
            span) or not begin <= span[0] < span[1] <= end for span in spans)):
            return None, 'source-' + field + '-unverified'
    for field in ('code_intervals', 'literal_intervals', 'data_intervals', 'boot_guard_intervals'):
        spans = profile.get(field)
        if (not isinstance(spans, (list, tuple)) or not spans or any(not isinstance(span, (list, tuple)) or len(span) != 2 or any(type(v) is not int for v in
            span) or not 0 <= span[0] < span[1] <= len(loaded) or original[span[0]:span[1]] != loaded[span[0]:span[1]] for span in spans)):
            return None, 'source-loaded-bytes-unverified'
    if copied_window.find_copied_window_profile(loaded)[0] != profile:
        return None, 'source-loaded-owner-mismatch'
    if (profile.get('signature') != 'copied-byte-range-half128-v1' or profile.get('admission') != 'temporary-evidence-gated' or profile.get('role') != 'main' or
        profile.get('protocol') != 'copied-half128' or tuple(profile.get(k) for k in ('command_port', 'data_port', 'command_width', 'access_width', 'width',
        'height')) != (0x02000000, 0x02000002, 1, 2, 128, 128)):
        return None, 'source-register-contract-unclosed'
    return profile, 'static-source-candidate-awaiting-full-raster'

LEGACY_FORMATS = {'byte31': (128, 128, 8), 'column16': (128, 160, 16), 'direct16': (176, 220, 16), 'half43': (128, 144, 16), 'byte565_boot': (120, 133, 16)}

def bind_legacy(original, loaded, cfg, *, ram_claimed=False, window_present=False):
    if (window_present or _layout_failures(original, loaded, cfg, ram_claimed, chipset=False, canonical=False, ram_fields=False, extent=False)):
        return None
    protocol = legacy_lcd.find_legacy_lcd_profile(original, cfg.ram_base, cfg.ram_size)
    if protocol is None or legacy_lcd.find_legacy_lcd_profile(loaded, cfg.ram_base, cfg.ram_size) != protocol:
        return None
    return protocol if _geometry(cfg, *LEGACY_FORMATS[protocol][:2]) else None

def bind_loaded_sources(decoder, original, loaded, *, ram_claimed, allowed_patch):
    """Bind source-closed consumers with one common ownership claim."""
    if loaded != decoder.image:
        decoder._lcd_page_loaded_image = loaded
    for kind in ('window', 'mux', 'boot_page', 'rgb565_boot', 'bytepair565'):
        options = {'allowed_patch': allowed_patch} if kind == 'rgb565_boot' else {}
        getattr(decoder, '_lcd_bind_source_' + kind)(original, loaded, ram_claimed=ram_claimed, **options)
    return decoder._lcd_bind_source_gpio(original, loaded, ram_claimed=ram_claimed)

def project_legacy_panel(decoder, machine, original, loaded, *, ram_reserved, claimed):
    protocol = decoder._lcd_bind_legacy_panel(original, loaded, ram_claimed=ram_reserved is not None)
    if protocol == 'direct16':
        if claimed:
            decoder._lcd_legacy_panel = None
        else:
            machine += ',direct-lcd=on'
    return machine
