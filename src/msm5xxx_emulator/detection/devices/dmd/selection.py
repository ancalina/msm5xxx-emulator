"""DMD 5100 source-owner admission and machine property selection."""

REQUIRES = {'find_dmd5100_profile': ('dmd.detector', 'find_dmd5100_profile'), 'qemu_property': ('dmd.projection', 'qemu_property'), 'padding_sources_requested':
    ('dmd.projection', 'padding_sources_requested'), 'permits_tail_padding': ('uart_console', 'permits_tail_padding'), 'qemu_loaded_uart_console_property': ('uart_console',
    'qemu_loaded_uart_console_property'), 'resource_windows': ('uart_console', 'resource_windows'), 'find_indirect_boot_page_profile': ('display.boot_page_indirect',
    'find_indirect_boot_page_profile')}

def qemu_dmd5100_property(original: bytes, loaded: bytes, config: object, *, immutable_limit: int | None = None, layout_claimed: bool = False, input_profile:
    dict | None = None, eeprom_window: tuple[int, int] | None = None, allow_read_760: bool = False,) -> tuple[str | None, str | None]:
    """Collect independent source-owner closures and delegate DMD admission."""
    profile, reason = find_dmd5100_profile(original)
    if profile is None:
        return qemu_property(original, loaded, config, profile=None, reason=reason)
    legacy_padded_console = False
    uart = getattr(config, "uart_console", None)
    needs_console, needs_indirect = padding_sources_requested(profile, original, loaded, config, uart_can_pad=permits_tail_padding(uart))
    if needs_console:
        # This independently checks the complete reset/copy/console source,
        # present guard spans, canonical FF tail, and final memory ownership.
        # Keeping the native DSP bridge avoids a legacy ROM patch invalidating
        # that same loaded-source contract later in the launch pipeline.
        console_wire, _ = qemu_loaded_uart_console_property(uart, original, loaded, config, ram_claimed=layout_claimed)
        legacy_padded_console = console_wire is not None
    legacy_padded_indirect_page = False
    if needs_indirect:
        parent, _ = find_indirect_boot_page_profile(original)
        # A complete indirect LCD reset/selector graph independently owns the
        # short primary dump. Preserve that source by using native DSP upload,
        # rather than a legacy ROM patch that would invalidate its observer.
        if (parent is not None and find_indirect_boot_page_profile(loaded)[0] == parent and all(config.ram_base <= a < b <= config.ram_base + config.ram_size
            for a,b in parent["ram_intervals"])):
            legacy_padded_indirect_page = True
    return qemu_property(original, loaded, config, profile=profile, reason=reason, immutable_limit=immutable_limit, layout_claimed=layout_claimed, input_profile=input_profile,
        eeprom_window=eeprom_window, allow_read_760=allow_read_760, uart_windows=resource_windows(uart), padded_console_source=legacy_padded_console,
        padded_indirect_source=legacy_padded_indirect_page)
