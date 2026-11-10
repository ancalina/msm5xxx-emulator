"""Source-bound machine property for the paired DMD upload path."""
from .detector import find_dmd5100_profile

def padding_sources_requested(profile, original, loaded, config, *, uart_can_pad: bool = False) -> tuple[bool, bool]:
    """Decide whether DMD admission needs independent tail-padding proofs."""
    read_760 = (isinstance(profile, dict) and profile.get("signature") == "dmd5100-paired-program-readback-760-v1")
    chipset_ok = getattr(config, "chipset", None) in ("MSM5100", "MSM5105")
    console = (not read_760 and isinstance(loaded, bytes) and type(getattr(config, "flash_size", None)) is int and len(original) < config.flash_size and
        chipset_ok and uart_can_pad)
    indirect = (not read_760 and isinstance(loaded, bytes) and all(type(getattr(config, key, None)) is int for key in ("flash_size", "ram_base", "ram_size"))
        and len(original) < config.flash_size and chipset_ok)
    return console, indirect

def qemu_property(original: bytes, loaded: bytes, config: object, *, profile: dict | None, reason: str | None = None, immutable_limit: int | None = None,
    layout_claimed: bool = False, input_profile: dict | None = None, eeprom_window: tuple[int, int] | None = None, allow_read_760: bool = False, uart_windows:
    tuple[tuple[int, int], ...] = (), padded_console_source: bool = False, padded_indirect_source: bool = False,) -> tuple[str | None, str | None]:
    """Bind paired programming to the immutable primary source and owners."""
    if profile is None:
        return None, None if reason == "dmd5100-typed-driver-not-found" else reason
    read_760 = profile.get("signature") == "dmd5100-paired-program-readback-760-v1"
    if read_760 and getattr(config, "chipset", None) not in ("MSM5100", "MSM5105"):
        return None, "dmd5100-760-chipset-scope-unclosed"
    if read_760 and not allow_read_760:
        return None, "dmd5100-760-runtime-validation-pending"
    fields = ("load_address", "image_offset", "entry", "flash_size", "ram_base", "ram_size")
    if (any(type(getattr(config, name, None)) is not int for name in fields) or getattr(config, "image_kind", None) != "firmware" or (config.load_address,
        config.image_offset, config.entry) != (0, 0, 0) or not isinstance(loaded, bytes) or not 0 < config.flash_size <= 0xFFFFFFFF or (not read_760 and not
        padded_console_source and not padded_indirect_source and config.flash_size > len(original)) or not 0 <= config.ram_base < 0x100000000 or not 0 < config.ram_size
        <= 0x100000000 - config.ram_base or len(loaded) != config.flash_size):
        return None, "dmd5100-source-layout-unclosed"
    if (layout_claimed or getattr(config, "ram_bootstrap_profile", None) is not None or getattr(config, "missing_overlays", None) or getattr(config,
        "ram_image_size", 0)):
        return None, "dmd5100-memory-owner-unclosed"
    read_base = 0x03000760 if read_760 else 0x030007e0
    ports = (0x0300004C, 0x03000050, 0x0300005C, read_base + 8, read_base + 12)
    conflict = owner_conflict(config, input_profile, eeprom_window, uart_windows, ports)
    if conflict:
        reason = 'input-owner-unclosed' if conflict == 'invalid-window' else conflict
        return None, 'dmd5100-' + reason
    limit = config.flash_size if immutable_limit is None else immutable_limit
    if type(limit) is not int or not 0 < limit <= config.flash_size:
        return None, "dmd5100-immutable-prefix-unclosed"
    expected = (original[:limit].ljust(limit, b"\xff") if (read_760 or padded_console_source or padded_indirect_source) else original[:limit])
    if expected != loaded[:limit]:
        return None, "dmd5100-loaded-immutable-source-changed"
    if (profile.get("signature") != ("dmd5100-paired-program-readback-760-v1" if read_760 else "dmd5100-paired-program-readback-v1") or (read_760 and (profile.get("read_base")
        != read_base or profile.get("halfword_count") != 0x1000)) or profile.get("admission") != "temporary-evidence-gated" or profile.get("mode") != 0 or any(not
        0 <= start < end <= limit for start, end in profile["source_intervals"]) or (read_760 and any(end > len(original) for _, end in profile["source_intervals"]))
        or getattr(config, "dmd_download_address", None) != profile["entry_file_offset"] or not config.ram_base <= profile["completion_byte_address"] < config.ram_base
        + config.ram_size <= 0x100000000):
        return None, "dmd5100-source-owner-unclosed"
    current, _ = find_dmd5100_profile(loaded)
    if current != profile:
        return None, "dmd5100-loaded-profile-changed"
    values = (profile["entry_file_offset"], profile["descriptor_file_offset"], profile["payload_file_offset"], profile["pair_count"])
    name = "dmd5100-program-760=" if read_760 else "dmd5100-program="
    return name + ":".join(f"{value:x}" for value in values), None

def owner_conflict(config, input_profile, eeprom_window, uart_windows, ports):
    """Check the native DMD port windows against independently selected owners."""
    windows = list(uart_windows)
    status = getattr(config, 'board_status_input', None)
    if status is not None:
        windows.append((getattr(status, 'address', None), getattr(status, 'width', 1)))
    key = getattr(config, 'key_register', None)
    if key is not None:
        windows.append((key, 4))
    if input_profile is not None:
        if not isinstance(input_profile, dict):
            return 'input-owner-unclosed'
        width = (2 if str(input_profile.get('grammar', '')).startswith('indirect-halfword') else input_profile.get('register_width', 1))
        windows.append((input_profile.get('register', input_profile.get('sense_address')), width))
    if eeprom_window is not None:
        windows.append(eeprom_window)
    for start, size in windows:
        if (type(start) is not int or type(size) is not int or not 0 <= start < start + size <= 0x100000000):
            return 'invalid-window'
        if any(start < port + 4 and port < start + size for port in ports):
            return 'input-owner-conflict'
    return None
