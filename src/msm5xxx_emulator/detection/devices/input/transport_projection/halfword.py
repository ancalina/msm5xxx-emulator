from __future__ import annotations

def qemu_halfword_status_property(image: bytes, load_address: int, matrix: dict | None, level: int | None, existing_status: object = None) -> tuple[str | None,
    str | None]:
    """Use the closed loop's provisional scan level; no physical fold claim."""
    from . import resolve_indirect_board_status
    if level is None:
        if not (isinstance(matrix, dict) and matrix.get("grammar") == "indirect-halfword-loop-six-row-v1" and matrix.get("promotion") ==
            "temporary-evidence-gated"):
            return None, None
        # Provisional full-scan level, verified through public-key UI response.
        # Its physical contact role remains unassigned; explicit 0 is preserved.
        level = 16
    if type(level) is not int or level not in (0, 4, 16):
        return None, "invalid-level"
    if existing_status is not None:
        return None, "conflicting-status-profile"
    if not isinstance(matrix, dict) or matrix.get("grammar") not in ("indirect-halfword-six-row-v1", "indirect-halfword-loop-six-row-v1"):
        return None, "halfword-matrix-not-admitted"
    loop = matrix["grammar"] == "indirect-halfword-loop-six-row-v1"
    mask = 16 if loop else 4
    if level not in (0, mask):
        return None, "invalid-level"
    profile, status, _ = resolve_indirect_board_status(image, load_address)
    if profile is None:
        return None, status
    try:
        sink = int(matrix.get("queue_sink", ""), 16)
    except (ValueError, TypeError):
        return None, "matrix-status-mismatch"
    descriptor = matrix.get("descriptor")
    if (not isinstance(profile, dict) or type(descriptor) is not int or descriptor & 3 or not 0x1000000 <= descriptor <= 0x2000000-0x38 or profile.get("descriptor")
        != descriptor or type(profile.get("descriptor")) is not int or profile.get("queue_sink") != sink or type(profile.get("queue_sink")) is not int):
        return None, "matrix-status-mismatch"
    if not loop and profile.get("grammar") not in (None, "indirect-halfword-status-events-v1"):
        return None, "matrix-status-mismatch"
    if loop and (profile.get("grammar") != "indirect-halfword-loop-status-events-v1" or type(profile.get("mask")) is not int or profile["mask"] != mask or type(profile.get("width"))
        is not int or profile["width"] != 2 or type(profile.get("pointer_offset")) is not int or profile["pointer_offset"] != 4 or profile.get("promotion") !=
        "temporary-evidence-gated" or profile.get("runtime_admitted") is not False or profile.get("default_level") is not None or profile.get("physical_role")
        is not None or not 0 <= sink <= len(image)-4):
        return None, "unsupported-loop-status-contract"
    # Temporary GPIO class; native verifies live descriptor+4 before each read.
    return (f"board-status-input=3000720:{mask:x}:{level:x},"
            f"board-status-descriptor={profile['descriptor']:x}"), None

def qemu_boot_keysense_property(config: object, image: bytes, *, input_claimed: bool = False):
    from . import _boot_storage_profile, find_boot_keysense_release
    candidate = getattr(config, "boot_keysense_release", None)
    if isinstance(candidate, dict) and candidate.get("signature") == "arm-thumb-single-boot-contact-v1":
        # This class binds after the final primary seed and GPIO owners resolve.
        return None, None
    profile, reason = _boot_storage_profile(config, image, "boot_keysense_release", find_boot_keysense_release)
    if profile is None:
        return None, reason
    if (input_claimed or getattr(config, "key_register", None) is not None or getattr(config, "board_status_input", None) is not None):
        return None, "boot-key-input-owner-unclosed"
    return "boot-keysense-release=" + ":".join(
        f"{pc:x}" for pc in profile["read_pcs"]), None

def qemu_row734_property(image: bytes, config: object, profile: dict | None, *, input_claimed: bool = False, eeprom_window: tuple[int, int] | None = None) -> tuple[str
    | None, str | None]:
    from . import _source_class_limit, struct
    if profile is None:
        return None, None
    limit = _source_class_limit(image, config)
    if limit is None:
        return None, "row734-source-layout-unverified"
    if input_claimed or getattr(config, "key_register", None) is not None or getattr(config, "board_status_input", None) is not None:
        return None, "row734-input-owner-conflict"
    expected = dict(grammar="descriptor-row734-low5-6x5-v1", admission="temporary-evidence-gated", family= "descriptor-row734-byte-ring32-v1", rows=6, columns=5,
        no_key=31, row_mask=0x9f, row_output=0x03000728, row_select=0x03000734, sense_address=0x0300072c)
    if not isinstance(profile, dict) or any(profile.get(k) != v for k, v in expected.items()):
        return None, "row734-contract-unclosed"
    aux = profile.get("auxiliary_status", {})
    if not isinstance(aux, dict) or any(aux.get(k) != v for k, v in dict(address=0x03000720, width=2, mask=4, level=4).items()):
        return None, "row734-auxiliary-contract-unclosed"
    try:
        senses = tuple(profile["senses"])
        sites = [*profile["presence_sites"], *profile["row_sense_sites"]]
        if (len(profile["presence_sites"]) != 2 or len(profile["row_sense_sites"]) != 2 or len(senses) != 5 or set(senses) != {30, 29, 27, 23, 15} or any(type(v)
            is not int for v in senses)):
            return None, "row734-sense-roles-unclosed"
        descriptor, boot, tables = profile["descriptor_pointer"], profile["boot_sense_site"], profile["row_tables"]
        rb, rs = config.ram_base, config.ram_size
        if type(rb) is not int or type(rs) is not int or rb < 0 or rs <= 0 or rb + rs > 0x100000000:
            return None, "row734-ram-layout-unverified"
        if type(descriptor) is not int or descriptor & 3 or not rb <= descriptor <= rb + rs - 0x38:
            return None, "row734-descriptor-outside-ram"
        if not isinstance(tables, (list, tuple)) or len(tables) != 2 or any(type(v) is not int or v & 1 or not rb <= v <= rb + rs - 12 for v in tables):
            return None, "row734-row-tables-outside-ram"
        if any(type(v) is not int or v & 1 or not 2 <= v <= limit - 4 for v in [*sites, boot]) or len(set([*sites, boot])) != 5:
            return None, "row734-source-sites-unclosed"
        for site in sites:
            pointer, read = struct.unpack_from("<HH", image, site - 2)
            reg = pointer & 7
            if pointer & 0xf800 != 0x6800 or (pointer >> 6 & 31) != 13 or read != 0x8800 | reg << 3 | reg:
                return None, "row734-source-load-mismatch"
        literal, read = struct.unpack_from("<HH", image, boot - 2)
        pool = ((boot + 2) & ~3) + (literal & 255) * 4
        if (literal & 0xff00 != 0x4800 or read != 0x8980 or pool > limit - 4 or struct.unpack_from("<I", image, pool)[0] != 0x03000720 or not profile.get("boot_guard_intervals")):
            return None, "row734-boot-source-unclosed"
        if eeprom_window is not None:
            base, size = eeprom_window
            if any(type(v) is not int for v in (base, size)) or base < 0 or size <= 0 or base + size > 0x100000000:
                return None, "row734-eeprom-owner-unverified"
            if any(base < port + 2 and port < base + size for port in (0x03000720, 0x03000728, 0x0300072c, 0x03000734)):
                return None, "row734-eeprom-owner-conflict"
    except (KeyError, TypeError, ValueError, AttributeError, struct.error):
        return None, "row734-malformed-profile"
    p, r = profile["presence_sites"], profile["row_sense_sites"]
    return "matrix-row734=" + ":".join(f"{v:x}" for v in (descriptor, p[0], r[0], p[1], r[1], boot, *tables)), None

def matrix_input_command(profile: dict[str, object], position: tuple[int, int, int] | None, pressed: bool) -> bytes:
    """Encode one detector-resolved physical matrix transition."""
    from . import HOST_INPUT, matrix_senses
    if not pressed:
        return bytes((HOST_INPUT, 0, 0, 0))
    if position is None:
        raise ValueError("matrix key position is unavailable")
    _event, row, column = position
    senses = matrix_senses(profile)
    rows = int(profile["rows"])
    no_key = int(profile["no_key"])
    if (not 0 <= row < rows or not 0 <= column < len(senses) or int(senses[column]) == no_key):
        raise ValueError("invalid detector-resolved matrix position")
    if profile.get("grammar") == "distributed-seven-byte-v1":
        # Native GPIO rows use port order, then ascending pin number. Firmware
        # scans the 0x04 pin last; derive its physical position from the switch.
        pins = [(port, 1 << bit) for port, entry in enumerate(profile["gpio_ports"]) for bit in range(8) if entry["mask"] & (1 << bit)]
        selected = [index for index, (port, pin) in enumerate(pins) if not profile["row_values"][row][port] & pin]
        if len(selected) != 1:
            raise ValueError("seven-row selector does not select one wire")
        row = selected[0]
    return bytes((HOST_INPUT, 1, row, int(senses[column])))

def sideband_input_command(producer: dict[str, object], pressed: bool) -> bytes:
    """Encode one detector-resolved active-low sideband transition."""
    from . import HOST_INPUT
    if not pressed:
        return bytes((HOST_INPUT, 0, 0, 0))
    mask = int(producer.get("mask", 0))
    if (producer.get("register_width") != 1 or producer.get("polarity") != "active-low" or not 0 < mask <= 0xF0 or mask & 0x0F or mask & (mask - 1)):
        raise ValueError("invalid detector-resolved sideband producer")
    return bytes((HOST_INPUT, 1, 0xFF, mask))
