from __future__ import annotations
from msm5xxx_emulator.detection.contracts import fields_match

HOST_INPUT = 0x80

def qemu_legacy_keypad_status_available(profile: dict | None, status: BoardStatusInput | None) -> bool:
    """The released scanner input is supplied by the matrix pull-ups."""
    from . import BoardStatusInput
    return profile is not None and (status is None or status == BoardStatusInput(0x03000694, 4, 4))

def qemu_legacy_keypad_source_matches(image: bytes, profile: dict | None) -> bool:
    """Recheck keypad wiring against the actual loaded source bytes."""
    if profile is None:
        return True
    from msm5xxx_emulator.detection.devices.input.legacy_keypad import find_legacy_six_row_keypad
    return find_legacy_six_row_keypad(image) == profile

def matrix_senses(profile: dict[str, object]) -> tuple[int, ...]:
    """Return the detector-admitted, unique physical sense values."""
    senses = tuple(int(value) for value in profile.get("senses", profile.get("single_key_column_sense", ())))
    no_key = int(profile["no_key"])
    low5 = profile.get("grammar") in {"lg-descriptor-low5-6x5-raw-v1", "descriptor-row734-low5-6x5-v1", "lg-kp-legacy-low5-6x5-v1"}
    loop = profile.get("grammar") == "indirect-halfword-loop-six-row-v1"
    if loop and (no_key != 31 or senses != (30, 29, 27, 23)):
        raise ValueError("invalid detector-resolved loop senses")
    if low5 and (no_key != 0x1F or set(senses) != {30, 29, 27, 23, 15}):
        raise ValueError("invalid detector-resolved five-column senses")
    if (not senses or len(set(senses)) != len(senses) or any(not 0 <= value <= (0x1F if low5 or loop else 0x0F) or value == no_key for value in senses)):
        raise ValueError("invalid detector-resolved matrix senses")
    return senses

def qemu_kp2600_matrix_property(image: bytes, config: object, profile: dict[str, object] | None) -> str | None:
    """Enable only the scanner whose matrix and C80 clock are source-closed."""
    from . import find_kp2600_scanner
    source = find_kp2600_scanner(image, config)
    if (source is None or profile != source or getattr(config, 'board_status_input', None) is not None):
        return None
    return 'matrix-low5=19462c4:6d5e4:6d712:6d574:6d5d2'

def qemu_kp2600_irq_compatible(c80: str | None, read_consume: object, w1c: object, stack_w1c: object, experimental_ma5_irq: bool) -> bool:
    return (c80 == '3000c80:3000c94:200:4c4b40:1800000:3824:19fb0ec:a47a8:1b6:1949048:c604' and read_consume is None and w1c is None and stack_w1c is None and
        not experimental_ma5_irq)

def qemu_sd810_sxs_menu_selection(image: bytes, config: object, profile: dict[str, object]) -> dict[str, object] | None:
    """Use the SXS menu-selection contact verified through the guest UI."""
    from . import sd810_gpio_board_status_profile
    events = profile.get("event_codes")
    table = 0x25d957
    if (getattr(config, 'load_address', None) != 0 or getattr(config, 'flash_size', 0) < table + 30 or (not fields_match(profile, (('function', 493436), ('descriptor_pointer',
        25257496), ('raw_enqueue', 492708)))) or (profile.get('event_table') != table) or (not isinstance(events, (list, tuple))) or (len(events) != 30) or any((type(event)
        is not int or not 0 <= event <= 255 for event in events)) or (bytes(events) != image[table:table + 30]) or (events.count(140) != 1) or (sd810_gpio_board_status_profile(image)
        != (50333472, 1, 1))):
        return None
    mappings = profile.get("provisional_mappings")
    if not isinstance(mappings, dict) or not mappings:
        return None
    mappings = dict(mappings)
    # This contact selects the highlighted menu item; its previous volume
    # label was provisional and would send the same contact for two keys.
    mappings.pop(8, None)
    mappings[5] = {"event": 0x8c, "rule": "sxs-guest-menu-selection"}
    return {**profile, "provisional_mappings": mappings}

def qemu_low5_matrix_property(image: bytes, config: object, profile: dict[str, object] | None,) -> tuple[str | None, str | None]:
    """Serialize an admitted scanner; native reads also gate descriptor/selector.

    Temporary electrical approximation: released columns follow the firmware's
    no-key predicate. Other reads and upper sense bits retain native backing.
    """
    from . import facts_for, matrix_senses, qemu_sd840_low5_contacts, qemu_sd840_status_source, qemu_sd9210_low5_contacts, sd810_gpio_board_status_profile, struct
    if profile is None or profile.get("grammar") != "lg-descriptor-low5-6x5-raw-v1":
        return None, None
    status = getattr(config, "board_status_input", None)
    if status is not None and not ((getattr(status, "address", None), getattr(status, "mask", None), getattr(status, "default", None)) == (0x03000720, 1, 1) and
        ((sd810_gpio_board_status_profile(image) == (0x03000720, 1, 1) and profile.get("descriptor_pointer") == 0x01816618) or qemu_sd840_status_source(image,
        config, profile))):
        return None, "conflicting-status-profile"
    if (not fields_match(profile, (('rows', 6), ('columns', 5), ('sense_bits', 5), ('register', 50333484), ('event_sink_validation',
        'validated-raw-enqueue-callsites'))) or not profile.get('descriptor_mmio_provenance') or (not profile.get('timer_bridge'))):
        return None, "unclosed-scanner-profile"
    try:
        matrix_senses(profile)
    except (KeyError, TypeError, ValueError):
        return None, "invalid-sense-table"
    descriptor = profile.get("descriptor_pointer")
    if (type(descriptor) is not int or descriptor & 3 or not config.ram_base <= descriptor <= config.ram_base + config.ram_size - 0x38):
        return None, "descriptor-outside-ram"
    global_sites = profile.get("global_sense_sites")
    row_sites = profile.get("row_sense_sites")
    if (not isinstance(global_sites, (list, tuple)) or len(global_sites) != 1 or not isinstance(row_sites, (list, tuple)) or len(row_sites) not in (1, 2)):
        return None, "ambiguous-sense-roles"
    # The paired-site form is confined to the verified scanner layout whose
    # second read rechecks the same port for its row-zero special case.
    if len(row_sites) == 2 and (profile.get("function") != 0x8216c or profile.get("prologue") != 0x8216e or global_sites !=[0x82192] or row_sites !=[0x822b8,
        0x822d4]):
        return None, "ambiguous-sense-roles"
    role_sites = [global_sites[0], *row_sites]
    if any(type(site) is not int or site & 1 for site in role_sites):
        return None, "ambiguous-sense-roles"
    sites = []
    for candidate in role_sites:
        offset = candidate - config.load_address
        if not 0 <= offset <= min(len(image), config.flash_size) - 4:
            return None, "sense-outside-primary-nor"
        pointer, read = struct.unpack_from("<HH", image, offset)
        register = pointer & 7
        if (pointer & 0xF800 != 0x6800 or (pointer >> 6 & 31) != 0x34 // 4 or read != 0x8800 | register << 3 | register):
            return None, "sense-load-shape-mismatch"
        sites.append(candidate + 2)  # Actual LDRH, not its pointer load.
    if len(set(sites)) != len(sites):
        return None, "ambiguous-sense-roles"
    if len(sites) == 3:
        return f"matrix-low5={descriptor:x}:{sites[0]:x}:{sites[1]:x}:{sites[2]:x}", None
    suffix = ""
    contact_sites = (qemu_sd840_low5_contacts(image, config, profile) or qemu_sd9210_low5_contacts(image, config, profile))
    if contact_sites is not None:
        suffix = ":" + ":".join(f"{site:x}" for site in contact_sites)
    elif status is not None:
        # The scanner also checks the shared fifth sense line before driving
        # an individual row. Close both conditional halfword reads.
        start = int(profile["function"]) - config.load_address
        contact_sites = []
        for offset in (0x3a, 0x60):
            pos = start + offset
            if pos < 2 or pos + 8 > len(image):
                return None, "contact-read-outside-image"
            pointer, read, shift, branch = struct.unpack_from("<4H", image, pos)
            reg = pointer & 7
            if (pointer & 0xF800 != 0x6800 or (pointer >> 6 & 31) != 13 or read != 0x8800 | reg << 3 | reg or shift != 0x0800 | 5 << 6 | reg << 3 | reg or
                branch & 0xFF00 != 0xD200 or facts_for(image).thumb_literal_value(pos - 2, (pointer >> 3) & 7) != descriptor):
                return None, "contact-read-shape-mismatch"
            contact_sites.append(config.load_address + pos + 2)
        bridge = profile.get("timer_bridge")
        registration = bridge.get("registration_callsite") if isinstance(bridge, dict) else None
        if type(registration) is not int:
            return None, "contact-initializer-unclosed"
        init = registration - config.load_address - 0xbe
        if (init < 0 or init + 10 > len(image) or struct.unpack_from("<5H", image, init) != (0x6b60, 0x8800, 0x0940, 0xd207, 0x2051)):
            return None, "contact-initializer-unclosed"
        contact_sites.append(config.load_address + init + 2)
        suffix = ":" + ":".join(f"{site:x}" for site in contact_sites)
    return f"matrix-low5={descriptor:x}:{sites[0]:x}:{sites[1]:x}{suffix}", None

def qemu_sd840_low5_contacts(image: bytes, config: object, profile: dict[str, object],) -> tuple[int, int, int] | None:
    """Close SD840's sense-bit prechecks over its verified timer callback."""
    from . import ASCII_KEY_EVENTS, _thumb_path_preserves_register, facts_for, struct
    status = getattr(config, "board_status_input", None)
    if (status is not None and (getattr(status, "address", None), getattr(status, "mask", None), getattr(status, "default", None)) != (0x03000720, 1, 1)):
        return None
    if profile.get("descriptor_pointer") != 0x0181661c:
        return None
    scanner = profile.get("function")
    bridge = profile.get("timer_bridge")
    registration = bridge.get("registration_callsite") if isinstance(bridge, dict) else None
    if (type(scanner) is not int or type(registration) is not int or bridge.get("scanner") != scanner or bridge.get("initial") != 25 or bridge.get("reload") !=
        25):
        return None
    events = profile.get("event_codes")
    if not isinstance(events, (list, tuple)) or any(events.count(event) != 1 for event in ASCII_KEY_EVENTS):
        return None
    load = config.load_address
    start, call = scanner - load, registration - load
    if (start < 0 or start + 0x88 > len(image) or call < 0x15c or call + 4 > len(image) or facts_for(image).thumb_literal_value(call - 0x15c, 7) != 0x0181661c):
        return None
    # The precheck isolates all five row drives before re-reading bit 4.
    if struct.unpack_from("<7H", image, start + 0x68) != (0x231f, 0x8d91, 0x4319, 0x8591, 0x8d91, 0x6a12, 0x8011):
        return None
    contacts = []
    for offset in (0x5a, 0x80):
        pos = start + offset
        pointer, read, shift, branch = struct.unpack_from("<4H", image, pos)
        reg = pointer & 7
        if (pointer & 0xf800 != 0x6800 or (pointer >> 6 & 31) != 13 or read != 0x8800 | reg << 3 | reg or shift != 0x0800 | 5 << 6 | reg << 3 | reg or branch &
            0xff00 != 0xd200 or facts_for(image).thumb_literal_value(pos - 2, (pointer >> 3) & 7) != 0x0181661c):
            return None
        contacts.append(load + pos + 2)
    init = call - 0xc2
    if (init < 0 or not _thumb_path_preserves_register(image, call - 0x15a, init, init + 2, 7) or struct.unpack_from("<5H", image, init) != (0x6b78, 0x8800,
        0x0940, 0xd207, 0x2051)):
        return None
    return contacts[0], contacts[1], load + init + 2

def qemu_sd9210_low5_contacts(image: bytes, config: object, profile: dict[str, object],) -> tuple[int, int] | None:
    """Close SD9210's two released bit-4 prechecks for numeric keys."""
    from . import ASCII_KEY_EVENTS, _rex_legacy_irq_route_metadata_valid, facts_for, struct
    bridge = profile.get("timer_bridge")
    scanner = profile.get("function")
    if (getattr(config, "board_status_input", None) is not None or profile.get("descriptor_pointer") != 0x01816618 or profile.get("row_order") !=[4, 0, 1, 2, 3,
        5] or type(scanner) is not int or not isinstance(bridge, dict) or bridge.get("scanner") != scanner or bridge.get("initial") != 25 or bridge.get("reload")
        != 25 or not isinstance(bridge.get("irq_route"), dict) or not _rex_legacy_irq_route_metadata_valid(bridge["irq_route"])):
        return None
    route = bridge["irq_route"]
    if (bridge.get("outer_callback") != route.get("outer_callback") or getattr(config, "rex_tick_address", None) != bridge.get("outer_callback") or getattr(config,
        "rex_irq_handler_address", None) != route.get("handler") or getattr(config, "rex_irq_status_address", None) != route.get("status") or getattr(config,
        "rex_irq_enable_address", None) != route.get("enable")):
        return None
    events = profile.get("event_codes")
    if not isinstance(events, (list, tuple)) or any(events.count(event) != 1 for event in ASCII_KEY_EVENTS):
        return None
    start = scanner - config.load_address
    if start < 0 or start + 0x68 > len(image):
        return None
    if struct.unpack_from("<7H", image, start + 0x48) != (0x220f, 0x8d99, 0x4311, 0x8599, 0x8d99, 0x6a1a, 0x8011):
        return None
    contacts = []
    for offset in (0x3a, 0x60):
        pos = start + offset
        pointer, read, shift, branch = struct.unpack_from("<4H", image, pos)
        reg = pointer & 7
        if (pointer & 0xf800 != 0x6800 or (pointer >> 6 & 31) != 13 or read != 0x8800 | reg << 3 | reg or shift != 0x0800 | 5 << 6 | reg << 3 | reg or branch &
            0xff00 != 0xd200 or facts_for(image).thumb_literal_value(pos - 2, (pointer >> 3) & 7) != 0x01816618):
            return None
        contacts.append(config.load_address + pos + 2)
    return contacts[0], contacts[1]

def qemu_sd840_numeric_profile(profile: dict[str, object]) -> dict[str, object]:
    """Keep only table-proven numeric key labels for this scanner."""
    from . import ASCII_KEY_EVENTS
    return {**profile, "provisional_mappings": { bit: {"event": event} for bit, event in zip(range(11, 23), ASCII_KEY_EVENTS) }}

def qemu_kp_low5_property(image: bytes, config: object, profile: dict[str, object] | None) -> str | None:
    """Serialize only a KP scanner with a closed timer and IRQ route."""
    from . import _rex_legacy_irq_route_metadata_valid, find_kp_legacy_scanner, matrix_senses
    if (profile is None or profile.get("grammar") != "lg-kp-legacy-low5-6x5-v1" or getattr(config, "board_status_input", None) is not None):
        return None
    source = find_kp_legacy_scanner(image)
    bridge = profile.get("timer_bridge")
    if (source is None or not isinstance(bridge, dict) or not isinstance(bridge.get("irq_route"), dict) or profile.get("event_sink_validation") !=
        "validated-raw-enqueue-callsites"):
        return None
    route = bridge["irq_route"]
    if (route.get("controller_class") != "legacy-c80-two-bank-group10-v1" or not _rex_legacy_irq_route_metadata_valid(route) or bridge.get("outer_callback") !=
        route.get("outer_callback") or getattr(config, "rex_tick_address", None) != bridge.get("outer_callback") or getattr(config, "rex_irq_handler_address",
        None) != route.get("handler") or getattr(config, "rex_irq_status_address", None) != route.get("status") or getattr(config, "rex_irq_enable_address",
        None) != route.get("enable")):
        return None
    load = config.load_address
    for field in ("function", "sense_site", "presence_site", "contact_site", "contact2_site"):
        if profile.get(field) != source[field] + load:
            return None
    if (profile.get("descriptor_pointer") != source["descriptor_pointer"] or profile.get("event_codes") != source["event_codes"] or profile.get("single_key_column_sense")
        != source["single_key_column_sense"] or profile.get("descriptor_mmio_provenance") != source["descriptor_mmio_provenance"] or (profile.get("rows"),
        profile.get("columns"), profile.get("no_key")) != (6, 5, 31) or profile.get("register") != 0x0300072c or bridge.get("scanner") != profile["function"]):
        return None
    try:
        matrix_senses(profile)
    except (KeyError, TypeError, ValueError):
        return None
    return (f"matrix-kp-low5={source['descriptor_pointer']:x}:"
            f"{profile['presence_site']:x}:{profile['sense_site'] + 2:x}:"
            f"{profile['contact_site']:x}:{profile['contact2_site']:x}")

def qemu_kp2100_low5_property(image: bytes, config: object, profile: dict[str, object] | None) -> str | None:
    """Close KP2100's distinct global read and two bit-4 checks."""
    from . import ASCII_KEY_EVENTS, _descriptor_mmio_provenance, _rex_legacy_irq_route_metadata_valid, facts_for, matrix_senses, qemu_kp2100_status_source, struct
    status = getattr(config, "board_status_input", None)
    if (profile is None or (status is not None and ((status.address, status.mask, status.default) != (50333472, 1, 1) or not qemu_kp2100_status_source(image,
        config, profile))) or (not fields_match(profile, (('grammar', 'lg-descriptor-low5-6x5-raw-v1'), ('descriptor_pointer', 17839748), ('event_sink_validation',
        'validated-raw-enqueue-callsites'), ('row_order',[0, 1, 2, 3, 4, 5])))) or (not profile.get('descriptor_mmio_provenance'))):
        return None
    provenance = _descriptor_mmio_provenance(image, 0x01103684)
    if provenance is None or provenance["kind"] != profile["descriptor_mmio_provenance"]:
        return None
    scanner = profile.get("function")
    bridge = profile.get("timer_bridge")
    if (type(scanner) is not int or not isinstance(bridge, dict) or bridge.get("scanner") != scanner or bridge.get("initial") != 25 or bridge.get("reload") !=
        25 or not isinstance(bridge.get("irq_route"), dict)):
        return None
    route = bridge["irq_route"]
    if (not _rex_legacy_irq_route_metadata_valid(route) or bridge.get("outer_callback") != route.get("outer_callback") or getattr(config, "rex_tick_address",
        None) != bridge.get("outer_callback") or getattr(config, "rex_irq_handler_address", None) != route.get("handler") or getattr(config,
        "rex_irq_status_address", None) != route.get("status") or getattr(config, "rex_irq_enable_address", None) != route.get("enable")):
        return None
    events = profile.get("event_codes")
    if not isinstance(events, (list, tuple)) or any(events.count(x) != 1 for x in ASCII_KEY_EVENTS):
        return None
    try:
        matrix_senses(profile)
    except (KeyError, TypeError, ValueError):
        return None
    start = scanner - config.load_address
    if (start < 0 or start + 0x14c > len(image) or facts_for(image).thumb_literal_value(start + 0x1a, 4) != 0x01103684):
        return None
    operations = { 0x02: 0xb5f0, 0x04: 0x7908, 0x06: 0x2800, 0x80: 0x6b60, 0x82: 0x8800, 0x84: 0x0940, 0x86: 0xd201, 0x88: 0x2751, 0x90: 0x6b60, 0x92: 0x1c26,
        0x94: 0x8800, 0x96: 0x06c0, 0x98: 0x0ec0, 0x9a: 0x281f, 0x134: 0x6b70, 0x136: 0x8800, 0x138: 0x06c0, 0x13a: 0x0ec0, 0x13c: 0x281f, 0x144: 0x6b71, 0x146:
        0x8809, 0x148: 0x0949, 0x14a: 0xd201, }
    if any(struct.unpack_from("<H", image, start + off)[0] != word for off, word in operations.items()):
        return None
    return (f"matrix-low5=1103684:{scanner + 0x94:x}:{scanner + 0x136:x}:"
            f"{scanner + 0x82:x}:{scanner + 0x146:x}")

def qemu_kp2100_status_source(image: bytes, config: object, profile: dict[str, object] | None) -> bool:
    """Link GPIO720 bit 0 to this scanner's ordinary-key admission flag."""
    from . import _descriptor_mmio_provenance, facts_for, struct
    if (profile is None or profile.get("descriptor_pointer") != 0x01103684 or profile.get("raw_enqueue") != 0x6f794 or getattr(config, "load_address", None) !=
        0 or len(image) < 0x173844):
        return False
    provenance = _descriptor_mmio_provenance(image, 0x01103684)
    if (provenance is None or provenance["source"] + 8 > len(image) or struct.unpack_from("<I", image, provenance["source"] + 4)[0] != 0x03000720):
        return False
    reader, sink = 0x1737ec, 0x6f794
    operations = { 0x06: 0x2001, 0x0a: 0x6849, 0x0c: 0x8809, 0x0e: 0x0849, 0x10: 0xd200, 0x12: 0x2000, 0x16: 0x6208, 0x1a: 0x69c0, 0x1c: 0x6a09, 0x1e: 0x4288,
        0x20: 0xd010, 0x24: 0x6a00, 0x28: 0x61c8, 0x2c: 0x69c0, 0x30: 0x2221, 0x32: 0x0192, 0x34: 0x1889, 0x36: 0x7248, }
    if (any(struct.unpack_from("<H", image, reader + off)[0] != word for off, word in operations.items()) or facts_for(image).thumb_literal_value(reader + 8, 1)
        != 0x01103684 or any(facts_for(image).thumb_literal_value(reader + off, reg) != 0x0146aa14 for off, reg in ((0x14, 1), (0x18, 0), (0x22, 0), (0x26, 1),
        (0x2a, 0))) or facts_for(image).thumb_literal_value(reader + 0x2e, 1) != 0x011abaa8 or struct.unpack_from("<I", image, 0x1f35c)[0] != 0x70cc1 or
        facts_for(image).thumb_literal_value(0x70cde, 4) != 0x01103684 or facts_for(image).thumb_literal_value(0x70cec, 0) != 0x011abaa8 or tuple(struct.unpack_from
        ("<H", image, pos)[0] for pos in (0x70ce0, 0x70ce2, 0x70ce4, 0x70ce6, 0x70ce8, 0x70cea, 0x70cf2, 0x70cf4, 0x70cfa, 0x70cfc, 0x70d02, 0x70d0e, 0x70d10,
        0x70d16)) != (0x6860, 0x8800, 0x07c1, 0x0fc9, 0x2221, 0x0192, 0x1810, 0x2900, 0x7247, 0x2006, 0x20ff, 0x7245, 0x2008, 0x20ff) or any(facts_for(image).thumb_call_target(pos)
        != sink for pos in (0x70cfe, 0x70d04, 0x70d12, 0x70d18)) or struct.unpack_from("<4H", image, 0x173622) != (0x2f1a, 0xd001, 0x2f1b, 0xd1e7) or facts_for(image).thumb_call_target(0x17362a)
        != reader or facts_for(image).thumb_literal_value(sink + 6, 0) != 0x011abaa8 or tuple(struct.unpack_from("<H", image, sink + off)[0] for off in (4, 8,
        10, 12, 14)) != (0x2121, 0x0189, 0x1841, 0x7a49, 0x2900)):
        return False
    compares = {struct.unpack_from("<H", image, pos)[0] for pos in range(sink + 0x12, sink + 0x78, 2)}
    return all((0x2f00 | value) in compares for value in b"1234567890")

def qemu_lg_matrix_irq_property(config: object, profile: dict[str, object] | None) -> str | None:
    """Promote a detector-closed LG scan timer to the native C80 route."""
    from . import _rex_legacy_irq_route_metadata_valid
    if (profile is None or (profile.get("grammar"), profile.get("descriptor_pointer")) not in { ("lg-kp-legacy-low5-6x5-v1", 0x010bd680), ("lg-descriptor-low5-6x5-raw-v1",
        0x01103684), ("lg-descriptor-low5-6x5-raw-v1", 0x01816618)} or (profile.get("descriptor_pointer") == 0x01816618 and profile.get("row_order") !=[4, 0, 1,
        2, 3, 5]) or getattr(config, "rex_irq_arm_address", None) is not None):
        return None
    bridge = profile.get("timer_bridge")
    route = bridge.get("irq_route") if isinstance(bridge, dict) else None
    if (not isinstance(route, dict) or route.get("controller_class") != "legacy-c80-two-bank-group10-v1" or not _rex_legacy_irq_route_metadata_valid(route) or
        bridge.get("scanner") != profile.get("function") or bridge.get("initial") != 25 or bridge.get("reload") != 25 or bridge.get("outer_callback") != route.get("outer_callback")):
        return None
    fields = ("vector_target", "wrapper", "handler_slot", "handler", "handler_runtime_size", "callback_slot", "outer_callback")
    if any(type(route.get(field)) is not int for field in fields):
        return None
    vector, wrapper, handler_slot, handler, size, callback_slot, callback = (route[field] for field in fields)
    ram_base, ram_end = config.ram_base, config.ram_base + config.ram_size
    if (not fields_match(route, (('status', 50334848), ('enable', 50334868), ('mask', 512))) or vector != ram_base or (not all((ram_base <= slot <= ram_end - 4
        and (not slot & 3) for slot in (handler_slot, callback_slot)))) or (not 0 < size <= 1024) or handler & 1 or wrapper & 3 or (callback & 1) or (not 0 <=
        handler <= config.flash_size - size) or (not 0 <= wrapper < config.flash_size) or (not 0 <= callback < config.flash_size) or (getattr(config,
        'rex_tick_ms', None) != 5) or (getattr(config, 'rex_tick_address', None) != callback) or (getattr(config, 'rex_irq_wrapper_address', None) != wrapper)
        or (getattr(config, 'rex_irq_handler_address', None) != handler) or (getattr(config, 'rex_irq_handler_slot', None) != handler_slot) or (getattr(config,
        'rex_irq_callback_slot', None) != callback_slot) or (getattr(config, 'rex_irq_status_address', None) != route['status']) or (getattr(config,
        'rex_irq_enable_address', None) != route['enable']) or (getattr(config, 'rex_irq_mask', None) != route['mask'])):
        return None
    return (f"3000c80:3000c94:200:4c4b40:{vector:x}:{wrapper:x}:"
            f"{handler_slot:x}:{handler:x}:{size:x}:{callback_slot:x}:{callback:x}")

def qemu_matching_lg_irq(existing: str | None, candidate: str | None) -> bool:
    """The handler span may differ; all route endpoints must match."""
    if existing is None or candidate is None:
        return False
    try:
        left = tuple(int(value, 16) for value in existing.split(':'))
        right = tuple(int(value, 16) for value in candidate.split(':'))
    except ValueError:
        return False
    return (len(left) == len(right) == 11 and left[8] > 0 and right[8] > 0 and left[:8] == right[:8] and left[9:] == right[9:])
