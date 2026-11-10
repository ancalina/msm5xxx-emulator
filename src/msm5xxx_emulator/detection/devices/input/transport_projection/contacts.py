from __future__ import annotations
from msm5xxx_emulator.detection.contracts import fields_match

def qemu_sd840_status_source(image: bytes, config: object, profile: dict[str, object],) -> bool:
    """Link GPIO720 bit 0 to this scanner's ordinary-key admission gate."""
    from . import ASCII_KEY_EVENTS, _descriptor_mmio_provenance, facts_for, qemu_sd840_low5_contacts, struct
    if qemu_sd840_low5_contacts(image, config, profile) is None:
        return False
    provenance = _descriptor_mmio_provenance(image, 0x0181661c)
    if (provenance is None or provenance["source"] + 8 > len(image) or struct.unpack_from("<I", image, provenance["source"] + 4)[0] != 0x03000720):
        return False
    load = config.load_address
    scanner = profile["function"] - load
    reader = profile["timer_bridge"]["registration_callsite"] - load + 0x86
    sink = profile.get("raw_enqueue")
    if type(sink) is not int or reader < 0 or reader + 0x46 > len(image):
        return False
    sink -= load
    if (facts_for(image).thumb_literal_value(reader, 0) != 0x0181661c or tuple(struct.unpack_from("<H", image, reader + off)[0] for off in (2, 4, 6, 8, 10, 14,
        16, 18, 22, 24, 26, 32, 54, 56, 58, 64)) != (0x6840, 0x8800, 0x07c0, 0x0fc0, 0x227f, 0x0112, 0x1851, 0x2800, 0xd10e, 0x7148, 0x2008, 0x20ff, 0x2001,
        0x7148, 0x2006, 0x20ff) or any(facts_for(image).thumb_call_target(reader + off) != sink for off in (28, 34, 60, 66))):
        return False
    state = facts_for(image).thumb_literal_value(reader + 12, 1)
    classifier = facts_for(image).thumb_call_target(scanner + 0x326)
    if (state is None or not config.ram_base <= state + 0x7f5 < config.ram_base + config.ram_size or classifier is None or classifier < 0 or classifier + 0x1a >
        len(image) or facts_for(image).thumb_call_target(scanner + 0x330) != sink or facts_for(image).thumb_literal_value(classifier + 0x0a, 0) != state):
        return False
    if (classifier + 0x4c > len(image) or tuple(struct.unpack_from("<H", image, classifier + off)[0] for off in (6, 8, 12, 14, 16, 20, 22)) != (0x227f, 0x7901,
        0x0112, 0x1810, 0x2901, 0x7941, 0x2900)):
        return False
    checks = {struct.unpack_from("<H", image, pos)[0] for pos in range(classifier + 0x1a, classifier + 0x4c, 2)}
    return all((0x2f00 | event) in checks for event in ASCII_KEY_EVENTS)

def qemu_low5_rex_c80_property(config: object, profile: dict[str, object] | None,) -> tuple[str | None, str | None]:
    """Encode the paired scanner's independently validated 5 ms parent route."""
    from . import _rex_legacy_irq_route_metadata_valid
    if profile is None or not fields_match(profile, (('grammar', 'lg-descriptor-low5-6x5-raw-v1'), ('function', 532844), ('prologue', 532846), ('descriptor_pointer',
        25396212), ('global_sense_sites',[532882]), ('row_sense_sites',[533176, 533204]), ('event_sink_validation', 'validated-raw-enqueue-callsites'))):
        return None, None
    bridge = profile.get("timer_bridge")
    if not isinstance(bridge, dict) or (bridge.get("signature") != "legacy-rex-5ms-scanner-timer-v1" or bridge.get("tick_ms") != 5 or bridge.get("scanner") !=
        profile["function"]):
        return None, "scanner-timer-bridge-unclosed"
    route = bridge.get("irq_route")
    if not isinstance(route, dict) or (not fields_match(route, (('signature', 'legacy-rex-5ms-irq-route-v1'), ('controller_class',
        'legacy-c80-three-bank-group14-v1'), ('status', 50334848), ('enable', 50334868), ('mask', 512), ('vector', 24), ('index', 43), ('status_bank_count', 3),
        ('group_row_size', 14), ('status_banks', (50334848, 50334852, 50334896)), ('clear_banks', (50334848, 50334852, 50334924)), ('controller_write_banks', (50334868,
        50334872, 50334916)), ('controller_aperture', (50334848, 50334926)))) or not _rex_legacy_irq_route_metadata_valid(route)):
        return None, "scanner-c80-route-unclosed"
    fields = ("vector_target", "wrapper", "handler_slot", "handler", "handler_validation_size", "callback_slot", "outer_callback", "wrapper_file_offset",
        "wrapper_validation_size", "handler_file_offset",)
    if any(type(route.get(field)) is not int for field in fields):
        return None, "scanner-c80-route-unclosed"
    ram_base = getattr(config, "ram_base", None)
    ram_size = getattr(config, "ram_size", None)
    flash_size = getattr(config, "flash_size", None)
    handler_file = int(route["handler_file_offset"])
    handler_size = int(route["handler_validation_size"])
    wrapper_size = int(route["wrapper_validation_size"])
    if (getattr(config, "load_address", None) != 0 or ram_base != 0x01800000 or ram_size != 0x00800000 or type(flash_size) is not int or flash_size <= 0 or
        route["vector_target"] != ram_base or not 0 <= int(route["handler_slot"]) <= 0xFFFFFFFF - 4 or not ram_base <= int(route["handler_slot"]) <= ram_base +
        ram_size - 4 or not ram_base <= int(route["callback_slot"]) <= ram_base + ram_size - 4 or route["callback_slot"] & 3 or route["handler_slot"] & 3 or not
        0 <= handler_file <= flash_size - handler_size or not 0 <= int(route["wrapper_file_offset"]) <= flash_size - wrapper_size or not 0 <= int(bridge.get("outer_callback_file_offset",
        -1)) < flash_size or route["outer_callback"] != bridge.get("outer_callback") or route["outer_callback"] != bridge.get("outer_callback_file_offset") or
        route["wrapper"] != route["wrapper_file_offset"]):
        return None, "scanner-c80-route-outside-memory"
    overlay = [item for item in getattr(config, "overlays", ()) if all(type(getattr(item, name, None)) is int for name in ("source", "target", "size")) and item.source
        <= handler_file and handler_file + handler_size <= item.source + item.size and item.target + handler_file - item.source == route["handler"]]
    if len(overlay) != 1:
        return None, "scanner-c80-handler-overlay-unclosed"
    values = (int(route["status"]), int(route["enable"]), int(route["mask"]), int(bridge["tick_ms"]) * 1_000_000, int(route["vector_target"]), int(route["wrapper"]),
        int(route["handler_slot"]), int(route["handler"]), handler_size, int(route["callback_slot"]), int(route["outer_callback"]), 3,)
    return "rex-static-c80=" + ":".join(f"{value:x}" for value in values), None

def qemu_sv130_initial_ram_seed(image: bytes, config: object, profile: dict[str, object] | None, rex_property: str | None, *, enabled: bool,) -> tuple[int, int,
    int] | None:
    """Return the validated SV130 RAM-seed source and destination range.

    This is intentionally opt-in and bound to the exact low-five scanner/C80
    route. The segment must be the complete detector-qualified RAM tail, and
    its initial vector branch must point at the route's checked wrapper.
    """
    from . import qemu_low5_matrix_property, qemu_low5_rex_c80_property, struct, sv130_keypad_source
    if type(enabled) is not bool or not enabled or profile is None:
        return None
    if (not sv130_keypad_source(image, config, profile) or getattr(config, "load_address", None) != 0 or getattr (config, "image_offset", None) != 0 or getattr(config,
        "entry", None) != 0 or getattr(config, "flash_size", None) != 0x01800000 or getattr(config, "ram_base", None) != 0x01800000 or getattr(config,
        "ram_size", None) != 0x00800000 or getattr(config, "ram_image_offset", None) != 0x01800000 or getattr(config, "ram_image_size", None) != 0x00800000 or
        len(image) != 0x02000000):
        return None
    low5_property, _ = qemu_low5_matrix_property(image, config, profile)
    expected_rex, _ = qemu_low5_rex_c80_property(config, profile)
    if (low5_property != "matrix-low5=18383f4:82194:822ba:822d6" or expected_rex is None or rex_property != expected_rex):
        return None
    fields = expected_rex.partition("=")[2].split(":")
    try:
        values = tuple(int(field, 16) for field in fields)
    except ValueError:
        return None
    if (len(values) != 12 or values[0:6] != (0x03000c80, 0x03000c94, 0x0200, 5_000_000, 0x01800000, 0x3460) or values[-1] != 3):
        return None
    seed_offset, seed_size, seed_base = (config.ram_image_offset, config.ram_image_size, config.ram_base)
    if (not 0 <= seed_offset <= len(image) - seed_size or seed_offset + seed_size != len(image) or seed_base + seed_size > 0x02000000):
        return None
    word = struct.unpack_from("<I", image, seed_offset)[0]
    if word & 0xff000000 != 0xea000000:
        return None
    displacement = (word & 0x00ffffff) << 2
    if displacement & (1 << 25):
        displacement -= 1 << 26
    if (seed_base + 8 + displacement) & 0xffffffff != values[5]:
        return None
    return seed_offset, seed_size, seed_base

def qemu_mapped_scan_gate_property(image: bytes, config: object, matrix: dict) -> tuple[str | None, str | None]:
    """Qualify provisional scan levels without assigning physical contact roles."""
    from . import _required_board_contact_matrix_status_matches, eeprom_gpio_profile, qemu_board_revision_property, qemu_ready_poll_property, struct
    gates = matrix.get("scan_gates")
    if (config.load_address != 0 or not isinstance(gates, dict) or gates.get("grammar") != "mapped-halfword-contact-status-gates-v1" or gates.get("promotion")
        != "temporary-evidence-gated" or gates.get("runtime_admitted") is not False or gates.get("physical_role", False) is not None or gates.get ("default_level",
        False) is not None):
        return None, "unclosed-mapped-scan-gates"
    contract = {"contact_mask": 16, "status_mask": 2, "contact_pointer_offset": 0x34, "configuration_pointer_offset": 8, "status_pointer_offset": 0x24,
        "contact_width": 2, "status_width": 2, "status_state_offset": 8, "status_set_bit_state": 0, "status_clear_bit_state": 1}
    if any(type(gates.get(k)) is not int or gates[k] != v for k, v in contract.items()):
        return None, "invalid-mapped-gate-contract"
    try:
        sink = int(matrix.get("queue_sink", ""), 16)
    except (TypeError, ValueError):
        return None, "mapped-gate-sink-mismatch"
    descriptor, state = gates.get("descriptor"), gates.get("scanner_state")
    if (descriptor != matrix.get("descriptor") or type(gates.get("queue_sink")) is not int or gates["queue_sink"] != sink or any(type(p) is not int or p & 3 or
        not config.ram_base <= p <= config.ram_base + config.ram_size - n for p, n in ((descriptor, 0x38), (state, 0x20))) or descriptor < state + 0x20 and
        state < descriptor + 0x38):
        return None, "mapped-gate-state-mismatch"
    spans = gates.get("ram_spans")
    if (not isinstance(spans, list) or not spans or any(not isinstance(span, (list, tuple)) or len(span) != 2 or any(type(value) is not int for value in span)
        or span[1] <= 0 or not config.ram_base <= span[0] <= config.ram_base + config.ram_size - span[1] for span in spans)):
        return None, "mapped-gate-ram-spans-mismatch"
    ordered = sorted(tuple(span) for span in spans)
    if ((descriptor, 0x38) not in ordered or (state, 0x20) not in ordered or any(start + size > following[0] for (start, size), following in zip(ordered,
        ordered[1:]))):
        return None, "mapped-gate-ram-spans-mismatch"
    sites = (gates.get("contact_site"), gates.get("status_site"), matrix.get("presence_site"), matrix.get("sense_site"))
    extent = min(len(image), config.flash_size)
    if (any(type(p) is not int or p & 1 or not 2 <= p <= extent - 2 for p in sites) or len(set(sites)) != 4 or not 0 <= sink <= extent - 2 or image[sites[0]-2:sites[0]+2]
        != bytes.fromhex("706b0088") or image[sites[1]-2:sites[1]+2] != bytes.fromhex("406a0088")):
        return None, "mapped-gate-site-mismatch"
    copy = matrix.get("descriptor_copy")
    if not isinstance(copy, dict):
        return None, "unclosed-mapped-gate-copy"
    rom, source, target, size = (copy.get(k) for k in ("descriptor_rom", "source", "target", "size"))
    if (any(type(p) is not int for p in (rom, source, target, size)) or (rom | source | target) & 3 or size < 0x38 or not 0 <= source <= extent - size or not
        config.ram_base <= target <= config.ram_base + config.ram_size - size or copy.get("descriptor_ram") != descriptor or not target <= descriptor <= target
        + size - 0x38 or rom != source + descriptor - target or[struct.unpack_from("<I", image, rom + off)[0] for off in (8, 0x24, 0x34)] !=[0x0300072c,
        0x03000728, 0x0300072c]):
        return None, "unclosed-mapped-gate-copy"
    status_owner = getattr(config, 'board_status_input', None)
    if not _required_board_contact_matrix_status_matches(image, status_owner, gates, sites[1]):
        return None, 'conflicting-status-profile'
    revision, _ = qemu_board_revision_property(config)
    ready = getattr(config, "ready_poll", None)
    ready_property, _ = qemu_ready_poll_property(ready)
    for address in (0x03000728, 0x0300072c):
        if (revision and config.board_revision_register < address + 2 and config.board_revision_register + 4 > address):
            return None, "mapped-gate-mmio-owner-conflict"
        if (ready_property and not ready_property.startswith("lcd-status-poll=") and any(type(ready.get(k)) is int and address <= ready[k] < address + 2 for k
            in ("status_address", "pulse_address", "control_address"))):
            return None, "mapped-gate-mmio-owner-conflict"
    eeprom, _ = eeprom_gpio_profile(image, config)
    if eeprom is None:
        return None, "mapped-gate-eeprom-owner-missing"
    base, data, data_mask, clock, clock_mask, direction, _ = eeprom
    if not base <= 0x03000728 < 0x0300072e <= base + 0x20:
        return None, "mapped-gate-eeprom-aperture-mismatch"
    for address, mask in ((0x03000728, 2), (0x0300072c, 16)):
        if any(base + offset == address and pins & mask for offset, pins in ((data, data_mask), (clock, clock_mask), (direction, data_mask))):
            return None, "mapped-gate-eeprom-pin-conflict"
    # Temporary scan-enabling policy verified through ordinary numeric UI input.
    # These levels do not identify a physical switch or its released default.
    contact = f"experimental-matrix-contact={sites[0]:x}:10"
    if status_owner is not None:
        return contact, None
    return f"{contact},experimental-matrix-status={sites[1]:x}:2", None

def qemu_halfword_matrix_property(image: bytes, config: object, profile: dict, *, enabled: bool = True) -> tuple[str | None, str | None]:
    """Serialize closed classes; explicit opt-in retains raw mapped gate backing."""
    from . import find_seven_row_scanners, qemu_mapped_scan_gate_property, struct
    grammar = profile.get("grammar")
    if grammar == "indirect-halfword-seven-row-ring32-v1":
        if (config.load_address != 0 or profile not in find_seven_row_scanners(image) or not config.ram_base <= profile["descriptor"] <= config.ram_base +
            config.ram_size - 0x38):
            return None, "seven-row-source-mismatch"
        return "matrix-halfword=" + ":".join(f"{profile[k]:x}" for k in
            ("descriptor", "presence_site", "sense_site", "row_select_mask")), None
    automatic_mapped = (not enabled and grammar == "indirect-halfword-mapped-row-v1" and isinstance(profile.get("scan_gates"), dict))
    if not enabled and not automatic_mapped and not (grammar == "indirect-halfword-loop-six-row-v1" and profile.get("promotion") == "temporary-evidence-gated"):
        return None, "experimental-only-halfword-profile"
    if grammar not in ("indirect-halfword-six-row-v1", "indirect-halfword-mapped-row-v1", "indirect-halfword-loop-six-row-v1"):
        return None, "unsupported-halfword-grammar"
    descriptor = profile.get("descriptor")
    sites = (profile.get("presence_site"), profile.get("sense_site"))
    if (type(descriptor) is not int or descriptor & 3 or not config.ram_base <= descriptor <= config.ram_base + config.ram_size - 0x38 or any(type(site) is not
        int or site & 1 or not 0 <= site < config.flash_size - 2 for site in sites)):
        return None, "outside-memory-map"
    if grammar == "indirect-halfword-loop-six-row-v1":
        if (not fields_match(profile, (('rows', 6), ('columns', 4), ('no_key', 31), ('single_key_column_sense',[30, 29, 27, 23])))):
            return None, "invalid-loop-row-contract"
        if getattr(config, "board_status_input", None) is not None:
            return None, "conflicting-status-profile"
        contact = profile.get("contact_site")
        all_sites = (contact, *sites)
        if (any(type(site) is not int or site & 1 or site < 2 or site + 2 > min(len(image), config.flash_size) for site in all_sites) or len(set(all_sites)) !=
            3 or any(image[site-2:site+2] != bytes.fromhex("686b0088") for site in all_sites)):
            return None, "sense-load-shape-mismatch"
        copied = profile.get("copied_descriptor")
        copy = profile.get("descriptor_copy")
        if (type(copied) is not int or copied & 3 or not isinstance(copy, dict) or copy.get("target") != copied or type(copy.get("size")) is not int or not 0x38
            <= copy["size"] <= 0x100 or not config.ram_base <= copied <= config.ram_base + config.ram_size - copy["size"] or type(copy.get("source")) is not int
            or copy["source"] & 3 or not 0 <= copy["source"] <= min(len(image), config.flash_size) - copy["size"] or type(copy.get("copy_loop")) is not int or
            copy["copy_loop"] & 1 or not 0 <= copy["copy_loop"] < min(len(image), config.flash_size)):
            return None, "unclosed-descriptor-copy"
        if[struct.unpack_from("<I", image, copy["source"] + off)[0] for off in (0, 8, 0x20, 0x34)] !=[0x3000720, 0x300072c, 0x3000728, 0x300072c]:
            return None, "descriptor-port-mismatch"
        return f"matrix-halfword-loop={descriptor:x}:{contact:x}:{sites[0]:x}:{sites[1]:x}", None
    value = f"matrix-halfword={descriptor:x}:{sites[0]:x}:{sites[1]:x}"
    if grammar == "indirect-halfword-mapped-row-v1":
        mask = profile.get("row_select_mask")
        if (type(mask) is not int or not 0 < mask <= 65535 or mask.bit_count() != 7 or (not fields_match(profile, (('rows', 7), ('columns', 4), ('no_key', 15),
            ('single_key_column_sense',[14, 13, 11, 7])))) or (profile.get('row_select_bits') !=[bit for bit in range(16) if mask & 1 << bit])):
            return None, "invalid-mapped-row-contract"
        if (sites[0] == sites[1] or any(site < 2 or site + 2 > len(image) or image[site - 2:site + 2] != bytes.fromhex("706b0088") for site in sites)):
            return None, "sense-load-shape-mismatch"
        value += f":{mask:x}"
        if automatic_mapped:
            gates, reason = qemu_mapped_scan_gate_property(image, config, profile)
            if gates is None:
                return None, reason
            value += "," + gates
    return value, None

def qemu_distributed_sideband_producer(image: bytes, config: object, profile: dict) -> tuple[dict | None, str | None]:
    """Optional electrical producer must agree with the same source queue."""
    from . import _samsung_sideband_51_family_metadata
    raw = profile.get("sideband_producers")
    if raw is None:
        reasons = profile.get("sideband_detection_reject_reasons", ())
        if not isinstance(reasons, (list, tuple)):
            return None, "invalid-sideband-rejection-reasons"
        return None, (";".join(map(str, reasons)) if reasons else None)
    if (profile.get("grammar") != "distributed-six-byte-numeric-v1" or config.load_address != 0 or profile.get("sideband_detection_status") != "accepted" or not
        isinstance(raw, list) or len(raw) != 1 or not isinstance(raw[0], dict)):
        return None, "invalid-distributed-sideband"
    producer = raw[0]
    integers = ("semantic_key", "event", "event_register", "register", "register_width", "mask", "press_callsite", "release_event", "release_callsite",
        "event_sink")
    queue = profile.get("producer")
    sites = (profile.get("function"), profile.get("sense_site"), queue.get("enqueue") if isinstance(queue, dict) else None)
    if (any(type(site) is not int or site & 1 or not 0 <= site <= min(len(image), config.flash_size) - 4 for site in sites) or any(type(producer.get(key)) is
        not int for key in integers)):
        return None, "invalid-sideband-source-bounds"
    expected = _samsung_sideband_51_family_metadata(image[:min(len(image), config.flash_size)], *sites, 0)
    if expected.get("sideband_producers") != raw:
        return None, "sideband-source-contract-mismatch"
    release_sites = producer.get("release_callsites",[producer["release_callsite"]])
    events = profile.get("event_codes")
    if (not isinstance(release_sites, list) or not isinstance(events, (list, tuple)) or any(type(site) is not int or site & 1 or not 0 <= site <= min(len(image),
        config.flash_size) - 4 for site in [producer["press_callsite"], *release_sites]) or producer["register"] != profile.get("register") or producer["event"]
        in events):
        return None, "sideband-source-ownership-conflict"
    return dict(producer), None

def qemu_distributed_matrix_property(image: bytes, config: object, profile: dict) -> tuple[str | None, str | None]:
    """Temporary numeric-only byte class; GPIO ownership stays with native devices."""
    from . import facts_for, qemu_distributed_sideband_producer
    if (not fields_match(profile, (('grammar', 'distributed-six-byte-numeric-v1'), ('rows', 6), ('columns', 4), ('register_width', 1), ('no_key', 15), ('single_key_column_sense',[14,
        13, 11, 7]))) or config.load_address != 0):
        return None, "unsupported-distributed-contract"
    ports = profile.get("gpio_ports")
    if (not isinstance(ports, list) or len(ports) != 3 or any(not isinstance(port, dict) or type(port.get("address")) is not int or type(port.get("mask")) is
        not int or not 0 < port["mask"] <= 255 for port in ports)):
        return None, "invalid-gpio-ports"
    base = ports[0]["address"] - 12
    address = profile.get("register")
    masks = [port["mask"] for port in ports]
    if (not 0x03000000 <= base <= 0x03001000 - 53 or base & 31 or type(address) is not int or address != base + 52 or[p["address"] for p in ports] !=[base + n
        for n in (12, 8, 4)]):
        return None, "invalid-gpio-ports"
    rows = []
    for index, mask in enumerate(masks):
        for bit in range(8):
            if mask & (1 << bit):
                values = masks.copy()
                values[index] &= ~(1 << bit)
                rows.append(values)
    if (len(rows) != 6 or profile.get("row_values") != rows or profile.get("global_values") !=[0, 0, 0]):
        return None, "invalid-gpio-row-order"
    producer = profile.get("producer", {})
    if (not isinstance(producer, dict) or not fields_match(producer, (('family', 'distributed-filtered-byte-ring32-v1'), ('slots', 32), ('wrap_mask', 31)))):
        return None, "unclosed-ring-profile"
    spans = [(profile.get("scanner_state"), 0xA), (profile.get("batch_state"), 0xE), (producer.get("state"), 0x34), (producer.get("ring"), 34)]
    spans +=[(port.get("shadow"), 1) for port in ports]
    if (any(type(start) is not int or not config.ram_base <= start <= config.ram_base + config.ram_size - size for start, size in spans) or len({port["shadow"]
        for port in ports}) != 3):
        return None, "state-outside-ram"
    sites = (profile.get("presence_site"), profile.get("sense_site"))
    if (any(type(site) is not int or site & 1 or not 2 <= site <= min(len(image), config.flash_size) - 2 for site in sites) or sites[0] == sites[1]):
        return None, "sense-outside-primary-nor"
    for site, instruction in zip(sites, (b"\x01\x79", b"\x00\x79")):
        if (image[site:site + 2] != instruction or facts_for(image).thumb_literal_value(site - 2, 0) != address - 4):
            return None, "sense-load-shape-mismatch"
    status = getattr(config, "board_status_input", None)
    if status is not None and status.address in [address] +[p["address"] for p in ports]:
        return None, "conflicting-status-profile"
    fields = [address, *sites]
    for port in ports:
        fields.extend((port["address"], port["mask"]))
    sideband, reject = qemu_distributed_sideband_producer(image, config, profile)
    if sideband is not None:
        fields.append(sideband["mask"])
    return "matrix-gpio=" + ":".join(f"{value:x}" for value in fields), reject

def qemu_seven_row_matrix_property(image: bytes, config: object, profile: dict) -> str:
    """Seven physical drive wires; native pin order is independent of scan order.

    """
    from . import find_seven_row_input_profile
    verified, reason = find_seven_row_input_profile(image, config.load_address)
    if verified != profile or reason != "accepted":
        raise ValueError("seven-row GPIO profile no longer matches source")
    fields = [profile["register"], profile["presence_site"], profile["sense_site"]]
    for port in profile["gpio_ports"]:
        fields.extend((port["address"], port["mask"]))
    fields.append(profile["sideband_input"]["mask"])
    return "matrix-gpio=" + ":".join(f"{value:x}" for value in fields)
