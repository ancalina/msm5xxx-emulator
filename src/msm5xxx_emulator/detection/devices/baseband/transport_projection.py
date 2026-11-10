"""Source-qualified machine properties owned by this device domain."""
from __future__ import annotations

def qemu_virtual_cell_property(image: bytes, config: object, scenario: object) -> tuple[str | None, str | None]:
    """Bind an explicit experimental cell to this image; never enable SIP."""
    if scenario is None:
        return None, None
    required = {"pilot_phase", "raw_energy", "virtual_delay_ns", "decoder_init_delay_ns", "sync_message_hex", "paging_messages_hex"}
    fields = {"sid": ((0, 32, 15), (1, 31, 15)), "nid": ((0, 47, 16), (1, 46, 16)), "channel": ((0, 167, 11), (4, 31, 11))}
    if (not isinstance(scenario, dict) or not required <= scenario.keys() or scenario.keys() - required - fields.keys() - { "tx_init_delay_ns",
        "tx_frame_period_ns", "access_response_probe", "access_assignment_code", "traffic_decoder_probe", "traffic_frame_hex", "allow_receive_only"}):
        raise ValueError("invalid virtual cell fields")
    allow_receive_only = scenario.get("allow_receive_only", False)
    if type(allow_receive_only) is not bool:
        raise ValueError("invalid virtual cell allow_receive_only")
    access_response = scenario.get("access_response_probe", False)
    if type(access_response) is not bool:
        raise ValueError("invalid experimental access_response_probe")
    if access_response and "tx_frame_period_ns" not in scenario:
        raise ValueError("experimental access_response_probe requires tx_frame_period_ns")
    assignment_code = scenario.get("access_assignment_code", 0)
    if type(assignment_code) is not int or not 0 <= assignment_code <= 128:
        raise ValueError("invalid experimental access_assignment_code")
    if assignment_code and not access_response:
        raise ValueError("experimental access_assignment_code requires access_response_probe")
    traffic_decoder = scenario.get("traffic_decoder_probe", False)
    if type(traffic_decoder) is not bool:
        raise ValueError("invalid experimental traffic_decoder_probe")
    if traffic_decoder and not assignment_code:
        raise ValueError("experimental traffic_decoder_probe requires access_assignment_code")
    traffic_frame = None
    if "traffic_frame_hex" in scenario:
        value = scenario["traffic_frame_hex"]
        if (type(value) is not str or (value != "auto" and (len(value) != 48 or any(char not in "0123456789abcdefABCDEF" for char in value) or value[-2:] !=
            "00"))):
            raise ValueError("invalid virtual cell traffic_frame_hex")
        if traffic_decoder is not True:
            raise ValueError("traffic_frame_hex requires traffic_decoder_probe")
        traffic_frame = value.lower()
    tx_delay = scenario.get("tx_init_delay_ns")
    if "tx_init_delay_ns" in scenario and (type(tx_delay) is not int or not 1 <= tx_delay <= 1000000000):
        raise ValueError("invalid virtual cell tx_init_delay_ns")
    tx_period = scenario.get("tx_frame_period_ns")
    if "tx_frame_period_ns" in scenario:
        if type(tx_period) is not int or not 1 <= tx_period <= 1000000000:
            raise ValueError("invalid virtual cell tx_frame_period_ns")
        if "tx_init_delay_ns" not in scenario:
            raise ValueError("tx_frame_period_ns requires tx_init_delay_ns")
    for name, sites in fields.items():
        if name in scenario and (type(scenario[name]) is not int or not 0 <= scenario[name] < 1 << sites[0][2]):
            raise ValueError(f"invalid virtual cell {name}")
    for key, maximum in (("pilot_phase", 0x3ffff), ("raw_energy", 0xffff), ("virtual_delay_ns", 1000000000), ("decoder_init_delay_ns", 1000000000)):
        value = scenario[key]
        minimum = 1 if key.endswith("_ns") else 0
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError(f"invalid virtual cell {key}")
    if scenario["decoder_init_delay_ns"] != 80000000:
        raise ValueError("virtual cell sync requires an 80ms decoder initialization")
    from msm5xxx_emulator.detection.devices.baseband.rules import find_legacy_cdma_profile
    legacy_profile = find_legacy_cdma_profile(image)
    if legacy_profile.get("accepted"):
        from .virtual_cell import virtual_cell_scenario
        # The announced time may differ (host clock); the rest must be the stock cell.
        def without_time(cell):
            return {key: value for key, value in cell.items() if key != "sync_message_hex"}
        if without_time(scenario) == without_time(virtual_cell_scenario(True)):
            sid, channel = ((17500, 750) if legacy_profile["pll_bits"] == 22 else (4120, 625))
            scenario = {**scenario, "sid": sid, "channel": channel, "pilot_phase": 0x20080}
    def crc30(value, bits):
        crc = 0x3fffffff
        for bit in range(bits - 1, -1, -1):
            feedback = ((crc >> 29) ^ (value >> bit)) & 1
            crc = ((crc << 1) ^ (0x6030b9c7 if feedback else 0)) & 0x3fffffff
        return (~crc) & 0x3fffffff
    def packet(value, maximum, message_type):
        if not isinstance(value, str) or not 10 <= len(value) <= maximum * 2:
            raise ValueError("invalid virtual cell packet")
        try:
            data = bytes.fromhex(value)
        except ValueError:
            raise ValueError("invalid virtual cell packet") from None
        if len(data) < 5 or len(data) > maximum or data[0] != len(data):
            raise ValueError("invalid virtual cell packet length")
        if data[1] not in ((message_type,) if isinstance(message_type, int) else message_type):
            raise ValueError("invalid virtual cell message type")
        if crc30(int.from_bytes(data, "big"), len(data) * 8) != 0x0b105aa5:
            raise ValueError("invalid virtual cell packet CRC")
        return data.hex()
    sync = packet(scenario["sync_message_hex"], 147, 1)
    messages = scenario["paging_messages_hex"]
    if not isinstance(messages, (list, tuple)) or len(messages) != 4:
        raise ValueError("virtual cell requires four paging messages")
    paging_messages = [packet(value, 255, (3, 14) if legacy_profile.get("accepted") and index == 2 else index + 1) for index, value in enumerate(messages)]
    if access_response or scenario.keys() & fields.keys():
        packets = [bytes.fromhex(value) for value in (sync, *paging_messages)]
        # Longer System messages enable extra firmware features; preserve this layout.
        if tuple(map(len, packets)) != (26, 33, 19, 9, 9) or packets[0][2] >= 6:
            if access_response:
                raise ValueError("experimental access_response_probe requires legacy packet layout")
            raise ValueError("unsupported virtual cell field layout")
        for name, sites in fields.items():
            if name not in scenario:
                continue
            for index, bit, width in sites:
                data = packets[index]
                bits = len(data) * 8
                shift = bits - bit - width
                value = int.from_bytes(data, "big")
                value = (value & ~(((1 << width) - 1) << shift)) | (scenario[name] << shift)
                prefix = value >> 30
                packets[index] = ((prefix << 30) | crc30(prefix, bits - 30)).to_bytes(len(data), "big")
        sync, *paging_messages = [value.hex() for value in packets]
    if (getattr(config, "load_address", None) != 0 or getattr(config, "image_offset", None) != 0):
        return None, "primary-map-unsupported"
    if legacy_profile.get("accepted"):
        if c80_rex_irq_profile(config, False) is None:
            return None, "legacy-c80-route-unavailable"
        if not allow_receive_only and (tx_delay is not None or access_response or traffic_decoder):
            return None, "legacy-receive-only"
        packets = [bytearray.fromhex(value) for value in (sync, *paging_messages)]
        if tuple(map(len, packets)) != (26, 33, 19, 9, 9):
            return None, "legacy-cell-layout-unsupported"
        def replace(packet_data, start, width, value):
            bits = len(packet_data) * 8
            shift = bits - start - width
            number = int.from_bytes(packet_data, "big")
            number = (number & ~(((1 << width) - 1) << shift)) | (value << shift)
            prefix = number >> 30
            return bytearray(((prefix << 30) | crc30(prefix, bits - 30)).to_bytes(len(packet_data), "big"))
        packets[0] = replace(replace(packets[0], 16, 8, 1), 24, 8, 1)
        packets[3] = replace(packets[3], 8, 8, 14)
        channel = (int.from_bytes(packets[0], "big") >> (26 * 8 - 167 - 11)) & 0x7ff
        # The legacy decoder clocks SYS_TIME from this epoch; take it from the Sync packet.
        sys_time = (int.from_bytes(packets[0], "big") >> (26 * 8 - 114 - 36)) & ((1 << 36) - 1)
        if channel > 1199:
            return None, "legacy-pcs-channel-unsupported"
        profile_keys = ("writer", "consumer", "descriptor", "decoder", "fifo_copy", "sync_mode", "paging_mode", "pll_bits", "pll")
        words = lambda values: ":".join(format(value, "x") for value in values)
        properties = ["legacy-cdma=on", "legacy-profile=" + words(legacy_profile[key] for key in profile_keys), "legacy-search=" + words((scenario["pilot_phase"],
            scenario["raw_energy"], legacy_profile["mask_i"], legacy_profile["mask_q"], channel)), "legacy-decoder=" + format(sys_time, "x") + ":" + ":".join(packet.hex()
            for packet in packets),]
        limited = "legacy-receive-only" if tx_delay is not None or access_response or traffic_decoder else None
        return ",".join(properties), limited
    if getattr(config, "rex_static_controller_experimental", False):
        return None, "controller-mode-unsupported"
    from msm5xxx_emulator.detection.devices.baseband.rules import find_search1_transport_profile, find_search1_abort_profile, find_finger_transport_profile, find_decoder_init_profile, find_combiner_clock_profile, find_paging_decoder_profile
    timer = find_rex_5ms_sleep_timer(image)
    if timer is None or timer[1] != getattr(config, "rex_tick_address", None):
        return None, "tick-image-mismatch"
    tick = timer[1]
    profiles = []
    for finder in (find_search1_transport_profile, find_search1_abort_profile, find_finger_transport_profile, find_decoder_init_profile,
        find_combiner_clock_profile, find_paging_decoder_profile):
        profile = finder(image, tick)
        if profile.get("accepted") is not True:
            return None, str(profile.get("reject_reason", "protocol-unmatched"))
        profiles.append(profile)
    legacy, abort, finger, decoder, clock, paging = profiles
    transport = legacy["shared_search2_profile"]
    def words(values):
        return ":".join(format(value, "x") for value in values)
    route = [transport["write_sites"][0], transport["consumer"]["loop_file_offset"], transport["irq_callback_slot"], transport["callback"], transport["task"],
        transport["irq_handler_slot"], transport["irq_handler"], transport["irq_wrapper"], transport["irq_mask"], scenario["virtual_delay_ns"], scenario["pilot_phase"],
        scenario["raw_energy"]]
    properties = ["search2-virtual=" + words(route), "search1-virtual=" + words([legacy["first_store"], legacy["consumer"]["loop_file_offset"], abort["first_store"]]),
        "finger-virtual=" + words([finger["rss_word_read"], *finger["mask_tables"]]), "decoder-init-probe=" + words([decoder["reader"], decoder["init_write"],
        decoder["isr"], scenario["decoder_init_delay_ns"]]), "decoder-sync-source=" + words([clock["position_getter"], clock["roll_isr"], clock["sync_consumer"]])
        + ":" + sync, "decoder-paging-source=" + words([paging[key] for key in ("isr", "reader", "status_reader", "initializer", "wordcount_address", "consumer",
        "pipeline_cache", "pipeline_layout")]) + ":" + ":".join(paging_messages),]
    receiver_properties = tuple(properties)
    def optional_unavailable(reason):
        if allow_receive_only:
            return ",".join(receiver_properties), "receive-only:" + reason
        return None, reason
    if tx_delay is not None:
        if tx_period is None:
            from msm5xxx_emulator.detection.devices.baseband.rules import find_tx_init_profile as find_tx_profile
        else:
            from msm5xxx_emulator.detection.devices.baseband.rules import find_tx_frame_profile as find_tx_profile
        tx = find_tx_profile(image, tick)
        if tx.get("accepted") is not True:
            return optional_unavailable(str(tx.get("reject_reason", "tx-init-unmatched")))
        flash = getattr(config, "flash_size", None)
        ram_base = getattr(config, "ram_base", None)
        ram_size = getattr(config, "ram_size", None)
        if (type(flash) is not int or flash <= 0 or any(not 0 <= offset <= min(flash, len(image)) - size for offset, size in tx["code_dependencies"])):
            return optional_unavailable("tx-init-code-unmapped")
        if (type(ram_base) is not int or type(ram_size) is not int or ram_size < 24 or tx["callback_slot"] & 3 or tx["tx_tcb"] & 3 or tx["counter_address"] & 1
            or tx["control_shadow"] & 1 or any(not ram_base <= address <= ram_base + ram_size - size for address, size in tx["ram_dependencies"])):
            return optional_unavailable("tx-init-state-unmapped")
        if (tx["callback_slot"] != transport["irq_callback_slot"] - 56 or tx["irq_mask"] != 8 or tx["irq_status"] != transport["irq_status"] or tx["irq_enable"]
            != transport["irq_enable"]):
            return optional_unavailable("tx-init-controller-mismatch")
        tx_fields = [tx["callback"], tx["callback_slot"], tx["armed_flag"], tx["tx_tcb"], tx["signal10_call"], tx["control_helper"], tx["registrations"][0],
            tx_delay]
        if tx_period is not None:
            tx_fields.extend((tx_period, tx["mode_base"], tx["fixed_writer"]))
        properties.append("tx-init-probe=" + words(tx_fields))
    if access_response:
        properties.append("access-response-probe=on")
    if assignment_code:
        properties.append(f"access-assignment-code={assignment_code:x}")
    service_source = None
    service_limit = None
    if traffic_decoder:
        from msm5xxx_emulator.detection.devices.baseband.rules import find_traffic_decoder_profile
        traffic = find_traffic_decoder_profile(image, tick)
        if traffic.get("accepted") is not True:
            return optional_unavailable(str(traffic.get("reject_reason", "traffic-decoder-unmatched")))
        flash = getattr(config, "flash_size", None)
        ram_base = getattr(config, "ram_base", None)
        ram_size = getattr(config, "ram_size", None)
        if (type(flash) is not int or flash <= 0 or any(not 0 <= offset <= min(flash, len(image)) - size for offset, size in traffic["code_dependencies"])):
            return optional_unavailable("traffic-decoder-code-unmapped")
        if (type(ram_base) is not int or type(ram_size) is not int or ram_size < 48 or any(not ram_base <= address <= ram_base + ram_size - size for address,
            size in traffic["ram_dependencies"])):
            return optional_unavailable("traffic-decoder-state-unmapped")
        if any(traffic[key] != decoder[key] for key in ("descriptor_template", "irq_callback_slot", "irq_status", "irq_enable", "irq_mask")):
            return optional_unavailable("traffic-decoder-controller-mismatch")
        if traffic_frame is not None:
            layout_source = traffic["layout_source"]
            if (type(layout_source) is not int or not 0 <= layout_source <= min(flash, len(image)) - 13):
                return optional_unavailable("traffic-full-frame-layout-unsupported")
            if traffic_frame == "auto":
                traffic_frame = ("00000000000000000000000000000000000000000003d700" if image[layout_source + 12] == 24 else None)
                if traffic_frame is not None:
                    from msm5xxx_emulator.detection.devices.baseband.service import find_origination_service_profile
                    service = find_origination_service_profile(image, ram_base, ram_size)
                    if service.get("accepted") is not True:
                        service_limit = str(service.get("reject_reason", "service-packer-unmatched"))
                    elif any(not 0 <= offset <= min(flash, len(image)) - size for offset, size in service["code_dependencies"]):
                        service_limit = "service-packer-code-unmapped"
                    elif any(not ram_base <= address <= ram_base + ram_size - size for address, size in service["ram_dependencies"]):
                        service_limit = "service-packer-state-unmapped"
                    else:
                        service_source = words(service[key] for key in ("entry", "header_packer", "dispatcher", "revision_address"))
                        traffic_frame = None
            elif image[layout_source + 12] != 24:
                return optional_unavailable("traffic-full-frame-layout-unsupported")
        properties.append("decoder-traffic-source=" + words([traffic[key] for key in ("isr", "reader", "status_reader", "initializer", "mode_base",
            "layout_address", "layout_source", "linker_table_offset")]))
        if service_source is not None:
            properties.append("traffic-service-source=" + service_source)
        elif traffic_frame is not None:
            properties.append("decoder-traffic-frame=" + traffic_frame)
    return ",".join(properties), service_limit

# Required evidence providers are bound by registry discovery.
REQUIRES = {'c80_rex_irq_profile': ('rex.transport_projection', 'c80_rex_irq_profile'), 'find_rex_5ms_sleep_timer': ('rex.rules', 'find_rex_5ms_sleep_timer')}
