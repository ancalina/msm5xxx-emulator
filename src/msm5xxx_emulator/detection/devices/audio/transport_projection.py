"""Source-qualified machine properties owned by this device domain."""
from __future__ import annotations
from msm5xxx_emulator.detection.contracts import fields_match
from msm5xxx_emulator.detection.devices.audio.rules import (_KP6200_MA3_SITES, _SV130_MA3_SITES, find_audio_transport, find_ma5_readback_candidate)
from msm5xxx_emulator.detection.devices.audio.ma5_gpio_irq import find_ma5_gpio_irq_candidate
from msm5xxx_emulator.detection.devices.audio.ma3_gpio_irq import find_ma3_gpio_irq_candidate
AUDIO_SITE_LIMIT = 64

def qemu_audio_irq_property(audio: object, config: FirmwareConfig) -> tuple[str | None, str | None]:
    """Provisional route for owned MA2 accessors; native readback gates use."""
    if not isinstance(audio, dict) or audio.get('static_status') != 'accepted':
        return None, 'audio-transport-unavailable'
    route = audio.get('irq_controller_candidate')
    if (audio.get('family') != 'ma2' or audio.get('grammar') != 'ma2-command-v1' or not isinstance(route, dict) or route.get('status') != 'candidate' or route.get('profile')
        not in ('two-bank-callback-descriptor-v1', 'byte-count-halfword-mask-v1')):
        return None, 'descriptor-class-unavailable'
    link = route.get('callback_linkage')
    words = route.get('words')
    if (not isinstance(link, dict) or not isinstance(words, list) or len(words) != 7 or any(type(word) is not int for word in words)):
        return None, 'callback-linkage-unavailable'
    fields = [route.get('descriptor_address'), *words[:5], route.get('dispatcher_offset'), link.get('state_address'), link.get('table_address'), link.get('callback_offset')]
    read = link.get('data_read_offset')
    if (any(type(value) is not int or not 0 <= value <= 0xffffffff for value in fields) or type(read) is not int or config.load_address != 0 or read not in
        audio.get('sites', {}).get('read_2',[]) or any(not 0 <= address < config.flash_size or address & 1 for address in (fields[6], fields[9]))):
        return None, 'audio-route-mapping-unverified'
    start, end = config.ram_base, config.ram_base + config.ram_size
    if (any(not start <= fields[index] <= end - size or fields[index] % alignment for index, size, alignment in ((0, 28, 4), (4, 2, 2), (5, 2, 2), (7, 8, 4), (8,
        16, 4))) or fields[1:3] !=[0x03000624, 0x0300062c] or not 0 < fields[3] <= 0x8000 or fields[3] & (fields[3] - 1) or words[6] != 0 or not ((config.rex_irq_status_address
        == 0x03000620 and config.rex_irq_enable_address == 0x03000628) or (route.get('profile') == 'byte-count-halfword-mask-v1' and (w1c_rex_irq_profile(config)
        or '').startswith('3000620:3000628:')))):
        return None, 'audio-route-controller-unverified'
    suffix = ':1' if route.get('profile') == 'byte-count-halfword-mask-v1' else ''
    return 'audio-irq-route=' + ':'.join(f'{value:x}' for value in fields) + suffix, None

def qemu_ma3_gpio_irq_property(image: bytes, config: object, audio: object,) -> tuple[str | None, str | None]:
    """Serialize the statically closed SC GPIO23-to-parent route for native checks."""
    if (not isinstance(audio, dict) or not fields_match(audio, (('family', 'ma3'), ('grammar', 'ma3-indexed-v1'), ('static_status', 'accepted')))):
        return None, "ma3-audio-profile-unverified"
    if (getattr(config, "chipset", None) != "MSM5100" or getattr(config, "flash_size", None) != 0x01000000 or getattr(config, "ram_base", None) != 0x01000000 or
        getattr(config, "ram_size", None) != 0x00800000):
        return None, "ma3-ram-profile-unverified"
    candidate = find_ma3_gpio_irq_candidate(image)
    fields = candidate.get("fields") if candidate.get("status") == "candidate" else None
    if (candidate.get("profile") != "ma3-sc-gpio23-v1" or not isinstance(fields, list) or len(fields) != 11 or fields !=[0x17, 0x1D, 0x0100B914, 0x0129E278,
        0x0100B584, 0x00161F69, 0x00161BFC, 0x0009BB71, 0x2000, 0x03000C84, 0x03000C98]):
        return None, str(candidate.get("reject_reason") or "ma3-irq-route-unverified")
    return "ma3-gpio-irq=" + ":".join(f"{value:x}" for value in fields), None

def qemu_audio_packet_property(image: bytes, config: object, audio: object) -> tuple[str | None, str | None]:
    if (not isinstance(audio, dict) or audio.get("grammar") != "repeated-bit-sequence-v1"):
        return None, "protocol-unmatched"
    if (getattr(config, "load_address", None) != 0 or type(getattr(config, "flash_size", None)) is not int or config.flash_size < 0x1000):
        return None, "primary-nor-unmapped"
    if (audio.get("static_status") != "accepted" or find_audio_transport(image) != audio):
        return None, "same-image-contract-mismatch"
    spans = [(audio["begin"] - 6, 72), (audio["sequence_producer"], 86), (audio["timer_producer"], 170), (audio["timer_stop_producer"], 76), (audio["immediate_sender"],
        112), (audio["reset_producer"], 0xb0), (audio["status_consumers"][0] - 0x112, 0x112 + 138)]
    spans += audio["nor_dependencies"]
    if any(type(offset) is not int or not 0 <= offset <= config.flash_size - length for offset, length in spans):
        return None, "primary-nor-out-of-bounds"
    ram_base = getattr(config, "ram_base", None)
    ram_size = getattr(config, "ram_size", None)
    if (type(ram_base) is not int or type(ram_size) is not int or ram_size < 8 or any((size > 1 and address & 3) or not ram_base <= address <= ram_base +
        ram_size - size for address, size in audio["ram_dependencies"])):
        return None, "consumer-state-unmapped"
    clear = ",audio-packet-clear-pulse=on" if audio.get("control_clear_status") == "accepted" else ""
    return (f"experimental-audio-packet-bus={audio['begin']:x},"
            "audio-packet-sequence=on" + clear), None

def qemu_ma5_readback_property(image: bytes, config: object, byte_ns: int | None, *, upper_nor_present: bool = False, clki_hz: int | None = None, target_rate_hz:
    int | None = None,) -> tuple[str | None, str | None]:
    """Recheck the image for an explicit or temporary evidence-gated MA5 profile."""
    if clki_hz is not None and target_rate_hz is not None:
        raise ValueError("explicit CLKI and inferred target rate are mutually exclusive")
    if clki_hz is not None and (type(clki_hz) is not int or not 1 <= clki_hz <= 1_000_000_000 or byte_ns is None):
        raise ValueError("invalid experimental MA5 CLKI or missing byte period")
    if target_rate_hz is not None and (type(target_rate_hz) is not int or not 8000 <= target_rate_hz <= 96000 or byte_ns is None):
        raise ValueError("invalid experimental MA5 target rate or missing byte period")
    if byte_ns is None:
        return None, None
    if type(upper_nor_present) is not bool:
        raise ValueError("invalid upper NOR presence")
    if type(byte_ns) is not int or not 1 <= byte_ns <= 1_000_000_000:
        raise ValueError("invalid experimental MA5 byte service period")
    if (getattr(config, "load_address", None) != 0 or type(getattr(config, "flash_size", None)) is not int):
        return None, "primary-nor-unmapped"
    candidate = find_ma5_readback_candidate(image)
    if candidate["static_status"] != "candidate":
        return None, str(candidate["reject_reason"])
    audio = getattr(config, "audio_transport", None)
    if (audio is not None and audio.get("static_status") == "accepted" and (audio.get("family") != "ma5" or audio.get("grammar") != "indexed-rw-v1" or audio.get("base")
        != candidate["base"] or audio.get("data_offset") != candidate["data_offset"] or audio.get("sites") != candidate["sites"])):
        return None, "conflicting-audio-profile"
    if any(not 0 <= offset <= config.flash_size - length for offset, length in candidate["nor_dependencies"]):
        return None, "primary-nor-out-of-bounds"
    ram_base, ram_size = getattr(config, "ram_base", None), getattr(config, "ram_size", None)
    if (type(ram_base) is not int or type(ram_size) is not int or ram_size < 8 or any(not ram_base <= address <= ram_base + ram_size - length for address,
        length in candidate["ram_dependencies"])):
        return None, "consumer-state-unmapped"
    base, stride = candidate["base"], candidate["data_offset"]
    timed = candidate.get("structural_evidence", {}).get("transport_class") == "local-counter-direction-timing-v1"
    alternate_direct = (candidate.get("structural_evidence", {}).get("transport_class") == "alternate-direct-reset-readback-v1")
    shared_lcd = ((timed and stride == 4) or (alternate_direct and stride == 2)) and any(lcd <= base and base + stride < lcd + 0x1000 for lcd in (0x02000000,
        0x02800000, 0x02C00000, 0x02200000))
    if (not 0x02001000 <= base <= 0x02FFFF00 or not (stride in (2, 128) or (timed and stride == 4)) or base < config.flash_size or (upper_nor_present and base <
        UPPER_FLASH_ADDRESS + UPPER_FLASH_SIZE and base + stride + 1 > UPPER_FLASH_ADDRESS) or (base < ram_base + ram_size and base + stride + 1 > ram_base) or
        (not shared_lcd and any(base < lcd + 0x1000 and base + stride + 1 > lcd for lcd in (0x02000000, 0x02800000, 0x02C00000, 0x02200000)))):
        return None, "aperture-unmapped-or-conflicting"
    sites = candidate["sites"]
    entries = [f"{kind}{port:x}/{pc:x}"
               for key, kind, port in (("write_0", "w", 0), ("read_0", "r", 0),
                                       (f"write_{stride}", "w", stride),
                                       (f"read_{stride}", "r", stride))
               for pc in sites[key]]
    clock = "" if clki_hz is None else f",experimental-ma5-clki-hz={clki_hz}"
    target_rate = ("" if target_rate_hz is None else
                   f",experimental-ma5-target-rate-hz={target_rate_hz}")
    return (f"audio-aperture={base:x}:{stride:x}:ma5,"
            f"audio-sites={';'.join(entries)},experimental-ma5-byte-ns={byte_ns}"
            f"{clock}{target_rate}"), None

def qemu_ma5_temporary_auto_property(image: bytes, config: object, *, audio_pcm: bool, upper_nor_present: bool = False,) -> tuple[str | None, str | None]:
    """Select witnessed MA5 readback candidates with explicitly provisional timing."""
    if type(audio_pcm) is not bool:
        raise ValueError("invalid MA5 PCM request")
    if not audio_pcm:
        return None, None
    candidate = find_ma5_readback_candidate(image)
    if (candidate.get("static_status") != "candidate" or candidate.get("protocol_status") != "temporary-evidence-gated" or candidate.get("structural_evidence",
        {}).get("transport_class") != "ram-counter-synthesized-data-v1" and candidate.get("structural_evidence", {}).get("transport_class") !=
        "local-counter-literal-data-v1" and candidate.get("structural_evidence", {}).get("transport_class") != "local-counter-direction-timing-v1" and candidate.get("structural_evidence",
        {}).get("transport_class") != "alternate-direct-reset-readback-v1"):
        return None, None
    return qemu_ma5_readback_property(image, config, 1000, upper_nor_present=upper_nor_present, target_rate_hz= 48000)

def qemu_ma5_gpio_irq_property(image: bytes, config: object) -> tuple[str | None, str | None]:
    """Serialize a fresh static route; native live gates still own admission."""
    flash = getattr(config, "flash_size", None)
    if (type(getattr(config, "load_address", None)) is not int or config.load_address != 0 or type(flash) is not int or flash <= 0):
        return None, "primary-nor-unmapped"
    audio = find_ma5_readback_candidate(image)
    route = find_ma5_gpio_irq_candidate(image, audio)
    if route.get("status") != "candidate":
        return None, str(route.get("reject_reason") or "ma5-irq-route-unavailable")
    if (not fields_match(route, (('family', 'ma5'), ('grammar', 'ma5-gpio-parent-irq-v1'), ('static_status', 'candidate'), ('source_profile',
        'three-bank-gpio-parent-descriptor-v1'))) or route.get('runtime_admitted') is not False):
        return None, "ma5-irq-class-unavailable"
    nor = route.get("nor_dependencies")
    ram = route.get("ram_dependencies")
    if (not isinstance(nor, list) or not nor or any(not isinstance(span, (list, tuple)) or len(span) != 2 or any (type(value) is not int for value in span) or
        span[1] <= 0 or not 0 <= span[0] <= min(flash, len(image)) - span[1] for span in nor)):
        return None, "primary-nor-out-of-bounds"
    start, size = getattr(config, "ram_base", None), getattr(config, "ram_size", None)
    if (type(start) is not int or type(size) is not int or size <= 0 or not 0 <= start < start + size <= 0x100000000):
        return None, "consumer-state-unmapped"
    end = start + size
    if (not isinstance(ram, list) or not ram or any(not isinstance(span, (list, tuple)) or len(span) != 2 or any (type(value) is not int for value in span) or
        span[1] <= 0 or not start <= span[0] <= end - span[1] for span in ram)):
        return None, "consumer-state-unmapped"
    auxiliaries = route.get("aux_addresses")
    if not isinstance(auxiliaries, list):
        return None, "auxiliary-state-unmapped"
    for auxiliary in auxiliaries:
        if not isinstance(auxiliary, dict):
            return None, "auxiliary-state-unmapped"
        address, width = auxiliary.get("address"), auxiliary.get("width")
        width = 1 if width is None else width
        if (type(address) is not int or type(width) is not int or width not in (1, 2, 4) or not start <= address <= end - width or address % width):
            return None, "auxiliary-state-unmapped"
        accessor = auxiliary.get("direct_accessor")
        if accessor is not None:
            if not isinstance(accessor, dict):
                return None, "auxiliary-state-unmapped"
            address, width = accessor.get("address"), accessor.get("width")
            if (type(address) is not int or type(width) is not int or width not in (1, 2, 4) or not start <= address <= end - width or address % width):
                return None, "auxiliary-state-unmapped"
    required = { "gpio": ("table_ram", "callbacks_ram", "pin", "dispatcher"), "parent": ("descriptor_ram", "status_ack", "enable", "mask", "enable_shadow",
        "priority_shadow", "installed_gpio_dispatcher", "installed_soc_dispatcher", "exception_callback_slot", "dispatcher"), "installation": ("direct_callback",),
        "chip": ("context_holder", "isr"), }
    if any(not isinstance(route.get(name), dict) or any(type(route[name].get(key)) is not int or not 0 <= route[name][key] <= 0xFFFFFFFF for key in keys) for
        name, keys in required.items()):
        return None, "ma5-irq-route-unmapped"
    gpio, parent = route["gpio"], route["parent"]
    install, chip = route["installation"], route["chip"]
    first_gate = override_gate = 0
    deferred = install.get("deferred_callback")
    installed_flag = install.get("installed_flag")
    no_flag = install.get("profile") == "direct-install-no-flag-v1"
    if (install.get("polarity_argument") != 0 or (no_flag and (installed_flag is not None or install.get("installed_value") is not None)) or (not no_flag and (type(installed_flag)
        is not int or installed_flag <= 0 or install.get("installed_value") != 1))):
        return None, "ma5-irq-installation-unverified"
    if no_flag:
        if (deferred is not None or install.get("direct_gate") is not None or install.get("deferred_gate") is not None or install.get("trigger_argument") != 0):
            return None, "ma5-irq-installation-unverified"
        installed_flag = deferred = 0
    elif install.get("profile") == "conditional-install-direct-or-task-v1":
        direct = install.get("direct_gate")
        if not isinstance(direct, dict) or not isinstance(direct.get("any"), list):
            return None, "ma5-irq-installation-unverified"
        gates = direct["any"]
        if (len(gates) != 2 or any(not isinstance(gate, dict) for gate in gates) or gates[0].get("op") != "eq" or gates[0].get("value") != 0 or gates[1].get("op")
            != "ne" or gates[1].get("value") != 0):
            return None, "ma5-irq-installation-unverified"
        first_gate, override_gate = gates[0].get("address"), gates[1].get("address")
        if (type(first_gate) is not int or type(override_gate) is not int or first_gate != install["installed_flag"] + 0x1D or not first_gate or not
            override_gate or type(deferred) is not int or not deferred or install.get("deferred_gate") != {"all":[{"address": first_gate, "op": "ne", "value": 0
            }, {"address": override_gate, "op": "eq", "value": 0}]}):
            return None, "ma5-irq-installation-unverified"
    elif install.get("profile") == "explicit-sense-direct-install-v1":
        if (deferred is not None or install.get("direct_gate") is not None or install.get("deferred_gate") is not None or install.get("trigger_argument") != 0):
            return None, "ma5-irq-installation-unverified"
        deferred = 0
    else:
        return None, "ma5-irq-installation-unverified"
    fields = [gpio["table_ram"], gpio["callbacks_ram"], gpio["pin"], parent["descriptor_ram"], parent["status_ack"], parent["enable"], parent["mask"], parent["enable_shadow"],
        parent["priority_shadow"], parent["installed_gpio_dispatcher"], parent["installed_soc_dispatcher"], parent["exception_callback_slot"], install["direct_callback"],
        deferred, installed_flag, first_gate, override_gate, chip["context_holder"]]
    if (any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in fields) or not 0 <= fields[2] < 48 or fields[9] != gpio["dispatcher"] | 1 or
        fields[10] != parent["dispatcher"] | 1 or fields[12] != chip["isr"] | 1):
        return None, "ma5-irq-route-unmapped"
    if any(not pointer & 1 or not 0 <= pointer - 1 <= min(flash, len(image)) - 2 for pointer in (fields[9], fields[10], fields[12], *([fields[13]] if fields[13]
        else[]))):
        return None, "primary-nor-out-of-bounds"
    spans = [(fields[0], 72, 4), (fields[1], 192, 4), (fields[3], 28, 4), (fields[7], 2, 2), (fields[8], 2, 2), (fields[11], 4, 4), (fields[17], 4, 4)]
    if fields[14]:
        spans.append((fields[14], 1, 1))
    spans.extend((gate, 1, 1) for gate in (first_gate, override_gate) if gate)
    if any(not start <= address <= end - length or address % alignment for address, length, alignment in spans):
        return None, "consumer-state-unmapped"
    direct = (getattr(config, "rex_irq_status_address", None) == 0x03000C80 and getattr(config, "rex_irq_enable_address", None) == 0x03000C94)
    if not direct:
        controller = find_rex_static_controller_callback_candidate(image, ram_base=start, ram_size=size)
        if (controller is None or controller != getattr(config, 'rex_static_controller_candidate', None) or c80_rex_irq_profile(config, False) is None or (not
            fields_match(controller, (('signature', 'static-c80-controller-callback-v1'), ('status', 50334848), ('enable', 50334868)))) or (controller.get('handler_slot')
            != fields[11]) or (controller.get('handler_file_offset') != fields[10] & ~1)):
            return None, "ma5-irq-controller-unverified"
    if (fields[4:6] !=[0x03000C84, 0x03000C98] or not 0 < fields[6] <= 0x8000 or fields[6] & (fields[6] - 1)):
        return None, "ma5-irq-controller-unverified"
    return "experimental-ma5-irq-route=" + ":".join(f"{value:x}" for value in fields), None

def qemu_audio_sites(audio: object) -> str | None:
    """Serialize detector-owned audio bus PCs for the native QEMU gate."""
    if not isinstance(audio, dict):
        return None
    family = audio.get("family")
    grammar = audio.get("grammar")
    base = audio.get("base")
    data_offset = audio.get("data_offset")
    ma2 = (family == "ma2" and type(base) is int and (0x02001000 <= base < 0x02800000 or base == 0x02880000 and audio.get("sites") == { "read_2":[0x1595c4],
        "write_0":[0x15953c, 0x15957e, 0x1595be, 0x159f2c], "write_2":[0x159542, 0x159590], }) and type(data_offset) is int and data_offset == 2 and (base +
        data_offset < 0x02800000 or base == 0x02880000) and (base + data_offset < 0x02200000 or base >= 0x02201000))
    ma5_signature = { "write_0":[0x582, 0x58A, 0x10566, 0x1056E, 0x37CAE2], "write_2":[0x586, 0x58E, 0x1056A, 0x10572, 0x37CB1E, 0x37CB48, 0x37CB74,], }
    ma5 = (family == "ma5" and type(base) is int and base == 0x02840000 and type(data_offset) is int and data_offset == 2 and audio.get("aperture_write_sites")
        == ma5_signature)
    ma3_readback = (family == "ma3" and grammar == "ma3-readback-v1" and audio.get("static_status") == "accepted" and base == 0x02840000 and data_offset == 2
        and isinstance(audio.get("verifier_entry"), int) and isinstance(audio.get("register_reader"), int) and audio.get("register_readback") ==[[0x90, 0xA0,
        0x60],[0xA0, 0xB0, 0x3C],[0x14A, 0x152, 0x40]])
    ma3_indexed = (family == 'ma3' and grammar == 'ma3-indexed-v1' and fields_match(audio, (('static_status', 'accepted'), ('verifier_entry', 573450), ('register_reader',
        569660), ('fifo_writers',[569544, 569868, 570192]), ('status_poller', 575054), ('wrapper_helper', 574744), ('register_readback',[[144, 160, 96],[160,
        176, 60],[330, 338, 64]]), ('sites', {'write_0':[574780], 'read_0':[574798], 'write_2':[574822], 'read_2':[574840]}))) and (base == 20971520) and (data_offset
        == 2))
    ma3_packetized = (family == 'ma3' and grammar == 'ma3-readback-fifo-v1' and fields_match(audio, (('static_status', 'accepted'), ('verifier_entry', 1533886),
        ('register_reader', 1530148), ('fifo_writers',[1530032, 1530640]), ('status_pollers',[1795838, 1795800, 1795948]), ('register_readback',[[144, 160, 96],[160,
        176, 60],[330, 338, 64]]))) and (base == 41943040) and (data_offset == 128) and (audio.get('sites') == {name: list(sites) for name, sites in
        _SV130_MA3_SITES.items()}))
    ma3_kp6200 = (family == 'ma3' and grammar == 'ma3-kp-readback-fifo-v1' and fields_match(audio, (('static_status', 'accepted'), ('verifier_entry', 930158), ('register_reader',
        926476), ('fifo_writers',[926372]), ('status_pollers',[1132704, 1132522, 1132580]), ('register_readback',[[144, 160, 96],[160, 176, 60],[330, 338, 64]])))
        and (base == 46137344) and (data_offset == 4) and (audio.get('sites') == {name: list(sites) for name, sites in _KP6200_MA3_SITES.items()}))
    ma3 = ma3_readback or ma3_indexed or ma3_packetized or ma3_kp6200
    begin = audio.get("begin")
    opaque_sites = audio.get("sites")
    opaque = (family == "opaque" and grammar == "command-status-data-v1" and base == 0x02880000 and data_offset == 2 and type(begin) is int and not begin & 1
        and audio.get("end") == begin + 0x36 and opaque_sites == { "read_0":[begin + 0x10], "read_2":[begin + 0x34], "write_0":[begin], "write_2":[begin + 0x24],
        })
    sites = audio.get("sites" if ma2 or opaque or ma3 else "aperture_write_sites")
    if (not ma2 and not ma5 and not opaque and not ma3) or not isinstance(sites, dict):
        return None
    entries: list[tuple[str, int, int]] = []
    seen: set[int] = set()
    write_ports: set[int] = set()
    for name, values in sites.items():
        if not isinstance(name, str):
            return None
        is_write = name.startswith("write_")
        is_data_read = (
            ma2 and name == f"read_{data_offset}"
            or opaque and name in ("read_0", f"read_{data_offset}")
            or ma3 and name in ("read_0", f"read_{data_offset}")
        )
        if ma5 and not is_write:
            return None
        if not is_write and not is_data_read:
            continue
        suffix = name[name.index("_") + 1:]
        ma3_wide = ma3_packetized or ma3_kp6200
        if (not suffix or len(suffix) > (3 if ma3_packetized else 2) or any(character not in "0123456789" for character in suffix)):
            return None
        port = int(suffix, 10)
        if (str(port) != suffix or port > data_offset or port >= (256 if ma3_packetized else 16) or not isinstance(values, (list, tuple)) or not values):
            return None
        if is_write:
            write_ports.add(port)
        site_limit = 192 if ma3_wide else AUDIO_SITE_LIMIT
        if len(values) > site_limit:
            return None
        for value in values:
            if (type(value) is not int or not 0 <= value <= 0xFFFFFFFF or value & 1):
                return None
            if value in seen:
                return None
            seen.add(value)
            entry = ("w" if is_write else "r", port, value)
            entries.append(entry)
            if len(entries) > (192 if ma3_wide else AUDIO_SITE_LIMIT):
                return None
    if 0 not in write_ports or data_offset not in write_ports:
        return None
    entries.sort()
    return ";".join(f"{kind}{port:x}/{pc:x}"
                    for kind, port, pc in entries)

# Required evidence providers are bound by registry discovery.
REQUIRES = {'c80_rex_irq_profile': ('rex.transport_projection', 'c80_rex_irq_profile'), 'w1c_rex_irq_profile': ('rex.transport_projection',
    'w1c_rex_irq_profile'), 'find_rex_static_controller_callback_candidate': ('rex.rules', 'find_rex_static_controller_callback_candidate'),
    'UPPER_FLASH_ADDRESS': ('storage.upper_nor', 'UPPER_FLASH_ADDRESS'), 'UPPER_FLASH_SIZE': ('storage.upper_nor', 'UPPER_FLASH_SIZE')}
