"""Source-qualified machine properties owned by this device domain."""
from __future__ import annotations
from msm5xxx_emulator.detection.contracts import fields_match
from msm5xxx_emulator.detection.devices.rex.stack_w1c import find_stack_w1c_irq_profile
from msm5xxx_emulator.detection.devices.rex.rules import UIS_IDLE_BODY_DELTAS, find_rex_legacy_row0_profile
from msm5xxx_emulator.detection.contracts import boot_storage_profile as _boot_storage_profile

def qemu_uis_idle_observer_addresses(config: object,) -> tuple[int, int] | None:
    """Return only the detector-closed UI-idle entry/body pair."""
    entry = getattr(config, "uis_idle_entry_address", None)
    body = getattr(config, "uis_idle_body_address", None)
    if (type(entry) is not int or type(body) is not int or not 0 < entry < body <= 0xFFFFFFFF or entry & 1 or body & 1 or body - entry not in
        UIS_IDLE_BODY_DELTAS):
        return None
    return entry, body

def qemu_rex_idle_candidate_observer_address(config: object) -> int | None:
    """Return one detector-derived, read-only REX-idle candidate address."""
    address = getattr(config, "rex_idle_address", None)
    if (type(address) is not int or not 0 < address <= 0xFFFFFFFF or address & 1):
        return None
    return address

def qemu_basic_row0_property(config: object, image: bytes):
    profile, reason = _boot_storage_profile(config, image, "rex_basic_irq_profile", lambda primary: find_rex_legacy_row0_profile(primary, config.ram_base,
        config.ram_size, config.overlays),)
    if profile is None:
        return None, reason
    actual = (config.rex_irq_wrapper_address, config.rex_irq_handler_address, config.rex_irq_handler_slot, config.rex_irq_callback_slot, config.rex_irq_status_address,
        config.rex_irq_enable_address, config.rex_irq_mask)
    if (config.rex_idle_address is not None or config.rex_tick_ms != 5 or actual != tuple(profile["route"]) or config.rex_tick_address != profile["callback_file_offset"]
        or config.rex_irq_arm_address != profile["arm_address"]):
        return None, "row0-configuration-source-mismatch"
    # Zero disables the optional native observer; config idle remains None.
    return (f"rex-irq={actual[4]:x}:{actual[5]:x}:"
            f"{profile['arm_address']:x}:{actual[6]:x}:4c4b40:0"), None

def c80_rex_irq_profile(config: object, enabled: bool) -> str | None:
    """Encode the proven exact class or an explicitly enabled experiment."""
    candidate = getattr(config, "rex_static_controller_candidate", None)
    if not isinstance(candidate, dict):
        return None
    signature = candidate.get("signature")
    automatic = (signature == 'static-c80-controller-callback-v1' and fields_match(candidate, (('promotion', 'temporary-evidence-gated'), ('status_bank_count',
        2), ('pending_read_semantics', 'latched-read'), ('pending_ack_semantics', 'write-one-to-clear'), ('time_tick_status_bank', 50334848), ('time_tick_clear_bank',
        50334848), ('time_tick_mask', 512))) and (candidate.get('group_row_size') in (10, 12)))
    if not enabled and not automatic:
        return None
    fb0 = signature == "static-fb0-controller-callback-v1"
    overlay = signature == "static-c80-overlay-controller-callback-v1"
    required = { "signature": signature, "controller_class": ("legacy-c80-three-bank-group14-v1" if overlay else
        "legacy-fb0-index1b-delta5-controller-candidate-v1" if fb0 else "legacy-c80-index1e-delta5-controller-candidate-v1"), "accepted": True, "active": False,
        "vector": 0x18, "mask": 0x0200, "callback_delta": 5, "callback_validation_size": 68, }
    if (signature not in ("static-c80-controller-callback-v1", "static-c80-overlay-controller-callback-v1", "static-fb0-controller-callback-v1",) or any(candidate.get(key)
        != value for key, value in required.items())):
        return None
    integer_fields = ("vector_target", "status", "enable", "wrapper_file_offset", "handler_slot", "handler_file_offset", "handler_validation_size",
        "callback_slot", "callback_file_offset", "wrapper_validation_size",) + (("wrapper_runtime_address", "handler_runtime_address",
        "callback_runtime_address") if overlay else ())
    if any(type(candidate.get(field)) is not int for field in integer_fields):
        return None
    status = int(candidate["status"])
    enable = int(candidate["enable"])
    ram_base = int(getattr(config, "ram_base", 0))
    ram_end = ram_base + int(getattr(config, "ram_size", 0))
    flash_size = int(getattr(config, "flash_size", 0))
    wrapper = int(candidate["wrapper_file_offset"])
    wrapper_size = int(candidate["wrapper_validation_size"])
    handler = int(candidate["handler_file_offset"])
    handler_size = int(candidate["handler_validation_size"])
    callback = int(candidate["callback_file_offset"])
    callback_size = int(candidate["callback_validation_size"])
    handler_slot = int(candidate["handler_slot"])
    callback_slot = int(candidate["callback_slot"])
    vector_target = int(candidate["vector_target"])
    runtime_wrapper = int(candidate.get("wrapper_runtime_address", wrapper))
    runtime_handler = int(candidate.get("handler_runtime_address", handler))
    runtime_callback = int(candidate.get("callback_runtime_address", callback))
    direct_fields = ("rex_irq_wrapper_address", "rex_irq_handler_address", "rex_irq_handler_slot", "rex_irq_callback_slot", "rex_irq_status_address",
        "rex_irq_enable_address", "rex_irq_arm_address",)
    if not overlay:
        direct_fields = ("rex_tick_address", *direct_fields)
    common_invalid = (getattr(config, "load_address", None) != 0 or any(getattr(config, field, None) is not None for field in direct_fields) or getattr(config,
        "rex_irq_mask", 0) or status != (0x03000FB0 if fb0 else 0x03000C80) or enable != status + 0x14 or not ram_base <= vector_target <= ram_end - 4 or any(address
        & 3 or not ram_base <= address <= ram_end - 4 for address in (handler_slot, callback_slot)) or wrapper & 3 or handler & 1 or callback & 1 or
        runtime_wrapper & 3 or runtime_handler & 1 or runtime_callback & 1 or any(not 0 <= address < flash_size for address in (wrapper, handler, callback)) or
        any(size <= 0 or address + size > flash_size for address, size in ((wrapper, wrapper_size), (handler, handler_size), (callback, callback_size),)))
    if overlay:
        linker = getattr(config, "linker", None)
        overlays = getattr(config, "overlays", ())
        handler_overlays = [item for item in overlays if all(type(getattr(item, field, None)) is int for field in ("source", "target", "size")) and item.source
            <= handler and handler + handler_size <= item.source + item.size and item.target + handler - item.source == runtime_handler]
        class_invalid = (not fields_match(candidate, (('promotion', 'temporary-evidence-gated'), ('pending_read_semantics', 'latched-read'), ('status_bank_count',
            3), ('group_row_size', 14), ('time_tick_mask', 512))) or tuple(candidate.get('status_banks', ())) != (status, status + 4, status + 48) or tuple(candidate.get('clear_banks',
            ())) != (status, status + 4, enable + 56) or (tuple(candidate.get('controller_write_banks', ())) != (enable, enable + 4, enable + 48)) or (tuple(candidate.get('controller_aperture',
            ())) != (status, enable + 58)) or (candidate.get('time_tick_status_bank') != status) or (candidate.get('time_tick_clear_bank') != status) or (linker
            is None) or any((type(getattr(linker, field, None)) is not int for field in ('data_source', 'data_target', 'data_size'))) or (linker.data_target !=
            vector_target) or (linker.data_size < 4) or (not 0 <= linker.data_source <= flash_size - linker.data_size) or (len(handler_overlays) != 1) or (runtime_wrapper
            != wrapper) or (runtime_callback != callback))
    else:
        class_invalid = (not ram_base <= vector_target <= ram_end - 4 or tuple(candidate.get("status_banks", ())) != (status, status + 4) or tuple(candidate.get("clear_banks",
            ())) != (status, status + 4) or tuple(candidate.get("controller_write_banks", ())) != (enable, enable + 4) or tuple(candidate.get("controller_aperture",
            ())) != (status, enable + 6) or (runtime_wrapper, runtime_handler, runtime_callback) != (wrapper, handler, callback))
        if fb0:
            class_invalid |= (candidate.get("promotion") != "experimental-only" or candidate.get("status_bank_count") != 2 or candidate.get("group_row_size") !=
                10 or candidate.get("pending_read_semantics") != "latched-read" or candidate.get("pending_ack_semantics") != "write-one-to-clear" or candidate.get("time_tick_status_bank")
                != status or candidate.get("time_tick_clear_bank") != status or candidate.get("time_tick_mask") != 0x0200 or candidate.get("time_tick_control_address")
                != 0x030006E0 or handler_size != 0x182)
    if common_invalid or class_invalid:
        return None
    # The experimental FB0 class shares the provisional 5-unit cadence;
    # physical timer frequency is not inferred from the callback alone.
    values = (status, enable, 0x0200, 5_000_000, vector_target, runtime_wrapper, handler_slot, runtime_handler, handler_size, callback_slot, runtime_callback,)
    if overlay:
        values += (3,)
    return ":".join(f"{value:x}" for value in values)

def _legacy_620_rex_irq_profile(config: object, enabled: bool, classes: dict[str, int], promotion: str, pending_read_semantics: str,) -> str | None:
    """Validate and encode one detector-closed legacy 0x620 route."""
    if not enabled:
        return None
    candidate = getattr(config, "rex_static_controller_candidate", None)
    required = { "signature": "static-msm5000-620-controller-callback-v1", "accepted": True, "active": False, "promotion": promotion, "vector": 0x18, "mask":
        0x0200, "callback_delta": 5, "callback_validation_size": 68, "pending_read_semantics": pending_read_semantics, "time_tick_control_address": 0x030006E0,
        }
    if (not isinstance(candidate, dict) or any(candidate.get(key) != value for key, value in required.items()) or candidate.get("controller_class") not in
        classes or candidate.get("group_row_size") != classes.get(candidate.get("controller_class"))):
        return None
    integer_fields = ("vector_target", "vector_copy_source", "vector_copy_size", "descriptor_file_offset", "descriptor_runtime_address", "mask_table", "status",
        "enable", "wrapper_file_offset", "wrapper_validation_size", "handler_slot", "handler_file_offset", "handler_validation_size", "callback_slot",
        "callback_file_offset",)
    if any(type(candidate.get(field)) is not int for field in integer_fields):
        return None
    status = int(candidate["status"])
    enable = int(candidate["enable"])
    arm = int(candidate["time_tick_control_address"])
    vector_target = int(candidate["vector_target"])
    copy_source = int(candidate["vector_copy_source"])
    copy_size = int(candidate["vector_copy_size"])
    descriptor = int(candidate["descriptor_file_offset"])
    descriptor_runtime = int(candidate["descriptor_runtime_address"])
    mask_table = int(candidate["mask_table"])
    ram_base = int(getattr(config, "ram_base", 0))
    ram_end = ram_base + int(getattr(config, "ram_size", 0))
    flash_size = int(getattr(config, "flash_size", 0))
    wrapper = int(candidate["wrapper_file_offset"])
    wrapper_size = int(candidate["wrapper_validation_size"])
    handler = int(candidate["handler_file_offset"])
    handler_size = int(candidate["handler_validation_size"])
    callback = int(candidate["callback_file_offset"])
    callback_size = int(candidate["callback_validation_size"])
    handler_slot = int(candidate["handler_slot"])
    callback_slot = int(candidate["callback_slot"])
    direct_fields = ("rex_tick_address", "rex_irq_wrapper_address", "rex_irq_handler_address", "rex_irq_handler_slot", "rex_irq_callback_slot",
        "rex_irq_status_address", "rex_irq_enable_address", "rex_irq_arm_address",)
    if (getattr(config, "load_address", None) != 0 or any(getattr(config, field, None) is not None for field in direct_fields) or getattr(config, "rex_irq_mask",
        0) or status != 0x03000620 or enable != status + 8 or tuple(candidate.get("status_banks", ())) != (status, status + 4) or tuple(candidate.get("clear_banks"
        if pending_read_semantics == "latched-read" else "mask_set_banks", ())) != (status, status + 4) or (pending_read_semantics == "latched-read" and
        candidate.get("pending_ack_semantics") != "write-one-to-clear") or tuple(candidate.get("mask_output_banks", ())) != (enable, enable + 4) or tuple(candidate.get("controller_aperture",
        ())) != (status, enable + 8) or vector_target & 3 or not ram_base <= vector_target <= ram_end - 4 or copy_size <= 0 or vector_target + copy_size >
        ram_end or copy_source < 0 or copy_source + copy_size > flash_size or not copy_source <= descriptor or descriptor + 0x1C > copy_source + copy_size or
        descriptor_runtime != vector_target + descriptor - copy_source or descriptor_runtime != mask_table + 8 + 0x1C * 0x1C or callback_slot !=
        descriptor_runtime + 0x14 or any(address & 3 or not ram_base <= address <= ram_end - 4 for address in (handler_slot, callback_slot)) or wrapper & 3 or
        handler & 1 or callback & 1 or any(not 0 <= address < flash_size for address in (wrapper, handler, callback)) or any(size <= 0 or address + size >
        flash_size for address, size in ((wrapper, wrapper_size), (handler, handler_size), (callback, callback_size),))):
        return None
    values = (status, enable, arm, 0x0200, 5_000_000, vector_target, wrapper, handler_slot, handler, handler_size, callback_slot, callback,)
    return ":".join(f"{value:x}" for value in values)

def read_consume_rex_irq_profile(config: object, enabled: bool) -> str | None:
    """Encode the proven exact class or an explicitly enabled experiment."""
    profile = _legacy_620_rex_irq_profile(config, True, { "legacy-msm5000-620-two-bank-read-consume-v1": 12,
        "legacy-msm5000-620-two-bank-read-consume-group10-v1": 10, }, "temporary-evidence-gated", "consume-on-read",)
    if profile is not None:
        return profile
    return _legacy_620_rex_irq_profile(config, enabled, { "legacy-msm5000-620-two-bank-read-consume-v1": 12,
        "legacy-msm5000-620-two-bank-read-consume-group10-v1": 10, }, "experimental-only", "consume-on-read",)

def w1c_rex_irq_profile(config: object) -> str | None:
    """Encode closed callback-then-W1C classes without an unproven idle PC."""
    profile = _legacy_620_rex_irq_profile(config, True, {"legacy-msm5000-620-two-bank-w1c-8call-v1": 12, "legacy-msm5000-620-two-bank-w1c-group10-v1": 10,
        "legacy-msm5000-620-two-bank-w1c-group12-v1": 12}, "temporary-evidence-gated", "latched-read",)
    return ":".join(profile.split(":")[:5]) if profile is not None else None

def qemu_stack_w1c_property(image: bytes, config: object, *, loaded: bytes | None = None) -> str | None:
    """Bind W1C and narrowly correct the automatic read-consume selection."""
    from .power_w1c import find_power_stack_w1c_irq_profile
    from .rules import _find_rex_620_static_controller_callback_candidate
    size = getattr(config, "flash_size", None)
    candidate = getattr(config, "rex_static_controller_candidate", None)
    if (getattr(config, "load_address", None) != 0 or type(size) is not int or size <= 0 or getattr(config, "rex_irq_mask", 0) or getattr(config,
        "rex_basic_irq_profile", None) is not None or any(getattr(config, key, None) is not None for key in ("rex_irq_status_address", "rex_irq_enable_address",
        "rex_irq_arm_address")) or loaded is not None and (not isinstance(loaded,bytes) or len(loaded)!=size)):
        return None
    ram_base,ram_size = getattr(config,"ram_base",None),getattr(config,"ram_size",None)
    power = find_power_stack_w1c_irq_profile(image[:size],ram_base,ram_size)
    if power is not None and candidate is not None:
        if (not isinstance(candidate,dict) or type(candidate.get("accepted")) is not bool or candidate.get("active") is not False or candidate !=
            _find_rex_620_static_controller_callback_candidate(image[: size],ram_base=ram_base,ram_size=ram_size)):
            return None
    if isinstance(candidate,dict) and candidate.get("accepted") is True:
        if (power is None or candidate.get("signature") != "static-msm5000-620-controller-callback-v1" or candidate.get("controller_class") !=
            "legacy-msm5000-620-two-bank-read-consume-v1"):
            return None
        # Every ownership edge in old telemetry must agree with the new typed
        # W1C graph. Unknown extra/native claims fail canonical equality above.
        for key in ("status","enable","mask","vector","vector_target", "vector_copy_source","vector_copy_size", "wrapper_file_offset", "handler_file_offset","callback_file_offset","registrar_file_offset",
            "handler_slot","callback_slot","descriptor_file_offset", "descriptor_runtime_address","mask_table"):
            if type(candidate.get(key)) is not int or candidate[key] != power[key]:
                return None
    profile = power or find_stack_w1c_irq_profile(image[:size],ram_base,ram_size)
    if profile is None:
        return None
    if loaded is not None:
        current = (find_power_stack_w1c_irq_profile(loaded,ram_base,ram_size) if power else find_stack_w1c_irq_profile(loaded,ram_base,ram_size))
        if current != profile:
            return None
    return ":".join(f"{profile[key]:x}" for key in (
        "status", "enable", "arm", "mask", "interval_ns"))
