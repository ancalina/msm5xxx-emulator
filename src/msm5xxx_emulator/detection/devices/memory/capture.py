"""Domain-owned boot captures over shared evidence."""

from .boot_rules import MEMORY_CLEAR_128_SIGNATURE
from .boot_rules import MEMORY_CLEAR_LOOP_SIGNATURE
from .boot_rules import MEMORY_COPY_LOOP_SIGNATURE
from .boot_rules import REGISTER_RAMP_PREFIX
from msm5xxx_emulator.detection.signatures import find_all
from msm5xxx_emulator.detection.layout_queries import find_arm_memory_copy_addresses
def capture_operations(layout, drivers):
    clear_positions = [*find_all(layout.primary_image, MEMORY_CLEAR_LOOP_SIGNATURE), *find_all(layout.primary_image, MEMORY_CLEAR_128_SIGNATURE),]
    clear_layout = [drivers.mapped_position(position) for position in dict.fromkeys(clear_positions)]
    copy_layout = [drivers.mapped_position(position) for position in find_all(layout.primary_image, MEMORY_COPY_LOOP_SIGNATURE)]
    ramp_layout = [drivers.mapped_position(position + len(REGISTER_RAMP_PREFIX)) for position in find_all(layout.primary_image, REGISTER_RAMP_PREFIX)]
    memory_clear_addresses = [address for address, _relative in clear_layout if address is not None]
    memory_copy_addresses = [address for address, _relative in copy_layout if address is not None]
    register_ramp_addresses = [address for address, _relative in ramp_layout if address is not None]
    arm_memory_copy_addresses = find_arm_memory_copy_addresses(layout.primary_image, drivers.overlays, layout.linker, layout.requested_load_address)
    return (clear_layout, copy_layout, ramp_layout, memory_clear_addresses, memory_copy_addresses, register_ramp_addresses, arm_memory_copy_addresses,)

from dataclasses import asdict
from msm5xxx_emulator.detection.startup_sdram import reset_copy_ram_profile
from msm5xxx_emulator.detection.layout_queries import (infer_ram_base, high_ram_bootstrap_profile, dual_stage_ram_profile, has_dual_sdram_bootstrap,
    has_high_bank_reader_bootstrap, find_high_ram_readback_tests)

def _source_proven_two_bank_linker_span(primary_image, linker, requested_load_address):
    """Accept only a linker row whose complete source and destination span is in evidence."""
    if linker is None:
        return False
    fields = (linker.data_source, linker.data_target, linker.data_size,
              linker.bss_target, linker.bss_size)
    if (type(linker.table_offset) is not int or linker.table_offset < 0
            or linker.table_offset & 3
            or any(type(value) is not int or not 0 <= value <= 0xffffffff
                   or value & 3 for value in fields)):
        return False
    if (linker.data_size == 0 or linker.bss_size == 0
            or linker.table_offset + 20 > len(primary_image)):
        return False

    import struct
    if struct.unpack_from("<5I", primary_image, linker.table_offset) != fields:
        return False

    source_offset = linker.data_source - requested_load_address
    source_end = linker.data_source + linker.data_size
    data_end = linker.data_target + linker.data_size
    bss_end = linker.bss_target + linker.bss_size
    return (
        source_offset >= 0
        and source_offset + linker.data_size <= len(primary_image)
        and source_end <= 0x01000000
        and data_end <= 0xffffffff
        and bss_end <= 0xffffffff
        and data_end == linker.bss_target
        and 0x01000000 <= linker.data_target < 0x01800000 < bss_end <= 0x02000000
    )

def capture_layout(primary_image, linker, chipset, requested_load_address, requested_ram_base, requested_ram_size, image_kind, detection_notes):
    ram_base = infer_ram_base(linker, chipset, primary_image)
    if requested_ram_base is not None:
        ram_base = requested_ram_base
    ram_size = (0x00800000 if requested_ram_size is None else requested_ram_size)
    ram_bootstrap_profile = None
    if requested_ram_base is None and requested_ram_size is None:
        bootstrap_candidate = (reset_copy_ram_profile(primary_image) if requested_load_address == 0 else None)
        high_ram = (high_ram_bootstrap_profile(primary_image) if requested_load_address == 0 else None)
        dual_stage, dual_stage_reject = (dual_stage_ram_profile(primary_image, linker) if requested_load_address == 0 and image_kind == "firmware" else (None,
            None))
        if (bootstrap_candidate is not None and ram_base == bootstrap_candidate["ram_base"] and (linker is None or asdict(linker) == bootstrap_candidate["bootstrap_linker"])):
            ram_bootstrap_profile = bootstrap_candidate
            ram_size = bootstrap_candidate["ram_size"]
            detection_notes.append("experimental reset-linked logical SDRAM span detected; "
                "external-bus gap reserved, physical capacity and device protocol unverified")
        elif high_ram is not None and linker is None:
            ram_base, ram_size = high_ram
            detection_notes.append("reset-linked high-RAM readback/extent profile detected; " "peripheral protocol remains unverified")
        elif dual_stage is not None:
            ram_base = dual_stage["ram_base"]
            ram_size = dual_stage["ram_size"]
            # Appended RAM snapshots must not become additional primary code.
            primary_image = primary_image[:ram_base - requested_load_address]
            detection_notes.append("source-linked boot/application RAM scatter envelope detected; "
                "private boot layout preserved, physical capacity unverified")
        elif has_dual_sdram_bootstrap(primary_image, linker):
            ram_base = 0x01000000
            ram_size = 0x01000000
            detection_notes.append("closed dual-bank SDRAM bootstrap span detected")
        elif has_high_bank_reader_bootstrap(primary_image):
            ram_base = 0x01000000
            ram_size = 0x01000000
            detection_notes.append("closed high-bank reader bootstrap detected")
        elif (image_kind == "firmware"
                and _source_proven_two_bank_linker_span(
                    primary_image, linker, requested_load_address)):
            ram_base = 0x01000000
            ram_size = 0x01000000
            detection_notes.append("source-proven linker RAM envelope detected; capacity unverified")
        elif find_high_ram_readback_tests(primary_image):
            detection_notes.append("high-RAM candidate rejected: no unique reset-linked " "readback/extent proof or conflicting linker; native fallback")
        if dual_stage_reject is not None:
            detection_notes.append(
                f"dual-stage RAM class rejected: {dual_stage_reject}; native fallback"
            )
    return ram_base, ram_size, ram_bootstrap_profile, primary_image
