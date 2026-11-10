"""Domain-owned boot captures over shared evidence."""

def note_spi(layout, spi_nv_profile, _spi_nv_reason):
    if spi_nv_profile is not None:
        layout.detection_notes.append("four-wire serial NVM producer detected: source-compatible virtual "
            "16KiB/page32 geometry; physical part and timing unverified")
    elif _spi_nv_reason not in (None, "spi-nv-typed-root-unclosed"):
        layout.detection_notes.append(
            f"serial NVM not applied: {_spi_nv_reason}; native fallback"
        )
    return spi_nv_profile

from .boot_rules import FLASH_ID_SIGNATURE
from .boot_rules import NAND_BAD_BLOCK_SIGNATURE
from .boot_rules import NAND_READ_SIGNATURE
from .boot_rules import NAND_WRITE_SIGNATURE
from .rules import find_fs_device_flash_id
def capture_identifiers(layout, drivers):
    nand_bad_block_address = drivers.runtime_signature("nand_bad_block_address", NAND_BAD_BLOCK_SIGNATURE)
    nand_read_address = drivers.runtime_signature("nand_read_address", NAND_READ_SIGNATURE)
    nand_write_address = drivers.runtime_signature("nand_write_address", NAND_WRITE_SIGNATURE)
    flash_id_address = drivers.runtime_signature("flash_id_address", FLASH_ID_SIGNATURE)
    descriptor_flash_id = find_fs_device_flash_id(layout.primary_image, flash_id_address)
    if descriptor_flash_id is not None:
        layout.detection_notes.append(
            f"flash ID 0x{descriptor_flash_id:08X} selected from unique "
            "fs_dev descriptor/table/trampoline linkage"
        )
    return (nand_bad_block_address, nand_read_address, nand_write_address, flash_id_address, descriptor_flash_id,)

from .boot_rules import DIRECT_INTEL_X16_PROBE_SIGNATURE
from .boot_rules import LEGACY_EFS_PAGE_READ_SIGNATURE
from .boot_rules import LEGACY_SECONDARY_FLASH_READ_SIGNATURE
from .boot_rules import LEGACY_SECONDARY_FLASH_WRITE_SIGNATURE
from .boot_rules import PRIMARY_FLASH_DESCRIPTOR_PROBE_SIGNATURE
from .boot_rules import PRIMARY_FLASH_EXTERNAL_DESCRIPTOR_PROBE_SIGNATURE
from .boot_rules import PRIMARY_FLASH_PROBE_SIGNATURE
from .boot_rules import SECONDARY_FLASH_WRAPPER_PATTERN
from msm5xxx_emulator.detection.signatures import find_all
from .rules import find_fujitsu_x16_bulk_write
def capture_nor(layout, drivers):
    primary_probe_positions = sorted({ position for signature in (PRIMARY_FLASH_PROBE_SIGNATURE, PRIMARY_FLASH_DESCRIPTOR_PROBE_SIGNATURE,
        PRIMARY_FLASH_EXTERNAL_DESCRIPTOR_PROBE_SIGNATURE, DIRECT_INTEL_X16_PROBE_SIGNATURE,) for position in find_all(layout.primary_image, signature) })
    primary_flash_probe_address = (drivers.runtime_position("primary_flash_probe_address", primary_probe_positions[0]) if len(primary_probe_positions) == 1 else
        None)
    if len(primary_probe_positions) > 1:
        layout.detection_notes.append("primary flash probe detector rejected: ambiguous exact grammar")
    secondary_flash_read_address = None
    secondary_flash_write_address = None
    legacy_efs_page_read_address = drivers.runtime_signature("legacy_efs_page_read_address", LEGACY_EFS_PAGE_READ_SIGNATURE)
    wrapper_offset = 0
    wrapper_reads: list[int] = []
    wrapper_writes: list[int] = []
    while match := SECONDARY_FLASH_WRAPPER_PATTERN.search(layout.primary_image, wrapper_offset):
        if match.group("dispatch") == b"\xc3\x6b":
            wrapper_reads.append(match.start())
        else:
            wrapper_writes.append(match.start())
        wrapper_offset = match.start() + 2
    if len(wrapper_reads) == 1:
        secondary_flash_read_address = drivers.runtime_position("secondary_flash_read_address", wrapper_reads[0])
    if len(wrapper_writes) == 1:
        secondary_flash_write_address = drivers.runtime_position("secondary_flash_write_address", wrapper_writes[0])
    legacy_read = drivers.runtime_signature("secondary_flash_read_address", LEGACY_SECONDARY_FLASH_READ_SIGNATURE)
    legacy_write = drivers.runtime_signature("secondary_flash_write_address", LEGACY_SECONDARY_FLASH_WRITE_SIGNATURE)
    if secondary_flash_read_address is None:
        secondary_flash_read_address = legacy_read
    if secondary_flash_write_address is None:
        secondary_flash_write_address = legacy_write
    if secondary_flash_write_address is None:
        bulk_write = find_fujitsu_x16_bulk_write(layout.primary_image, layout.requested_load_address + layout.scan_flash_size)
        if bulk_write is not None:
            secondary_flash_write_address = drivers.runtime_position("secondary_flash_write_address", bulk_write)
            layout.detection_notes.append("Fujitsu x16 bulk writer proves adjacent secondary NOR command bus")
    return (primary_flash_probe_address, secondary_flash_read_address, secondary_flash_write_address, legacy_efs_page_read_address,)

from .guarded_middle_nand import find_guarded_middle_nand_profile
from .low_port_nand import find_low_port_nand_driver
from .low_port_nand import find_middle_nand_driver_marker
from .low_port_nand import find_middle_nand_producers
from .static_middle_nand import find_static_middle_nand_profile
from .small_page_nand import small_page_nand_profile
def capture_nand(layout, nand_bad_block_address, nand_read_address, nand_write_address):
    raw_nand_ports = (find_low_port_nand_driver(layout.primary_image) or find_middle_nand_producers(layout.primary_image) or find_middle_nand_driver_marker(layout.primary_image))
    native_nand_profile = (small_page_nand_profile(layout.primary_image) if layout.ram_bootstrap_profile is not None else None)
    if layout.ram_bootstrap_profile is not None and native_nand_profile is None:
        layout.detection_notes.append("reset-linked NAND candidate rejected: complete read/program/erase/"
            "transfer ownership is not closed; native fallback retained")
    direct_middle_nand = (find_static_middle_nand_profile(layout.primary_image) if find_table7_matrix(layout.primary_image) is not None else None)
    guarded_nand = find_guarded_middle_nand_profile(layout.primary_image)
    nand_enabled = (guarded_nand is not None or direct_middle_nand is not None or native_nand_profile is not None or raw_nand_ports or any(item is not None for
        item in (nand_bad_block_address, nand_read_address, nand_write_address)))
    if raw_nand_ports and all(item is None for item in (nand_bad_block_address, nand_read_address, nand_write_address)):
        layout.detection_notes.append("raw NAND enabled from driver content and physical port evidence")
    return (raw_nand_ports, native_nand_profile, direct_middle_nand, guarded_nand, nand_enabled,)

REQUIRES = {'find_table7_matrix': ('input.table7', 'find_table7_matrix')}

from .configuration import default_state_paths
from .rules import find_adjacent_amd_x16_nor
from .rules import find_adjacent_fujitsu_x16_nor
from msm5xxx_emulator.detection.layout_queries import normalised_flash_size
def capture_geometry(layout):
    flash_size = (layout.compound_fujitsu[0] if layout.compound_fujitsu else normalised_flash_size(max(len(layout.image), layout.required_flash_extent), layout.ram_base))
    adjacent_fujitsu = find_adjacent_fujitsu_x16_nor(layout.primary_image, flash_size)
    adjacent_amd = (find_adjacent_amd_x16_nor(layout.primary_image, flash_size) if layout.scan_chipset == "MSM5100" else None)
    if adjacent_fujitsu is not None and adjacent_amd is not None:
        layout.detection_notes.append("adjacent x16 NOR detectors conflict; native fallback retained")
        adjacent_fujitsu = adjacent_amd = None
    if (adjacent_fujitsu is not None and adjacent_fujitsu[0] + adjacent_fujitsu[1] > layout.ram_base):
        layout.detection_notes.append("adjacent Fujitsu x16 NOR rejected because it overlaps SDRAM")
        adjacent_fujitsu = None
    if adjacent_fujitsu is not None:
        layout.detection_notes.append("adjacent Fujitsu x16 NOR selected from unique " "writer/descriptor/usable/physical-geometry linkage")
    if (adjacent_amd is not None and adjacent_amd[0] + adjacent_amd[1] > layout.ram_base):
        layout.detection_notes.append("adjacent AMD x16 NOR rejected because it overlaps SDRAM")
        adjacent_amd = None
    if adjacent_amd is not None:
        layout.detection_notes.append("temporary exact adjacent AMD x16 NOR selected from unique " "writer/record-init/geometry linkage")
    adjacent = adjacent_fujitsu or adjacent_amd
    compound_secondary_size = layout.compound_fujitsu[1] if layout.compound_fujitsu else None
    adjacent_secondary_size = adjacent[1] if adjacent else None
    compound_secondary_offset = flash_size if layout.compound_fujitsu else None
    compound_secondary_seed = (layout.image[compound_secondary_offset: compound_secondary_offset + compound_secondary_size] if compound_secondary_offset is not
        None and compound_secondary_size is not None else None)
    default_flash_state, default_secondary_state = default_state_paths(layout.path, layout.image, flash_size, compound_secondary_size or adjacent_secondary_size
        or flash_size, secondary_seed=compound_secondary_seed,)
    return (flash_size, adjacent, adjacent_amd, adjacent_secondary_size, compound_secondary_offset, compound_secondary_size, default_flash_state,
        default_secondary_state,)

from .spi_nv import find_spi_nv_profile
def capture_spi(layout):
    if layout.requested_load_address == 0:
        return find_spi_nv_profile(layout.primary_image)
    return None, None

from .rules import find_compound_fujitsu_layout
from .boot_extent import boot_nor_extent
from .boot_rules import MAX_FLASH_SIZE
from msm5xxx_emulator.detection.image_view import ADDRESS_SPACE
from msm5xxx_emulator.detection.layout_queries import referenced_flash_extent

def capture_primary_extent(image, requested_load_address, requested_flash_size, scan_ram_base, detection_notes):
    compound_fujitsu = (find_compound_fujitsu_layout(image, requested_load_address) if requested_flash_size is None else None)
    required_flash_extent = referenced_flash_extent(image, requested_load_address)
    boot_extent = boot_nor_extent(image, requested_load_address)
    if boot_extent:
        required_flash_extent = max(required_flash_extent, boot_extent)
        detection_notes.append("reset-linked boot and 270-sector download descriptor declare " "16MiB virtual primary NOR; physical part ID remains unqualified")
    if requested_flash_size is None:
        scan_limit = (scan_ram_base - requested_load_address if scan_ram_base > requested_load_address else min(MAX_FLASH_SIZE, ADDRESS_SPACE -
            requested_load_address))
        scan_flash_size = (compound_fujitsu[0] if compound_fujitsu else normalised_flash_size(max(len(image), required_flash_extent), min(MAX_FLASH_SIZE,
            scan_limit),))
    else:
        if requested_flash_size <= 0:
            raise ValueError("flash size must be positive")
        scan_flash_size = requested_flash_size
    return compound_fujitsu, required_flash_extent, scan_flash_size
