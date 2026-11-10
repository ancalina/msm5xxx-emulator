"""Projection of captured evidence into firmware configuration."""
from .rules import MSM5500_REVISION_REGISTER, MSM5500_REVISION_F025_RAW

def configuration_fields(layout, drivers, storage):
    return {'path': str(layout.path), 'file_size': layout.loaded.source_size, 'firmware_sha256': layout.loaded.source_sha256, 'image_kind': layout.image_kind,
        'dump_status': 'pending', 'detection_notes': layout.detection_notes, 'board_revision': drivers.revision, 'board_revision_register':
        MSM5500_REVISION_REGISTER if storage.revision_profile else None, 'board_revision_value': MSM5500_REVISION_F025_RAW if storage.revision_profile else None,
        'image_offset': layout.image_offset, 'load_address': 0, 'entry': 0, 'fast_boot_address': drivers.fast_boot_address, 'delay_address': drivers.delay_address,
        'busy_delay_address': drivers.busy_delay_address, 'crc16_address': storage.crc16_address, 'memory_clear_addresses': storage.memory_clear_addresses,
        'memory_copy_addresses': storage.memory_copy_addresses, 'register_ramp_addresses': storage.register_ramp_addresses, 'arm_memory_copy_addresses': storage.arm_memory_copy_addresses,
        'linker': layout.linker, 'overlays': drivers.overlays, 'missing_overlays': [], 'runtime_overlays': []}

def apply_revision_override(config):
    if config.board_revision_value is None:
        try:
            config.board_revision_value = int(config.board_revision, 0)
        except ValueError:
            pass
