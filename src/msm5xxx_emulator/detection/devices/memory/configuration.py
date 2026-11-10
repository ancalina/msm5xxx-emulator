"""Projection of captured evidence into firmware configuration."""

def configuration_fields(layout, drivers, storage):
    return {'ram_base': layout.ram_base, 'ram_size': layout.ram_size, 'ram_bootstrap_profile': layout.ram_bootstrap_profile}

from msm5xxx_emulator.detection.layout_queries import infer_ram_base

def apply_overrides(config, overrides, primary_image):
    if (getattr(overrides, "chipset", None) is not None and getattr(overrides, "ram_base", None) is None):
        config.ram_base = infer_ram_base(config.linker, config.chipset, primary_image)

def relocate_operations(config, clear_layout, copy_layout, ramp_layout):
    config.memory_clear_addresses = [config.load_address + address if relative else address for address, relative in clear_layout if address is not None]
    config.memory_copy_addresses = [config.load_address + address if relative else address for address, relative in copy_layout if address is not None]
    config.register_ramp_addresses = [config.load_address + address if relative else address for address, relative in ramp_layout if address is not None]

def scan_base(scan_chipset, requested_ram_base):
    if requested_ram_base is not None:
        return requested_ram_base
    return 0x01000000 if scan_chipset in ('MSM5000', 'MSM5500') else 0x01800000
