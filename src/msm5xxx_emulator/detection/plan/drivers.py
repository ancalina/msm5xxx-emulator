from __future__ import annotations
from msm5xxx_emulator.detection.facts import with_fact_scope

def _assemble_config(layout, drivers, storage):
    from . import FirmwareConfig, _apply_overrides
    from msm5xxx_emulator.detection.registry import device_domain
    config = FirmwareConfig(**_configuration_values(layout, drivers, storage))
    device_domain('storage.postprocess').note_native_nand(config, storage)
    if layout.overrides is not None:
        _apply_overrides(config, layout.overrides, image=layout.image, primary_image=layout.primary_image, compound_fujitsu=layout.compound_fujitsu,
            required_flash_extent=layout.required_flash_extent, auto_relative=drivers.auto_relative, clear_layout=storage.clear_layout, copy_layout=storage.copy_layout,
            ramp_layout=storage.ramp_layout, descriptor_flash_id=storage.descriptor_flash_id,)
    device_domain('storage.postprocess').extend_primary_span(config, layout)
    device_domain('storage.configuration').infer_secondary_nor(config, layout.image, layout.overrides, storage.descriptor_flash_id)
    internal_secondary_seed = device_domain('storage.configuration').configure_state_paths(config, layout.path, layout.image, layout.overrides)
    device_domain('storage.postprocess').note_inline_source(config, layout)
    device_domain('storage.configuration').infer_upper_nor(config, layout.primary_image)
    device_domain('storage.postprocess').finalize_dump_status(config, layout.image, internal_secondary_seed)
    device_domain('watchdog.configuration').bind_configuration(config, layout.image)
    device_domain('display.configuration').bind_geometry(config, layout.image)
    device_domain('external_bus.configuration').bind_configuration(config, layout.image)
    return config

@with_fact_scope
def detect(path: Path, overrides: argparse.Namespace | None = None) -> FirmwareConfig:
    from . import _assemble_config, _scan_drivers, _scan_layout, _scan_resources
    layout = _scan_layout(path, overrides)
    drivers = _scan_drivers(layout)
    storage = _scan_resources(layout, drivers)
    return _assemble_config(layout, drivers, storage)

def _configuration_values(layout, drivers, storage):
    from msm5xxx_emulator.detection.registry import device_domain, device_domains
    values = {}
    for domain in device_domains():
        projector = getattr(device_domain(domain), 'configuration_fields', None)
        if projector is not None:
            fields = projector(layout, drivers, storage)
            overlap = values.keys() & fields.keys()
            if overlap:
                raise ValueError(f'duplicate configuration fields: {sorted(overlap)}')
            values.update(fields)
    return values
