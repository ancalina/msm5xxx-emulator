"""Domain-owned final configuration and source admission."""

from .rules import detect_external_bus

def bind_configuration(config, image):
    if config.load_address == 0 and config.image_kind == "firmware":
        reserved_external = (() if config.ram_bootstrap_profile is None else ((config.ram_bootstrap_profile["reserved_base"], config.ram_bootstrap_profile["reserved_size"]),))
        config.external_bus, external_reason = detect_external_bus(image[:config.flash_size], ram_base=config.ram_base, ram_size=config.ram_size, reserved_ram=reserved_external,)
        if config.external_bus is not None:
            config.detection_notes.append("external bus admitted from linked device consumers and linker extents")
        elif "halt" in external_reason or "ambiguous" in external_reason:
            config.detection_notes.append(f"external RAM rejected: {external_reason}")
