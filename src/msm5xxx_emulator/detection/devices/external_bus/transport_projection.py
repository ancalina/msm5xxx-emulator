"""Source-qualified machine properties owned by this device domain."""
from __future__ import annotations
import json

def qemu_boot_contact_property(config: object, original: bytes, loaded: bytes, *, input_claimed: bool = False, layout_claimed: bool = False, eeprom_window:
    tuple[int, int] | None = None):
    """Bind one released contact read to the actual immutable primary image."""
    from msm5xxx_emulator.detection.devices.external_bus.boot_contact_5100 import find_boot_contact_release
    profile, reason = find_boot_contact_release(original)
    if profile is None:
        return None, None
    fields = ("load_address", "image_offset", "entry", "flash_size", "ram_base", "ram_size")
    if (any(type(getattr(config, key, None)) is not int for key in fields) or (config.load_address, config.image_offset, config.entry) != (0, 0, 0) or getattr(config,
        "image_kind", None) != "firmware" or getattr (config, "chipset", None) not in ("MSM5100", "MSM5105") or not isinstance(loaded, bytes) or len(loaded) !=
        config.flash_size or not original or not 0 < config.flash_size <= 0xffffffff or not 0 <= config.ram_base < config.ram_base+config.ram_size <=
        0x100000000):
        return None, "boot-contact-memory-layout-unclosed"
    if (layout_claimed or getattr(config, "missing_overlays", None) or getattr(config, "ram_bootstrap_profile", None) is not None or getattr(config,
        "ram_image_size", 0)):
        return None, "boot-contact-memory-owner-unclosed"
    if (input_claimed or getattr(config, "key_register", None) is not None or getattr(config, "board_status_input", None) is not None or getattr(config,
        "spi_nv_profile", None) is not None):
        return None, "boot-contact-input-owner-unclosed"
    windows= []
    if eeprom_window is not None:windows.append(eeprom_window)
    revision=getattr(config,"board_revision_register",None)
    adc=getattr(config,"board_adc_address",None)
    if revision is not None:windows.append((revision,4))
    if adc is not None:windows.append((adc,4))
    for base,size in windows:
        if type(base) is not int or type(size) is not int or not 0 <= base < base+size <= 0x100000000:
            return None,"boot-contact-port-owner-unclosed"
        if base < profile["address"]+4 and profile["address"] < base+size:
            return None,"boot-contact-port-owner-conflict"
    spans=profile["code_intervals"]+profile["literal_intervals"]+profile["display_source_intervals"]
    ram=profile["ram_intervals"]+profile["display_ram_intervals"]
    if (any(not 0 <= a < b <= min(config.flash_size,len(original)) for a,b in spans) or any(not config.ram_base <= a < b <= config.ram_base+config.ram_size for
        a,b in ram)):
        return None,"boot-contact-source-layout-unclosed"
    # No mutated helper bodies or executable overlays can share this admission.
    if original[:config.flash_size].ljust(config.flash_size, b"\xff") != loaded:
        return None,"boot-contact-loaded-source-changed"
    current,_=find_boot_contact_release(loaded)
    if current != profile:
        return None,"boot-contact-loaded-profile-changed"
    stored=getattr(config,"boot_keysense_release",None)
    if stored is not None and json.loads(json.dumps(stored)) != json.loads(json.dumps(profile)):
        return None,"boot-contact-config-profile-changed"
    return "experimental-boot-contact="+":".join(f"{v:x}" for v in
        (profile["address"],profile["read_pcs"][0],profile["mask"],profile["width"])),None
