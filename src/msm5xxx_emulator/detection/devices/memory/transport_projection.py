"""Source-qualified machine properties owned by this device domain."""
from __future__ import annotations
from dataclasses import asdict
from msm5xxx_emulator.core.initial_state import REGISTER_NAMES
from msm5xxx_emulator.detection.startup_sdram import reset_copy_ram_profile

def qemu_ram_argument(size: int) -> str:
    """Preserve exact bytes; keep MiB spelling for aligned RAM allocations."""
    if type(size) is not int or size <= 0:
        raise ValueError("QEMU RAM size must be a positive integer byte count")
    mib = 1024 * 1024
    return f"{size // mib}M" if size % mib == 0 else f"{size}B"

def qemu_memory_profile(config: object, registers: dict[str, int]) -> str:
    """Encode only the memory/reset state represented by the machine."""
    expected = {name: 0 for name in REGISTER_NAMES}
    expected["sp"] = registers["sp"]
    expected["cpsr"] = 0xD3
    flash_size = int(config.flash_size)
    ram_base = int(config.ram_base)
    ram_end = ram_base + int(config.ram_size)
    if (not 0x1000 <= flash_size <= ram_base or registers != expected or registers["sp"] & 3 or not ram_base <= registers["sp"] <= ram_end - 4):
        raise ValueError("QEMU memory profile cannot represent initial state")
    return f"{flash_size:x}:{ram_base:x}:{registers['sp']:x}"

def qemu_ram_reserved_property(image: bytes, config: object, sp: int) -> str | None:
    """Bind the reserved bus window to the same reset-consumed RAM class."""
    profile = getattr(config, "ram_bootstrap_profile", None)
    if profile is None:
        return None
    flash_size = getattr(config, "flash_size", None)
    if (type(profile) is not dict or type(flash_size) is not int or flash_size <= 0 or type(getattr(config, "load_address", None)) is not int or config.load_address
        != 0):
        raise ValueError("invalid reset-linked RAM profile")
    expected = reset_copy_ram_profile(image[:flash_size])
    if (expected is None or profile != expected or profile.get("experimental") is not True or any(type(profile.get(key)) is not int for key in ("ram_base",
        "ram_size", "reserved_base", "reserved_size")) or any(type(getattr(config, key, None)) is not int or getattr(config, key) != expected[key] for key in ("ram_base",
        "ram_size"))):
        raise ValueError("reset-linked RAM profile does not match firmware or memory layout")
    linker = getattr(config, "linker", None)
    try:
        if linker is not None and asdict(linker) != expected["bootstrap_linker"]:
            raise ValueError("reset-linked RAM linker does not match firmware")
    except TypeError as exc:
        raise ValueError("invalid reset-linked RAM linker") from exc
    base, size = expected["reserved_base"], expected["reserved_size"]
    if (type(sp) is not int or sp & 3 or not expected["ram_base"] + 4 <= sp <= expected["ram_base"] + expected["ram_size"] - 4 or sp <= base + size and sp + 4 >
        base):
        raise ValueError("reset-linked RAM stack overlaps the reserved bus window")
    return f"ram-reserved={base:x}:{size:x}"

def validate_loaded_reserved(loaded, config, sp, expected, owners):
    if any(profile is not None for profile in owners):
        raise ValueError('reset-linked RAM profile requires a stable primary NOR image')
    if qemu_ram_reserved_property(loaded, config, sp) != expected:
        raise ValueError('loaded NOR changed the reset-linked RAM profile')
