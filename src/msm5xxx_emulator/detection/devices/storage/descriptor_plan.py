"""Source and ownership decisions for descriptor-backed NOR banks."""
from types import SimpleNamespace
from ...capabilities import Capability, CapabilityPredicate, CapabilityRegistry, Evidence, ResourceClaim
from .descriptor_bank import find_descriptor_bank, find_truncated_descriptor_bank, source_prefix_matches
from .rules import direct_amd_x16_nor_profile, mapped_primary_intel_x16_nor_profile
from .sharp_intel import find_sharp_intel_profile
from .upper_nor import find_upper_amd_x16_nor


def _early(ctx):
    cfg, image = ctx.config, ctx.image
    if not (cfg.load_address == 0 and cfg.secondary_flash_address is None
            and cfg.upper_flash_address is None and cfg.native_nand_profile is None
            and cfg.nand_image is None and cfg.primary_flash_probe_address is None
            and cfg.ram_image_size == 0 and cfg.ram_bootstrap_profile is None):
        return None
    result = find_truncated_descriptor_bank(image, cfg.flash_id_address, cfg.flash_size, cfg.ram_base, cfg.ram_size)
    if result is None:
        return None
    extent, profile = result
    direct, _ = direct_amd_x16_nor_profile(image, cfg.load_address, extent, 0, cfg.ram_base, cfg.ram_size)
    mapped, _ = mapped_primary_intel_x16_nor_profile(image.ljust(extent, b'\xff'), extent, cfg.ram_base)
    sharp = find_sharp_intel_profile(image, extent, cfg.ram_base, cfg.ram_size)
    upper = find_upper_amd_x16_nor(image)
    if any(owner is not None for owner in (direct, mapped, sharp, upper)):
        return None
    return _capability(image, profile, extent, 'descriptor-truncated')


def _bank(ctx):
    cfg = ctx.config
    if ctx.claimed or cfg.load_address != 0:
        return None
    profile = ctx.profile or find_descriptor_bank(ctx.image, cfg.flash_id_address, cfg.flash_size, cfg.ram_base, cfg.ram_size)
    if profile is None or not source_prefix_matches(ctx.image, ctx.loaded, profile):
        return None
    return _capability(ctx.image, profile, cfg.flash_size, 'descriptor-bank')


def _capability(image, profile, extent, name):
    evidence = Evidence(name, profile, (0, min(len(image), profile[0])), 'linkage')
    return Capability(name, (name,), (evidence,), parameters=(('profile', profile), ('extent', extent)),
                      claims=(ResourceClaim('address', name, profile[0], profile[0] + profile[1]),))

_EARLY = CapabilityRegistry()
_EARLY.register(CapabilityPredicate('descriptor-truncated', (), _early))
_BANK = CapabilityRegistry()
_BANK.register(CapabilityPredicate('descriptor-bank', (), _bank))

def early_plan(image, config):
    return _EARLY.resolve(SimpleNamespace(image=image, config=config)).plan

def bank_plan(image, loaded, config, *, claimed, profile=None):
    return _BANK.resolve(SimpleNamespace(image=image, loaded=loaded, config=config, claimed=claimed, profile=profile)).plan
