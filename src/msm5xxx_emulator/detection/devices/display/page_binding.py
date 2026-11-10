"""Source and loader ownership for observed page protocols."""
from __future__ import annotations
_PAIRED_PAGE_CLASSES = ("source-byte-paired-plane-page-v1", "source-byte-pair128-page-v1")

def resolve_page_profile(image, loaded, config):
    from .mono_page import find_odd_byte_page_profile
    profile, reason = find_odd_byte_page_profile(image)
    if profile is None:
        from .paired_page128 import find_paired_page128
        profile = find_paired_page128(image)
        if profile is not None:
            reason = "accepted-interleaved-page-driver"
            loaded = loaded
            if not isinstance(loaded, bytes) or find_paired_page128(loaded) != profile:
                profile, reason = None, "interleaved-page-loaded-source-mismatch"
    if profile is None:
        from .byte_lane_page import find_byte_lane_page_profile
        profile, reason = find_byte_lane_page_profile(image)
    if profile and profile.get("class_name") == "descending-paired-byte-page128-v1":
        loaded = loaded
        spans = profile["source_intervals"]
        base, length = getattr(config, "ram_base", None), getattr(config, "ram_size", None)
        if (type(base) is not int or type(length) is not int or not all(base <= a < b <= base + length for a, b in profile["ram_intervals"])):
            profile, reason = None, "paired-page-RAM-layout-unverified"
        elif (not isinstance(loaded, bytes) or not spans or any(not 0 <= a < b <= min(len(image), len(loaded)) or image[a:b] != loaded[a:b] for a, b in spans)):
            profile, reason = None, "paired-page-loaded-source-mismatch"
        elif loaded is not image and find_byte_lane_page_profile(loaded)[0] != profile:
            profile, reason = None, "paired-page-loaded-owner-mismatch"
    if (profile and profile.get("class_name") == "source-byte-paired-plane-page-v1" and getattr(config, "chipset", None) not in ("MSM5100", "MSM5105")):
        profile, reason = None, "paired-plane-chipset-scope-unclosed"
    if profile and profile.get("class_name") in _PAIRED_PAGE_CLASSES:
        loaded = loaded
        base, length = getattr(config, "ram_base", None), getattr(config, "ram_size", None)
        spans = profile["code_intervals"] + profile["literal_intervals"] + profile["data_intervals"]
        if (type(base) is not int or type(length) is not int or not all(base <= a < b <= base + length for a, b in profile["ram_intervals"])):
            profile, reason = None, "paired-plane-RAM-layout-unverified"
        elif (not isinstance(loaded, bytes) or any(not 0 <= a < b <= min(len(image), len(loaded)) or image[a:b] != loaded[a:b] for a, b in spans)):
            profile, reason = None, "paired-plane-loaded-source-mismatch"
        elif loaded is not image and find_odd_byte_page_profile(loaded)[0] != profile:
            profile, reason = None, "paired-plane-loaded-owner-mismatch"
    if profile and (type(profile.get("page_step", 1)) is not int or profile.get("page_step", 1) not in (-1, 1)):
        profile, reason = None, "source-page-step-unverified"
    return profile, reason

def natural_columns(image, loaded):
    return loaded_natural_columns(image, loaded)

def secondary_source_matches(image, loaded, config, profile):
    base, length = getattr(config, 'ram_base', None), getattr(config, 'ram_size', None)
    descriptor = profile['descriptor']
    return not (not isinstance(loaded, bytes) or type(base) is not int or type(length) is not int or not base <= descriptor < descriptor + 0x2c4 <= base +
        length or any(not 0 <= a < b <= min(len(image), len(loaded)) or image[a:b] != loaded[a:b] for a, b in profile['source_intervals']))

REQUIRES = {'loaded_natural_columns': ('input.table7', 'loaded_natural_columns')}
