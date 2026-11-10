"""Source-bound completion protocol and native property contract."""
from msm5xxx_emulator.detection.facts import facts_for
import struct
from ...facts import facts_for, source_prefix
from ...signatures import find_all

DMD_DOWNLOAD_5500_LITERALS = struct.pack("<5I", 0x030E0000, 0x030F0120, 0x00001388, 0x030E01A0, 0x0000FFFF)
DMD_DOWNLOAD_5500_SIZE = 0x54

def is_dmd_download_5500(image: bytes, entry: int = 0) -> bool:
    """Match complete MSM5500 DMD start/wait/ack grammar at one entry."""
    fixed = { 0: bytes.fromhex("b0b50020"), 8: bytes.fromhex("002803d10c480088"), 17: bytes.fromhex("2803d00020b0bc08bc1847094800248480"), 38: bytes.fromhex("084f084d02e0381c"),
        50: bytes.fromhex("e889064b9842f8d1ec810120eae7"), 64: DMD_DOWNLOAD_5500_LITERALS, }
    if (not 0 <= entry <= len(image) - DMD_DOWNLOAD_5500_SIZE or not facts_for(image).view.covers(entry, DMD_DOWNLOAD_5500_SIZE)):
        return False
    if not all(image[entry + offset:entry + offset + len(value)] == value for offset, value in fixed.items()):
        return False
    return all(facts_for(image).thumb_call_target(entry + offset) is not None for offset in (4, 34, 46))

def detect_dmd_download_5500(image: bytes) -> int | None:
    """Find one source-backed MSM5500 DMD download completion routine."""
    entries = [literal - 64 for literal in find_all(image, DMD_DOWNLOAD_5500_LITERALS) if is_dmd_download_5500(image, literal - 64)]
    return entries[0] if len(entries) == 1 else None

def qemu_5500_property(image: bytes, config: object, immutable_limit: int | None = None,) -> tuple[str | None, str | None]:
    """Admit only the unique complete MSM5500 DMD completion grammar."""
    entry = getattr(config, "dmd_download_address", None)
    if entry is None:
        return None, None
    load = getattr(config, "load_address", None)
    flash_size = getattr(config, "flash_size", None)
    if (type(entry) is not int or type(load) is not int or type(flash_size) is not int or flash_size <= 0):
        return None, "malformed-config"
    limit = min(len(image), flash_size, immutable_limit if immutable_limit is not None else len(image))
    primary = source_prefix(image, limit)
    detected = detect_dmd_download_5500(primary)
    if detected is None:
        return None, None
    if getattr(config, "chipset", None) != "MSM5500":
        return None, "unsupported-chipset"
    if entry != load + detected:
        return None, "address-mismatch"
    if detected + DMD_DOWNLOAD_5500_SIZE > limit:
        return None, "outside-immutable-primary-nor"
    return f"dmd-5500={entry:x}:{primary[detected + 16]:x}", None
