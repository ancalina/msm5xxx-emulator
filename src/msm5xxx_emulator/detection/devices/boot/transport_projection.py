"""Source-qualified machine properties owned by this device domain."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import struct

PAUSE_TIMER_ADDRESS = 0x04800020
PAUSE_TIMER_LDR_OFFSETS = (0x26, 0x4E, 0x78, 0xA4)
PAUSE_TIMER_FIXED_HELPER = bytes.fromhex("90b4322813dc00211423041c5c431f23e318223b9b1106d414214843031c1f21"
    "5918223989110048198090bc704700211424322363431f241b19223b9b1106d4" "1421322359431f23c9182239891100481980c11f2b39081c322813dd00211424"
    "322363431f241b199b1105d41421322359431f23c918891100481980c11f2b39" "081ce9e70028d0dd00211423041c5c431f23e3189b1105d414214843031c1f21" "5918891100481980bfe7")

def qemu_legacy_board_revision_property(image: bytes, flash_size: int, keypad: dict | None) -> str | None:
    return _required_dmd_board_revision_property(image, flash_size, keypad, bus_qualified= legacy_sharp_pcr_profile(image, flash_size) is not None)

def qemu_board_revision_property(config: object) -> tuple[str | None, str | None]:
    """Serialize only a complete detector-owned MSM revision readback."""
    register = getattr(config, "board_revision_register", None)
    value = getattr(config, "board_revision_value", None)
    if register is None and value is None:
        return None, None
    if type(register) is not int or type(value) is not int:
        return None, "malformed-pair"
    if register & 3 or not 0x03000000 <= register <= 0x03FFFFFC:
        return None, "unsupported-register"
    if not 0 <= value <= 0xFFFFFFFF:
        return None, "malformed-value"
    return f"board-revision={register:x}:{value:x}", None

def qemu_pause_timer_profile(image: bytes, config: object, immutable_limit: int | None = None,) -> tuple[str | None, str | None]:
    """Return one exact fixed-rate pause timer or its reject reason."""
    load = int(getattr(config, "load_address", 0))
    limit = min(len(image), int(getattr(config, "flash_size", len(image))), immutable_limit if immutable_limit is not None else len(image),)
    template = PAUSE_TIMER_FIXED_HELPER
    prefix = template[:PAUSE_TIMER_LDR_OFFSETS[0]]
    starts: list[int] = []
    anchored = bounded = literal_match = False
    cursor = 0
    while True:
        start = image.find(prefix, cursor, limit)
        if start < 0:
            break
        anchored = True
        cursor = start + 1
        if start & 1 or start + len(template) + 6 > limit:
            continue
        bounded = True
        candidate = bytearray(image[start:start + len(template)])
        if any(facts_for(image).thumb_literal_value(start + offset, 3) != PAUSE_TIMER_ADDRESS for offset in PAUSE_TIMER_LDR_OFFSETS):
            continue
        literal_match = True
        for offset in PAUSE_TIMER_LDR_OFFSETS:
            struct.pack_into("<H", candidate, offset, 0x4800)
        if bytes(candidate) == template:
            starts.append(start)
    if not starts:
        reason = None
        if literal_match:
            reason = "fixed-helper-shape-mismatch"
        elif bounded:
            reason = "pause-register-literal-mismatch"
        elif anchored:
            reason = "fixed-helper-outside-immutable-nor"
        return None, reason
    if len(starts) != 1:
        return None, "fixed-helper-ambiguous"
    start = starts[0]
    literal = struct.pack("<I", 100_000)
    pool = image.find(literal, 0, limit)
    while pool >= 0:
        first = max(0, pool - 0x400) & ~1
        for caller in range(first, min(pool + 1, limit - 5), 2):
            if (facts_for(image).thumb_literal_value(caller, 0) == 100_000 and facts_for(image).thumb_call_target(caller + 2) == start):
                return (
                    f"{PAUSE_TIMER_ADDRESS:x}:{312_500:x}:"
                    f"{load + start:x}:{load + start + len(template):x}",
                    None,
                )
        pool = image.find(literal, pool + 1, limit)
    return None, "100ms-caller-not-found"

def legacy_dmd_loader_patch(image: bytes, config: object, immutable_limit: int | None = None) -> tuple[int, bytes] | None:
    """Return the existing legacy DMD completion contract as Thumb code."""
    entry = getattr(config, "dmd_download_address", None)
    load = int(getattr(config, "load_address", 0))
    if type(entry) is not int:
        return None
    offset = entry - load
    signature = DMD_DOWNLOAD_SIGNATURE
    if (not 0 <= offset <= len(image) - 0xF4 or image[offset:offset + len(signature)] != signature or image.find (signature) != offset or image.find(signature,
        offset + 1) >= 0):
        return None
    try:
        completion, control, _, dmd = struct.unpack_from("<4I", image, offset + 0xE0)
        file_load = struct.unpack_from("<H", image, offset + 0xD4)[0]
        if file_load == 0x4906:
            filename = struct.unpack_from("<I", image, offset + 0xF0)[0]
        elif file_load == 0xA106:
            filename = entry + 0xF0
        else:
            return None
    except struct.error:
        return None
    filename_offset = filename - load
    ram_base = int(getattr(config, "ram_base", 0))
    ram_end = ram_base + int(getattr(config, "ram_size", 0))
    if (control != 0x03000050 or dmd != 0x030007E0 or not ram_base <= completion < ram_end or not 0 <= filename_offset <= len(image) - 12 or not image[filename_offset:filename_offset
        + 12].startswith(b"dmddown_")):
        return None
    halfwords = (
        0xB406,              # push {r1, r2}
        0x4906, 0x4A06,     # completion, 2
        0x700A,              # strb r2, [r1]
        0x4906, 0x4A07,     # control, 1
        0x730A,              # strb r2, [r1, #12]
        0x4907, 0x4A07,     # dmd, 0
        0x608A, 0x818A,     # clear dmd + 8 through + 13
        0xBC06,              # pop {r1, r2}
        0x4803, 0x4770,     # r0 = 1; bx lr
    )
    patch = struct.pack("<14H6I", *halfwords, completion, 2, control, 1, dmd, 0,)
    limit = min(len(image), int(config.flash_size), immutable_limit if immutable_limit is not None else len(image))
    if offset + len(patch) > limit:
        return None
    return offset, patch

def ma2_silent_boot_loader_patch(image: bytes, config: object, immutable_limit: int | None = None) -> tuple[int, bytes] | None:
    """Return the detector-qualified MA2 wait success contract as Thumb code."""
    entry = getattr(config, "ma2_silent_boot_address", None)
    load = int(getattr(config, "load_address", 0))
    detected = find_ma2_silent_boot_wait(image)
    if (type(entry) is not int or detected is None or entry != load + detected or entry & 3):
        return None
    patch = bytes.fromhex("0048704700000000")  # ldr r0, [pc]; bx lr; 0
    limit = min(len(image), int(config.flash_size), immutable_limit if immutable_limit is not None else len(image))
    if detected + len(patch) > limit:
        return None
    return detected, patch

# Required evidence providers are bound by registry discovery.

REQUIRES = {'legacy_sharp_pcr_profile': ('storage.sharp_intel', 'legacy_sharp_pcr_profile'), '_required_dmd_board_revision_property': ('dmd',
    'board_revision_property'), 'DMD_DOWNLOAD_SIGNATURE': ('dmd.boot_rules', 'DMD_DOWNLOAD_SIGNATURE'), 'find_ma2_silent_boot_wait': ('audio.boot_rules',
    'find_ma2_silent_boot_wait')}
