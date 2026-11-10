"""Firmware boot and guarded-HLE signature detection."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import re
import struct
from msm5xxx_emulator.detection.signatures import find_all

FAST_BOOT_SIGNATURE = bytes.fromhex("234a80b401201070002111702148224f03683f68de19214b1d68046801e001cd"
    "01c4b442fbd30120107011701c481d4f03683f68de191c1c012005e02160a303")
DELAY_SIGNATURE = bytes.fromhex("f0b41d4a978c116a79437a013f239a1a0026322809dc4843222179438018401a"
    "801100d4061c154f22e032234b439d1822237b43341ceb1a9b1100d41c1c0f4f")
BUSY_DELAY_SIGNATURE = bytes.fromhex("0943094309430138fadcf746")
BUSY_DELAY_REGISTER_SIGNATURE = bytes.fromhex("094309430943401efadcf746")
BUSY_DELAY_SIGNATURES = (BUSY_DELAY_SIGNATURE, BUSY_DELAY_REGISTER_SIGNATURE)
CRC16_SIGNATURE = bytes.fromhex("90b4c0430004000c0a4f0ce00c78031263405b00fb5a000258400004000c013a" "1204120c0131002af0dcc0430004000c90bc7047")
MSM5500_REVISION_BLOCK = 0x03000740
MSM5500_REVISION_REGISTER = MSM5500_REVISION_BLOCK + 0x1C
MSM5500_REVISION_F025_RAW = 0x20F5
MSM5500_REVISION_TRANSFORMER = bytes.fromhex("1087108f0f2109030140090af02303401b0219430007000f08431087108f7047")
MSM5500_REVISION_RAW_GETTER = bytes.fromhex("0248808b0005000d7047")
MSM5500_REVISION_BOOT_COMPARE = bytes.fromhex("984202da")
MSM5500_REVISION_BL = re.compile(rb".[\xf0-\xf7].[\xf8-\xff]", re.S)
MSM5500_REVISION_LITERAL_LOAD = re.compile(rb".[\x48-\x4f]", re.S)
MSM5500_REVISION_DIAGNOSTIC = re.compile(rb" ?unsupported msm rev ", re.I)

def detect_msm5500_revision_f025(image: bytes, file_to_runtime=lambda position: position, runtime_to_file= lambda address: address,) -> tuple[bool, str]:
    """Recognise firmware whose complete revision consumers accept real F025."""
    transformers = find_all(image, MSM5500_REVISION_TRANSFORMER)
    getters = find_all(image, MSM5500_REVISION_RAW_GETTER)
    if len(transformers) != 1 or len(getters) != 1:
        return False, "revision transformer/raw-getter count is not unique"
    transformer, getter = transformers[0], getters[0]
    if (transformer < 4 or facts_for(image).thumb_literal_value(transformer - 4, 0) != MSM5500_REVISION_BLOCK or facts_for(image).thumb_literal_value(getter, 0)
        != MSM5500_REVISION_BLOCK):
        return False, "revision reader MMIO literal mismatch"
    reads = []
    for match in MSM5500_REVISION_LITERAL_LOAD.finditer(image):
        site = match.start()
        if site & 1 or site + 4 > len(image):
            continue
        load = struct.unpack_from("<H", image, site)[0]
        base_register = load >> 8 & 7
        if (facts_for(image).thumb_literal_value(site, base_register) != MSM5500_REVISION_BLOCK):
            continue
        read = struct.unpack_from("<H", image, site + 2)[0]
        operation = read & 0xF800
        scale = {0x6800: 4, 0x7800: 1, 0x8800: 2}.get(operation)
        if (scale is not None and read >> 3 & 7 == base_register and (read >> 6 & 0x1F) * scale == 0x1C):
            reads.append(site)
    if set(reads) != {transformer - 4, getter}:
        return False, "0x0300075C has unqualified or missing direct consumers"
    callers = []
    for match in MSM5500_REVISION_BL.finditer(image):
        caller = match.start()
        if not caller & 1 and facts_for(image).thumb_call_target(caller) == getter:
            callers.append(caller)
    stored_fields = set()
    for caller in callers:
        for offset in (4, 6):
            if caller + offset + 2 > len(image):
                continue
            store = struct.unpack_from("<H", image, caller + offset)[0]
            if store & 0xF807 == 0x7000 and store >> 3 & 7 == 7:
                stored_fields.add(store >> 6 & 0x1F)
    if len(callers) != 2 or stored_fields != {1, 3}:
        return False, "raw revision getter is not byte-truncated at fields 1 and 3"
    def relocated_gate(call: int, compare: int) -> bool:
        # New diagnostic spellings require the actual copied getter call and
        # failure-string relation, rather than marker presence alone.
        if call & 1 or compare & 1:
            return False
        raw_target = facts_for(image).thumb_call_target(call)
        caller_address = file_to_runtime(call)
        if (not isinstance(raw_target, int) or not isinstance(caller_address, int) or caller_address & 1 or not 0 <= caller_address <= 0xFFFFFFFF):
            return False
        target_address = caller_address + raw_target - call
        target = runtime_to_file(target_address)
        if (not isinstance(target, int) or target & 3 or not 0 <= target <= len(image) - 16 or file_to_runtime(target) != target_address or target_address & 3
            or image[target:target + 12] != bytes.fromhex("7847c04600c09fe51cff2fe1")):
            return False
        pointer = struct.unpack_from("<I", image, target + 12)[0]
        entry = transformer - 18
        if (not pointer & 1 or entry < 0 or runtime_to_file(pointer & ~1) != entry or file_to_runtime(entry) != pointer & ~1 or image[entry + 4:entry + 14] !=
            bytes.fromhex("0879002811d101200871")):
            return False
        diagnostic = compare + 4
        if diagnostic + 6 > len(image):
            return False
        adr = struct.unpack_from("<H", image, diagnostic)[0]
        diagnostic_address = file_to_runtime(diagnostic)
        if (adr & 0xFF00 != 0xA000 or not isinstance(diagnostic_address, int) or diagnostic_address & 1 or not 0 <= diagnostic_address <= 0xFFFFFFFB or
            runtime_to_file(diagnostic_address) != diagnostic):
            return False
        string_address = ((diagnostic_address + 4) & ~3) + (adr & 0xFF) * 4
        if not 0 <= string_address <= 0xFFFFFFFF:
            return False
        string = runtime_to_file(string_address)
        if (not isinstance(string, int) or not 0 <= string < len(image) or file_to_runtime(string) != string_address):
            return False
        marker = MSM5500_REVISION_DIAGNOSTIC.match(image, string)
        return (marker is not None and string_address + marker.end() - string <= 0x100000000 and all(file_to_runtime(position) == string_address + position -
            string and runtime_to_file(string_address + position - string) == position for position in range(string, marker.end())) and facts_for(image).thumb_call_target(diagnostic
            + 2) is not None)
    legacy_diagnostic = b" Unsupported MSM REV " in image
    boot_gate = False
    for compare in find_all(image, MSM5500_REVISION_BOOT_COMPARE):
        load, call = compare - 2, compare - 6
        if (call >= 0 and facts_for(image).thumb_call_target(call) is not None and facts_for(image).thumb_literal_value(load, 3) == 0xF022 and (legacy_diagnostic
            or relocated_gate(call, compare))):
            boot_gate = True
            break
    if not boot_gate:
        return False, "signed F022 boot gate/diagnostic relation absent"
    return True, ("closed MSM5500 revision class detected; supplying compatible F025 " "stepping through 16-bit 0x0300075C read")

def busy_delay_addresses(image: bytes, load_address: int, configured_address: int | None) -> list[int]:
    """Return all exact primary-ROM busy-delay entries, including overrides."""
    addresses = {load_address + offset for signature in BUSY_DELAY_SIGNATURES for offset in find_all(image, signature)}
    if configured_address is not None:
        addresses.add(configured_address)
    return sorted(addresses)
