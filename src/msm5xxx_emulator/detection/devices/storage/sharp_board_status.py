"""Source-closed status inputs used by Sharp CDM-8500 startup paths."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import struct
from msm5xxx_emulator.detection.layout_queries import find_linker_layout
from msm5xxx_emulator.detection.devices.storage.sharp_intel import find_sharp_intel_profile

_RF_ADDRESS = 0x03000730
_LID_ADDRESS = 0x03000728

def _half(image: bytes, at: int) -> int | None:
    if at < 0 or at > len(image) - 2:
        return None
    return struct.unpack_from("<H", image, at)[0]

def _word(image: bytes, at: int) -> int | None:
    if at < 0 or at > len(image) - 4:
        return None
    return struct.unpack_from("<I", image, at)[0]

def _thumb_cond_target(image: bytes, at: int) -> int | None:
    op = _half(image, at)
    if op is None or op & 0xF000 != 0xD000 or (op >> 8) & 15 >= 14:
        return None
    displacement = (op & 0xFF) << 1
    if displacement & 0x100:
        displacement -= 0x200
    return at + 4 + displacement

def _thumb_movs(op: int | None, reg: int, immediate: int) -> bool:
    return (op is not None and op & 0xF800 == 0x2000 and (op >> 8) & 7 == reg and (op & 0xFF) == immediate)

def _thumb_status_return(image: bytes, at: int) -> bool:
    first, second, branch = (_half(image, at + offset) for offset in (2, 4, 6))
    return (first is not None and first & 0xFE00 == 0xBC00 and second is not None and second & 0xFE00 == 0xBC00 and second & 0xFF == 0x08 and branch is not None
        and branch & 0xFFF8 == 0x4718)

def _rf_getter_candidates(image: bytes) -> list[dict]:
    candidates = []
    for literal_load in range(4, len(image) - 0x50, 2):
        if facts_for(image).thumb_literal_value(literal_load, 0) != _RF_ADDRESS:
            continue
        entry = literal_load - 4
        push = _half(image, entry)
        preserve = _half(image, entry + 2)
        if (push is None or push & 0xFF00 != 0xB500 or not push & 0x0100 or preserve not in (0x1C04, 0x1C05) or _half(image, literal_load + 2) != 0x7800):
            continue
        # Shift left/right by 31 to normalize input bit zero to a boolean.
        left = _half(image, literal_load + 4)
        right = _half(image, literal_load + 6)
        if (left is None or left & 0xF83F != 0x0000 or (left >> 6) & 31 != 31 or right is None or right & 0xF83F != 0x0800 or (right >> 6) & 31 != 31):
            continue
        result_reg = None
        for branch in range(literal_load + 8, min(entry + 0x50, len(image) - 2), 2):
            op = _half(image, branch)
            if op is None or op >> 8 != 0xD1:
                continue
            target = _thumb_cond_target(image, branch)
            target_op = _half(image, target) if target is not None else None
            if target_op is None or target_op & 0xF800 != 0x2000 or target_op & 0xFF != 1:
                continue
            reg = target_op >> 8 & 7
            if any(_thumb_movs(_half(image, p), reg, 0) for p in range(branch + 2, target, 2)):
                result_reg = reg
                break
        if result_reg is None:
            continue
        # The getter returns the selected 0/1 register through R0.
        return_moves = []
        for at in range(entry + 8, min(entry + 0x100, len(image) - 2), 2):
            op = _half(image, at)
            if op is not None and op & 0xFFC7 == 0x1C00 and (op >> 3) & 7 == result_reg and op & 7 == 0:
                return_moves.append(at)
        if not return_moves:
            continue
        variant = "t030-r4-r7" if preserve == 0x1C04 and result_reg == 7 else ("shared-r5-r4" if preserve == 0x1C05 and result_reg == 4 else None)
        if variant is None:
            continue
        candidates.append({"entry": entry, "load": literal_load, "status_literal": ((literal_load + 4) & ~3) + (_half(image, literal_load) & 0xFF) * 4, "branch":
            branch, "result_register": result_reg, "variant": variant})
    return candidates

def _thumb_calls_to(image: bytes, target: int) -> list[int]:
    result = []
    for at in range(0, len(image) - 4, 2):
        if facts_for(image).thumb_call_target(at) == target:
            result.append(at)
    return result

def _rf_initializer(image: bytes, getter: int) -> dict | None:
    calls = _thumb_calls_to(image, getter)
    pairs = []
    for first in calls:
        second = first + 0x1E
        if (second not in calls or not _thumb_movs(_half(image, first - 2), 0, 4) or not _thumb_movs(_half(image, second - 2), 0, 4) or _half(image, first + 4)
            != 0x2800 or _half(image, second + 4) != 0x2800):
            continue
        # Both readiness failures converge on the same error return value.
        b1_op, b2_op = _half(image, first + 6), _half(image, second + 6)
        b1 = _thumb_cond_target(image, first + 6)
        b2 = _thumb_cond_target(image, second + 6)
        if (b1_op is None or b1_op >> 8 != 0xD1 or b2_op is None or b2_op >> 8 != 0xD1 or b1 is None or b2 is None):
            continue
        failure_sites = [at for at in range(second + 8, min(second + 0x30, len(image) - 2), 2) if _thumb_movs(_half(image, at), 0, 13)]
        if (len(failure_sites) != 1 or not (b1 < failure_sites[0] and b2 > failure_sites[0]) or not _thumb_status_return(image, failure_sites[0])):
            continue
        if not any(facts_for(image).thumb_call_target(at) is not None for at in range(first + 8, second, 2)):
            continue
        entries = [at for at in range(max(0, first - 0x150), first, 2) if (_half(image, at) is not None and _half(image, at) & 0xFF00 == 0xB500 and _half(image,
            at) & 0x0100)]
        if len(entries) != 1:
            continue
        pairs.append({"initializer": entries[0], "first_call": first, "second_call": second, "failure_value_site": failure_sites[0], "calls": calls})
    return pairs[0] if len(pairs) == 1 else None

def _arm_literal(image: bytes, at: int, register: int) -> int | None:
    op = _word(image, at)
    if (op is None or op & 0x0F7F0000 != 0x051F0000 or (op >> 12) & 15 != register):
        return None
    delta = op & 0xFFF
    pool = at + 8 + (delta if op & 0x00800000 else -delta)
    return _word(image, pool)

def _arm_imm(op: int) -> int:
    value, rotate = op & 0xFF, ((op >> 8) & 15) * 2
    return ((value >> rotate) | (value << (32 - rotate))) & 0xFFFFFFFF if rotate else value

def _arm_cmp_imm(op: int, condition: int, register: int, immediate: int) -> bool:
    return (op >> 28 == condition and bool(op & 0x02000000) and (op >> 21) & 15 == 10 and bool(op & 0x00100000) and (op >> 16) & 15 == register and _arm_imm(op)
        == immediate)

def _arm_event_wrapper(image: bytes, entry: int) -> bool:
    for at in range(entry, min(entry + 0x24, len(image) - 4), 4):
        first, second, branch = _word(image, at), _word(image, at + 4), _word(image, at + 8)
        if (first is None or not _arm_cmp_imm(first, 14, 0, 0x85) or second is None or not _arm_cmp_imm(second, 1, 0, 0x84) or branch is None or branch >> 28 !=
            1 or branch & 0x0E000000 != 0x0A000000):
            continue
        snapshot = any(_word(image, p) is not None and _word(image, p) & 0x0FFFFFFF == 0x05C102CC for p in range (at + 12, min(at + 0x34, len(image) - 4), 4))
        if not snapshot:
            continue
        callback_slot = None
        for p in range(at + 12, min(at + 0x28, len(image) - 8), 4):
            slot = _arm_literal(image, p, 1)
            if (slot is not None and 0x01000000 <= slot < 0x02000000 and _word(image, p + 4) == 0xE5D11000 and _word(image, p + 8) == 0xE3510000):
                callback_slot = slot
                break
        if callback_slot is None:
            continue
        callback_load = False
        for p in range(entry, min(entry + 0x80, len(image) - 8), 4):
            op = _word(image, p)
            if (op is None or op & 0x0C500000 != 0x04100000 or (op >> 16) & 15 != 4 or (op >> 12) & 15 != 1 or op & 0x00800000):
                continue
            if any(_word(image, q) is not None and _word(image, q) & 0x0FFFFFFF == 0x012FFF11 for q in range(p + 4, min(p + 0x18, len(image) - 4), 4)):
                callback_load = True
                break
        if callback_load:
            return True
    return False

def _arm_branch(image: bytes, at: int) -> int | None:
    op = _word(image, at)
    if op is None or op & 0x0E000000 != 0x0A000000:
        return None
    offset = (op & 0xFFFFFF) << 2
    if offset & 0x02000000:
        offset -= 0x04000000
    return at + 8 + offset

def _lid_candidates(image: bytes, flash_size: int) -> list[dict]:
    layout = find_linker_layout(image, required_span=(0x01000000, 1))
    # The descriptor address is resolved from each candidate PC-relative literal;
    # use a second layout lookup once the RAM address is known.
    if layout is None:
        return []
    found = []
    for at in range(0, min(len(image), flash_size) - 0xA0, 4):
        if _arm_literal(image, at, 0) is None:
            continue
        # Candidate order: descriptor pointer, descriptor+0x24 load, LDRH,
        # bit-six TST, then polarity conversion to a boolean.
        descriptor_ram = _arm_literal(image, at, 0)
        if (descriptor_ram is None or not 0x01000000 <= descriptor_ram < 0x02000000 or _word(image, at + 4) != 0xE5900024 or _word(image, at + 8) != 0xE1D000B0):
            continue
        tst = _word(image, at + 12)
        mov_ne, mov_eq = _word(image, at + 16), _word(image, at + 20)
        if (tst is None or tst & 0x0FFFFFFF != 0x03100040 or mov_ne is None or mov_ne & 0x0FFFFFFF != 0x03A00000 or mov_ne >> 28 != 1 or mov_eq is None or
            mov_eq & 0x0FFFFFFF != 0x03A00001):
            continue
        descriptor_layout = find_linker_layout(image, required_span=(descriptor_ram, 0x28))
        if (descriptor_layout is None or descriptor_layout != layout or not descriptor_layout.data_target <= descriptor_ram <= descriptor_layout.data_target +
            descriptor_layout.data_size - 0x28):
            continue
        descriptor_source = (descriptor_layout.data_source + descriptor_ram - descriptor_layout.data_target)
        if _word(image, descriptor_source + 0x24) != _LID_ADDRESS:
            continue
        # The read value must flow into the change comparison, then into the
        # paired 0x84/0x85 events and their event wrapper.
        changed_value = _word(image, at + 0x18)
        changed_compare = _word(image, at + 0x24)
        unchanged_branch = _word(image, at + 0x28)
        event_compare = _word(image, at + 0x4C)
        enabled = _word(image, at + 0x50)
        disabled = _word(image, at + 0x54)
        mask = _word(image, at + 0x58)
        call = _word(image, at + 0x5C)
        wrapper = _arm_branch(image, at + 0x5C)
        if (changed_value != 0xE20060FF or changed_compare != 0xE1560000 or unchanged_branch is None or unchanged_branch >> 28 != 0 or unchanged_branch &
            0x0E000000 != 0x0A000000 or event_compare != 0xE3560000 or enabled is None or enabled & 0x0FFFFFFF != 0x03A00084 or enabled >> 28 != 0 or disabled
            is None or disabled & 0x0FFFFFFF != 0x03A00085 or disabled >> 28 != 1 or mask is None or mask & 0x0FFFFFFF != 0x020000FF or call is None or call >>
            28 != 14 or call & 0x0F000000 != 0x0B000000 or wrapper is None or not _arm_event_wrapper(image, wrapper)):
            continue
        found.append({"scanner": at, "descriptor_ram": descriptor_ram, "descriptor_source": descriptor_source, "event_pair": at + 0x50, "event_wrapper": wrapper})
    return found

def find_sharp_board_status_profile(image: bytes, flash_size: int, ram_base: int, ram_size: int) -> tuple[dict | None, str]:
    """Recognize the RF-ready and panel-open status paths in Sharp CDM images.

    Admission requires the independently closed Sharp LCD and EFS source
    profiles. The returned bits are hardware inputs; filenames and hashes are
    not consulted.
    """
    if not isinstance(image, bytes) or not image:
        return None, "sharp-board-status-image-invalid"
    page, reason = find_byte_lane_page_profile(image[:flash_size])
    if (page is None or page.get("class_name") != "descending-paired-byte-page128-v1"):
        return None, "sharp-board-status-lcd-source-unverified:" + reason
    efs = find_sharp_intel_profile(image[:flash_size], flash_size, ram_base, ram_size)
    if efs is None or efs.get("signature") != "sharp-pcr-selected-efs-partition-v1":
        return None, "sharp-board-status-efs-source-unverified"
    rf_candidates = _rf_getter_candidates(image[:flash_size])
    rf_matches = []
    for rf in rf_candidates:
        initializer = _rf_initializer(image[:flash_size], rf["entry"])
        if initializer is not None:
            rf_matches.append((rf, initializer))
    lid_matches = _lid_candidates(image, flash_size)
    if len(rf_matches) > 1 or len(lid_matches) > 1:
        return None, "sharp-board-status-source-ambiguous"
    rf = None
    if len(rf_matches) == 1 and rf_matches[0][0]["variant"] == "t030-r4-r7":
        getter, init = rf_matches[0]
        rf = {"address": _RF_ADDRESS, "mask": 1, "default": 1, "getter": getter["entry"], "initializer": init["initializer"], "status_literal": getter["status_literal"],
            "first_call": init["first_call"], "second_call": init["second_call"], "failure_value_site": init["failure_value_site"]}
    lid = None
    if len(lid_matches) == 1:
        match = lid_matches[0]
        lid = {"address": _LID_ADDRESS, "mask": 0x40, "default": 0x40, "scanner": match["scanner"], "descriptor_ram": match["descriptor_ram"],
            "descriptor_source": match["descriptor_source"], "event_pair": match["event_pair"], "event_wrapper": match["event_wrapper"]}
    if rf is None and lid is None:
        return None, "sharp-board-status-paths-not-matched"
    return {"signature": "sharp-cdm-board-status-v1", "rf": rf, "lid": lid, "lcd_source": page, "efs_source": efs}, "accepted-sharp-cdm-board-status"

# Required evidence providers are bound by registry discovery.
REQUIRES = {'find_byte_lane_page_profile': ('display.byte_lane_page', 'find_byte_lane_page_profile')}
