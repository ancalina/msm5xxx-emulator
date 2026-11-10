"""Firmware input and board-status detection."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import re
import struct
from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.detection.devices.input.table7 import find_table7_matrix
from msm5xxx_emulator.detection.devices.input.scanner import scanner_at
from msm5xxx_emulator.detection.devices.input.scanner_arm_clock import arm_clock_scanner_at
from msm5xxx_emulator.detection.devices.input.scanner_direct import direct_scanner_at
from msm5xxx_emulator.detection.devices.input.sd810 import sd810_gpio_board_status_profile
from msm5xxx_emulator.detection.devices.input.seven_row import find_seven_row_board_status
from msm5xxx_emulator.detection.devices.input.scanner_gated import gated_scanner_at

LG_INPUT_PATTERN = re.compile(rb"\x00\xb5.{4}.{4}\x08\xbc\x18\x47\x00\x00" rb"\x90\xb5\x07\x1c\x0c\x1c.{4}\x39\x88\x21\x43\x39\x80"
    rb"\x00\x28\x01\xd1.{4}\x90\xbc\x08\xbc\x18\x47" rb"\x90\xb5\x07\x1c\x0c\x1c.{4}\x39\x88\x21\x40\x39\x80" rb"\x00\x28\x01\xd1", re.S,)
LG_DECODED_ENQUEUE_SIGNATURE = bytes.fromhex("f7b50c1c151c17480121490240188078202803db0020febc08bc1847")
SAMSUNG_INPUT_PATTERN = re.compile(rb"\x54\x2f.{2}\x55\x2f.{2}.{0,120}" rb"\x50\x78\x13\x78\x41\x1c\xc9\x06\xc9\x0e\x99\x42\x07\xd0"
    rb"\x80\x18\x87\x70\x50\x78\x01\x30\xc0\x06\xc0\x0e\x50\x70", re.S,)
BOARD_STATUS_INPUT_BODY = bytes.fromhex("007808231840082801d1012100e00021002700260124002936484ad0")

def detect_input_profile(image: bytes, load_address: int = 0) -> tuple[str, int, int | None] | None:
    """Locate LG/Samsung input signatures for diagnostics only."""
    lg_matches = list(LG_INPUT_PATTERN.finditer(image))
    if len(lg_matches) == 1:
        wrapper = lg_matches[0].start()
        decoder = facts_for(image).thumb_call_target(wrapper + 2)
        drain = facts_for(image).thumb_call_target(wrapper + 6)
        enqueue = decoder + 0x6C if decoder is not None else -1
        if (drain is not None and image[enqueue:enqueue + len(LG_DECODED_ENQUEUE_SIGNATURE)] == LG_DECODED_ENQUEUE_SIGNATURE):
            return "lg-decoded", load_address + enqueue, load_address + drain
    samsung_matches = list(SAMSUNG_INPUT_PATTERN.finditer(image))
    if len(samsung_matches) == 1:
        match = samsung_matches[0].start()
        for entry in range(match & ~1, max(-1, match - 0xC0), -2):
            if image[entry:entry + 4] in (b"\x80\xb5\x07\x1c", b"\xb0\xb5\x07\x1c"):
                return "samsung-queue", load_address + entry, None
    return None

def _board_status_and_flags(image: bytes, start: int) -> bool:
    """Recognize the inverted-state, paired-event byte-input control class."""
    if image[start + 4:start + 10] != bytes.fromhex("007808231840"):
        return False
    state = facts_for(image).thumb_literal_value(start + 10, 4)
    if state is None or not 0x01000000 <= state < 0x01800000 - 9:
        return False
    if start + 14 > len(image):
        return False
    branch = struct.unpack_from("<H", image, start + 12)[0]
    if branch & 0xFF80 != 0xD000:  # Forward BEQ consuming ANDS flags; LDR preserves them.
        return False
    clear = start + 16 + (branch & 0x7F) * 2
    if (image[clear:clear + 4] != bytes.fromhex("00270120") or facts_for(image).thumb_literal_value(clear + 4, 1) is None or image[clear + 6:clear + 10] !=
        bytes.fromhex("20720870") or image[clear - 6:clear - 2] not in (bytes.fromhex("00202072"), bytes.fromhex("00212172")) or image[clear - 2:clear] != bytes.fromhex("04e0")):
        return False
    end = image.find(bytes.fromhex("281cf0bc08bc1847"), clear + 10, min(start + 0x400, len(image)))
    if end < 0 or (end - start) & 1:
        return False
    # Both counters must load/increment/truncate/store the same byte, then compare.
    for field, threshold in ((6, 1), (7, 2)):
        patterns = [struct.pack("<6H", 0x7820 | field << 6 | reg, 0x3001 | reg << 8, 0x0600 | reg << 3 | reg, 0x0E00 | reg << 3 | reg, 0x7020 | field << 6 | reg,
            0x2800 | reg << 8 | threshold) for reg in (0, 1)]
        if not any(image[pos:pos + 12] in patterns for pos in range(clear + 10, end - 11, 2)):
            return False
    if image[end - 4:end - 2] != bytes.fromhex("6025"):
        return False
    jump = struct.unpack_from("<H", image, end - 2)[0]
    if jump & 0xF800 != 0xE000:
        return False
    displacement = jump & 0x7FF
    if displacement & 0x400:
        displacement -= 0x800
    join = end + 2 + displacement * 2
    return (clear < join < end - 4 and image[join:join + 2] == b"\x28\x1c" and (target := facts_for(image).thumb_call_target(join + 2)) is not None and 0 <=
        target < len(image) and any(image[pos:pos + 2] == b"\x5f\x25" for pos in range(clear + 10, join, 2)))

_SD810_UNSET = object()

def find_board_status_input(image: bytes, notes: list[str] | None = None, *, sd810_profile: tuple[int, int, int] | None | object = _SD810_UNSET, source_info:
    dict | None = None) -> BoardStatusInput | None:
    """Accept one unique source-closed board contact and its default level."""
    boot_inputs = find_boot_download_inputs(image)
    found: set[BoardStatusInput] = set(boot_inputs)
    seven_row_status = find_seven_row_board_status(image)
    if seven_row_status is not None:
        found.add(seven_row_status)
        if notes is not None:
            notes.append("source-closed seven-row lid GPIO: open/high default")
    guard = find_cold_power_guard(image)
    if guard is not None:
        found.add(guard)
        if notes is not None:
            notes.append("cold-boot power guard GPIO input: boot-allowed high")
    table7 = find_table7_matrix(image)
    if table7 is not None:
        fold = table7["fold_input"]
        found.add(BoardStatusInput(fold["address"], fold["mask"], fold["default"]))
        if notes is not None:
            notes.append("table-driven keypad fold input high")
    sd810 = (sd810_gpio_board_status_profile(image) if sd810_profile is _SD810_UNSET else sd810_profile)
    if sd810 is not None:
        found.add(BoardStatusInput(*sd810))
    # This compiler layout loads the GPIO literal before saving registers.
    for match in re.finditer(b"\xb0\xb5\x00\x78", image):
        start = match.start() - 2
        if start < 0 or start & 1:
            continue
        scanner, reason = direct_scanner_at(image, start)
        if scanner is not None:
            found.add(scanner)
        elif reason and notes is not None:
            notes.append(f"board-status scanner rejected at {start:#x}: {reason}")
    found.update(_required_board_contact_find_inputs(image, notes))
    offset = 0
    while (offset := image.find(b"\xf0\xb5", offset)) >= 0:
        scanner, reason = arm_clock_scanner_at(image, offset)
        if scanner is not None:
            found.add(scanner)
        elif reason and notes is not None:
            notes.append(f"board-status scanner rejected at {offset:#x}: {reason}")
        scanner, reason = scanner_at(image, offset)
        if scanner is not None:
            found.add(scanner)
        elif reason and notes is not None:
            notes.append(f"board-status scanner rejected at {offset:#x}: {reason}")
        scanner, reason = gated_scanner_at(image, offset)
        if scanner is not None:
            found.add(scanner)
        elif reason and notes is not None:
            notes.append(f"board-status scanner rejected at {offset:#x}: {reason}")
        address = facts_for(image).thumb_literal_value(offset + 2, 0)
        # Offset-byte variant shares the debounced 5F/60 status events.
        # Asserted default is experimental; physical fold polarity is unverified.
        offset_byte = image[offset + 4:offset + 14] == bytes.fromhex("007a04231840042801d1")
        mask = 0x04 if offset_byte else 0x08
        if offset_byte and address is not None:
            address += 8
        candidate = (BoardStatusInput(address, mask, mask) if address is not None and 0x03000000 <= address < 0x03800000 else None)
        if (image[offset + 4:offset + 4 + len(BOARD_STATUS_INPUT_BODY)] == BOARD_STATUS_INPUT_BODY):
            if candidate is not None:
                found.add(candidate)
        elif candidate is not None and _board_status_and_flags(image, offset):
            found.add(candidate)
        elif candidate is not None and (offset_byte or image[offset + 4:offset + 6] == b"\x00\x78"):
            body_end = min(offset + 0x400, len(image) - 1)
            pop = next((position for position in range(offset + 6, body_end, 2) if struct.unpack_from("<H", image, position)[0] == 0xBDF0), None)
            early_end = min(offset + 0x100, pop if pop is not None else offset)
            debounced = (pop is not None and b"\x5f\x27" in image[offset + 6:pop] and b"\x60\x27" in image[offset + 6:pop])
            for movs in range(offset + 6, early_end, 2):
                move = struct.unpack_from("<H", image, movs)[0]
                if move & 0xF8FF != 0x2000 | mask:
                    continue
                mask_register = (move >> 8) & 7
                if mask_register == 0:
                    continue
                for ands in range(movs + 2, min(movs + 10, early_end), 2):
                    word = struct.unpack_from("<H", image, ands)[0]
                    if word & 0xFFC0 != 0x4000:
                        continue
                    result = word & 7
                    source = (word >> 3) & 7
                    if {result, source} != {0, mask_register}:
                        continue
                    compare = 0x2800 | mask | (result << 8)
                    for position in range(ands + 2, min(ands + 16, early_end), 2):
                        if struct.unpack_from("<H", image, position)[0] != compare:
                            continue
                        for branch in range(position + 2, min(position + 8, early_end), 2):
                            if struct.unpack_from("<H", image, branch)[0] & 0xFF00 != 0xD100:
                                continue
                            if (debounced and all((word := struct.unpack_from("<H", image, delay)[0]) == 0xBF00 or word & 0xF800 == 0x4800 for delay in range(position
                                + 2, branch, 2))):
                                found.add(candidate)
                        break
        offset += 2
    if len(found) > 1 and notes is not None:
        notes.append("board-status input rejected: ambiguous descriptors")
    result = next(iter(found)) if len(found) == 1 else None
    if source_info is not None:
        source_info['native_default'] = (seven_row_status is not None or guard is not None or (result is not None and result in boot_inputs))
    if result is not None and result in boot_inputs and notes is not None:
        notes.append("closed active-low boot-download GPIO: released key default")
    return result

# Required evidence providers are bound by registry discovery.
REQUIRES = {'find_boot_download_inputs': ('external_bus.boot_download', 'find_boot_download_inputs'), 'find_cold_power_guard': ('external_bus.cold_power_guard',
    'find_cold_power_guard'), '_required_board_contact_find_inputs': ('board_contact', 'find_inputs')}
