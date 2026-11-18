"""Released boot-download input from a closed GPIO consumer and loader route."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import struct
from msm5xxx_emulator.core.config import BoardStatusInput

# GPIO+0xC bit 2: high skips the UART framed downloader.
_HALFWORD_BOOT_DOWNLOAD = bytes.fromhex(
    "00b5042088820020088101300004000c6428fadb8889c008"
)


def halfword_boot_download_input_at(image: bytes, at: int) -> BoardStatusInput | None:
    """Close a halfword GPIO+0xC bit2 gate into the UART framed downloader."""
    if at < 2 or at & 1 or at + 0x30 > len(image):
        return None
    if image[at:at + len(_HALFWORD_BOOT_DOWNLOAD)] != _HALFWORD_BOOT_DOWNLOAD:
        return None
    branch = struct.unpack_from("<H", image, at + 0x18)[0]
    if branch & 0xFF00 != 0xD200 or (branch & 0xFF) < 4:
        return None
    if (facts_for(image).thumb_literal_value(at - 2, 1) != 0x03000660 or
            struct.unpack_from("<HH", image, at + 0x1C) != (0x8208, 0x8088)):
        return None
    hello = facts_for(image).thumb_call_target(at + 0x20)
    veneer = facts_for(image).thumb_call_target(at + 0x24)
    if (hello is None or hello & 1 or hello + 0x40 > len(image) or
            veneer is None or veneer & 3 or veneer + 8 > len(image)):
        return None
    if (0x227E not in struct.unpack_from("<32H", image, hello) or
            struct.unpack_from("<HHI", image, veneer) != (0x4778, 0, 0xE321F0D3)):
        return None
    if struct.unpack_from("<HHH", image, at + 0x28) != (0x2000, 0xBC08, 0x4718):
        return None
    return BoardStatusInput(0x0300066C, 4, 4)


def boot_download_input_at(image: bytes, at: int) -> BoardStatusInput | None:
    if at < 0 or at & 1 or at + 0x1C > len(image):
        return None
    words = struct.unpack_from('<14H', image, at)
    expected = { 0: 0xB500, 3: 0x7108, 4: 0x2000, 6: 0x7008, 8: 0x7900, 9: 0x08C0, 10: 0xD201, 13: 0xBD00, }
    if any(words[index] != word for index, word in expected.items()):
        return None
    # The GPIO direction/row producer differs between the two board wirings.
    if words[1] not in (0x2004, 0x2008):
        return None
    if (facts_for(image).thumb_literal_value(at + 4, 1) != 0x03000670 or facts_for(image).thumb_literal_value(at + 10, 1) != 0x03000660 or facts_for(image).thumb_literal_value(at
        + 14, 0) != 0x03000690):
        return None
    loader = facts_for(image).thumb_call_target(at + 22)
    if loader is None or loader & 3 or loader + 12 > len(image):
        return None
    # BL enters an ARM downloader through BX pc, preserves Thumb return state,
    # then masks interrupts in supervisor mode. It cannot be an ordinary key.
    if struct.unpack_from('<HHII', image, loader) != (0x4778, 0, 0xE38EE001, 0xE321F0D3):
        return None
    return BoardStatusInput(0x03000694, 4, 4)

def direct_boot_download_input_at(image: bytes, at: int) -> BoardStatusInput | None:
    """Close a selected GPIO gate into the in-image framed downloader."""
    if at < 0 or at & 1 or at + 0x1E > len(image):
        return None
    words = struct.unpack_from('<15H', image, at)
    expected = {0: 0x2010, 2: 0x7108, 3: 0x2000, 5: 0x7008, 7: 0x7900, 8: 0x08C0, 9: 0xD202, 13: 0x2C0B}
    if any(words[index] != word for index, word in expected.items()):
        return None
    if (facts_for(image).thumb_literal_value(at + 2, 1) != 0x03000670 or facts_for(image).thumb_literal_value(at + 8, 1) != 0x03000660 or facts_for(image).thumb_literal_value(at
        + 12, 0) != 0x03000690 or words[12] & 0xF800 != 0xE000 or words[14] & 0xFF00 != 0xD100):
        return None
    loader = facts_for(image).thumb_call_target(at + 20)
    if loader is None or loader & 1 or loader + 0x24 > len(image):
        return None
    # Dispatcher allocates its packet buffer, calls its receiver and bounds the
    # command byte before indexing the command table. The key gate skips it.
    body = struct.unpack_from('<18H', image, loader)
    fixed = {0: 0xB580, 2: 0x6800, 3: 0x2301, 4: 0x035B, 5: 0x1AC0, 7: 0x6048, 9: 0x6840, 12: 0x1C07, 14: 0x6840, 15: 0x7800, 16: 0x280F}
    receiver = facts_for(image).thumb_call_target(loader + 20)
    if (any(body[index] != word for index, word in fixed.items()) or body[17] & 0xFF00 != 0xD200 or receiver is None or receiver & 1 or not 0 <= receiver < len(image)):
        return None
    return BoardStatusInput(0x03000694, 4, 4)

def find_boot_download_inputs(image: bytes) -> set[BoardStatusInput]:
    found, at = set(), 0
    marker = struct.pack('<H', 0xB500)  # PUSH {lr}.
    while (at := image.find(marker, at)) >= 0:
        result = boot_download_input_at(image, at)
        if result is not None:
            found.add(result)
        result = halfword_boot_download_input_at(image, at)
        if result is not None:
            found.add(result)
        at += 2
    at = 0
    marker = struct.pack('<H', 0x2010)  # MOV r0, #0x10, row/direction selector.
    while (at := image.find(marker, at)) >= 0:
        result = direct_boot_download_input_at(image, at)
        if result is not None:
            found.add(result)
        at += 2
    return found
