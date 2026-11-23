"""Find the linked x16 W18 probe and program routine in a boot image."""

_PROGRAM = bytes.fromhex(
    '0021402020802088000613d476489623026801315343d01e033b05e01a1c834200db021c')
_DESCRIPTOR = bytes.fromhex('0200890065880000000000000000600000001f00000001001f00')


def has_boot_w18(image):
    return (isinstance(image, bytes) and 0x600000 <= len(image) <= 0x800000
            and _PROGRAM in image and _DESCRIPTOR in image)

_CLOCK = bytes.fromhex('2868031c28688342fbd18018a04200d2201c401830603b68db07f1d5')
_CHIP = bytes.fromhex('2c48c0690005400d702801d100207047')
_POWER_REASON = bytes.fromhex('1148c069000f000700d1704701210907884201d101207047')


def has_boot_legacy_clock(image):
    if not has_boot_w18(image):
        return False
    clock = image.find(_CLOCK)
    chip = image.find(_CHIP)
    reason = image.find(_POWER_REASON)
    if min(clock, chip, reason) < 0:
        return False
    chip_literal = ((chip + 4) & ~3) + image[chip] * 4
    reason_literal = ((reason + 4) & ~3) + image[reason] * 4
    return (image[clock + 46:clock + 58] == bytes.fromhex('08400088c4400088c0400088')
            and image[chip_literal:chip_literal + 4] == bytes.fromhex('40070080')
            and image[reason_literal:reason_literal + 4] == bytes.fromhex('40070080'))

_RAM_TEST = bytes.fromhex(
    '28119fe5001091e5001081e0031001e50420a0e314319fe5003093e50240e0e1004082e78220a0e1030052e1faffffba')
_BUS_INIT = bytes.fromhex('002102286a4a6d4b05d0002803d0012801d0032801d1d36011617047')


def boot_legacy_ram_size(image):
    if not has_boot_legacy_clock(image) or _BUS_INIT not in image:
        return None
    at = image.find(_RAM_TEST)
    if at < 0 or at % 4 or image.find(_RAM_TEST, at + 1) >= 0:
        return None
    limit = int.from_bytes(image[at + 0xe4:at + 0xe8], 'little')
    if limit not in (0x1fffff, 0x3fffff):
        return None
    return 0x4000 + limit + 1
