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
