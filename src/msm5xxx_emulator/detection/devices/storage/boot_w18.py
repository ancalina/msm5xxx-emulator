"""Find the linked x16 W18 probe and program routine in a boot image."""

_PROGRAM = bytes.fromhex(
    '0021402020802088000613d476489623026801315343d01e033b05e01a1c834200db021c')
_DESCRIPTOR = bytes.fromhex('0200890065880000000000000000600000001f00000001001f00')


def has_boot_w18(image):
    return (isinstance(image, bytes) and 0x600000 <= len(image) <= 0x800000
            and _PROGRAM in image and _DESCRIPTOR in image)
