"""Synthetic UART boot-download GPIO recognition."""
import struct
import unittest

from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.detection.registry import device_domain

find_boot_download_inputs = device_domain(
    "external_bus.boot_download"
).find_boot_download_inputs
find_board_status_input = device_domain("input.rules").find_board_status_input


class HalfwordBootDownloadTests(unittest.TestCase):
    def image(self):
        image = bytearray(0x400)
        struct.pack_into("<H", image, 0x100, 0x490B)
        image[0x102:0x11A] = bytes.fromhex(
            "00b5042088820020088101300004000c6428fadb8889c008"
        )
        struct.pack_into("<HHHH", image, 0x11A, 0xD206, 0x4805, 0x8208, 0x8088)

        def bl(at, target):
            delta = target - at - 4
            struct.pack_into(
                "<HH",
                image,
                at,
                0xF000 | (delta >> 12 & 0x7FF),
                0xF800 | (delta >> 1 & 0x7FF),
            )

        bl(0x122, 0x200)
        bl(0x126, 0x280)
        struct.pack_into("<HHH", image, 0x12A, 0x2000, 0xBC08, 0x4718)
        struct.pack_into("<I", image, 0x130, 0x03000660)
        struct.pack_into("<I", image, 0x134, 0x408A)
        struct.pack_into("<H", image, 0x200, 0x227E)
        struct.pack_into("<HHI", image, 0x280, 0x4778, 0, 0xE321F0D3)
        return image

    def test_halfword_gpio_bit2_skips_uart_downloader(self):
        image = bytes(self.image())
        status = BoardStatusInput(0x0300066C, 4, 4)
        self.assertEqual(find_boot_download_inputs(image), {status})
        self.assertEqual(find_board_status_input(image), status)
        for offset in (0x102, 0x116, 0x11B, 0x11E, 0x200, 0x280, 0x130):
            altered = bytearray(image)
            altered[offset] ^= 1
            self.assertNotIn(status, find_boot_download_inputs(bytes(altered)))
