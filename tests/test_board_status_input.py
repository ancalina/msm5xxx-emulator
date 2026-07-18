"""Board-status signature and default-bit regression tests."""
from __future__ import annotations

import struct
from types import SimpleNamespace
import unittest

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM

from msm5xxx import BoardStatusInput, GenericMSMEmulator, find_board_status_input


class BoardStatusInputTests(unittest.TestCase):
    @staticmethod
    def _image() -> bytearray:
        image = bytearray(b"\xff" * 0x400)
        start = 0x100
        image[start:start + 4] = bytes.fromhex("f0b53c48")
        image[start + 4:start + 36] = bytes.fromhex(
            "007808231840082801d1012100e00021002700260124002936484ad0"
        )
        struct.pack_into("<I", image, 0x1F4, 0x03000670)
        return image

    @staticmethod
    def _delayed_image(start: int = 0x100, address: int = 0x03000670,
                       compare_delay: int = 0, branch_delay: int = 0,
                       debounce: bool = True, mask_register: int = 3,
                       result: int = 0, source: int = 3,
                       branch_words: tuple[int, ...] = ()) -> bytearray:
        image = bytearray(b"\xff" * 0x600)
        literal = ((start + 6) & ~3) + 0xF0
        image[start:start + 6] = bytes.fromhex("f0b53c480078")
        words = [0x2008 | (mask_register << 8),
                 0x4000 | (source << 3) | result]
        words.extend([0x2100] * compare_delay)
        words.append(0x2808 | (result << 8))
        words.extend(branch_words or [0x2100] * branch_delay)
        words.append(0xD101)
        if debounce:
            words.extend([0x275F, 0x2760])
        words.append(0xBDF0)
        for index, word in enumerate(words):
            struct.pack_into("<H", image, start + 6 + index * 2, word)
        struct.pack_into("<I", image, literal, address)
        return image

    def test_signature_accepts_exact_shape_and_rejects_near_miss(self) -> None:
        image = self._image()
        self.assertEqual(find_board_status_input(image),
                         BoardStatusInput(0x03000670, 0x08, 0x08))
        image[0x106] = 0x04  # movs r3,#4: wrong mask/compare control shape.
        self.assertIsNone(find_board_status_input(image))

    def test_delayed_compare_x250_style(self) -> None:
        self.assertEqual(find_board_status_input(self._delayed_image(
            compare_delay=5, mask_register=1, result=1, source=0)),
                         BoardStatusInput(0x03000670, 0x08, 0x08))

    def test_delayed_branch_x4500_style(self) -> None:
        self.assertEqual(find_board_status_input(self._delayed_image(
            branch_words=(0x4800,))),
                         BoardStatusInput(0x03000670, 0x08, 0x08))

    def test_delayed_shape_rejects_missing_debounce(self) -> None:
        self.assertIsNone(find_board_status_input(self._delayed_image(debounce=False)))

    def test_delayed_shape_rejects_ands_without_loaded_status(self) -> None:
        self.assertIsNone(find_board_status_input(self._delayed_image(
            result=1, source=3)))

    def test_delayed_shape_rejects_flag_clobber_before_branch(self) -> None:
        self.assertIsNone(find_board_status_input(self._delayed_image(
            branch_words=(0x2100,))))

    def test_duplicate_descriptor_is_accepted(self) -> None:
        image = self._delayed_image()
        duplicate = self._delayed_image(0x300)
        image[0x300:0x600] = duplicate[0x300:0x600]
        self.assertEqual(find_board_status_input(image),
                         BoardStatusInput(0x03000670, 0x08, 0x08))

    def test_distinct_descriptors_are_rejected(self) -> None:
        image = self._delayed_image()
        distinct = self._delayed_image(0x300, 0x03000674)
        image[0x300:0x600] = distinct[0x300:0x600]
        self.assertIsNone(find_board_status_input(image))

    def test_default_assertion_preserves_other_status_bits(self) -> None:
        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = SimpleNamespace(
            board_status_input=BoardStatusInput(0x03000670, 0x08, 0x08)
        )
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x03000000, 0x1000)
        uc.mem_write(0x03000670, b"\x03")
        emulator._refresh_board_status_input(uc)
        self.assertEqual(uc.mem_read(0x03000670, 1), b"\x0b")
        uc.mem_write(0x03000670, b"\x03")
        emulator._refresh_board_status_input(uc, 0x03000670, 1)
        self.assertEqual(uc.mem_read(0x03000670, 1), b"\x0b")


if __name__ == "__main__":
    unittest.main()
