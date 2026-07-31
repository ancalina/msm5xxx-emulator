"""Focused regression tests for descriptor-backed fs_dev flash IDs."""
from __future__ import annotations

import argparse
import struct
from types import SimpleNamespace
import unittest

from msm5xxx_emulator.detection.boot import FLASH_ID_SIGNATURE
from msm5xxx_emulator.detection.firmware import _apply_overrides, _infer_secondary_nor
from msm5xxx_emulator.detection.storage import (
    find_fs_device_flash_id,
    flash_id_for_size,
)


def _thumb_bl(source: int, target: int) -> bytes:
    displacement = target - source - 4
    if not -(1 << 22) <= displacement < 1 << 22 or displacement & 1:
        raise ValueError("Thumb BL target out of range")
    encoded = displacement & ((1 << 23) - 1)
    return struct.pack(
        "<2H", 0xF000 | (encoded >> 12), 0xF800 | (encoded >> 1 & 0x7FF)
    )


def _fixture() -> tuple[bytearray, int, int]:
    image = bytearray(b"\xff" * 0x2000)
    outer, lookup, veneer = 0x300, 0x400, 0x200
    entry, descriptor = 0xF80, 0x1000
    module_base, table = 0x010009FC, 0x01000AA4
    flash_id_address = table + 8

    signature_site = 0x1800
    struct.pack_into("<2I", image, signature_site - 8, entry, 0)
    image[signature_site:signature_site + len(FLASH_ID_SIGNATURE)] = (
        FLASH_ID_SIGNATURE
    )
    image[veneer:veneer + 2] = b"\x08\x47"
    image[lookup:lookup + 0x44] = bytes.fromhex(
        "90b5104810494069096840004718"
        "00000000"
        "041c381c0d49"
        "00000000"
        "071c002c01d1"
        "00000000"
        "0a4807e080310a89498909041143b94203d0043001680029f4d1006890bd"
    )
    image[lookup + 0x0E:lookup + 0x12] = _thumb_bl(lookup + 0x0E, 0x220)
    image[lookup + 0x18:lookup + 0x1C] = _thumb_bl(lookup + 0x18, veneer)
    image[lookup + 0x22:lookup + 0x26] = _thumb_bl(lookup + 0x22, 0x224)
    struct.pack_into(
        "<4I", image, lookup + 0x44,
        descriptor, module_base, flash_id_address | 1, table,
    )

    image[outer:outer + 0x24] = bytes.fromhex(
        "90b5084c002727606760"
        "00000000"
        "6060002805d1"
        "00000000"
        "03a1fc20"
        "00000000"
        "277290bd"
    )
    image[outer + 10:outer + 14] = _thumb_bl(outer + 10, lookup)
    struct.pack_into("<I", image, outer + 0x24, module_base)

    struct.pack_into("<I", image, entry + 4, 2)
    struct.pack_into("<2I", image, entry + 8, 0x10000, 0x20000)
    struct.pack_into("<I", image, descriptor + 8, 0x12340001)
    struct.pack_into("<3I", image, descriptor + 0x10, 1, 0x80000, 0x18000)
    return image, flash_id_address, descriptor


def _config(value: int) -> SimpleNamespace:
    return SimpleNamespace(
        flash_id_address=0x1000,
        flash_id_value=value,
        framebuffer_address=None,
        framebuffer_stride=0,
        framebuffer_format="none",
        framebuffer_flush_address=None,
        framebuffer_rect_flush_address=None,
        width=176,
        height=220,
        display_geometry_source="auto-default",
        board_revision="auto/unknown",
        board_revision_value=None,
        nand_image=None,
        nand_enabled=False,
        chipset="MSM5000",
        linker=None,
        ram_base=0x01380000,
        ram_size=0x800000,
        load_address=0,
        flash_size=0x200000,
        secondary_flash_address=None,
        secondary_flash_size=0x200000,
        secondary_flash_image=None,
        secondary_flash_image_offset=None,
        ram_image_offset=0x200000,
        ram_image_size=0,
        memory_clear_addresses=[],
        memory_copy_addresses=[],
        register_ramp_addresses=[],
        secondary_flash_read_address=None,
        secondary_flash_write_address=None,
        legacy_efs_page_read_address=None,
        detection_notes=[],
    )


class DescriptorFlashIDTests(unittest.TestCase):
    def test_unique_linked_descriptor_accepts_and_mutations_reject(self) -> None:
        image, address, descriptor = _fixture()
        self.assertEqual(
            find_fs_device_flash_id(bytes(image), address), 0x12340001
        )

        mutations = {
            "duplicate-signature": lambda data: data.__setitem__(
                slice(0x1900, 0x1900 + len(FLASH_ID_SIGNATURE)),
                FLASH_ID_SIGNATURE,
            ),
            "copy-payload": lambda data: struct.pack_into(
                "<I", data, 0x17F8, descriptor - 0x7C
            ),
            "runtime-link": lambda data: struct.pack_into(
                "<I", data, 0x44C, address + 5
            ),
            "table-plus-nine": lambda data: struct.pack_into(
                "<I", data, 0x450, 0x01000A98
            ),
            "geometry": lambda data: struct.pack_into(
                "<I", data, descriptor + 0x18, 0x17000
            ),
            "outer-call": lambda data: data.__setitem__(
                0x30A, data[0x30A] ^ 1
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = bytearray(image)
                mutate(changed)
                self.assertIsNone(
                    find_fs_device_flash_id(bytes(changed), address)
                )

    def test_overrides_do_not_replace_descriptor_id(self) -> None:
        descriptor_id = 0x12340001
        config = _config(descriptor_id)
        _apply_overrides(
            config, argparse.Namespace(flash_size=0x400000),
            image=b"", primary_image=b"", compound_fujitsu=None,
            required_flash_extent=0, auto_relative=set(),
            clear_layout=[], copy_layout=[], ramp_layout=[],
            descriptor_flash_id=descriptor_id,
        )
        self.assertEqual(config.flash_id_value, descriptor_id)

        config = _config(flash_id_for_size(0x200000))
        _apply_overrides(
            config, argparse.Namespace(flash_size=0x400000),
            image=b"", primary_image=b"", compound_fujitsu=None,
            required_flash_extent=0, auto_relative=set(),
            clear_layout=[], copy_layout=[], ramp_layout=[],
        )
        self.assertEqual(
            config.flash_id_value, flash_id_for_size(0x400000)
        )

        config = _config(descriptor_id)
        _apply_overrides(
            config, argparse.Namespace(flash_id_value=0xDEAD0001),
            image=b"", primary_image=b"", compound_fujitsu=None,
            required_flash_extent=0, auto_relative=set(),
            clear_layout=[], copy_layout=[], ramp_layout=[],
        )
        self.assertEqual(config.flash_id_value, 0xDEAD0001)

    def test_secondary_inference_preserves_only_descriptor_provenance(
            self) -> None:
        descriptor_id = 0x12340001
        config = _config(descriptor_id)
        config.secondary_flash_address = 0x200000
        config.secondary_flash_size = 0x400000
        _infer_secondary_nor(config, b"", None, descriptor_id)
        self.assertEqual(config.flash_id_value, descriptor_id)

        config = _config(flash_id_for_size(0x200000))
        config.secondary_flash_address = 0x200000
        config.secondary_flash_size = 0x400000
        _infer_secondary_nor(config, b"", None)
        self.assertEqual(
            config.flash_id_value, flash_id_for_size(0x400000)
        )


if __name__ == "__main__":
    unittest.main()
