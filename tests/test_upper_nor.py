"""Admitted upper-NOR detector and device ownership regressions."""
from __future__ import annotations

from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from msm5xxx_emulator.detection.firmware import detect
from msm5xxx_emulator.detection.firmware import _infer_upper_nor
from msm5xxx_emulator.detection import upper_nor
from msm5xxx_emulator.detection.upper_nor import (
    find_upper_amd_x16_nor,
    find_upper_nor,
)
from msm5xxx import GenericMSMEmulator
from unicorn.arm_const import UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_R0, UC_ARM_REG_R1


class UpperNorTests(unittest.TestCase):
    @staticmethod
    def _bl(raw: bytearray, site: int, target: int) -> None:
        offset = target - site - 4
        if offset < 0:
            offset += 1 << 23
        raw[site:site + 4] = ((0xF000 | (offset >> 12)).to_bytes(2, "little")
                              + (0xF800 | (offset >> 1 & 0x7FF)).to_bytes(2, "little"))

    @classmethod
    def _synthetic(cls) -> bytes:
        raw = bytearray(b"\xff" * 0x100000)
        material, caller = 0x60000, 0x5FF30
        writer, translator = 0xE9E, material + 0x54 + 0x61C2C
        enum_call, material_call = caller + 0x26, caller + 0x5E
        enum = enum_call + 0x7DFE2
        for start, mask in ((material, upper_nor._MATERIAL_MASK),
                            (writer, upper_nor._WRITER_MASK)):
            for index in range(0, len(mask), 2):
                token = mask[index:index + 2]
                if token != "??":
                    raw[start + index // 2] = int(token, 16)
        raw[material + 208:material + 210] = bytes.fromhex("cc65")
        for offset in (70, 84, 106, 132, 302, 310, 320, 352, 370):
            cls._bl(raw, material + offset, material + offset + 4)
        cls._bl(raw, material + 84, translator)
        cls._bl(raw, material + 302, writer)
        for offset in (8, 42, 262, 316, 350, 402, 436):
            cls._bl(raw, writer + offset, writer + offset + 4)
        raw[translator:translator + len(upper_nor._TRANS_HEAD)] = upper_nor._TRANS_HEAD
        raw[translator + 36:translator + 36 + len(upper_nor._TRANS_TAIL)] = upper_nor._TRANS_TAIL
        initializer = 0x200
        raw[initializer:initializer + len(upper_nor._INIT_HEAD)] = upper_nor._INIT_HEAD
        raw[initializer + 48:initializer + 48 + len(upper_nor._INIT_STORE)] = upper_nor._INIT_STORE
        for start, shape in zip((caller - 0x1C, caller - 0x10, caller - 4), upper_nor._INIT_SHAPES):
            raw[start:start + 8] = shape
            cls._bl(raw, start + 8, initializer)
        raw[caller + 0x3E:caller + 0x3E + len(upper_nor._CALLER_WINDOW)] = upper_nor._CALLER_WINDOW
        cls._bl(raw, enum_call, enum)
        cls._bl(raw, material_call, material)
        raw[enum + 0x1C:enum + 0x21] = bytes.fromhex("0316233649")
        raw[enum + 174:enum + 174 + len(upper_nor._CASE4)] = upper_nor._CASE4
        return bytes(raw)

    @staticmethod
    def _fixtures() -> tuple[Path, ...]:
        root = Path(__file__).resolve().parents[1] / "firmwares"
        paths = tuple(path for name in ("lg-sd9210.bin", "LG-SD810-General.bin")
                      if (path := root / name).is_file())
        if not paths:
            raise unittest.SkipTest("upper-NOR fixtures absent")
        return paths

    def test_relocatable_detector_accepts_synthetic_and_rejects_mutation(self) -> None:
        raw = self._synthetic()
        self.assertEqual(find_upper_nor(raw), (True, "accepted"))
        material = raw.find(upper_nor._MATERIAL_HEAD)
        relocated = bytearray(raw)
        relocated[material + 208:material + 210] = bytes.fromhex("40d7")
        self.assertEqual(find_upper_nor(relocated), (True, "accepted"))
        relocated[material + 208] |= 1
        self.assertEqual(
            find_upper_nor(relocated), (False, "materializer-links")
        )
        changed = bytearray(raw)
        # Post +0xF4 materializer code is an admitted required gate.
        changed[material + 0xF4] ^= 1
        self.assertNotEqual(find_upper_nor(changed), (True, "accepted"))

    def test_mapped_upper_x16_detector_requires_linked_driver_shape(self) -> None:
        raw = bytearray(b"\xff" * 0xC00)
        builder, mapper, material = 0x100, 0x300, 0x500
        writer, bridge, erase = 0x700, 0x900, 0xA00
        raw[builder:builder + len(upper_nor._UPPER_X16_BUILDER_PREFIX)] = (
            upper_nor._UPPER_X16_BUILDER_PREFIX
        )
        raw[builder + 0xCC:builder + 0xCC + len(
            upper_nor._UPPER_X16_CAMERA_CASE
        )] = upper_nor._UPPER_X16_CAMERA_CASE
        raw[builder + 0x150:builder + 0x15C] = b"CAMERA\0\0LMS\0"
        raw[mapper:mapper + 8] = upper_nor._UPPER_X16_MAPPER_PREFIX
        raw[mapper + 0x0C:mapper + 0x16] = bytes.fromhex(
            "a52109047b2000047a68"
        )
        raw[mapper + 0x1A:mapper + 0x24] = bytes.fromhex(
            "0121c9050520c0057a68"
        )
        raw[mapper + 0x28:mapper + 0x30] = bytes.fromhex(
            "80bc08bc01201847"
        )
        raw[material:material + 4] = bytes.fromhex("b0b592b0")
        raw[material + 8:material + 0x0C] = bytes.fromhex("051c281c")
        raw[material + 0x10:material + 0x14] = bytes.fromhex("1c491d48")
        raw[material + 0x22:material + 0x26] = bytes.fromhex("041c201c")
        raw[material + 0x2A:material + 0x3C] = bytes.fromhex(
            "0027a74224da02e0781c071cf9e76946381c"
        )
        self._bl(raw, material + 0x1A, mapper)
        self._bl(raw, material + 0x3C, builder)
        for offset in (0x3A, 0x44, 0x4E, 0x58):
            raw[mapper + offset:mapper + offset + 2] = b"\0\xb5"
            raw[mapper + offset + 6:mapper + offset + 10] = bytes.fromhex(
                "08bc1847"
            )
        self._bl(raw, mapper + 0x50, bridge)
        self._bl(raw, mapper + 0x5A, erase)
        raw[bridge:bridge + 2] = b"\0\xb5"
        self._bl(raw, bridge + 2, writer)
        raw[bridge + 6:bridge + 10] = bytes.fromhex("08bc1847")
        raw[writer:writer + len(upper_nor.ADJACENT_AMD_X16_WRITER_PREFIX)] = (
            upper_nor.ADJACENT_AMD_X16_WRITER_PREFIX
        )
        raw[erase:erase + 4] = bytes.fromhex("f0b5071c")
        raw[erase + 0x94:erase + 0x94 + len(
            upper_nor._UPPER_X16_ERASE_COMMAND
        )] = upper_nor._UPPER_X16_ERASE_COMMAND

        with mock.patch.object(
                upper_nor, "_adjacent_amd_x16_writer_at", return_value=True):
            self.assertEqual(find_upper_amd_x16_nor(raw), (
                upper_nor.UPPER_FLASH_ADDRESS,
                upper_nor.UPPER_FLASH_SIZE,
                upper_nor.UPPER_FLASH_SECTOR_SIZE,
            ))
            raw[material + 0x1A:material + 0x1E] = b"\0" * 4
            self.assertIsNone(find_upper_amd_x16_nor(raw))

    def test_reject_reason_is_preserved_for_native_fallback(self) -> None:
        config = SimpleNamespace(detection_notes=[])
        _infer_upper_nor(config, b"\xff" * 0x1000)
        self.assertEqual(
            config.detection_notes,
            ["upper NOR detector rejected at enumerator-case4"],
        )

    def test_upper_nor_owns_full_range_persists_and_state_cannot_collide(self) -> None:
        for fixture in self._fixtures():
            with self.subTest(fixture=fixture.name), tempfile.TemporaryDirectory() as directory:
                config = detect(fixture)
                config.flash_state = str(Path(directory) / "primary.json")
                config.secondary_flash_state = str(Path(directory) / "secondary.json")
                config.upper_flash_state = str(Path(directory) / "upper.json")
                emulator = GenericMSMEmulator(config)
                try:
                    self.assertEqual(emulator.uc.mem_read(0x02800000, 1), b"\xff")
                    self.assertEqual(emulator.uc.mem_read(0x02FFFFFF, 1), b"\xff")
                    code = config.ram_base
                    emulator.uc.mem_write(code, bytes.fromhex("001080e51eff2fe1"))
                    emulator.uc.reg_write(UC_ARM_REG_CPSR, 0x13)
                    emulator.uc.reg_write(UC_ARM_REG_LR, code + 8)
                    for port in (0x02800000, 0x02C00000, 0x02000000):
                        emulator.uc.reg_write(UC_ARM_REG_R0, port)
                        emulator.uc.reg_write(UC_ARM_REG_R1, 0xF0)
                        emulator.uc.emu_start(code, code + 8, count=2)
                    self.assertEqual(emulator.lcd_writes, 1)
                    base, flash = emulator.upper_base, emulator.upper_flash
                    assert base is not None and flash is not None
                    for address, value in ((base + 0xAAA, 0xAA),
                                           (base + 0x554, 0x55),
                                           (base + 0xAAA, 0xA0),
                                           (base + 0x10, 0x5A)):
                        emulator._flash_write(emulator.uc, 0, address, 1, value,
                                              (base, flash))
                    emulator._restore_flash_once(emulator.uc, 0, 0, None)
                    self.assertEqual(emulator.uc.mem_read(base + 0x10, 1), b"Z")
                    self.assertEqual(emulator.lcd_writes, 1)
                    vector = bytes(emulator.uc.mem_read(config.load_address, 4))
                    emulator.uc.reg_write(UC_ARM_REG_CPSR, 0xD3)
                    emulator.uc.emu_start(config.load_address, 0, count=1)
                    self.assertEqual(emulator.uc.mem_read(base + 0x10, 1), b"Z")
                    self.assertEqual(
                        emulator.uc.mem_read(config.load_address, 4), vector
                    )
                finally:
                    emulator.close()
                warm = GenericMSMEmulator(config)
                try:
                    self.assertEqual(warm.uc.mem_read(0x02800010, 1), b"Z")
                finally:
                    warm.close()
                config.upper_flash_state = config.flash_state
                with self.assertRaisesRegex(ValueError, "path collides"):
                    GenericMSMEmulator(config)


if __name__ == "__main__":
    unittest.main()
