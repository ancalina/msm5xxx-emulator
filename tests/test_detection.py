"""Detector regression tests for BSP and handset identity evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM
from unicorn.arm_const import (UC_ARM_REG_CPSR, UC_ARM_REG_LR, UC_ARM_REG_PC,
                               UC_ARM_REG_R0)

from msm5xxx import (
    BUSY_DELAY_SIGNATURE,
    DMD_DOWNLOAD_510X_SIGNATURE,
    EEPROM_24LC64_CLASS_A_READ_PREFIX,
    EEPROM_24LC64_CLASS_A_SENTINEL,
    EEPROM_24LC64_CLASS_A_WRITE_PREFIX,
    EEPROM_24LCXX_READ_SIGNATURE,
    EEPROM_24LCXX_WRITE_PREFIX,
    EEPROM_24LCXX_X430_INIT_SIGNATURE,
    EEPROM_24LCXX_X430_READ_PREFIX,
    EEPROM_24LCXX_X430_WRITE_PREFIX,
    EEPROM_24LCXX_X270_INIT_SIGNATURE,
    EEPROM_24LCXX_X270_READ_PREFIX,
    EEPROM_24LCXX_X270_WRITE_PREFIX,
    EEPROM_24LCXX_X7700_INIT_SIGNATURE,
    EEPROM_24LCXX_X7700_READ_PREFIX,
    EEPROM_24LCXX_X7700_WRITE_PREFIX,
    arm_vector_score,
    busy_delay_addresses,
    chipset_confidence,
    detect,
    detect_chipset,
    detect_model,
    GenericMSMEmulator,
    find_24lcxx_driver,
    find_compound_fujitsu_layout,
    find_fujitsu_x16_bulk_write,
    find_rex_5ms_irq_arm,
    find_rex_5ms_irq_route,
    find_rex_5ms_sleep_timer,
    find_trampm5_consumer,
    fujitsu_x16_flash_ids,
    trampm5_consumer_at,
    thumb_bl_target,
    thumb_literal_value,
)


PRIVATE_FIRMWARES = (Path(__file__).resolve().parent.parent / "firmwares").is_dir()


class DetectionTests(unittest.TestCase):
    @staticmethod
    def _thumb_literal_position(image: bytes | bytearray,
                                position: int) -> int:
        word = struct.unpack_from("<H", image, position)[0]
        return ((position + 4) & ~3) + (word & 0xFF) * 4

    def test_firmware_identity_and_diagnostic_config_are_path_safe(self) -> None:
        raw = bytearray(b"\xff" * 0x100)
        for offset in range(0, 32, 4):
            struct.pack_into("<I", raw, offset, 0xEA000000)
        with tempfile.TemporaryDirectory() as directory, patch(
                "msm5xxx.DEFAULT_STATE_ROOT", Path(directory)):
            firmware = Path(directory) / "private" / "phone.bin"
            firmware.parent.mkdir()
            firmware.write_bytes(raw)
            config = detect(firmware)

        self.assertEqual(config.firmware_identity(), {
            "basename": "phone.bin",
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
        telemetry = json.dumps(config.diagnostic_config(), sort_keys=True)
        self.assertNotIn(str(firmware.parent), telemetry)
        self.assertNotIn(str(Path(config.flash_state).parent), telemetry)

    def test_literal_arm_vector_table_is_executable_firmware(self) -> None:
        raw = bytearray(b"\xff" * 0x100)
        struct.pack_into("<I", raw, 0, 0xEA000000)  # reset: b 0x8
        for index in (1, 2, 3, 4, 6, 7):
            struct.pack_into("<I", raw, index * 4, 0xE59FF020)
            struct.pack_into("<I", raw, index * 4 + 8 + 0x20,
                             0x80 + index * 4)
        self.assertEqual(arm_vector_score(bytes(raw)), 7)
        invalid = bytearray(raw)
        for index in (1, 2, 3, 4, 6, 7):
            struct.pack_into("<I", invalid, index * 4 + 8 + 0x20,
                             0xFFFFFFFF)
        self.assertEqual(arm_vector_score(bytes(invalid)), 1)
        with tempfile.TemporaryDirectory() as directory:
            firmware = Path(directory) / "literal-vectors.bin"
            firmware.write_bytes(raw)
            self.assertEqual(detect(firmware).image_kind, "firmware")

    def test_busy_delay_addresses_keep_exact_duplicate_functions(self) -> None:
        image = bytearray(b"\xff" * 0x80)
        image[0x10:0x10 + len(BUSY_DELAY_SIGNATURE)] = BUSY_DELAY_SIGNATURE
        image[0x50:0x50 + len(BUSY_DELAY_SIGNATURE)] = BUSY_DELAY_SIGNATURE

        self.assertEqual(
            busy_delay_addresses(bytes(image), 0x10000000, None),
            [0x10000010, 0x10000050],
        )
        self.assertEqual(
            busy_delay_addresses(bytes(image), 0x10000000, 0x20000000),
            [0x10000010, 0x10000050, 0x20000000],
        )

    def test_510x_dmd_signature_is_unique_and_completes_only_its_contract(self) -> None:
        image = bytearray(b"\xff" * 0x400)
        image[0x100:0x100 + len(DMD_DOWNLOAD_510X_SIGNATURE)] = (
            DMD_DOWNLOAD_510X_SIGNATURE
        )
        with tempfile.TemporaryDirectory() as directory:
            firmware = Path(directory) / "dmd-510x.bin"
            firmware.write_bytes(image)
            self.assertEqual(detect(firmware).dmd_download_address, 0x100)
            image[0x200:0x200 + len(DMD_DOWNLOAD_510X_SIGNATURE)] = (
                DMD_DOWNLOAD_510X_SIGNATURE
            )
            firmware.write_bytes(image)
            self.assertIsNone(detect(firmware).dmd_download_address)

        entry, guard, completion, control, dmd, filename = (
            0x1000, 0x01002004, 0x01001D10, 0x03000050, 0x030007E0, 0x1800
        )
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_map(0x01000000, 0x10000)
        uc.mem_map(0x03000000, 0x1000)
        uc.mem_write(entry, DMD_DOWNLOAD_510X_SIGNATURE)
        uc.mem_write(entry + 0xE8, struct.pack("<I", guard))
        uc.mem_write(entry + 0xEC, struct.pack("<I", completion))
        uc.mem_write(entry + 0xF0, struct.pack("<I", control))
        uc.mem_write(entry + 0xF8, struct.pack("<I", dmd))
        uc.mem_write(entry + 0xFC, struct.pack("<I", filename))
        uc.mem_write(filename, b"dmddown_510x.c\0")
        uc.mem_write(dmd + 8, b"\xff" * 8)
        uc.reg_write(UC_ARM_REG_LR, 0x1801)
        uc.reg_write(UC_ARM_REG_CPSR, 0)

        emulator = GenericMSMEmulator.__new__(GenericMSMEmulator)
        emulator.config = type("Config", (), {
            "ram_base": 0x01000000, "ram_size": 0x10000,
        })()
        emulator.fast_dmd_downloads = 0

        uc.reg_write(UC_ARM_REG_PC, 0x1050)
        uc.mem_write(entry + 0xF0, struct.pack("<I", control + 4))
        emulator._dmd_download_fast(uc, entry, 2, None)
        self.assertEqual(uc.reg_read(UC_ARM_REG_PC), 0x1050)
        self.assertEqual(bytes(uc.mem_read(completion, 1)), b"\0")
        self.assertEqual(emulator.fast_dmd_downloads, 0)

        uc.mem_write(entry + 0xF0, struct.pack("<I", control))
        uc.mem_write(filename, b"not-dmd-file\0")
        emulator._dmd_download_fast(uc, entry, 2, None)
        self.assertEqual(uc.reg_read(UC_ARM_REG_PC), 0x1050)
        self.assertEqual(bytes(uc.mem_read(completion, 1)), b"\0")
        self.assertEqual(emulator.fast_dmd_downloads, 0)

        uc.mem_write(filename, b"dmddown_510x.c\0")
        uc.mem_write(guard, struct.pack("<I", 1))
        emulator._dmd_download_fast(uc, entry, 2, None)
        self.assertEqual(uc.reg_read(UC_ARM_REG_PC), 0x1050)
        self.assertEqual(bytes(uc.mem_read(completion, 1)), b"\0")
        self.assertEqual(emulator.fast_dmd_downloads, 0)

        uc.mem_write(guard, b"\0" * 4)
        emulator._dmd_download_fast(uc, entry, 2, None)

        self.assertEqual(bytes(uc.mem_read(guard, 4)), b"\x02\0\0\0")
        self.assertEqual(bytes(uc.mem_read(completion, 1)), b"\x02")
        self.assertEqual(bytes(uc.mem_read(control + 0xC, 1)), b"\x01")
        self.assertEqual(bytes(uc.mem_read(dmd + 8, 1)), b"\0")
        self.assertEqual(bytes(uc.mem_read(dmd + 9, 3)), b"\xff" * 3)
        self.assertEqual(bytes(uc.mem_read(dmd + 12, 1)), b"\0")
        self.assertEqual(bytes(uc.mem_read(dmd + 13, 3)), b"\xff" * 3)
        self.assertEqual(uc.reg_read(UC_ARM_REG_R0), 1)
        self.assertEqual(uc.reg_read(UC_ARM_REG_PC), 0x1800)
        self.assertEqual(uc.reg_read(UC_ARM_REG_CPSR) & 0x20, 0x20)
        self.assertEqual(emulator.fast_dmd_downloads, 1)

    def test_24lcxx_driver_requires_unique_read_write_and_geometry(self) -> None:
        image = bytearray(b"\xff" * 0x800)
        write = 0x40
        read = 0x180
        geometry = 0x0138159C
        image[write:write + len(EEPROM_24LCXX_WRITE_PREFIX)] = (
            EEPROM_24LCXX_WRITE_PREFIX
        )
        image[write + 14] = 0xF8  # literal distance varies by compiler layout
        operation = struct.unpack_from("<H", image, write + 14)[0]
        literal = ((write + 18) & ~3) + (operation & 0xFF) * 4
        struct.pack_into("<I", image, literal, geometry)
        image[read:read + len(EEPROM_24LCXX_READ_SIGNATURE)] = (
            EEPROM_24LCXX_READ_SIGNATURE
        )
        read_operation = struct.unpack_from("<H", image, read + 10)[0]
        read_literal = ((read + 14) & ~3) + (read_operation & 0xFF) * 4
        struct.pack_into("<I", image, read_literal, geometry)
        image[0x700:0x70B] = b"nv24lcxx.c\0"

        self.assertEqual(find_24lcxx_driver(bytes(image)),
                         (read, write, geometry))

        image[0x300:0x300 + len(EEPROM_24LCXX_READ_SIGNATURE)] = (
            EEPROM_24LCXX_READ_SIGNATURE
        )
        self.assertIsNone(find_24lcxx_driver(bytes(image)))

    def test_24lc64_class_a_requires_bound_inclusive_max_consumer(self) -> None:
        image = bytearray(b"\xff" * 0x1800)
        write = 0x100
        read = write + 0x768
        geometry = read + 0xACC
        call = geometry - 0x32
        image[write:write + len(EEPROM_24LC64_CLASS_A_WRITE_PREFIX)] = (
            EEPROM_24LC64_CLASS_A_WRITE_PREFIX
        )
        image[read:read + len(EEPROM_24LC64_CLASS_A_READ_PREFIX)] = (
            EEPROM_24LC64_CLASS_A_READ_PREFIX
        )
        image[call - 6:call - 2] = b"\x00\x21\x20\x1c"
        literal_base = (call + 2) & ~3
        struct.pack_into("<H", image, call - 2,
                         0x4A00 | ((geometry - literal_base) // 4))
        displacement = read - call - 4
        struct.pack_into(
            "<2H", image, call,
            0xF000 | (displacement >> 12 & 0x7FF),
            0xF800 | (displacement >> 1 & 0x7FF),
        )
        image[geometry - 0x1A:geometry - 0xA] = (
            EEPROM_24LC64_CLASS_A_SENTINEL
        )
        struct.pack_into("<I", image, geometry, 0x1FFF)
        image[0x1700:0x170B] = b"nv24lcxx.c\0"

        self.assertEqual(find_24lcxx_driver(bytes(image)),
                         (read, write, geometry))

        duplicate = bytearray(image)
        duplicate[0x40:0x40 + len(EEPROM_24LC64_CLASS_A_READ_PREFIX)] = (
            EEPROM_24LC64_CLASS_A_READ_PREFIX
        )
        self.assertIsNone(find_24lcxx_driver(bytes(duplicate)))

        broken = bytearray(image)
        struct.pack_into("<2H", broken, call, 0xF000, 0xF800)
        self.assertIsNone(find_24lcxx_driver(bytes(broken)))

    def test_24lcxx_x430_variant_requires_unique_pair_and_geometry(self) -> None:
        image = bytearray(b"\xff" * 0x1800)
        write = 0x40
        read = 0x800
        initializer = 0xC00
        geometry = 0x01184CDC
        image[write:write + len(EEPROM_24LCXX_X430_WRITE_PREFIX)] = (
            EEPROM_24LCXX_X430_WRITE_PREFIX
        )
        image[read:read + len(EEPROM_24LCXX_X430_READ_PREFIX)] = (
            EEPROM_24LCXX_X430_READ_PREFIX
        )
        image[initializer:initializer + len(EEPROM_24LCXX_X430_INIT_SIGNATURE)] = (
            EEPROM_24LCXX_X430_INIT_SIGNATURE
        )
        for position in (write, read):
            struct.pack_into("<I", image, position + 0x3E8, geometry)
        struct.pack_into("<I", image, initializer + 0x14, geometry)
        image[0x1700:0x170B] = b"nv24lcxx.c\0"

        self.assertEqual(find_24lcxx_driver(bytes(image)),
                         (read, write, geometry))

        bad_geometry = bytearray(image)
        struct.pack_into("<I", bad_geometry, read + 0x3E8, geometry + 4)
        self.assertIsNone(find_24lcxx_driver(bytes(bad_geometry)))

        duplicate_initializer = bytearray(image)
        duplicate_initializer[0xD00:0xD00 + len(EEPROM_24LCXX_X430_INIT_SIGNATURE)] = (
            EEPROM_24LCXX_X430_INIT_SIGNATURE
        )
        struct.pack_into("<I", duplicate_initializer, 0xD14, geometry)
        self.assertIsNone(find_24lcxx_driver(bytes(duplicate_initializer)))

    def test_24lcxx_x270_variant_requires_unique_pair_and_geometry(self) -> None:
        image = bytearray(b"\xff" * 0x2000)
        write = 0x40
        read = 0x800
        initializer = 0xC00
        geometry = 0x01176784
        image[write:write + len(EEPROM_24LCXX_X270_WRITE_PREFIX)] = (
            EEPROM_24LCXX_X270_WRITE_PREFIX
        )
        image[read:read + len(EEPROM_24LCXX_X270_READ_PREFIX)] = (
            EEPROM_24LCXX_X270_READ_PREFIX
        )
        image[initializer:initializer + len(EEPROM_24LCXX_X270_INIT_SIGNATURE)] = (
            EEPROM_24LCXX_X270_INIT_SIGNATURE
        )
        for position in (write, read):
            struct.pack_into("<I", image, position + 0x3EC, geometry)
        struct.pack_into("<I", image, initializer + 0x14, geometry)
        image[0x1E00:0x1E0B] = b"nv24lcxx.c\0"

        self.assertEqual(find_24lcxx_driver(bytes(image)),
                         (read, write, geometry))

        bad_geometry = bytearray(image)
        struct.pack_into("<I", bad_geometry, read + 0x3EC, geometry + 4)
        self.assertIsNone(find_24lcxx_driver(bytes(bad_geometry)))

        duplicate_marker = bytearray(image)
        duplicate_marker[0x1F00:0x1F0B] = b"NV24LCXX.C\0"
        self.assertIsNone(find_24lcxx_driver(bytes(duplicate_marker)))

    def test_24lcxx_x7700_variant_requires_full_pair_and_geometry(self) -> None:
        image = bytearray(b"\xff" * 0x2200)
        write = 0x40
        read = 0x800
        initializer = 0xC00
        geometry = 0x010CDB5C
        image[write:write + len(EEPROM_24LCXX_X7700_WRITE_PREFIX)] = (
            EEPROM_24LCXX_X7700_WRITE_PREFIX
        )
        image[read:read + len(EEPROM_24LCXX_X7700_READ_PREFIX)] = (
            EEPROM_24LCXX_X7700_READ_PREFIX
        )
        image[initializer:initializer + len(EEPROM_24LCXX_X7700_INIT_SIGNATURE)] = (
            EEPROM_24LCXX_X7700_INIT_SIGNATURE
        )
        struct.pack_into("<I", image, write + 0x3EC, geometry)
        struct.pack_into("<I", image, read + 0x3E8, geometry)
        struct.pack_into("<I", image, initializer + 0x14, geometry)
        image[0x2100:0x2116] = b"nv24lcxx.c\0nv24lcxx.c\0"

        self.assertEqual(find_24lcxx_driver(bytes(image)),
                         (read, write, geometry))

        bad_geometry = bytearray(image)
        struct.pack_into("<I", bad_geometry, read + 0x3E8, geometry + 4)
        self.assertIsNone(find_24lcxx_driver(bytes(bad_geometry)))

        duplicate_write = bytearray(image)
        duplicate_write[0x1200:0x1200 + len(EEPROM_24LCXX_X7700_WRITE_PREFIX)] = (
            EEPROM_24LCXX_X7700_WRITE_PREFIX
        )
        self.assertIsNone(find_24lcxx_driver(bytes(duplicate_write)))

        duplicate_read = bytearray(image)
        duplicate_read[0x1400:0x1400 + len(EEPROM_24LCXX_X7700_READ_PREFIX)] = (
            EEPROM_24LCXX_X7700_READ_PREFIX
        )
        self.assertIsNone(find_24lcxx_driver(bytes(duplicate_read)))

        duplicate_initializer = bytearray(image)
        duplicate_initializer[0x1800:0x1800 + len(EEPROM_24LCXX_X7700_INIT_SIGNATURE)] = (
            EEPROM_24LCXX_X7700_INIT_SIGNATURE
        )
        struct.pack_into("<I", duplicate_initializer, 0x1814, geometry)
        self.assertIsNone(find_24lcxx_driver(bytes(duplicate_initializer)))

        no_marker = bytearray(image)
        no_marker[0x2100:0x2116] = b"\xff" * 0x16
        self.assertIsNone(find_24lcxx_driver(bytes(no_marker)))

    def test_5105_clock_bsp_beats_inherited_dec5000_module(self) -> None:
        image = b"dec5000.c\0mclk_5105.c\0"

        chipset = detect_chipset(image, "SCP-4700")

        self.assertEqual(chipset, "MSM5105")
        self.assertEqual(chipset_confidence(image, chipset), "high")

    def test_generic_510x_bsp_remains_msm5100(self) -> None:
        image = b"dec5000.c\0clkrgm_5100.c\0boothw_510x.c\0"
        chipset = detect_chipset(image, "generic")

        self.assertEqual(chipset, "MSM5100")
        self.assertEqual(chipset_confidence(image, chipset), "high")

    def test_model_name_alone_does_not_assign_chipset(self) -> None:
        self.assertEqual(detect_chipset(b"generic firmware", "SPH-X9000"),
                         "MSM5xxx")

    def test_scp_filename_normalizes_identity_without_assigning_hardware_profile(self) -> None:
        self.assertEqual(
            detect_model(b"SCP-4700BySANYO\0", Path("SCP4700_Ver_1_108SP.bin")),
            "SCP-4700",
        )

    def test_fujitsu_bulk_writer_requires_unique_shape_and_adjacent_bus(self) -> None:
        variants = (
            (bytes.fromhex(
                "f0b5141c051c0f1c400803d2780801d2600802d3184919481ae00120c0050cf7"
                "a3fa174e301c1fe02e8895f0dffa154aa02151813e80002801d195f0e5fa0122"
                "381c311cfff78afc002805d00a490e481ef7a6fe0120f0bd0120c005023c0235"
                "02370cf781fa0648084967f713f8002cdad10020f0bd0000acca1b00dc050000"
                "308f4001a00a4000ed050000c5030000"
            ), 0x400000, 0x112378),
            (bytes.fromhex(
                "f0b50f1c041c151c400803d2780801d2680803d35120000119491be00120c005"
                "f5f7c4fb184e1749301c22e02688c6f1d9ff164aa02151813e80002801d1c6f1"
                "ddff0122311c381cfff788fc002807d00b490f48f5f71cfa0120f0bc08bc1847"
                "02340237023d0120c005f5f79ffb0549054814f082f8002dd8d10020ede70000"
                "dc0a2600c50300007cd81501a0aa800021050000"
            ), 0x800000, 0x84FC8),
        )
        for body, secondary_base, padding in variants:
            image = b"\xff" * padding + body + b"fs_fujitsu.c\0"
            self.assertEqual(
                find_fujitsu_x16_bulk_write(image, secondary_base), padding
            )
            self.assertEqual(
                fujitsu_x16_flash_ids(image, padding, 0, secondary_base),
                (0x0004, 0x005F),
            )
            self.assertIsNone(
                find_fujitsu_x16_bulk_write(image, secondary_base * 2)
            )
            self.assertIsNone(
                find_fujitsu_x16_bulk_write(image + body, secondary_base)
            )

    def test_complete_compound_fujitsu_dump_splits_secondary_nor(self) -> None:
        primary_size, secondary_size = 0x400000, 0x200000
        writer = bytes.fromhex(
            "f0b5141c051c0f1c400803d2780801d2600802d3184919481ae00120c0050cf7"
            "a3fa174e301c1fe02e8895f0dffa154aa02151813e80002801d195f0e5fa0122"
            "381c311cfff78afc002805d00a490e481ef7a6fe0120f0bd0120c005023c0235"
            "02370cf781fa0648084967f713f8002cdad10020f0bd0000acca1b00dc050000"
            "308f4001a00a4000ed050000c5030000"
        )
        image = bytearray(b"\xff" * (primary_size + secondary_size))
        for offset in range(0, 32, 4):
            struct.pack_into("<I", image, offset, 0xEA000000)
        image[0x1000:0x1000 + len(writer)] = writer
        image[0x2000:0x2000 + 13] = b"fs_fujitsu.c\0"
        marker = primary_size + 0x1001C
        image[marker:marker + 12] = b"\x0b$USER_DIRS\0"
        image[primary_size + 0x10040:primary_size + 0x10044] = b"nvm/"

        self.assertEqual(find_compound_fujitsu_layout(bytes(image)),
                         (primary_size, secondary_size))
        with tempfile.TemporaryDirectory() as directory, patch(
                "msm5xxx.DEFAULT_STATE_ROOT", Path(directory)):
            firmware = Path(directory) / "compound.bin"
            firmware.write_bytes(image)
            config = detect(firmware)
            self.assertEqual(config.flash_size, primary_size)
            self.assertEqual(config.secondary_flash_address, primary_size)
            self.assertEqual(config.secondary_flash_size, secondary_size)
            self.assertEqual(config.secondary_flash_image_offset, primary_size)
            self.assertEqual(config.ram_image_size, 0)
            self.assertIn("complete compound NOR image", config.dump_status)
            emulator = GenericMSMEmulator(config)
            try:
                self.assertEqual(bytes(emulator.flash.data),
                                 bytes(image[:primary_size]))
                self.assertIsNotNone(emulator.secondary_flash)
                self.assertEqual(bytes(emulator.secondary_flash.data),
                                 bytes(image[primary_size:]))
                self.assertEqual(emulator.secondary_flash.ids, (0x0004, 0x005F))
            finally:
                emulator.close()

        image[marker] = 0xFF
        self.assertIsNone(find_compound_fujitsu_layout(bytes(image)))
        image[marker] = 0x0B
        image[0x3000:0x3000 + len(writer)] = writer
        self.assertIsNone(find_compound_fujitsu_layout(bytes(image)))

    def test_rex_5ms_pair_requires_unique_sleep_wrapper_and_timer_shapes(self) -> None:
        sleep = bytes.fromhex(
            "134c2078012806d112480078012802d11148007800e00820"
            "00f000f800f000f80421071c0920c005227800f000f8002f"
            "01d100f000f880e7"
        )
        timer = bytes.fromhex(
            "f0b5041c00f000f8071c0f480026056811e0a868a0420bd8"
            "ae6003cd083d0860686829684860e868296900f000f801e0"
            "001ba8602d6805488542ead1002f01d100f000f8f0bd"
        )
        callback = bytearray(bytes.fromhex(
            "80b500f000f807043f0c05210c4800f000f80c4800f000f8"
            "800801d30a4800e00a48016805390160052000000000"
            "0848052100f000f8002f01d100f000f880bd"
        ))

        def bl(source: int, target: int) -> bytes:
            displacement = target - source - 4
            return struct.pack(
                "<2H", 0xF000 | (displacement >> 12 & 0x7FF),
                0xF800 | (displacement >> 1 & 0x7FF),
            )

        image = bytearray(b"\xff" * 0x400)
        image[0x40:0x40 + len(sleep)] = sleep
        image[0x100:0x100 + len(callback)] = callback
        image[0x12A:0x12E] = bl(0x12A, 0x200)
        image[0x200:0x200 + len(timer)] = timer

        self.assertEqual(find_rex_5ms_sleep_timer(image), (0x6E, 0x100, 5))
        image[0x300:0x300 + len(sleep)] = sleep
        self.assertIsNone(find_rex_5ms_sleep_timer(image))

    def test_trampm5_consumer_accepts_x150_x350_and_requires_unique_shape(self) -> None:
        variants = (
            (0xA1D88, bytes.fromhex(
                "90b50848d6f782fe0024071c002806d0f868b96860f701f93c71012090bd"
                "201c90bd00006c293e01"
            )),
            (0xA21A8, bytes.fromhex(
                "90b50848d6f760fe0024071c002806d0f868b9685ff7fbfe3c71012090bd"
                "201c90bd0000b80a3e01"
            )),
        )
        for address, body in variants:
            image = bytearray(b"\xff" * 0xB0000)
            image[address:address + len(body)] = body
            thunk = thumb_bl_target(image, address + 20)
            self.assertIsNotNone(thunk)
            image[thunk:thunk + 2] = b"\x08\x47"
            self.assertIsNotNone(trampm5_consumer_at(image, address))
            self.assertEqual(find_trampm5_consumer(image), address)

            for bl_offset in (4, 20):
                rejected = bytearray(image)
                rejected[address + bl_offset + 3] = 0
                self.assertIsNone(
                    trampm5_consumer_at(rejected, address), bl_offset
                )

            shifted = address + 2
            image = bytearray(b"\xff" * 0xB0000)
            image[shifted:shifted + 36] = body[:36]
            image[shifted + 38:shifted + 42] = body[36:]
            thunk = thumb_bl_target(image, shifted + 20)
            self.assertIsNotNone(thunk)
            image[thunk:thunk + 2] = b"\x08\x47"
            self.assertIsNotNone(trampm5_consumer_at(image, shifted))
            self.assertEqual(find_trampm5_consumer(image), shifted)

        image = bytearray(b"\xff" * 0xB0000)
        for address, body in variants:
            image[address:address + len(body)] = body
            thunk = thumb_bl_target(image, address + 20)
            self.assertIsNotNone(thunk)
            image[thunk:thunk + 2] = b"\x08\x47"
        self.assertIsNone(find_trampm5_consumer(image))

    @unittest.skipUnless(PRIVATE_FIRMWARES, "requires private firmware corpus")
    def test_rex_5ms_irq_route_accepts_four_homologs(self) -> None:
        root = Path(__file__).resolve().parent.parent
        cases = (
            ("schx150.bin", 0x13D7C,
             (0x1A62CC, 0xA1DB0, 0x1381D20, 0x1383238,
              0x03000620, 0x03000628, 0x0200)),
            ("x350_VC22.bin", 0x13D2C,
             (0x1A77CC, 0xA21D0, 0x1381D1C, 0x1383430,
              0x03000620, 0x03000628, 0x0200)),
            ("SCH-X250.bin", 0x13D14,
             (0x22C4, 0xAD818, 0x1101E3C, 0x110342C,
              0x03000620, 0x03000628, 0x0200)),
            ("SCH-x127.bin", 0x1FD10,
             (0x1878FC, 0xAD284, 0x1181CE8, 0x1183124,
              0x03000620, 0x03000628, 0x0200)),
        )
        for name, tick, expected in cases:
            image = (root / "firmwares" / name).read_bytes()
            self.assertEqual(find_rex_5ms_irq_route(image, tick), expected)
            self.assertEqual(find_rex_5ms_irq_arm(image, tick), 0x030006E0)

    @unittest.skipUnless(PRIVATE_FIRMWARES, "requires private firmware corpus")
    def test_rex_5ms_irq_route_accepts_x4500_enqueue_layout(self) -> None:
        root = Path(__file__).resolve().parent.parent
        image = bytearray((root / "firmwares" / "SPH-X4500.bin").read_bytes())
        expected = (0x18E2AC, 0x9400C, 0x1382AA8, 0x1382A70,
                    0x03000620, 0x03000628, 0x0200)
        self.assertEqual(find_rex_5ms_irq_route(image, 0x17978), expected)
        self.assertEqual(find_rex_5ms_irq_arm(image, 0x17978), 0x030006E0)
        self.assertEqual(
            detect(root / "firmwares" / "SPH-X4500.bin").rex_irq_arm_address,
            0x030006E0,
        )

        struct.pack_into("<I", image, 0x94264 + 0x4C, 0)
        self.assertIsNone(find_rex_5ms_irq_route(image, 0x17978))

        image = bytearray((root / "firmwares" / "SPH-X4500.bin").read_bytes())
        struct.pack_into("<H", image, 0x179EA - 8, 0x2001)
        self.assertIsNone(find_rex_5ms_irq_arm(image, 0x17978))

    @unittest.skipUnless(PRIVATE_FIRMWARES, "requires private firmware corpus")
    def test_rex_5ms_irq_route_rejects_broken_cross_checks(self) -> None:
        image = bytearray((Path(__file__).resolve().parent.parent
                           / "firmwares" / "schx150.bin").read_bytes())
        tick = 0x13D7C
        handler = 0xA1DB0
        default_position = handler - 0x38
        (summary, status, _, _, _, _, enable) = struct.unpack_from(
            "<7I", image, handler + 0x154
        )

        def rejected(offset: int, value: int) -> None:
            changed = bytearray(image)
            struct.pack_into("<I", changed, offset, value)
            self.assertIsNone(find_rex_5ms_irq_route(changed, tick), hex(offset))

        rejected(handler + 0x154 + 4 * 4, 0x1383244)  # groups
        rejected(handler + 0x154 + 5 * 4, 0x1382F18)  # descriptors
        rejected(handler + 0x154 + 6 * 4, 0x0300062C)  # enable relation
        rejected(handler + 0x170, 0x0300062E)  # second enable bank
        rejected(handler + 0x154 + 4, 0x03000621)  # unaligned status

        initializer = struct.pack(
            "<8I", status, enable, 0x0200, summary, summary + 4,
            default_position | 1, 0, 4,
        )
        initializer_position = image.find(initializer)
        self.assertGreaterEqual(initializer_position, 0)
        rejected(initializer_position + 24, 1)
        changed = bytearray(image)
        changed.extend(initializer)
        self.assertIsNone(find_rex_5ms_irq_route(changed, tick))

        def write_bl(changed: bytearray, source: int, target: int) -> None:
            displacement = target - source - 4
            struct.pack_into(
                "<2H", changed, source,
                0xF000 | (displacement >> 12 & 0x7FF),
                0xF800 | (displacement >> 1 & 0x7FF),
            )

        walker = 0x7908C
        producer = thumb_bl_target(image, tick + 50)
        self.assertIsNotNone(producer)
        for source in (tick + 2, tick + 42, tick + 58, producer + 6):
            changed = bytearray(image)
            write_bl(changed, source, 0x1000)
            self.assertIsNone(find_rex_5ms_irq_route(changed, tick), hex(source))

        changed = bytearray(image)
        write_bl(changed, walker + 42, 0x1000)
        self.assertIsNone(find_rex_5ms_irq_route(changed, tick))

        changed = bytearray(image)
        write_bl(changed, 0xA200C + 4, len(image) + 0x100)
        self.assertIsNone(find_rex_5ms_irq_route(changed, tick))

        registrars = {
            thumb_bl_target(image, position + 4)
            for position in range(0, len(image) - 8, 2)
            if (thumb_literal_value(image, position, 1) == tick | 1
                and struct.unpack_from("<H", image, position + 2)[0]
                == 0x201C)
        }
        self.assertEqual(len(registrars), 1)
        registrar = registrars.pop()
        self.assertIsNotNone(registrar)
        default_literal = self._thumb_literal_position(image, registrar + 14)
        for pointer in (tick | 1, 0xDEADBEEF):
            changed = bytearray(image)
            struct.pack_into("<I", changed, default_literal, pointer)
            struct.pack_into("<I", changed, initializer_position + 20, pointer)
            self.assertIsNone(find_rex_5ms_irq_route(changed, tick))

        changed = bytearray(image)
        struct.pack_into("<2H", changed, registrar + 6, 0xF000, 0xF800)
        self.assertIsNone(find_rex_5ms_irq_route(changed, tick))

        wrapper_body = 0x1A62D0
        for offset in (0x248, 0x24C, 0x258):
            rejected(wrapper_body + offset, 0xDEADBEEF)

        wrapper_entry = wrapper_body - 4
        changed = bytearray(image)
        copied = bytes(image[wrapper_entry:wrapper_entry + 0x260])
        changed[wrapper_entry] ^= 1
        relocated_entry = len(changed) + 2
        changed.extend(b"\xff" * (2 + len(copied)))
        changed[relocated_entry:relocated_entry + len(copied)] = copied
        relocated_body = relocated_entry + 4
        for offset, value in (
            (0x248, relocated_body + 0x3C),
            (0x24C, relocated_body + 0x40),
            (0x258, relocated_body + 0x168),
        ):
            struct.pack_into("<I", changed, relocated_body + offset, value)
        self.assertIsNone(find_rex_5ms_irq_route(changed, tick))

        self.assertIsNone(find_rex_5ms_irq_route(
            image[:0x1A62CC + 0x100], tick
        ))
        self.assertIsNone(find_rex_5ms_irq_route(
            image[:handler + 0x1DA], tick,
            lambda position: position + 0x1000,
        ))
        self.assertIsNone(find_rex_5ms_irq_route(
            image[:handler + 0x1DC], tick,
            lambda position: position + 0x1000,
        ))

    @unittest.skipUnless(PRIVATE_FIRMWARES, "requires private firmware corpus")
    def test_rex_5ms_irq_route_accepts_uniform_relocation_only(self) -> None:
        original = bytearray((Path(__file__).resolve().parent.parent
                              / "firmwares" / "schx150.bin").read_bytes())
        tick = 0x13D7C
        handler = 0xA1DB0
        wrapper = 0x1A62CC
        default_position = handler - 0x38

        def relocated(delta: int) -> bytearray:
            image = bytearray(original)
            (summary, status, _, _, _, _, enable) = struct.unpack_from(
                "<7I", image, handler + 0x154
            )
            initializer = struct.pack(
                "<8I", status, enable, 0x0200, summary, summary + 4,
                default_position | 1, 0, 4,
            )
            initializer_position = image.find(initializer)
            self.assertGreaterEqual(initializer_position, 0)
            struct.pack_into("<I", image, initializer_position + 20,
                             default_position + delta | 1)
            struct.pack_into("<I", image, handler + 0x1D4,
                             handler + delta | 1)
            registrations = []
            for position in range(0, len(image) - 8, 2):
                if (thumb_literal_value(image, position, 1) == tick | 1
                        and struct.unpack_from("<H", image, position + 2)[0]
                        == 0x201C):
                    literal = self._thumb_literal_position(image, position)
                    struct.pack_into("<I", image, literal, tick + delta | 1)
                    registrations.append(thumb_bl_target(image, position + 4))
            self.assertEqual(len(registrations), 3)
            self.assertEqual(len(set(registrations)), 1)
            registrar = registrations[0]
            self.assertIsNotNone(registrar)
            default_literal = self._thumb_literal_position(
                image, registrar + 14
            )
            struct.pack_into("<I", image, default_literal,
                             default_position + delta | 1)
            body = wrapper + 4
            for offset in (0x248, 0x24C, 0x258):
                value = struct.unpack_from("<I", image, body + offset)[0]
                struct.pack_into("<I", image, body + offset, value + delta)
            return image

        delta = 0x1000
        image = relocated(delta)

        expected = (wrapper + delta, handler + delta, 0x1381D20,
                    0x1383238, 0x03000620, 0x03000628, 0x0200)
        mapped = lambda position: position + delta
        self.assertEqual(find_rex_5ms_irq_route(image, tick, mapped), expected)

        walker = 0x7908C
        self.assertIsNone(find_rex_5ms_irq_route(
            image, tick,
            lambda position: position + delta + (4 if position == walker else 0),
        ))
        self.assertIsNone(find_rex_5ms_irq_route(
            image, tick,
            lambda position: position + delta
            + (4 if position == default_position else 0),
        ))
        self.assertIsNone(find_rex_5ms_irq_route(
            relocated(2), tick, lambda position: position + 2,
        ))


if __name__ == "__main__":
    unittest.main()
