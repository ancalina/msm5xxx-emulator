"""Experimental QEMU matrix input packet checks."""
from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from unicorn import UC_ARCH_ARM, UC_MODE_THUMB, Uc


EXPERIMENT = Path(__file__).parents[1] / "experiments/qemu-tcg"
sys.path.insert(0, str(EXPERIMENT))
SPEC = importlib.util.spec_from_file_location(
    "qemu_live_display", EXPERIMENT / "live-display.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class QEMUInputTransportTests(unittest.TestCase):
    PROFILE = {
        "rows": 6,
        "no_key": 0x0F,
        "single_key_column_sense": (0x0E, 0x0D, 0x0B, 0x07),
    }

    def test_loopback_transport_and_cancelled_picker(self) -> None:
        listener = MODULE.loopback_listener()
        try:
            self.assertEqual(listener.family, MODULE.socket.AF_INET)
            self.assertEqual(listener.getsockname()[0], "127.0.0.1")
        finally:
            listener.close()
        argv = ["live-display.py", "--qemu", "qemu-system-arm"]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(MODULE, "choose_firmware",
                               return_value=None) as chooser, \
             mock.patch.object(MODULE, "Transport") as transport:
            self.assertEqual(MODULE.main(), 0)
        chooser.assert_called_once_with()
        transport.assert_not_called()

    def test_transport_accept_reports_early_qemu_exit(self) -> None:
        transport = object.__new__(MODULE.Transport)
        transport.process = SimpleNamespace(poll=lambda: 2)
        transport.stderr = io.StringIO("bad QEMU option")
        listener = mock.Mock()
        listener.accept.side_effect = MODULE.socket.timeout

        with self.assertRaisesRegex(RuntimeError, "bad QEMU option"):
            transport._accept_qemu(listener)
        listener.settimeout.assert_called_once_with(0.1)

    def test_memory_profile_fails_closed_outside_native_shape(self) -> None:
        config = SimpleNamespace(flash_size=0x01800000,
                                 ram_base=0x01800000,
                                 ram_size=0x00800000)
        registers = {name: 0 for name in MODULE.REGISTER_NAMES}
        registers.update(sp=0x01FFFFFC, cpsr=0xD3)
        self.assertEqual(
            MODULE.qemu_memory_profile(config, registers),
            "1800000:1800000:1fffffc",
        )
        for name, value in (("r0", 1), ("cpsr", 0x400001D3),
                            ("sp", 0x017FFFFC)):
            changed = {**registers, name: value}
            with self.subTest(name=name), self.assertRaises(ValueError):
                MODULE.qemu_memory_profile(config, changed)
        config.flash_size = config.ram_base + 1
        with self.assertRaises(ValueError):
            MODULE.qemu_memory_profile(config, registers)
        config.flash_size = 1
        with self.assertRaises(ValueError):
            MODULE.qemu_memory_profile(config, registers)

    def test_upper_nor_accepts_only_the_detector_range(self) -> None:
        disabled = SimpleNamespace(upper_flash_address=None,
                                   upper_flash_size=0)
        accepted = SimpleNamespace(upper_flash_address=0x02800000,
                                   upper_flash_size=0x00800000)
        self.assertFalse(MODULE.qemu_upper_nor_enabled(disabled))
        self.assertTrue(MODULE.qemu_upper_nor_enabled(accepted))
        for changed in (
                SimpleNamespace(upper_flash_address=0x02801000,
                                upper_flash_size=0x00800000),
                SimpleNamespace(upper_flash_address=0x02800000,
                                upper_flash_size=0x00400000)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                MODULE.qemu_upper_nor_enabled(changed)

    def test_eeprom_gpio_profile_accepts_split_bank_open_drain_shape(
            self) -> None:
        image = bytearray(b"\xff" * 0x1400)
        write, read = 0x800, 0xEB0
        writer, ack, reader = write - 0x12C, write - 0x1D2, read - 0x718
        image[write:write + len(MODULE.EEPROM_24LCXX_X430_WRITE_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X430_WRITE_PREFIX
        )
        image[read:read + len(MODULE.EEPROM_24LCXX_X430_READ_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X430_READ_PREFIX
        )
        shapes = (
            (writer, "f0b5071c8025"),
            (writer + 0x16, "0122087810430870087826490871"),
            (writer + 0x2E, "202108431070107821490870"),
            (writer + 0x44, "202311789943117011781b4a1170"),
            (writer + 0x5A, "0878400840000870087815490871"),
            (writer + 0x72, "202108431070107810490870"),
            (writer + 0x88, "202311789943117011780a4a1170"),
            (ack, "f0b5"),
            (ack + 0x06, "234a11784908490011701178214a1172"),
            (ack + 0x24, "202229781c4c114329702978103c2170"),
            (ack + 0x40, "21790126301c490800d2002007063f0e"),
            (ack + 0x5A, "20239943297029782170"),
            (ack + 0x78, "0a7832430a700978064a1172"),
            (reader, "f0b50027164d"),
            (reader + 0x10, "20220878104308700878114904390870"),
            (reader + 0x28, "28783f0e400801d301200743"),
            (reader + 0x36, "20230878984308700878074904390870"),
        )
        for position, value in shapes:
            image[position:position + len(bytes.fromhex(value))] = bytes.fromhex(value)
        MODULE.struct.pack_into("<I", image, writer + 0xBC, 0x03000660)
        MODULE.struct.pack_into("<I", image, ack + 0x9A, 0x03000670)
        MODULE.struct.pack_into("<I", image, reader + 0x60, 0x03000664)
        config = SimpleNamespace(
            eeprom_read_address=read, eeprom_write_address=write,
            eeprom_geometry_address=0x01001000, load_address=0,
        )

        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            ((0x03000660, 4, 1, 0, 0x20, 0x18, 0x8000), None),
        )
        MODULE.struct.pack_into("<I", image, ack + 0x9A, 0x03000674)
        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            (None, "gpio-line-shape-mismatch"),
        )

    def test_press_and_release_packets(self) -> None:
        self.assertEqual(MODULE.matrix_senses(self.PROFILE),
                         (0x0E, 0x0D, 0x0B, 0x07))
        self.assertEqual(
            MODULE.matrix_input_command(self.PROFILE, (0x53, 1, 1), True),
            bytes.fromhex("8001010d"),
        )
        self.assertEqual(
            MODULE.matrix_input_command(self.PROFILE, (0x53, 1, 1), False),
            bytes.fromhex("80000000"),
        )

    def test_invalid_detector_position_fails_closed(self) -> None:
        for position in (None, (0x53, 6, 0), (0x53, 1, 4)):
            with self.subTest(position=position), self.assertRaises(ValueError):
                MODULE.matrix_input_command(self.PROFILE, position, True)
        for senses in ((), (0x0E, 0x0E), (0x0E, 0x0F), (0x0E, 0x10)):
            profile = {**self.PROFILE, "single_key_column_sense": senses}
            with self.subTest(senses=senses), self.assertRaises(ValueError):
                MODULE.matrix_senses(profile)

    def test_active_low_sideband_packets_fail_closed(self) -> None:
        producer = {
            "register_width": 1,
            "polarity": "active-low",
            "mask": 0x10,
        }
        self.assertEqual(
            MODULE.sideband_input_command(producer, True),
            bytes.fromhex("8001ff10"),
        )
        self.assertEqual(
            MODULE.sideband_input_command(producer, False),
            bytes.fromhex("80000000"),
        )
        for changed in (
                {**producer, "mask": 0x0F},
                {**producer, "mask": 0x30},
                {**producer, "polarity": "active-high"}):
            with self.subTest(producer=changed), self.assertRaises(ValueError):
                MODULE.sideband_input_command(changed, True)

    def test_transport_prefers_evidenced_sideband_over_matrix_cell(self) -> None:
        producer = {
            "register_width": 1,
            "polarity": "active-low",
            "mask": 0x10,
        }
        packets: list[bytes] = []
        transport = object.__new__(MODULE.Transport)
        transport.matrix_input_profile = self.PROFILE
        transport.matrix_input_sideband_producer = producer
        transport.matrix_held = {}
        transport.sideband_held = set()
        transport.lcd_socket = SimpleNamespace(sendall=packets.append)
        transport.decoder = SimpleNamespace(
            input_error="",
            _direct_sideband_producer=(
                lambda bit, event: (
                    producer if bit == 7 and event in (None, 0x51) else None
                )
            ),
            _direct_matrix_position=(
                lambda bit, event: (
                    None if event == 0x51 else (0x87, 0, 3)
                )
            ),
        )

        self.assertTrue(transport.can_set_key(7))
        self.assertTrue(transport.can_set_key(7, 0x51))
        self.assertFalse(transport.can_set_key(5, 0x51))
        transport.matrix_input_sideband_producer = None
        self.assertFalse(transport.can_set_key(7, 0x51))
        self.assertFalse(transport.set_key(7, True, 0x51))
        transport.matrix_input_sideband_producer = producer
        self.assertTrue(transport.set_key(7, True, 0x51))
        self.assertTrue(transport.set_key(7, False))
        self.assertEqual(
            packets,
            [bytes.fromhex("8001ff10"), bytes.fromhex("80000000")],
        )
        self.assertEqual((transport.sideband_held, transport.matrix_held),
                         (set(), {}))

    def test_legacy_state_import_reads_copy_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed = b"\xff" * 0x1000
            state = root / "legacy.json"
            flash = MODULE.NORFlash(seed, state)
            flash.program(0x20, b"\xaa")
            flash.save()
            original = state.read_bytes()

            imported, loaded = MODULE.load_legacy_nor_state(seed, (state,))
            self.assertTrue(loaded)
            self.assertEqual(imported[0x20], 0xAA)
            self.assertEqual(state.read_bytes(), original)

            raw = root / "legacy.bin"
            raw.write_bytes(b"\x55" * 8)
            self.assertEqual(
                MODULE.load_legacy_raw_state(b"\xff" * 8, raw),
                (b"\x55" * 8, True),
            )

    def test_raw_loader_splits_at_machine_ram_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "firmware.bin"
            image.write_bytes(bytes(range(10)))

            arguments = MODULE.raw_loader_arguments(image, 4, root)

            self.assertEqual(arguments[::2], ["-device"] * 3)
            self.assertEqual(
                [argument.rsplit("addr=", 1)[1].split(",", 1)[0]
                 for argument in arguments[1::2]],
                ["0x0", "0x4", "0x8"],
            )
            self.assertEqual(
                b"".join((root / f"primary-{offset:08x}.raw").read_bytes()
                         for offset in (0, 4, 8)),
                bytes(range(10)),
            )
            limited = MODULE.raw_loader_arguments(image, 4, root, 6)
            self.assertEqual(
                b"".join((root / f"primary-{offset:08x}.raw").read_bytes()
                         for offset in (0, 4)),
                bytes(range(6)),
            )
            self.assertEqual(len(limited), 4)

    def test_pause_timer_profile_requires_fixed_helper_and_long_caller(
            self) -> None:
        def thumb_bl(source: int, target: int) -> bytes:
            displacement = (target - source - 4) & 0x7FFFFF
            return MODULE.struct.pack(
                "<2H",
                0xF000 | displacement >> 12 & 0x7FF,
                0xF800 | displacement >> 1 & 0x7FF,
            )

        helper = bytes.fromhex(
            "90b4322813dc00211423041c5c431f23e318223b9b1106d414214843031c1f21"
            "591822398911214b198090bc704700211424322363431f241b19223b9b1106d4"
            "1421322359431f23c91822398911174b1980c11f2b39081c322813dd00211424"
            "322363431f241b199b1105d41421322359431f23c91889110c4b1980c11f2b39"
            "081ce9e70028d0dd00211423041c5c431f23e3189b1105d414214843031c1f21"
            "59188911014b1980bfe7000020008004"
        )
        image = bytearray(b"\xff" * 0x800)
        caller, pool, start = 0x100, 0x180, 0x300
        ldr = 0x4800 | (pool - ((caller + 4) & ~3)) // 4
        MODULE.struct.pack_into("<H", image, caller, ldr)
        image[caller + 2:caller + 6] = thumb_bl(caller + 2, start)
        MODULE.struct.pack_into("<I", image, pool, 100_000)
        image[start:start + len(helper)] = helper
        config = SimpleNamespace(load_address=0, flash_size=len(image))

        expected = "4800020:4c4b4:300:3aa"
        self.assertEqual(
            MODULE.qemu_pause_timer_profile(bytes(image), config),
            (expected, None),
        )
        self.assertEqual(MODULE.qemu_pause_timer_profile(
            bytes(image), config, start + len(helper) - 1
        ), (None, "fixed-helper-outside-immutable-nor"))

        MODULE.struct.pack_into("<I", image, pool, 20_000)
        self.assertEqual(
            MODULE.qemu_pause_timer_profile(bytes(image), config),
            (None, "100ms-caller-not-found"),
        )
        MODULE.struct.pack_into("<I", image, pool, 100_000)
        image[start + 0x30] ^= 1
        self.assertEqual(
            MODULE.qemu_pause_timer_profile(bytes(image), config),
            (None, "fixed-helper-shape-mismatch"),
        )
        image[start + 0x30] ^= 1
        image[0x500:0x500 + len(helper)] = helper
        self.assertEqual(
            MODULE.qemu_pause_timer_profile(bytes(image), config),
            (None, "fixed-helper-ambiguous"),
        )

    def test_legacy_dmd_loader_patch_preserves_call_contract(self) -> None:
        load = 0x1000
        entry = load + 0x100
        completion = 0x01001020
        control = 0x03000050
        dmd = 0x030007E0
        filename = load + 0x600
        image = bytearray(b"\xff" * 0x1000)
        signature = MODULE.DMD_DOWNLOAD_SIGNATURE
        image[0x100:0x100 + len(signature)] = signature
        image[0x100 + 0xD4:0x100 + 0xD6] = b"\x06\x49"
        MODULE.struct.pack_into(
            "<4I", image, 0x100 + 0xE0,
            completion, control, 0, dmd,
        )
        MODULE.struct.pack_into("<I", image, 0x100 + 0xF0, filename)
        image[0x600:0x60C] = b"dmddown_510"
        config = SimpleNamespace(
            dmd_download_address=entry, load_address=load,
            flash_size=len(image), ram_base=0x01000000, ram_size=0x2000,
        )

        result = MODULE.legacy_dmd_loader_patch(bytes(image), config)
        self.assertIsNotNone(result)
        offset, patch = result
        self.assertEqual((offset, len(patch)), (0x100, 52))

        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.mem_map(load, 0x1000)
        uc.mem_map(0x01000000, 0x2000)
        uc.mem_map(0x03000000, 0x1000)
        uc.mem_write(entry, patch)
        uc.mem_write(completion, b"\xaa\xbb\xcc\xdd")
        uc.mem_write(control + 0x0C, b"\xaa\xbb")
        uc.mem_write(dmd + 8, b"\xaa" * 8)
        registers = MODULE.arm_const
        uc.reg_write(registers.UC_ARM_REG_CPSR, 0xA0000033)
        uc.reg_write(registers.UC_ARM_REG_SP, 0x01001FF0)
        uc.reg_write(registers.UC_ARM_REG_LR, 0x1201)
        uc.reg_write(registers.UC_ARM_REG_R1, 0x11111111)
        uc.reg_write(registers.UC_ARM_REG_R2, 0x22222222)
        flags = uc.reg_read(registers.UC_ARM_REG_CPSR) & 0xF0000000

        uc.emu_start(entry | 1, 0, count=14)

        self.assertEqual(uc.reg_read(registers.UC_ARM_REG_PC), 0x1200)
        self.assertEqual(uc.reg_read(registers.UC_ARM_REG_R0), 1)
        self.assertEqual(uc.reg_read(registers.UC_ARM_REG_R1), 0x11111111)
        self.assertEqual(uc.reg_read(registers.UC_ARM_REG_R2), 0x22222222)
        self.assertEqual(uc.reg_read(registers.UC_ARM_REG_SP), 0x01001FF0)
        self.assertEqual(
            uc.reg_read(registers.UC_ARM_REG_CPSR) & 0xF0000000, flags
        )
        self.assertEqual(bytes(uc.mem_read(completion, 4)),
                         b"\x02\xbb\xcc\xdd")
        self.assertEqual(bytes(uc.mem_read(control + 0x0C, 2)),
                         b"\x01\xbb")
        self.assertEqual(bytes(uc.mem_read(dmd + 8, 8)),
                         b"\0" * 6 + b"\xaa" * 2)

        image[0x600] = 0
        self.assertIsNone(
            MODULE.legacy_dmd_loader_patch(bytes(image), config)
        )
        image[0x600] = ord("d")
        self.assertIsNone(MODULE.legacy_dmd_loader_patch(
            bytes(image), config, 0x100 + len(patch) - 1
        ))

    def test_c80_route_requires_explicit_closed_candidate(self) -> None:
        status = 0x03000C80
        candidate = {
            "signature": "static-c80-controller-callback-v1",
            "controller_class":
                "legacy-c80-index1e-delta5-controller-candidate-v1",
            "accepted": True,
            "active": False,
            "vector": 0x18,
            "vector_target": 0x01000000,
            "status": status,
            "status_banks": (status, status + 4),
            "enable": status + 0x14,
            "mask": 0x0200,
            "clear_banks": (status, status + 4),
            "controller_write_banks": (status + 0x14, status + 0x18),
            "controller_aperture": (status, status + 0x1A),
            "wrapper_file_offset": 0x1000,
            "wrapper_validation_size": 0x284,
            "handler_slot": 0x01001000,
            "handler_file_offset": 0x2000,
            "handler_validation_size": 0x100,
            "callback_slot": 0x01002000,
            "callback_file_offset": 0x3000,
            "callback_delta": 5,
            "callback_validation_size": 68,
        }
        config = SimpleNamespace(
            rex_static_controller_candidate=candidate,
            load_address=0, flash_size=0x10000,
            ram_base=0x01000000, ram_size=0x10000,
            rex_tick_address=None, rex_irq_wrapper_address=None,
            rex_irq_handler_address=None, rex_irq_handler_slot=None,
            rex_irq_callback_slot=None, rex_irq_status_address=None,
            rex_irq_enable_address=None, rex_irq_arm_address=None,
            rex_irq_mask=0,
        )

        self.assertIsNone(MODULE.c80_rex_irq_profile(config, False))
        self.assertEqual(
            MODULE.c80_rex_irq_profile(config, True),
            "3000c80:3000c94:200:4c4b40:1000000:1000:1001000:"
            "2000:100:1002000:3000",
        )
        candidate["wrapper_validation_size"] = config.flash_size
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, True))
        candidate["wrapper_validation_size"] = 0x284
        candidate["callback_slot"] += 2
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, True))


if __name__ == "__main__":
    unittest.main()
