"""Experimental QEMU matrix input packet checks."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest


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
