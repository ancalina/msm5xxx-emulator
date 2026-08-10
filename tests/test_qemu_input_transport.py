"""Experimental QEMU matrix input packet checks."""
from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import queue
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

    def test_qemu_state_directory_is_firmware_scoped(self) -> None:
        first = SimpleNamespace(firmware_sha256="a" * 64)
        second = SimpleNamespace(firmware_sha256="b" * 64)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(MODULE.qemu_state_directory(root, first),
                             root / ("a" * 64))
            (root / "primary-writable.raw").write_bytes(b"legacy")
            self.assertEqual(MODULE.qemu_state_directory(root, first), root)
            self.assertEqual(MODULE.qemu_state_directory(root, first), root)
            self.assertEqual(MODULE.qemu_state_directory(root, second),
                             root / ("b" * 64))
            self.assertEqual(
                (root / MODULE.LEGACY_STATE_OWNER).read_text().strip(),
                "a" * 64,
            )
            self.assertIsNone(MODULE.qemu_state_directory(None, first))
            with self.assertRaises(ValueError):
                MODULE.qemu_state_directory(root, SimpleNamespace(
                    firmware_sha256="../shared"
                ))

    def test_settings_restart_replaces_transport_with_saved_profile(self) -> None:
        events: list[str] = []
        firmware = Path("/tmp/settings.bin")
        config = SimpleNamespace(
            model="Detected", verified_model=None, chipset="MSM5000",
            width=128, height=160,
        )
        old_transport = mock.Mock()
        old_transport.interrupt.side_effect = lambda: events.append("interrupt")
        old_transport.close.side_effect = lambda: events.append("close")
        old_worker = mock.Mock()
        worker_running = [True]
        old_worker.is_alive.side_effect = lambda: worker_running[0]

        def join_worker() -> None:
            events.append("join")
            worker_running[0] = False

        old_worker.join.side_effect = join_worker
        new_transport = mock.Mock(
            config=config, decoder=mock.Mock(), replay=mock.Mock()
        )
        new_worker = mock.Mock()
        new_worker.start.side_effect = lambda: events.append("start")

        window = MODULE.LiveWindow.__new__(MODULE.LiveWindow)
        window._prepared_profile = None
        window.firmware = firmware
        window.overrides = {"width": 128}
        window.generation = 3
        window.stop = mock.Mock()
        window.root = mock.Mock()
        window.pending_key_releases = {"5": "callback"}
        window.keyboard_bits = {"5": 15}
        window.keyboard_sources = {"5"}
        window.held = {15: {"5"}}
        window.commands = queue.SimpleQueue()
        window.transport = old_transport
        window.worker = old_worker
        window.emulator = old_transport.decoder
        window._active_firmware = firmware
        window._active_overrides = {"width": 96}
        window._render_cache = (object(), b"", 1, 1, 1, 1)
        window.qemu = Path("/tmp/qemu-system-arm")
        window.state_dir = Path("/tmp/qemu-state")
        window.experimental_c80 = True
        window.ui_language = "en"
        window.model = mock.Mock()
        window.device_details = mock.Mock()
        window.status = mock.Mock()

        def create_transport(*_args: object, **_kwargs: object) -> object:
            events.append("create")
            return new_transport

        with mock.patch.object(MODULE, "_prepared_profile_matches",
                               return_value=False), \
             mock.patch.object(MODULE, "detect_profile",
                               return_value=(config, {"width": 128})) as detect, \
             mock.patch.object(MODULE, "Transport",
                               side_effect=create_transport) as transport, \
             mock.patch.object(MODULE.threading, "Thread",
                               return_value=new_worker):
            window._restart()

        detect.assert_called_once_with(firmware, {"width": 128})
        transport.assert_called_once_with(
            window.qemu, firmware, window.state_dir, True, config=config
        )
        self.assertEqual(
            events, ["interrupt", "join", "close", "create", "start"]
        )
        self.assertIs(window.transport, new_transport)
        self.assertIs(window.emulator, new_transport.decoder)
        self.assertEqual(window.generation, 4)
        window.root.after_cancel.assert_called_once_with("callback")
        self.assertEqual(window.keyboard_bits, {})
        self.assertEqual(window.keyboard_sources, set())
        self.assertEqual(window.held, {})
        window.closing = False
        window.overrides = {"framebuffer_format": "bgr565le"}
        window.commands.put(("framebuffer-format", "bgr565le"))
        window._forward_qemu_keys()
        new_transport.decoder.set_framebuffer_format.assert_called_once_with(
            "bgr565le"
        )
        self.assertEqual(window._active_overrides, window.overrides)

    def test_settings_restart_restores_previous_transport_on_launch_error(self) -> None:
        old_firmware = Path("/tmp/old.bin")
        new_firmware = Path("/tmp/new.bin")
        old_config = SimpleNamespace(
            model="Old", verified_model=None, chipset="MSM5000",
            width=96, height=64,
        )
        new_config = SimpleNamespace(
            model="New", verified_model=None, chipset="MSM5000",
            width=128, height=160,
        )
        restored = mock.Mock(
            config=old_config, decoder=SimpleNamespace(), replay=mock.Mock()
        )
        worker = mock.Mock()
        worker.is_alive.return_value = False

        window = MODULE.LiveWindow.__new__(MODULE.LiveWindow)
        window._prepared_profile = None
        window.firmware = new_firmware
        window.overrides = {"width": 128}
        window._active_firmware = old_firmware
        window._active_overrides = {"width": 96}
        window.generation = 1
        window.stop = mock.Mock()
        window.root = mock.Mock()
        window.pending_key_releases = {}
        window.keyboard_bits = {}
        window.keyboard_sources = set()
        window.held = {}
        window.commands = queue.SimpleQueue()
        window.transport = mock.Mock()
        window.worker = worker
        window.emulator = window.transport.decoder
        window._render_cache = None
        window.qemu = Path("/tmp/qemu-system-arm")
        window.state_dir = Path("/tmp/qemu-state")
        window.experimental_c80 = False
        window.ui_language = "en"
        window.model = mock.Mock()
        window.device_details = mock.Mock()
        window.status = mock.Mock()
        window._save_config = mock.Mock()

        with mock.patch.object(MODULE, "_prepared_profile_matches",
                               return_value=False), \
             mock.patch.object(MODULE, "detect_profile",
                               side_effect=((new_config, {"width": 128}),
                                            (old_config, {"width": 96}))), \
             mock.patch.object(MODULE, "Transport",
                               side_effect=(RuntimeError("launch failed"),
                                            restored)) as transport, \
             mock.patch.object(MODULE.threading, "Thread",
                               return_value=mock.Mock()), \
             mock.patch.object(MODULE.messagebox, "showerror") as showerror:
            window._restart()

        self.assertEqual(window.firmware, old_firmware)
        self.assertEqual(window.overrides, {"width": 96})
        self.assertIs(window.transport, restored)
        self.assertEqual(transport.call_count, 2)
        window._save_config.assert_called_once_with()
        showerror.assert_called_once()

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
            excluded = MODULE.raw_loader_arguments(
                image, 4, root, exclude=(4, 6)
            )
            self.assertEqual(
                [argument.rsplit("addr=", 1)[1].split(",", 1)[0]
                 for argument in excluded[1::2]],
                ["0x0", "0x6"],
            )
            self.assertEqual(
                b"".join((root / f"primary-{offset:08x}.raw").read_bytes()
                         for offset in (0, 6)),
                bytes(range(4)) + bytes(range(6, 10)),
            )

    def test_primary_loader_uses_zero_based_sliced_seed_and_guest_ranges(
            self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "firmware.bin"
            prefix = b"capture-header"
            seed = bytes(range(0x30))
            trailer = b"ram-snapshot-trailer"
            original.write_bytes(prefix + seed + trailer)

            primary_raw = root / "primary.raw"
            primary_raw.write_bytes(seed)
            arguments = MODULE.raw_loader_arguments(
                primary_raw, 0x10, root, size=0x20, exclude=(0x08, 0x10)
            )
            entries = {}
            for argument in arguments[1::2]:
                path_text, address_text = argument.split(",addr=", 1)
                path = Path(path_text.removeprefix("loader,file="))
                address = int(address_text.split(",", 1)[0], 16)
                entries[address] = path.read_bytes()

            self.assertEqual(entries, {
                0x00: seed[0x00:0x08],
                0x10: seed[0x10:0x20],
            })
            self.assertNotEqual(original.read_bytes()[0], seed[0])
            emitted = b"".join(entries.values())
            self.assertNotIn(prefix, emitted)
            self.assertNotIn(trailer, emitted)

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
        candidate["callback_slot"] = 0x01802000
        candidate["handler_slot"] = 0x01801000
        candidate["vector_target"] = 0x01800000
        config.ram_base = 0x01800000
        self.assertEqual(
            MODULE.c80_rex_irq_profile(config, True),
            "3000c80:3000c94:200:4c4b40:1800000:1000:1801000:"
            "2000:100:1802000:3000",
        )

    def test_read_consume_route_requires_copied_vector_relation(self) -> None:
        status = 0x03000620
        candidate = {
            "signature": "static-msm5000-620-controller-callback-v1",
            "controller_class":
                "legacy-msm5000-620-two-bank-read-consume-group10-v1",
            "accepted": True,
            "active": False,
            "promotion": "experimental-only",
            "vector": 0x18,
            "vector_target": 0x01100000,
            "vector_copy_source": 0x0039519C,
            "vector_copy_size": 0xE5B0,
            "descriptor_file_offset": 0x003987C4,
            "descriptor_runtime_address": 0x01103628,
            "mask_table": 0x01103310,
            "status": status,
            "status_banks": (status, status + 4),
            "enable": status + 8,
            "mask": 0x0200,
            "mask_set_banks": (status, status + 4),
            "mask_output_banks": (status + 8, status + 0xC),
            "controller_aperture": (status, status + 0x10),
            "group_row_size": 10,
            "pending_read_semantics": "consume-on-read",
            "time_tick_control_address": 0x030006E0,
            "wrapper_file_offset": 0x0024BE14,
            "wrapper_validation_size": 0x234,
            "handler_slot": 0x0118867C,
            "handler_file_offset": 0x00098E04,
            "handler_validation_size": 0x178,
            "callback_slot": 0x0110363C,
            "callback_file_offset": 0x00016B64,
            "callback_delta": 5,
            "callback_validation_size": 68,
        }
        config = SimpleNamespace(
            rex_static_controller_candidate=candidate,
            load_address=0, flash_size=0x400000,
            ram_base=0x01000000, ram_size=0x200000,
            rex_tick_address=None, rex_irq_wrapper_address=None,
            rex_irq_handler_address=None, rex_irq_handler_slot=None,
            rex_irq_callback_slot=None, rex_irq_status_address=None,
            rex_irq_enable_address=None, rex_irq_arm_address=None,
            rex_irq_mask=0,
        )

        self.assertIsNone(MODULE.read_consume_rex_irq_profile(config, False))
        self.assertEqual(
            MODULE.read_consume_rex_irq_profile(config, True),
            "3000620:3000628:30006e0:200:4c4b40:1100000:24be14:"
            "118867c:98e04:178:110363c:16b64",
        )
        candidate["descriptor_runtime_address"] += 4
        self.assertIsNone(
            MODULE.read_consume_rex_irq_profile(config, True)
        )
        candidate["descriptor_runtime_address"] -= 4
        original_copy_size = candidate["vector_copy_size"]
        candidate["vector_copy_size"] = (
            candidate["descriptor_file_offset"]
            - candidate["vector_copy_source"] + 4
        )
        self.assertIsNone(
            MODULE.read_consume_rex_irq_profile(config, True)
        )
        candidate["vector_copy_size"] = original_copy_size
        candidate["promotion"] = "production"
        self.assertIsNone(
            MODULE.read_consume_rex_irq_profile(config, True)
        )


if __name__ == "__main__":
    unittest.main()
