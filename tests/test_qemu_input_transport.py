"""Experimental QEMU matrix input packet checks."""
from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import queue
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from unicorn import UC_ARCH_ARM, UC_MODE_THUMB, Uc

from msm5xxx_emulator.detection.boot import (
    DMD_DOWNLOAD_5500_LITERALS,
    PRIMARY_FLASH_PROBE_SIGNATURE,
)


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

    def test_ready_poll_property_is_explicit_and_fail_closed(self) -> None:
        compact = {
            "signature": "thumb-lsrs-bhs-pulse-v1",
            "status_address": 0x030007B4,
            "mask": 8,
            "pulse_address": 0x03000600,
            "entries": [0x100],
        }
        control = {
            "signature": "thumb-byte-ready-pulse-control-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x03000F14,
            "mask": 8,
            "pulse_address": 0x03000700,
            "control_address": 0x03000F1C,
            "control_value": 0x20,
            "status_read_pc_offset": 4,
            "pulse_set_pc_offset": 0x18,
            "pulse_clear_pc_offset": 0x1C,
            "control_pc_offset": 0x22,
            "entries": [0xD5C],
        }
        control_uart = {
            **control,
            "signature": "thumb-byte-ready-pulse-control-uart-empty-v1",
            "uart_rx_empty_read_pc_offset": 0x96,
        }
        rotated = {
            "signature": "thumb-lsrs-bcc-pulse-rotated-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x03000F14,
            "mask": 8,
            "pulse_address": 0x03000700,
            "status_read_pc_offset": 0x10,
            "pulse_set_pc_offset": 0x0C,
            "pulse_clear_pc_offset": 0x0E,
            "entries": [0x1100],
        }
        uart = {
            "signature": "thumb-uart-csr-sr-rx-empty-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x030007B4,
            "mask": 8,
            "pulse_address": 0x03000600,
            "status_read_pc_offset": 2,
            "pulse_set_pc_offset": 0x0C,
            "pulse_clear_pc_offset": 0x10,
            "uart_rx_empty_read_pc_offset": 0xA0,
            "entries": [0x2314],
        }
        uart_framed = {
            **uart,
            "uart_rx_empty_frame_read_pc_offset": 0x100,
        }
        lcd = {
            "signature": "thumb-lcd-halfword-busy-clear-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x0280000C,
            "mask": 8,
            "command_address": 0x02800008,
            "command_value": 8,
            "status_read_pc_offset": 6,
            "command_write_pc_offset": 4,
            "entries": [0x1B437A],
        }
        self.assertEqual(MODULE.qemu_ready_poll_property(compact), (
            "ready-poll=30007b4:8:3000600:100", None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property(control), (
            "ready-poll-control=3000f14:8:3000700:3000f1c:20:d5c:4:18:1c:22",
            None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property(control_uart), (
            "ready-poll-control=3000f14:8:3000700:3000f1c:20:d5c:4:18:1c:22:96",
            None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property(rotated), (
            "ready-poll=3000f14:8:3000700:1100:10:c:e", None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property(uart), (
            "ready-poll=30007b4:8:3000600:2314:2:c:10:a0", None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property(uart_framed), (
            "ready-poll=30007b4:8:3000600:2314:2:c:10:a0:100", None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **rotated,
            "signature": "thumb-lsrs-bcc-pulse-rotated-followup-v1",
            "followup_entry": 0x11A8,
            "followup_mask": 1,
        }), (None, "unsupported-signature"))
        self.assertEqual(MODULE.qemu_ready_poll_property(lcd), (
            "lcd-status-poll=280000c:8:2800008:8:1b437a:6:4", None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **compact, "signature": "future-ready-v2",
        }), (None, "unsupported-signature"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **compact, "entries": [0x100, 0x200],
        }), ("ready-poll-sites=30007b4:8:3000600:100;200", None))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **rotated, "entries": [0x100, 0x200],
        }), (None, "ambiguous-entry-count"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **compact, "entries": [0x100, 0x100],
        }), (None, "malformed-entries"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **compact, "entries": [0x100 + 2 * index for index in range(9)],
        }), (None, "entry-count-limit"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **compact, "entries": (0x100,),
        }), (None, "malformed-entries"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **compact, "mask": "8",
        }), (None, "malformed-fields"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **control, "admission": "experimental-only",
        }), (None, "unsupported-admission"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **rotated, "admission": "experimental-only",
        }), (None, "unsupported-admission"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **lcd, "admission": "experimental-only",
        }), (None, "unsupported-admission"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **uart, "admission": "experimental-only",
        }), (None, "unsupported-admission"))

    def test_uart_csr_write_does_not_leak_into_sr_readback(self) -> None:
        source = (EXPERIMENT / "msm5xxx-poc.c").read_text()
        start = source.index("static uint64_t msm5xxx_poc_ready_status_read")
        end = source.index("\nstatic ", start + 1)
        read_body = source[start:end]
        uart_start = read_body.index("if (s->ready_uart_rx_empty_enabled")
        uart_end = read_body.index("if (!primary_read)", uart_start)
        uart_body = read_body[uart_start:uart_end]

        self.assertIn("#define MSM5XXX_POC_UART_SR_IDLE 0x0c", source)
        self.assertIn("return MSM5XXX_POC_UART_SR_IDLE;", uart_body)
        self.assertNotIn("ready_status_backing", uart_body)

    def test_sbi_property_keeps_legacy_and_closes_bootstrap_only(self) -> None:
        profile = {
            "signature": "thumb-sbi-bootstrap-only-v1",
            "admission": "temporary-evidence-gated",
            "accepted": True,
            "base_address": 0x03000780,
            "bootstrap": [
                [0, 1, 0x45], [0, 1, 0xC5], [4, 2, 0x085F],
                [0x0C, 2, 0x041F], [0x10, 1, 0], [0x10, 1, 1],
            ],
            "validation": [[0, 2, None], [0x0C, 2, 0x0900], [0, 2, None]],
            "entries": [0x580],
        }
        legacy = SimpleNamespace(
            chipset="MSM5000", board_adc_reader_address=0x4050,
            sbi_bootstrap_profile=profile,
        )
        self.assertEqual(MODULE.qemu_sbi_property(legacy), ("sbi=on", None))
        bootstrap_only = SimpleNamespace(
            chipset="MSM5000", board_adc_reader_address=None,
            sbi_bootstrap_profile=profile,
        )
        self.assertEqual(MODULE.qemu_sbi_property(bootstrap_only), (
            "sbi=on,sbi-bootstrap-only=on", None,
        ))
        bootstrap_only.sbi_bootstrap_profile = {**profile, "entries": [0x581]}
        self.assertEqual(MODULE.qemu_sbi_property(bootstrap_only),
                         (None, "malformed-entries"))
        bootstrap_only.sbi_bootstrap_profile = profile
        bootstrap_only.chipset = "MSM5100"
        self.assertEqual(MODULE.qemu_sbi_property(bootstrap_only),
                         (None, "unsupported-chipset"))

    def test_board_revision_property_is_complete_and_fail_closed(self) -> None:
        config = SimpleNamespace(
            board_revision_register=0x0300075C,
            board_revision_value=0x20F5,
        )
        self.assertEqual(MODULE.qemu_board_revision_property(config), (
            "board-revision=300075c:20f5", None,
        ))
        config.board_revision_value = None
        self.assertEqual(MODULE.qemu_board_revision_property(config),
                         (None, "malformed-pair"))
        config.board_revision_register = 0x0300075D
        config.board_revision_value = 0x20F5
        self.assertEqual(MODULE.qemu_board_revision_property(config),
                         (None, "unsupported-register"))
        config.board_revision_register = 0x04000000
        self.assertEqual(MODULE.qemu_board_revision_property(config),
                         (None, "unsupported-register"))

    def test_adjacent_amd_secondary_nor_requires_closed_class(self) -> None:
        config = SimpleNamespace(
            chipset="MSM5500",
            load_address=0,
            flash_size=0x800000,
            secondary_flash_address=0x800000,
            secondary_flash_size=0x800000,
            ram_base=0x1000000,
            flash_id_value=0x227E0001,
        )
        image = b"fsd_amd.c\0...\x0b$USER_DIRS\0"
        self.assertEqual(
            MODULE.adjacent_amd_x16_flash_ids(config, image),
            (0x0001, 0x227E),
        )
        for field, value in (
                ("chipset", "MSM5100"),
                ("secondary_flash_address", 0x900000),
                ("ram_base", 0x1100000),
                ("flash_id_value", 0x22500001)):
            rejected = SimpleNamespace(**vars(config))
            setattr(rejected, field, value)
            self.assertIsNone(
                MODULE.adjacent_amd_x16_flash_ids(rejected, image)
            )
        self.assertIsNone(MODULE.adjacent_amd_x16_flash_ids(
            config, b"\x0b$USER_DIRS\0",
        ))
        self.assertIsNone(MODULE.adjacent_amd_x16_flash_ids(
            config, b"fsd_amd.c\0",
        ))
        exact = SimpleNamespace(**vars(config))
        exact.chipset = "MSM5100"
        profile = (0x800000, 0x800000, 0x0001, 0x227E)
        function_globals = MODULE.adjacent_amd_x16_flash_ids.__globals__
        with mock.patch.dict(function_globals, {
                "find_adjacent_amd_x16_nor": mock.Mock(return_value=profile),
        }):
            self.assertEqual(
                MODULE.adjacent_amd_x16_flash_ids(exact, b"firmware"),
                (0x0001, 0x227E),
            )
        with mock.patch.dict(function_globals, {
                "find_adjacent_amd_x16_nor": mock.Mock(return_value=None),
        }):
            self.assertIsNone(
                MODULE.adjacent_amd_x16_flash_ids(exact, b"firmware")
            )

    def test_dmd_5500_bridge_requires_exact_static_and_runtime_class(
            self) -> None:
        routine = bytearray(b"\xff" * 0x54)
        for offset, value in {
                0: bytes.fromhex("b0b50020"),
                4: bytes.fromhex("00f000f8"),
                8: bytes.fromhex("002803d10c480088"),
                16: bytes.fromhex("6c2803d00020b0bc08bc1847094800248480"),
                34: bytes.fromhex("00f000f8"),
                38: bytes.fromhex("084f084d02e0381c"),
                46: bytes.fromhex("00f000f8"),
                50: bytes.fromhex("e889064b9842f8d1ec810120eae7"),
                64: DMD_DOWNLOAD_5500_LITERALS,
        }.items():
            routine[offset:offset + len(value)] = value
        image = bytearray(b"\xff" * 0x400)
        image[0x100:0x154] = routine
        image[0x300:0x310] = b"dmddown_5500.c\0"
        config = SimpleNamespace(
            chipset="MSM5500", dmd_download_address=0x100,
            load_address=0, flash_size=len(image),
        )

        self.assertEqual(
            MODULE.qemu_dmd_5500_property(bytes(image), config),
            ("dmd-5500=100:6c", None),
        )
        config.dmd_download_address += 2
        self.assertEqual(
            MODULE.qemu_dmd_5500_property(bytes(image), config),
            (None, "address-mismatch"),
        )
        config.dmd_download_address -= 2
        config.chipset = "MSM5100"
        self.assertEqual(
            MODULE.qemu_dmd_5500_property(bytes(image), config),
            (None, "unsupported-chipset"),
        )
        image[0x100 + 17] ^= 1
        self.assertEqual(
            MODULE.qemu_dmd_5500_property(bytes(image), config),
            (None, None),
        )

        source = (EXPERIMENT / "msm5xxx-poc.c").read_text()
        self.assertIn("qemu_in_vcpu_thread()", source)
        self.assertIn("msm5xxx_poc_dmd_5500_pc_is(s, 0x20)", source)
        self.assertIn("old == UINT16_MAX", source)
        self.assertIn("!s->dmd_5500_pending", source)
        self.assertIn("msm5xxx_poc_dmd_5500_pc_is(s, 0x32)", source)

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

    def test_launcher_uses_persistent_state_by_default(self) -> None:
        argv = [
            "live-display.py", "phone.bin",
            "--qemu", "qemu-system-arm",
        ]
        state_root = Path("/tmp/msm5xxx-state-root")
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(MODULE, "DEFAULT_STATE_ROOT", state_root), \
             mock.patch.object(MODULE.tk, "Tk") as make_root, \
             mock.patch.object(MODULE, "LiveWindow") as make_window:
            self.assertEqual(MODULE.main(), 0)
        make_window.assert_called_once_with(
            make_root.return_value,
            Path("phone.bin").resolve(),
            Path("qemu-system-arm").resolve(),
            (state_root / "qemu-state").resolve(),
            False,
        )
        make_window.return_value._close.assert_called_once_with()

    def test_qemu_gui_disables_partial_source_updates(self) -> None:
        with mock.patch.object(MODULE.threading, "Thread") as thread:
            MODULE.LiveWindow._check_for_update(object())
        thread.assert_not_called()

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

    def test_qemu_state_directory_recovers_flat_mapped_primary_state(self) -> None:
        first = SimpleNamespace(firmware_sha256="a" * 64)
        second = SimpleNamespace(firmware_sha256="b" * 64)
        for name in (
                "mapped-primary-x16.raw",
                "mapped-primary-x16-upper.raw"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / name).write_bytes(b"legacy")

                self.assertEqual(MODULE.qemu_state_directory(root, first), root)
                self.assertEqual(MODULE.qemu_state_directory(root, second),
                                 root / ("b" * 64))

    def test_primary_x16_detectors_must_agree(self) -> None:
        legacy = (0x10000, 0x40000, 0x10000, 0x98, 0x84)
        uniform = (0x10000, 0x40000, ((4, 0x10000),), 0x98, 0x84)
        segmented = (
            0x10000, 0x40000,
            ((2, 0x10000), (16, 0x2000)), 0x98, 0x84,
        )
        self.assertEqual(
            MODULE.select_primary_x16_nor_profile(legacy, uniform),
            (legacy, uniform[2], None),
        )
        self.assertEqual(
            MODULE.select_primary_x16_nor_profile(legacy, segmented),
            (None, None, "detector-conflict"),
        )
        self.assertEqual(
            MODULE.select_primary_x16_nor_profile(None, segmented),
            ((0x10000, 0x40000, 0x10000, 0x98, 0x84), segmented[2], None),
        )

    def test_qemu_detector_image_matches_canonical_normalization(self) -> None:
        header = b"dump-header"
        flash_size = ram_image_offset = 0x80000
        ram_base, ram_image_size = 0x01000000, 0x100
        image = bytearray(b"\xff" * (flash_size + ram_image_size))
        struct.pack_into("<I", image, 0, 0xEA000006)
        for index in range(1, 8):
            target = 0x4000 + index * 4
            displacement = (target - (index * 4 + 8)) // 4
            struct.pack_into(
                "<I", image, index * 4,
                0xEA000000 | (displacement & 0xFFFFFF),
            )
        boot_table_loop = bytes.fromhex(
            "c1002e4a515800290bd0c10089188988c2002a4b9a581180"
            "411c0904090c081ceee7"
        )
        image[0x11C:0x11C + len(boot_table_loop)] = boot_table_loop
        struct.pack_into("<I", image, 0x1D8, 0x1158)
        struct.pack_into(
            "<8I", image, 0x1158,
            0x048000A0, 6, 0x03000738, 0x1F,
            0x0300073C, 0x2001, 0, 0,
        )
        for index in range(8):
            struct.pack_into("<I", image, 0x4000 + index * 4, 0xEA000000)

        probe, entry = 0x800, 0x2000
        sectors = 71 * [0x1000]
        descriptor, name = entry + 0x124, entry + 0x15C
        image[probe:probe + len(PRIMARY_FLASH_PROBE_SIGNATURE)] = (
            PRIMARY_FLASH_PROBE_SIGNATURE
        )
        struct.pack_into(
            "<3I", image, probe + len(PRIMARY_FLASH_PROBE_SIGNATURE),
            descriptor - 0x24, ram_base + 0x10, ram_base + 0x20,
        )
        struct.pack_into("<2I", image, entry, name, len(sectors))
        struct.pack_into(f"<{len(sectors)}I", image, entry + 8, *sectors)
        struct.pack_into(
            "<14I", image, descriptor,
            0x00840098, 0, 1, 0, sum(sectors) // 2,
            *[0x301 + index * 0x20 for index in range(9)],
        )
        image[name:name + 8] = b"NOR X16\0"
        struct.pack_into("<I", image, ram_image_offset + 0x10, 0x10000)
        struct.pack_into("<2I", image, ram_image_offset + 0x20, entry, 0)

        sparse = bytes(image[:0x1000] + image[0x1020:])
        normalized = MODULE.detector_firmware_image(header + sparse, len(header))
        self.assertEqual(normalized, bytes(image))
        self.assertEqual(
            MODULE.primary_probe_x16_nor_profile(
                normalized, probe, 0, flash_size, 0, ram_base,
                ram_image_offset, ram_image_size,
            ),
            ((0x10000, sum(sectors), ((71, 0x1000),), 0x98, 0x84), None),
        )
        with self.assertRaisesRegex(ValueError, "image offset"):
            MODULE.detector_firmware_image(header + sparse, len(header + sparse))

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

    def test_uis_idle_observer_requires_one_closed_pair(self) -> None:
        accepted = SimpleNamespace(
            uis_idle_entry_address=0x000CC348,
            uis_idle_body_address=0x000CC4A6,
        )
        self.assertEqual(
            MODULE.qemu_uis_idle_observer_addresses(accepted),
            (0x000CC348, 0x000CC4A6),
        )
        compact = SimpleNamespace(
            uis_idle_entry_address=0x000C1D88,
            uis_idle_body_address=0x000C1E86,
        )
        self.assertEqual(
            MODULE.qemu_uis_idle_observer_addresses(compact),
            (0x000C1D88, 0x000C1E86),
        )
        for delta in (0x8B8, 0x908):
            draw = SimpleNamespace(
                uis_idle_entry_address=0x000F0000,
                uis_idle_body_address=0x000F0000 + delta,
            )
            with self.subTest(delta=delta):
                self.assertEqual(
                    MODULE.qemu_uis_idle_observer_addresses(draw),
                    (0x000F0000, 0x000F0000 + delta),
                )
        for changed in (
                SimpleNamespace(uis_idle_entry_address=None,
                                uis_idle_body_address=0x000CC4A6),
                SimpleNamespace(uis_idle_entry_address=0x000CC349,
                                uis_idle_body_address=0x000CC4A6),
                SimpleNamespace(uis_idle_entry_address=0x000CC348,
                                uis_idle_body_address=0x000CC4A8)):
            with self.subTest(changed=changed):
                self.assertIsNone(MODULE.qemu_uis_idle_observer_addresses(
                    changed
                ))

    def test_rex_idle_candidate_observer_requires_even_address(self) -> None:
        accepted = SimpleNamespace(rex_idle_address=0x000DEF50)
        self.assertEqual(
            MODULE.qemu_rex_idle_candidate_observer_address(accepted),
            0x000DEF50,
        )
        for address in (None, 0, 0x000DEF51, 0x1_0000_0000, True):
            with self.subTest(address=address):
                self.assertIsNone(
                    MODULE.qemu_rex_idle_candidate_observer_address(
                        SimpleNamespace(rex_idle_address=address)
                    )
                )

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

    def test_raw_nand_main_profile_requires_the_complete_closed_shape(
            self) -> None:
        image = bytearray(b"\xff" * 0x800)
        image[0x20:0x2B] = b"fs_ks_nand.c"
        for site in (0x100, 0x300):
            image[site:site + len(MODULE.RAW_NAND_STATUS_SIGNATURE)] = (
                MODULE.RAW_NAND_STATUS_SIGNATURE
            )
            reset = site + 0x30
            image[reset:reset + len(MODULE.RAW_NAND_RESET_SIGNATURE)] = (
                MODULE.RAW_NAND_RESET_SIGNATURE
            )
            image[site + 0x50:site + 0x54] = bytes.fromhex("29210905")
        for position in (0x500, 0x520):
            image[position:position + len(MODULE.RAW_NAND_PAGE_SIGNATURE)] = (
                MODULE.RAW_NAND_PAGE_SIGNATURE
            )
        image[0x600:0x606] = MODULE.RAW_NAND_BLOCK_PREFIX
        image[0x60A:0x614] = MODULE.RAW_NAND_BLOCK_SUFFIX
        image[0x680:0x684] = MODULE.RAW_NAND_X16_PREFIX
        image[0x688:0x68C] = MODULE.RAW_NAND_X16_TRANSFER
        config = SimpleNamespace(
            nand_enabled=True, flash_size=0x800000, nand_data_size=0x800000,
            nand_page_size=0x200, nand_pages_per_block=0x20,
            nand_bus_width=2, upper_flash_address=None,
        )

        self.assertEqual(MODULE.qemu_raw_nand_main_profile(image, config), (
            (0x02800000, 0x02900000, 0x02A00000,
             0x800000, 0x200, 0x20, 2),
            None,
        ))
        image[0x100] ^= 1
        image[0x300] ^= 1
        self.assertEqual(
            MODULE.qemu_raw_nand_main_profile(image, config),
            (None, "incomplete-status-reset-shape"),
        )

        low_image = bytearray(b"\xff" * 0x1000)
        low_image[0x20:0x2B] = b"fs_ks_nand.c"
        for position, signature in zip(
                (0x100, 0x200, 0x300, 0x500, 0x700),
                (MODULE.RAW_NAND_LOW_PORT_RESET_SIGNATURE,
                 MODULE.RAW_NAND_LOW_PORT_STATUS_SIGNATURE,
                 MODULE.RAW_NAND_LOW_PORT_READ_SIGNATURE,
                 MODULE.RAW_NAND_LOW_PORT_ERASE_SIGNATURE,
                 MODULE.RAW_NAND_LOW_PORT_PROGRAM_SIGNATURE)):
            low_image[position:position + len(signature)] = signature
        self.assertEqual(MODULE.qemu_raw_nand_main_profile(low_image, config), (
            (0x00800000, 0x00900000, 0x00A00000,
             0x800000, 0x200, 0x20, 2),
            None,
        ))
        low_image[0x500] ^= 1
        self.assertEqual(
            MODULE.qemu_raw_nand_main_profile(low_image, config),
            (None, "incomplete-status-reset-shape"),
        )

    def test_raw_nand_main_backend_is_named_and_non_orphaned(self) -> None:
        machine = (EXPERIMENT / "msm5xxx-poc.c").read_text()
        start = machine.index(
            "s->raw_nand_blk = blk_by_name(MSM5XXX_POC_RAW_NAND_DRIVE)"
        )
        end = machine.index("if (s->eeprom_gpio_enabled) {", start)
        raw_nand_init = machine[start:end]

        self.assertIn(
            "blk_by_name(MSM5XXX_POC_RAW_NAND_DRIVE)", raw_nand_init,
        )
        self.assertNotIn("drive_get(IF_MTD", raw_nand_init)
        self.assertNotIn("msm5xxx_poc_raw_nand_set_ready", machine)
        transport = (EXPERIMENT / "qemu_transport.py").read_text()
        self.assertIn(
            '"id=msm5xxx-raw-nand-main"', transport,
        )
        self.assertNotIn(
            'f"file={raw_nand_state},if=mtd', transport,
        )
        setter_start = machine.index("static void msm5xxx_poc_set_raw_nand_main")
        setter_end = machine.index("static char *msm5xxx_poc_get_eeprom_gpio",
                                   setter_start)
        setter = machine[setter_start:setter_end]
        for name in ("DATA", "ADDRESS", "COMMAND"):
            self.assertIn(
                f"MSM5XXX_POC_RAW_NAND_LOW_PORT_{name}_BASE", setter,
            )

    def test_eeprom_gpio_reset_preserves_shared_msm_backing(self) -> None:
        machine = (EXPERIMENT / "msm5xxx-poc.c").read_text()
        reset = machine[machine.index("static void msm5xxx_poc_reset"):
                        machine.index("static void msm5xxx_poc_init")]

        seed = reset.index("msm[0x72c] = 0x14;")
        copy = reset.index("memcpy(s->eeprom_gpio_backing,", seed)
        self.assertIn(
            "msm + s->eeprom_gpio_base - MSM5XXX_POC_MSM_BASE",
            reset[copy:copy + 240],
        )
        self.assertGreater(
            reset.index("msm5xxx_poc_eeprom_gpio_update(s);", copy), copy,
        )

    def test_mapped_primary_nor_persists_upper_bank_and_aliases_intel(self) -> None:
        machine = (EXPERIMENT / "msm5xxx-poc.c").read_text()
        transport = (EXPERIMENT / "qemu_transport.py").read_text()

        self.assertIn("mapped-primary-x16-nor-upper", machine)
        self.assertIn("intel_x16_nor_data_alias", machine)
        self.assertIn("mapped-primary-x16-upper.raw", transport)
        self.assertIn("pflash_unit += 2", transport)

    def test_primary_nor_honors_suspend_write_descriptor_option(self) -> None:
        machine = (EXPERIMENT / "msm5xxx-poc.c").read_text()
        transport = (EXPERIMENT / "qemu_transport.py").read_text()
        start = machine.index("    if (s->primary_x16_nor_enabled) {")
        end = machine.index("    if (s->record_x16_nor_enabled) {", start)
        primary_init = machine[start:end]
        transport_start = transport.index("        if primary_profile is not None:")
        transport_end = transport.index(
            "        if record_profile is not None:", transport_start
        )

        self.assertIn(
            'qdev_prop_set_bit(dev, "write-while-suspended", true);',
            primary_init,
        )
        self.assertIn(
            "if (s->primary_x16_write_while_suspended) {", primary_init,
        )
        self.assertIn(
            'object_class_property_add_bool(\n'
            '        oc, "primary-x16-write-while-suspended",',
            machine,
        )
        primary_transport = transport[transport_start:transport_end]
        regions_start = primary_transport.index(
            "            if primary_regions is not None:"
        )
        regions_end = primary_transport.index(
            "            storage_args.extend", regions_start
        )
        self.assertIn(
            'machine += ",primary-x16-write-while-suspended=on"',
            primary_transport[regions_start:regions_end],
        )
        self.assertEqual(
            transport.count("primary-x16-write-while-suspended=on"), 1,
        )

    def test_record_nor_is_descriptor_gated_and_identity_fail_closed(self) -> None:
        machine = (EXPERIMENT / "msm5xxx-poc.c").read_text()
        transport = (EXPERIMENT / "qemu_transport.py").read_text()
        start = machine.index("    if (s->record_x16_nor_enabled) {")
        start = machine.index("    if (s->record_x16_nor_enabled) {", start + 1)
        end = machine.index(
            "    if (s->mapped_primary_x16_nor_enabled) {", start
        )
        record_init = machine[start:end]

        self.assertIn('"record-x16-nor"', machine)
        self.assertIn("TYPE_PFLASH_CFI02", record_init)
        self.assertEqual(record_init.count("UINT16_MAX"), 4)
        self.assertIn('"unlock-addr0", 0x555', record_init)
        self.assertIn('"unlock-addr1", 0x2aa', record_init)
        self.assertIn("pow2ceil(s->record_x16_nor_size)", record_init)
        self.assertIn("record_x16_nor_alias", record_init)
        self.assertNotIn("sysbus_mmio_map_overlap", record_init)
        self.assertIn("find_record_amd_x16_nor", transport)
        self.assertIn("record-x16.raw", transport)
        self.assertIn("1 << (size - 1).bit_length()", transport)
        self.assertIn(
            "migrate_erased_raw_state(\n"
            "                                record_state, size, device_size",
            transport,
        )
        self.assertIn(
            "record_state, 0x200000, device_size,\n"
            "                                prepend=True",
            transport,
        )
        self.assertIn("record_base + record_size != primary_profile[0]",
                      transport)

    def test_secondary_nor_hides_power_of_two_backing_tail(self) -> None:
        machine = (EXPERIMENT / "msm5xxx-poc.c").read_text()
        transport = (EXPERIMENT / "qemu_transport.py").read_text()
        start = machine.index("    if (s->fujitsu_x16_nor_enabled) {")
        end = machine.index("    if (upper_nor_enabled) {", start)
        secondary_init = machine[start:end]

        self.assertIn("pow2ceil(s->secondary_nor_size)", secondary_init)
        self.assertIn("secondary_nor_alias", secondary_init)
        self.assertIn("device_size / 0x10000", secondary_init)
        self.assertIn("device_size != s->secondary_nor_size", secondary_init)
        self.assertIn(
            "s->secondary_nor_size == 0x800000 &&\n"
            "                s->secondary_nor_base < s->secondary_primary_size",
            secondary_init,
        )
        self.assertIn('"num-blocks2", 8', secondary_init)
        self.assertIn('"sector-length2", 0x2000', secondary_init)
        setter_start = machine.index(
            "static void msm5xxx_poc_set_fujitsu_x16_nor"
        )
        setter_end = machine.index(
            "static void msm5xxx_poc_set_primary_x16_nor", setter_start
        )
        setter = machine[setter_start:setter_end]
        self.assertNotIn("s->ram_base", setter)
        self.assertIn("s->secondary_primary_size = primary", setter)
        self.assertIn("if (!s->memory_profile_enabled)", setter)
        self.assertIn("size == 0x200000", setter)
        self.assertIn("size == 0x800000", setter)
        self.assertIn("(uint64_t)base + size == primary", setter)
        self.assertIn(
            "s->secondary_primary_size != s->primary_nor_size", machine
        )
        self.assertIn(
            "s->secondary_nor_base >= s->ram_base || end > s->ram_base",
            machine,
        )
        self.assertIn("find_catalog_amd_x16_nor", transport)
        self.assertIn('"catalog-x16.raw"', transport)
        self.assertIn("f\"{secondary_base:x}:{secondary_size:x}:\"", transport)
        self.assertIn(
            "find_embedded_fujitsu_x16_nor(\n"
            "                bytes(self.decoder.flash.data), "
            "self.config.flash_size",
            transport,
        )

    def test_raw_nand_state_is_observable_without_ready_synthesis(self) -> None:
        machine = (EXPERIMENT / "msm5xxx-poc.c").read_text()
        start = machine.index("    case 0xac:")
        end = machine.index("    default:", start)
        telemetry = machine[start:end]

        for field in (
            "raw_nand_reads", "raw_nand_writes", "raw_nand_rejections",
            "raw_nand_mode", "raw_nand_status", "raw_nand_address_count",
            "raw_nand_cursor_valid", "raw_nand_spare_selected",
        ):
            self.assertIn(f"s->{field}", telemetry)
        self.assertNotIn("board_status_input", telemetry)
        self.assertNotIn("msm5xxx_poc_raw_nand_set_ready", machine)

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

    def test_eeprom_gpio_profile_accepts_x270_protocol_class(self) -> None:
        image = bytearray(b"\xff" * 0x3000)
        write, read, initializer = 0x1000, 0x16D0, 0x2400
        writer, reader = write - 0x2DC, read - 0x7F8
        geometry = 0x0119BA08
        image[write:write + len(MODULE.EEPROM_24LCXX_X270_WRITE_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X270_WRITE_PREFIX
        )
        image[read:read + len(MODULE.EEPROM_24LCXX_X270_READ_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X270_READ_PREFIX
        )
        image[initializer:initializer + 18] = bytes.fromhex(
            "01200449c0030880012088700020c8707047"
        )
        for position in (write + 0x3EC, read + 0x3EC,
                         initializer + 0x14):
            MODULE.struct.pack_into("<I", image, position, geometry)
        image[0x2E00:0x2E0B] = b"nv24lcxx.c\0"

        shapes = (
            (writer, "f0b5071c"),
            (writer + 0x18, "2b7808263343"),
            (writer + 0x28, "2b702b782372"),
            (writer + 0x2E, "13780b43137013782373"),
            (writer + 0x3E, "137013782373"),
            (reader, "f0b50027"),
            (reader + 0x0E, "0a782a430a700b78"),
            (reader + 0x1A, "1373"),
            (reader + 0x1C, "2678330900d38027"),
            (reader + 0x24, "0b785b085b000b700b781373"),
            (write + 0xBE, "08251178294311701178"),
            (write + 0xCA, "1173"),
            (read + 0x304, "082311789943117011"),
            (read + 0x310, "1173"),
            (read + 0x324, "2070"),
        )
        for position, value in shapes:
            raw = bytes.fromhex(value)
            image[position:position + len(raw)] = raw
        MODULE.struct.pack_into("<H", image, writer + 0x12, 0x4C66)
        MODULE.struct.pack_into("<I", image, writer + 0x1AC, 0x03000660)
        MODULE.struct.pack_into("<H", image, reader + 0x04, 0x4C46)
        MODULE.struct.pack_into("<H", image, reader + 0x16, 0x4A42)
        MODULE.struct.pack_into("<I", image, reader + 0x120, 0x03000668)
        MODULE.struct.pack_into("<H", image, write + 0xC8, 0x4A01)
        MODULE.struct.pack_into("<I", image, write + 0xD0, 0x03000670)
        MODULE.struct.pack_into("<H", image, read + 0x30E, 0x4A02)
        MODULE.struct.pack_into("<I", image, read + 0x318, 0x03000670)
        displacement = reader - (read + 0x320 + 4)
        MODULE.struct.pack_into(
            "<2H", image, read + 0x320,
            0xF000 | (displacement >> 12 & 0x7FF),
            0xF800 | (displacement >> 1 & 0x7FF),
        )
        config = SimpleNamespace(
            eeprom_read_address=read, eeprom_write_address=write,
            eeprom_geometry_address=geometry, load_address=0,
        )

        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            ((0x03000660, 8, 8, 0xC, 1, 0x1C, 0x8000), None),
        )
        image[reader + 0x1E] ^= 1
        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            (None, "gpio-line-shape-mismatch"),
        )

    def test_eeprom_gpio_profile_accepts_f6f7_protocol_class(self) -> None:
        image = bytearray(b"\xff" * 0x4000)
        write, read, initializer = 0x1000, 0x16D0, 0x2400
        geometry = 0x0119BA08
        image[write:write + len(MODULE.EEPROM_24LCXX_F6F7_WRITE_PREFIX)] = (
            MODULE.EEPROM_24LCXX_F6F7_WRITE_PREFIX
        )
        image[read:read + len(MODULE.EEPROM_24LCXX_X270_READ_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X270_READ_PREFIX
        )
        image[initializer:initializer + 18] = bytes.fromhex(
            "01200449c0030880012088700020c8707047"
        )
        for position in (write + 0x3E8, read + 0x3EC,
                         initializer + 0x14):
            MODULE.struct.pack_into("<I", image, position, geometry)
        image[0x3A00:0x3A0B] = b"nv24lcxx.c\0"

        low_write, low_read = 0x2C00, 0x2D00
        image[low_write:low_write + 8] = bytes.fromhex(
            "f0b5071c1e481f49"
        )
        MODULE.struct.pack_into("<2I", image, low_write + 0x80,
                                0x03000660, 0x03000668)
        image[low_read:low_read + 6] = bytes.fromhex("f0b500271e48")
        MODULE.struct.pack_into("<I", image, low_read + 0x80, 0x03000668)

        def call(position: int, target: int) -> None:
            displacement = target - (position + 4)
            MODULE.struct.pack_into(
                "<2H", image, position,
                0xF000 | (displacement >> 12 & 0x7FF),
                0xF800 | (displacement >> 1 & 0x7FF),
            )

        for index in range(16):
            call(0x1400 + index * 4, low_write)
        for index in range(2):
            call(0x1480 + index * 4, low_read)
        config = SimpleNamespace(
            eeprom_read_address=read, eeprom_write_address=write,
            eeprom_geometry_address=geometry, load_address=0,
        )

        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            ((0x03000660, 8, 8, 0xC, 1, 0x1C, 0x8000), None),
        )
        MODULE.struct.pack_into("<I", image, low_write + 0x80, 0x03000728)
        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            (None, "transport-entry-signature-mismatch"),
        )

    def test_eeprom_gpio_profile_accepts_x7700_protocol_class(self) -> None:
        image = bytearray(b"\xff" * 0x5000)
        write, read, initializer = 0x1000, 0x16B0, 0x3000
        writer, reader = write - 0x160, read - 0x728
        geometry, descriptor = 0x01002000, 0x01000100
        image[write:write + len(MODULE.EEPROM_24LCXX_X7700_WRITE_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X7700_WRITE_PREFIX
        )
        image[read:read + len(MODULE.EEPROM_24LCXX_X7700_READ_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X7700_READ_PREFIX
        )
        image[initializer:initializer + 18] = bytes.fromhex(
            "01200449c0030880012088700020c8707047"
        )
        for position in (write + 0x3EC, read + 0x3E8,
                         initializer + 0x14):
            MODULE.struct.pack_into("<I", image, position, geometry)
        image[0x3F00:0x3F0B] = b"nv24lcxx.c\0"
        shapes = (
            (writer, "f0b5071c80260724"),
            (writer + 0x18, "324a202391891943918191891268"),
            (writer + 0x3A, "2a4a402391891943918191891268"),
            (writer + 0x5A, "224a402391899943918191891268"),
            (writer + 0x74, "1b4a202391899943918191891268"),
            (writer + 0x96, "134a402391891943918191891268"),
            (writer + 0xB6, "0b4a402391899943918191891268"),
            (reader, "f0b500271a4e0024"),
            (reader + 0x12, "184a402391891943918191891268"),
            (reader + 0x32, "30783f0e800901d301200743"),
            (reader + 0x42, "0c4a402391899943918191891268"),
        )
        for position, value in shapes:
            raw = bytes.fromhex(value)
            image[position:position + len(raw)] = raw
        MODULE.struct.pack_into("<I", image, writer + 0xE4, descriptor)
        MODULE.struct.pack_into("<II", image, reader + 0x70,
                                0x03000720, descriptor)
        MODULE.struct.pack_into("<III", image, 0x3900,
                                0x03000720, 0x03000720, 0x0300072C)
        config = SimpleNamespace(
            eeprom_read_address=read, eeprom_write_address=write,
            eeprom_geometry_address=geometry, load_address=0,
            linker=SimpleNamespace(
                data_source=0x3800, data_target=0x01000000,
                data_size=0x1000,
            ),
        )

        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            ((0x03000720, 0, 0x20, 0, 0x40, 0xC, 0x8000), None),
        )
        image[reader + 0x34] ^= 1
        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            (None, "gpio-line-shape-mismatch"),
        )

    def test_eeprom_gpio_profile_accepts_f7f6_protocol_class(self) -> None:
        image = bytearray(b"\xff" * 0x1800)
        write, read, initializer = 0x400, 0xAD8, 0x1200
        writer, ack, reader = write - 0x16C, write - 0x216, read - 0x754
        geometry = 0x01208494
        image[write:write + len(MODULE.EEPROM_24LCXX_X7700_WRITE_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X7700_WRITE_PREFIX
        )
        image[read:read + len(MODULE.EEPROM_24LCXX_X430_READ_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X430_READ_PREFIX
        )
        image[initializer:initializer + 18] = bytes.fromhex(
            "01200449c0030880012088700020c8707047"
        )
        for position in (write + 0x3EC, read + 0x3E8,
                         initializer + 0x14):
            MODULE.struct.pack_into("<I", image, position, geometry)
        image[0x1700:0x170B] = b"nv24lcxx.c\0"
        shapes = (
            (writer, "f0b5071c80260724"),
            (writer + 0x1A, "01231178194311701178304a1171"),
            (writer + 0x3C, "20231178194311701178"),
            (writer + 0x5C, "20231178994311701178"),
            (writer + 0x74, "1b4a11784908490011701178"),
            (writer + 0x98, "20231178194311701178"),
            (writer + 0xB8, "20231178994311701178"),
            (ack, "f0b5"),
            (ack + 0x06, "234a11784908490011701178214a1172"),
            (ack + 0x24, "202229781c4c114329702978103c2170"),
            (ack + 0x40, "21790126301c490800d2002007063f0e"),
            (ack + 0x5C, "20239943297029782170"),
            (ack + 0x7A, "0a7832430a700978054a1172"),
            (reader, "f0b500271b4e0024"),
            (reader + 0x12, "194a20231178194311701178154a043a1170"),
            (reader + 0x30, "7800070630783f0e400801d301200743"),
            (reader + 0x44, "0c4a20231178994311701178084a043a1170"),
        )
        for position, value in shapes:
            raw = bytes.fromhex(value)
            image[position:position + len(raw)] = raw
        for position, operation in zip(
                (writer + 0x46, writer + 0x66, writer + 0x80,
                 writer + 0xA2, writer + 0xC2),
                (0x4A28, 0x4A20, 0x4A19, 0x4A11, 0x4A09)):
            MODULE.struct.pack_into("<H", image, position, operation)
        MODULE.struct.pack_into("<I", image, writer + 0xE8, 0x03000660)
        MODULE.struct.pack_into("<I", image, ack + 0x9A, 0x03000670)
        MODULE.struct.pack_into("<I", image, reader + 0x74, 0x03000664)
        config = SimpleNamespace(
            eeprom_read_address=read, eeprom_write_address=write,
            eeprom_geometry_address=geometry, load_address=0,
        )

        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            ((0x03000660, 4, 1, 0, 0x20, 0x18, 0x8000), None),
        )
        image[reader + 0x32] ^= 1
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

    def test_gui_preserves_one_debounce_window_between_key_edges(self) -> None:
        window = MODULE.LiveWindow.__new__(MODULE.LiveWindow)
        window.closing = False
        window.root = mock.Mock()
        window.transport = mock.Mock()
        window.commands = queue.SimpleQueue()
        window.commands.put((15, True))
        window.commands.put((15, False))

        window._forward_qemu_keys()

        window.transport.set_key.assert_called_once_with(15, True, None)
        window.root.after.assert_called_once_with(20, window._forward_qemu_keys)
        window._forward_qemu_keys()
        self.assertEqual(
            window.transport.set_key.call_args_list,
            [mock.call(15, True, None), mock.call(15, False, None)],
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
        transport.input_socket = SimpleNamespace(sendall=packets.append)
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

    def test_input_ack_preempts_lcd_replay_batch(self) -> None:
        stop = MODULE.threading.Event()
        seen: list[int] = []
        input_record = bytes([MODULE.INPUT_TELEMETRY]) + bytes(15)
        lcd_record = bytes([MODULE.LCD_WRITE]) + bytes(15)

        class Stream:
            def __init__(self, record: bytes, finish: bool = False) -> None:
                self.record = record
                self.finish = finish

            def recv(self, size: int) -> bytes:
                self.assert_size = size
                if self.finish:
                    stop.set()
                return self.record

        transport = object.__new__(MODULE.Transport)
        transport.input_socket = Stream(input_record)
        transport.lcd_socket = Stream(lcd_record, True)
        transport.process = SimpleNamespace(poll=lambda: None)
        transport._replay_record = lambda record: seen.append(record[0])

        with mock.patch.object(
                MODULE.select, "select",
                return_value=([transport.lcd_socket,
                               transport.input_socket], [], [])):
            transport.replay(stop)

        self.assertEqual(seen, [MODULE.INPUT_TELEMETRY, MODULE.LCD_WRITE])
        self.assertEqual(transport.input_socket.assert_size, 4096)
        self.assertEqual(transport.lcd_socket.assert_size, 4096)

    def test_input_eof_stops_qemu(self) -> None:
        stop = MODULE.threading.Event()
        input_socket = SimpleNamespace(recv=lambda size: b"")
        transport = object.__new__(MODULE.Transport)
        transport.input_socket = input_socket
        transport.lcd_socket = SimpleNamespace()
        transport.process = SimpleNamespace(poll=lambda: None)
        transport.decoder = SimpleNamespace(input_error="")
        terminated: list[bool] = []
        transport._terminate_process = lambda: terminated.append(True)

        with mock.patch.object(
                MODULE.select, "select",
                return_value=([input_socket], [], [])):
            transport.replay(stop)

        self.assertEqual(transport.decoder.input_error,
                         "QEMU input channel closed")
        self.assertEqual(terminated, [True])

    def test_qemu_input_framing_survives_reset_and_reentry(self) -> None:
        source = (EXPERIMENT / "msm5xxx-poc.c").read_text()
        read_start = source.index("static void msm5xxx_poc_host_input_read")
        read_end = source.index("\nstatic ", read_start + 1)
        read_body = source[read_start:read_end]
        self.assertLess(
            read_body.index("s->matrix_input_buffer_length = 0;"),
            read_body.index("msm5xxx_poc_input_stream_write(s);"),
        )

        reset_start = source.index("static void msm5xxx_poc_reset")
        reset_end = source.index("\nstatic ", reset_start + 1)
        reset_body = source[reset_start:reset_end]
        self.assertNotIn("matrix_input_buffer_length = 0", reset_body)
        self.assertNotIn("matrix_input_ack_length = 0", reset_body)
        self.assertNotIn("g_source_remove(s->matrix_input_ack_watch)",
                         reset_body)
        self.assertIn("G_IO_HUP | G_IO_ERR | G_IO_NVAL", source)
        self.assertIn("CPUClass *cc = CPU_GET_CLASS(s->cpu);", reset_body)
        self.assertIn("s->reset_callbacks++;", reset_body)
        self.assertIn(
            "s->last_reset_callback_pc = cc->get_pc(CPU(s->cpu));",
            reset_body,
        )
        self.assertLess(
            reset_body.index("s->reset_callbacks++;"),
            reset_body.index("cpu_reset(CPU(s->cpu));"),
        )
        self.assertNotIn("s->reset_callbacks = 0", reset_body)
        self.assertNotIn("s->last_reset_callback_pc = 0", reset_body)

        mmio_start = source.index("\nstatic uint64_t msm5xxx_poc_read(")
        mmio_end = source.index("\nstatic ", mmio_start + 1)
        mmio_read = source[mmio_start:mmio_end]
        self.assertIn("case 0xbc:\n        return s->reset_callbacks;",
                      mmio_read)
        self.assertIn(
            "case 0xc0:\n        return s->last_reset_callback_pc;",
            mmio_read,
        )

    def test_qemu_sbi_adc_status_poll_preserves_completed_phase(self) -> None:
        source = (EXPERIMENT / "msm5xxx-poc.c").read_text()
        read_start = source.index("static uint64_t msm5xxx_poc_sbi_read")
        read_end = source.index("\nstatic ", read_start + 1)
        read_body = source[read_start:read_end]
        self.assertIn("s->sbi_board_adc_phase != 5 &&", read_body)
        self.assertIn("s->sbi_board_adc_phase != 7 &&", read_body)
        self.assertIn("s->sbi_board_adc_phase != 9", read_body)

        write_start = source.index("static void msm5xxx_poc_sbi_write")
        write_end = source.index("\nstatic ", write_start + 1)
        write_body = source[write_start:write_end]
        self.assertIn("(value & 0xff80) == 0x0a80", write_body)
        self.assertIn("s->sbi_board_adc_selector = value;", write_body)
        self.assertIn(
            "value == (s->sbi_board_adc_selector & ~0x0080)", write_body,
        )
        self.assertNotIn("value == 0x0ada", write_body)
        self.assertNotIn("value == 0x0a5a", write_body)

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

            self.assertTrue(MODULE.migrate_erased_raw_state(raw, 8, 16))
            backup = root / "legacy.bin.pre-00000008"
            self.assertEqual(raw.read_bytes(), b"\x55" * 8 + b"\xff" * 8)
            self.assertEqual(backup.read_bytes(), b"\x55" * 8)
            self.assertFalse(MODULE.migrate_erased_raw_state(raw, 8, 16))
            raw.write_bytes(b"\x44" * 8)
            with self.assertRaisesRegex(ValueError, "backup mismatch"):
                MODULE.migrate_erased_raw_state(raw, 8, 16)
            self.assertEqual(backup.read_bytes(), b"\x55" * 8)

            prefixed = root / "legacy-prefix.bin"
            prefixed.write_bytes(b"\x66" * 8)
            self.assertTrue(MODULE.migrate_erased_raw_state(
                prefixed, 8, 16, prepend=True,
            ))
            self.assertEqual(prefixed.read_bytes(), b"\xff" * 8 + b"\x66" * 8)

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

    def test_ma2_loader_patch_preserves_silent_boot_call_contract(self) -> None:
        load = 0x1000
        offset = 0x100
        entry = load + offset
        image = bytes(b"\xff" * 0x1000)
        config = SimpleNamespace(
            ma2_silent_boot_address=entry, load_address=load,
            flash_size=len(image),
        )
        with mock.patch.dict(
                MODULE.ma2_silent_boot_loader_patch.__globals__,
                {"find_ma2_silent_boot_wait": lambda _: offset}):
            result = MODULE.ma2_silent_boot_loader_patch(image, config)
            self.assertIsNotNone(result)
            patch_offset, patch = result
            self.assertEqual((patch_offset, len(patch)), (offset, 8))

            uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
            uc.mem_map(load, 0x1000)
            uc.mem_write(entry, patch)
            registers = MODULE.arm_const
            uc.reg_write(registers.UC_ARM_REG_CPSR, 0xA0000033)
            uc.reg_write(registers.UC_ARM_REG_SP, 0x1FF0)
            uc.reg_write(registers.UC_ARM_REG_LR, 0x1201)
            uc.reg_write(registers.UC_ARM_REG_R0, 0xFFFFFFFF)
            uc.reg_write(registers.UC_ARM_REG_R1, 0x11111111)
            uc.reg_write(registers.UC_ARM_REG_R7, 0x77777777)
            flags = uc.reg_read(registers.UC_ARM_REG_CPSR) & 0xF0000000

            uc.emu_start(entry | 1, 0, count=2)

            self.assertEqual(uc.reg_read(registers.UC_ARM_REG_PC), 0x1200)
            self.assertEqual(uc.reg_read(registers.UC_ARM_REG_R0), 0)
            self.assertEqual(uc.reg_read(registers.UC_ARM_REG_R1), 0x11111111)
            self.assertEqual(uc.reg_read(registers.UC_ARM_REG_R7), 0x77777777)
            self.assertEqual(uc.reg_read(registers.UC_ARM_REG_SP), 0x1FF0)
            self.assertEqual(uc.reg_read(registers.UC_ARM_REG_LR), 0x1201)
            self.assertEqual(
                uc.reg_read(registers.UC_ARM_REG_CPSR) & 0xF0000000, flags
            )

            self.assertIsNone(MODULE.ma2_silent_boot_loader_patch(
                image, config, offset + len(patch) - 1
            ))
            config.ma2_silent_boot_address += 2
            self.assertIsNone(
                MODULE.ma2_silent_boot_loader_patch(image, config)
            )

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
        candidate.update({
            "promotion": "temporary-evidence-gated",
            "status_bank_count": 2,
            "group_row_size": 10,
            "pending_read_semantics": "latched-read",
            "pending_ack_semantics": "write-one-to-clear",
            "time_tick_status_bank": status,
            "time_tick_clear_bank": status,
            "time_tick_mask": 0x0200,
        })
        self.assertEqual(
            MODULE.c80_rex_irq_profile(config, False),
            MODULE.c80_rex_irq_profile(config, True),
        )
        candidate["group_row_size"] = 12
        self.assertEqual(
            MODULE.c80_rex_irq_profile(config, False),
            MODULE.c80_rex_irq_profile(config, True),
        )
        candidate["group_row_size"] = 11
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, False))
        candidate["group_row_size"] = 10
        candidate["time_tick_mask"] = 0x0100
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, False))
        candidate["time_tick_mask"] = 0x0200
        candidate["wrapper_validation_size"] = config.flash_size
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, True))
        candidate["wrapper_validation_size"] = 0x284
        candidate["callback_slot"] += 2
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, True))
        candidate["callback_slot"] = 0x01802000
        candidate["handler_slot"] = 0x01801000
        candidate["vector_target"] = 0x01800000
        config.ram_base = 0x01000000
        config.ram_size = 0x01000000
        self.assertEqual(
            MODULE.c80_rex_irq_profile(config, True),
            "3000c80:3000c94:200:4c4b40:1800000:1000:1801000:"
            "2000:100:1802000:3000",
        )
        candidate["vector_target"] = 0x02000000
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, True))

    def test_c80_overlay_route_emits_runtime_addresses(self) -> None:
        status = 0x03000C80
        candidate = {
            "signature": "static-c80-overlay-controller-callback-v1",
            "controller_class": "legacy-c80-three-bank-group14-v1",
            "accepted": True, "active": False,
            "promotion": "temporary-evidence-gated",
            "vector": 0x18, "vector_target": 0x01200000,
            "status": status,
            "status_banks": (status, status + 4, status + 0x30),
            "enable": status + 0x14, "mask": 0x0200,
            "clear_banks": (status, status + 4, status + 0x4C),
            "controller_write_banks": (
                status + 0x14, status + 0x18, status + 0x44,
            ),
            "controller_aperture": (status, status + 0x4E),
            "status_bank_count": 3, "group_row_size": 14,
            "pending_read_semantics": "latched-read",
            "time_tick_status_bank": status,
            "time_tick_clear_bank": status,
            "time_tick_mask": 0x0200,
            "wrapper_file_offset": 0x4FC0,
            "wrapper_runtime_address": 0x4FC0,
            "wrapper_validation_size": 0x2F8,
            "handler_slot": 0x013466A8,
            "handler_file_offset": 0x7B48E8,
            "handler_runtime_address": 0x03800068,
            "handler_validation_size": 0x1EE,
            "callback_slot": 0x01206B80,
            "callback_file_offset": 0x23440,
            "callback_runtime_address": 0x23440,
            "callback_delta": 5,
            "callback_validation_size": 68,
        }
        config = SimpleNamespace(
            rex_static_controller_candidate=candidate,
            load_address=0, flash_size=0x800000,
            ram_base=0x01000000, ram_size=0x800000,
            linker=SimpleNamespace(
                data_source=0x78F51C, data_target=0x01200000,
                data_size=0x25364,
            ),
            overlays=[SimpleNamespace(
                source=0x7B4880, target=0x03800000, size=0x15A74,
            )],
            rex_tick_address=0xA7E04, rex_irq_wrapper_address=None,
            rex_irq_handler_address=None, rex_irq_handler_slot=None,
            rex_irq_callback_slot=None, rex_irq_status_address=None,
            rex_irq_enable_address=None, rex_irq_arm_address=None,
            rex_irq_mask=0,
        )

        self.assertIsNone(MODULE.c80_rex_irq_profile(config, False))
        self.assertEqual(
            MODULE.c80_rex_irq_profile(config, True),
            "3000c80:3000c94:200:4c4b40:1200000:4fc0:13466a8:"
            "3800068:1ee:1206b80:23440:3",
        )
        config.overlays[0].target += 0x1000
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, True))

    def test_c80_machine_parser_consumes_optional_bank_count(self) -> None:
        source = (EXPERIMENT / "msm5xxx-poc.c").read_text()
        start = source.index("static void msm5xxx_poc_set_rex_static_c80")
        end = source.index("\nstatic ", start + 1)
        setter = source[start:end]

        self.assertIn("%x:%x%n", setter)
        self.assertIn("consumed >= 0 && !value[consumed]", setter)
        self.assertNotIn("%x%c", setter)

    def test_read_consume_route_requires_copied_vector_relation(self) -> None:
        status = 0x03000620
        candidate = {
            "signature": "static-msm5000-620-controller-callback-v1",
            "controller_class":
                "legacy-msm5000-620-two-bank-read-consume-group10-v1",
            "accepted": True,
            "active": False,
            "promotion": "temporary-evidence-gated",
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

        self.assertEqual(
            MODULE.read_consume_rex_irq_profile(config, False),
            "3000620:3000628:30006e0:200:4c4b40:1100000:24be14:"
            "118867c:98e04:178:110363c:16b64",
        )
        candidate["promotion"] = "experimental-only"
        self.assertIsNone(MODULE.read_consume_rex_irq_profile(config, False))
        self.assertEqual(
            MODULE.read_consume_rex_irq_profile(config, True),
            "3000620:3000628:30006e0:200:4c4b40:1100000:24be14:"
            "118867c:98e04:178:110363c:16b64",
        )
        candidate["promotion"] = "temporary-evidence-gated"
        candidate.update({
            "controller_class":
                "legacy-msm5000-620-two-bank-read-consume-v1",
            "group_row_size": 12,
        })
        self.assertEqual(
            MODULE.read_consume_rex_irq_profile(config, False),
            "3000620:3000628:30006e0:200:4c4b40:1100000:24be14:"
            "118867c:98e04:178:110363c:16b64",
        )
        candidate.update({
            "controller_class":
                "legacy-msm5000-620-two-bank-read-consume-group10-v1",
            "group_row_size": 10,
            "promotion": "experimental-only",
        })
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
        candidate.update({
            "controller_class":
                "legacy-msm5000-620-two-bank-w1c-8call-v1",
            "promotion": "temporary-evidence-gated",
            "group_row_size": 12,
            "pending_read_semantics": "latched-read",
            "pending_ack_semantics": "write-one-to-clear",
            "clear_banks": (status, status + 4),
        })
        self.assertEqual(
            MODULE.w1c_rex_irq_profile(config),
            "3000620:3000628:30006e0:200:4c4b40",
        )
        del candidate["pending_ack_semantics"]
        self.assertIsNone(MODULE.w1c_rex_irq_profile(config))


if __name__ == "__main__":
    unittest.main()
