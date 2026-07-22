"""Pure GUI diagnostic telemetry regressions; no Tk or firmware required."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import queue
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from PIL import Image

from gui import (TELEMETRY_INSTRUCTION_CADENCE, TELEMETRY_POLL_ESCAPE_CAP,
                 TELEMETRY_SCREENSHOT_CADENCE, _compact_telemetry,
                 _frame_metrics,
                 create_repro_bundle, finish_repro_bundle,
                 frame_repaint_needed, hydrate_host_checkpoint, runtime_telemetry,
                 save_telemetry_frame,
                 system_ui_language, telemetry_artifact_due, telemetry_transition)
from msm5xxx_emulator.gui.display_view import (
    DISPLAY_REFRESH_MS, STATE_REFRESH_MS, DisplayViewMixin,
)


class GuiTelemetryTests(unittest.TestCase):
    def test_windows_without_lc_messages_uses_lc_ctype(self) -> None:
        windows_locale = SimpleNamespace(
            LC_CTYPE=0,
            getlocale=lambda category=0: ("Korean_Korea", "949"),
        )
        with mock.patch.dict("os.environ", {}, clear=True), \
             mock.patch("msm5xxx_emulator.gui.locale.locale", windows_locale):
            self.assertEqual(system_ui_language(), "ko")

    def test_frame_repaint_cache_requires_frame_emulator_or_geometry_change(self) -> None:
        emulator = object()
        frame = b"rgb"
        cache = (emulator, frame, 1, 1, 100, 100)
        self.assertFalse(frame_repaint_needed(cache, emulator, frame, 1, 1, 100, 100))
        self.assertTrue(frame_repaint_needed(cache, object(), frame, 1, 1, 100, 100))
        self.assertFalse(frame_repaint_needed(cache, emulator, bytes(bytearray(frame)),
                                              1, 1, 100, 100))
        self.assertTrue(frame_repaint_needed(cache, emulator, frame, 1, 1, 101, 100))

    def _state(self, **changes: object) -> dict[str, object]:
        state: dict[str, object] = {
            "fault": None,
            "instructions": 0,
            "pc": "0x00000000",
            "lr": "0x00000000",
            "registers": {"cpsr": "0x00000013"},
            "frame_sequence": 0,
            "firmware_frame_sequence": 0,
            "rex_ticks": 0,
            "rex_idle_entries": 0,
            "rex_elapsed_ms": 0,
            "rex_irq_deliveries": 0,
            "secondary_flash_reads": 0,
            "secondary_flash_writes": 0,
            "secondary_flash_changed_pages": 0,
            "secondary_flash_telemetry": {},
            "primary_flash_telemetry": {},
            "lcd_writes": 0,
            "lcd_protocol": "none",
            "lcd_frame_protocol": "none",
            "control_sink": None,
            "last_unmapped": None,
            "dynamic_page_first_accesses": [],
            "eeprom_capacity": 0,
            "eeprom_reads": 0,
            "eeprom_read_bytes": 0,
            "eeprom_writes": 0,
            "eeprom_write_bytes": 0,
            "eeprom_changed_bytes": 0,
            "eeprom_loaded_from_state": False,
            "eeprom_error": None,
            "nand_reads": 0,
            "nand_writes": 0,
            "nand_bad_block_probes": 0,
            "fault_context": {},
        }
        state.update(changes)
        return state

    def test_frame_metrics_reuses_identical_immutable_frame(self) -> None:
        frame = b"\0\0\0\xff\0\0"
        self.assertEqual(_frame_metrics(frame, frame, "cached", 4), ("cached", 4))

        equal_copy = bytes(bytearray(frame))
        self.assertEqual(_frame_metrics(equal_copy, frame, "cached", 4),
                         ("cached", 4))

        changed = b"\0\0\0\0\xff\0"
        frame_hash, nonblack = _frame_metrics(changed, frame, "cached", 4)
        self.assertEqual(frame_hash, hashlib.sha256(changed).hexdigest())
        self.assertEqual(nonblack, 1)

    def test_visible_pixels_preserves_partial_rgb_chunk_semantics(self) -> None:
        from boot_probe import visible_pixels

        self.assertEqual(visible_pixels(b""), 0)
        self.assertEqual(visible_pixels(b"\0\0\0\xff\0\0\0\xff\0\0\0\xff"), 3)
        self.assertEqual(visible_pixels(b"\0\0\0\0"), 0)
        self.assertEqual(visible_pixels(b"\0\0\0\1"), 1)

    def test_display_refresh_reuses_one_canvas_item(self) -> None:
        class Harness(DisplayViewMixin):
            pass

        class Emulator:
            frame = b"\xff\0\0"

            def display_snapshot(self) -> tuple[int, int, bytes]:
                return 1, 1, self.frame

        harness = Harness()
        harness.root = SimpleNamespace(after=mock.Mock())
        harness.screen = SimpleNamespace(
            winfo_width=mock.Mock(return_value=100),
            winfo_height=mock.Mock(return_value=80),
            create_image=mock.Mock(return_value=7),
            coords=mock.Mock(), itemconfigure=mock.Mock(),
        )
        harness.emulator = Emulator()
        harness.photo = None
        harness._screen_item = None
        harness._render_cache = None
        with mock.patch("msm5xxx_emulator.gui.display_view.ImageTk.PhotoImage",
                        return_value=object()) as photo:
            harness._refresh_display()
            harness.emulator.frame = b"\0\xff\0"
            harness._refresh_display()
            harness.emulator.frame = bytes(bytearray(harness.emulator.frame))
            harness._refresh_display()

        self.assertEqual(photo.call_count, 2)
        harness.screen.create_image.assert_called_once()
        harness.screen.coords.assert_called_once_with(7, 50, 40)
        harness.screen.itemconfigure.assert_called_once()
        self.assertEqual((DISPLAY_REFRESH_MS, STATE_REFRESH_MS), (33, 100))
        self.assertEqual(harness.root.after.call_args_list[-1].args,
                         (DISPLAY_REFRESH_MS, harness._refresh_display))

    def test_state_refresh_remains_ten_hertz(self) -> None:
        class Harness(DisplayViewMixin):
            pass

        harness = Harness()
        harness.root = SimpleNamespace(after=mock.Mock())
        harness._show_save_errors = mock.Mock()
        harness.update_results = queue.SimpleQueue()
        harness.states = queue.SimpleQueue()
        harness.generation = 1
        harness._refresh()

        harness.root.after.assert_called_once_with(STATE_REFRESH_MS, harness._refresh)

    def test_cadence_waits_for_one_million_instructions_and_phase_change_emits(self) -> None:
        before = self._state(instructions=TELEMETRY_INSTRUCTION_CADENCE - 1)
        phase, event, saw_splash, emit = telemetry_transition(
            before, 0, "seed", "seed", "seed", False,
            "early-boot", "early-boot", 0,
        )
        self.assertEqual((phase, event, saw_splash, emit),
                         ("early-boot", "early-boot", False, False))

        at_cadence = self._state(instructions=TELEMETRY_INSTRUCTION_CADENCE)
        _phase, _event, _saw_splash, emit = telemetry_transition(
            at_cadence, 0, "seed", "seed", "seed", False,
            "early-boot", "early-boot", 0,
        )
        self.assertTrue(emit)

        display = self._state(lcd_writes=1)
        phase, event, _saw_splash, emit = telemetry_transition(
            display, 0, "seed", "seed", "seed", False,
            "early-boot", "early-boot", 0,
        )
        self.assertEqual((phase, event), ("display-traffic", "display-traffic"))
        self.assertTrue(emit)

    def test_only_transitions_terminals_and_five_million_cadence_persist_artifacts(self) -> None:
        self.assertFalse(telemetry_artifact_due(
            transitioned=False, terminal=False,
            instructions=TELEMETRY_INSTRUCTION_CADENCE,
            last_screenshot_instructions=0,
        ))
        self.assertTrue(telemetry_artifact_due(
            transitioned=False, terminal=False,
            instructions=TELEMETRY_SCREENSHOT_CADENCE,
            last_screenshot_instructions=0,
        ))
        self.assertTrue(telemetry_artifact_due(
            transitioned=True, terminal=False, instructions=1,
            last_screenshot_instructions=1,
        ))
        self.assertTrue(telemetry_artifact_due(
            transitioned=False, terminal=True, instructions=1,
            last_screenshot_instructions=1,
        ))

    def test_payload_keeps_firmware_basename_not_local_path(self) -> None:
        config = SimpleNamespace(
            path="/private/dumps/SCH-X350.bin",
            file_size=128,
            model="SCH-X350",
            chipset="MSM5000",
            dump_status="complete",
            firmware_identity=lambda: {"sha256": "a" * 64},
        )
        payload = runtime_telemetry(
            config, self._state(instructions=123, eeprom_writes=2),
            generation=4, phase="early-boot", event="early-boot",
            width=1, height=1, frame=b"\x00\x00\x00", nonblack=0,
            frame_hash="precomputed",
        )

        encoded = json.dumps(payload, sort_keys=True)
        self.assertNotIn("/private/dumps", encoded)
        self.assertEqual(payload["firmware"], {
            "basename": "SCH-X350.bin", "bytes": 128, "sha256": "a" * 64,
        })
        self.assertEqual(payload["eeprom"]["writes"], 2)
        self.assertEqual(payload["frame"]["sha256"], "precomputed")
        self.assertEqual(payload["nor"]["primary_parallel_nor_direct_id_probes"], [])

        host_state = self._state(registers={
            "pc": "0x11111111", "lr": "0x22222222", "cpsr": "0x00000013",
        })
        host_state.pop("pc")
        host_state.pop("lr")
        host_payload = runtime_telemetry(
            config, host_state, generation=4,
            phase="host-backend-fault", event="host-backend-fault",
            width=1, height=1, frame=b"\x00\x00\x00", nonblack=0,
        )
        self.assertEqual((host_payload["pc"], host_payload["lr"]),
                         ("0x11111111", "0x22222222"))

    def test_session_frame_names_do_not_overwrite_same_checkpoint(self) -> None:
        config = SimpleNamespace(path=Path("/private/dumps/SCH-X350.bin"))
        first_frame = b"\x00\x00\x00"
        second_frame = b"\xff\xff\xff"
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory) / "gui-20260717-unique.log"
            with mock.patch("msm5xxx_emulator.gui.repro.current_session_log",
                            return_value=session):
                first = save_telemetry_frame(
                    config, generation=1, instructions=1_000_000,
                    phase="early-boot", capture=1, width=1, height=1,
                    frame=first_frame,
                )
                second = save_telemetry_frame(
                    config, generation=1, instructions=1_000_000,
                    phase="early-boot", capture=1, width=1, height=1,
                    frame=second_frame,
                )

            self.assertIsNotNone(first)
            self.assertIsNotNone(second)
            assert first is not None and second is not None
            self.assertNotEqual(first, second)
            self.assertIn(session.stem, first)
            first_path = Path(directory) / first
            second_path = Path(directory) / second
            self.assertTrue(first_path.is_file())
            self.assertTrue(second_path.is_file())
            with Image.open(first_path) as image:
                self.assertEqual(image.tobytes(), first_frame)
            with Image.open(second_path) as image:
                self.assertEqual(image.tobytes(), second_frame)

    def test_host_hle_provenance_is_bounded_and_kept_in_compact_log(self) -> None:
        config = SimpleNamespace(
            path="/private/dumps/SCH-X350.bin", file_size=128,
            model="SCH-X350", chipset="MSM5000", dump_status="complete",
            firmware_identity=lambda: {"sha256": "a" * 64},
        )
        events = [{
            "pc": 0x1000 + index, "address": 0x03000780,
            "value": 0xC4 + index, "bit": index % 4, "state": index % 2,
        } for index in range(TELEMETRY_POLL_ESCAPE_CAP + 1)]
        payload = runtime_telemetry(
            config, self._state(
                fast_boot_used=True, fast_memory_clears=1,
                fast_memory_copies=2, fast_register_ramps=3,
                fast_arm_memory_copies=4, hot_loop_hle_used=True,
                fast_crc16_calls=5, fast_dmd_downloads=6,
                ma2_silent_boot_calls=7, poll_escapes=events,
            ), generation=1, phase="early-boot", event="early-boot",
            width=1, height=1, frame=b"\x00\x00\x00", nonblack=0,
        )
        provenance = payload["host_hle"]
        self.assertEqual(provenance["fast_arm_memory_copies"], 4)
        self.assertTrue(provenance["fast_boot_used"])
        self.assertTrue(provenance["hot_loop_hle_used"])
        self.assertEqual(provenance["poll_escape_count"],
                         TELEMETRY_POLL_ESCAPE_CAP + 1)
        self.assertEqual(len(provenance["poll_escapes"]),
                         TELEMETRY_POLL_ESCAPE_CAP)
        self.assertEqual(provenance["poll_escapes"][0], {
            "pc": "0x00001000", "address": "0x03000780",
            "value": "0x000000C4", "bit": 0, "state": 0,
        })
        self.assertEqual(_compact_telemetry(payload)["host_hle"], provenance)

    def test_host_hle_provenance_rejects_malformed_state(self) -> None:
        config = SimpleNamespace(
            path="/private/dumps/SCH-X350.bin", file_size=128,
            model="SCH-X350", chipset="MSM5000", dump_status="complete",
            firmware_identity=lambda: {"sha256": "a" * 64},
        )
        payload = runtime_telemetry(
            config, self._state(
                fast_boot_used="yes", fast_memory_copies="2",
                hot_loop_hle_used=1, fast_dmd_downloads=-1,
                poll_escapes=[
                    {"pc": "bad", "address": 0, "value": 0,
                     "bit": 0, "state": 0},
                    {"pc": 0, "address": -1, "value": 0,
                     "bit": 0, "state": 0},
                    {"pc": 0, "address": 0, "value": 0,
                     "bit": 32, "state": 0},
                    {"pc": 0, "address": 0, "value": 0,
                     "bit": 0, "state": 2},
                    "not-an-event",
                ],
            ), generation=1, phase="early-boot", event="early-boot",
            width=1, height=1, frame=b"\x00\x00\x00", nonblack=0,
        )
        self.assertEqual(payload["host_hle"], {
            "fast_boot_used": False,
            "fast_memory_clears": 0,
            "fast_memory_copies": 0,
            "fast_register_ramps": 0,
            "fast_arm_memory_copies": 0,
            "hot_loop_hle_used": False,
            "fast_crc16_calls": 0,
            "fast_dmd_downloads": 0,
            "ma2_silent_boot_calls": 0,
            "poll_escape_count": 0,
            "poll_escapes": [],
        })

    def test_terminal_repro_copies_actual_nor_eeprom_not_nand_or_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory) / "private"
            private.mkdir()
            primary = private / "flash.json"
            secondary = private / "lazy-efs.json"
            eeprom = private / "eeprom.bin"
            nand = private / "nand.bin"
            nand_meta = private / "nand.json"
            for path, data in ((primary, b"primary"), (secondary, b"secondary"),
                               (eeprom, b"eeprom"), (nand, b"nand"),
                               (nand_meta, b"metadata")):
                path.write_bytes(data)
            config = SimpleNamespace(
                path=private / "firmware.bin", file_size=1, model="X250",
                chipset="MSM5000", dump_status="complete",
                firmware_identity=lambda: {"sha256": "a" * 64},
                diagnostic_config=lambda: {"model": "X250", "firmware": {
                    "basename": "firmware.bin", "bytes": 1, "sha256": "a" * 64,
                }},
            )
            emulator = SimpleNamespace(
                config=SimpleNamespace(nand_enabled=True),
                flash=SimpleNamespace(state_path=primary),
                secondary_flash=SimpleNamespace(state_path=secondary),
                eeprom_enabled=True, eeprom_state_path=eeprom,
                nand_image=b"seed", nand_state_path=nand,
            )
            session = Path(directory) / "logs" / "gui-session.log"
            with mock.patch("msm5xxx_emulator.gui.repro.current_session_log",
                            return_value=session):
                bundle = create_repro_bundle(config, emulator, {"width": 128}, 1)
                self.assertIsNotNone(bundle)
                assert bundle is not None
                eeprom.write_bytes(b"changed")
                finish_repro_bundle(bundle, config, emulator, {"width": 128}, 1)

            repro, _pre = bundle
            document = json.loads((repro / "metadata.json").read_text(encoding="utf-8"))
            encoded = json.dumps(document, sort_keys=True)
            self.assertNotIn(str(private), encoded)
            self.assertEqual(document["override_keys"], ["width"])
            pre = {item["role"]: item for item in document["state_files"]["pre"]}
            post = {item["role"]: item for item in document["state_files"]["post"]}
            self.assertIn("snapshot", pre["primary-flash-state"])
            self.assertIn("snapshot", pre["secondary-flash-state"])
            self.assertIn("snapshot", pre["eeprom-state"])
            self.assertNotIn("snapshot", pre["nand-state"])
            self.assertNotIn("snapshot", pre["nand-metadata"])
            self.assertNotEqual(pre["eeprom-state"]["sha256"],
                                post["eeprom-state"]["sha256"])
            self.assertFalse(any("nand" in path.name for path in (repro / "pre").iterdir()))

    def test_host_checkpoint_promotes_nested_counters_and_frame(self) -> None:
        state = hydrate_host_checkpoint({
            "instructions": 10,
            "registers": {"pc": "0x00000001", "lr": "0x00000002"},
            "display": {"frame_sequence": 8, "firmware_frame_sequence": 7},
            "counters": {
                "lcd_writes": 6, "rex_idle_entries": 5, "rex_ticks": 4,
                "rex_elapsed_ms": 3,
                "storage": {
                    "eeprom_reads": 2, "eeprom_writes": 1,
                    "eeprom_changed_bytes": 9, "secondary_nor_reads": 8,
                    "secondary_nor_writes": 7, "secondary_nor_changed_pages": 6,
                    "nand_reads": 5, "nand_writes": 4,
                },
            },
        })
        self.assertEqual((state["lcd_writes"], state["frame_sequence"],
                          state["eeprom_reads"], state["nand_writes"]),
                         (6, 8, 2, 4))


if __name__ == "__main__":
    unittest.main()
