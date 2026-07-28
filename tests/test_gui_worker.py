from __future__ import annotations

import hashlib
from pathlib import Path
import queue
from tempfile import TemporaryDirectory
import threading
import unittest
from unittest.mock import patch

from msm5xxx_emulator.gui.worker import (
    WorkerMixin, _prepared_profile_matches,
)


class _Config:
    model = "test"
    verified_model = None
    chipset = "test-chip"
    chipset_confidence = "high"
    width = 1
    height = 1
    dump_status = "test"


class _Emulator:
    def __init__(self, _config: _Config) -> None:
        self.calls: list[tuple[object, ...]] = []
        self.instructions = 0

    def set_key(self, bit: int, pressed: bool,
                event_code: int | None = None) -> None:
        self.calls.append(("key", bit, pressed, event_code))

    def set_framebuffer_format(self, value: str) -> None:
        self.calls.append(("format", value))

    def run(self, steps: int, *, light_state: bool = False) -> dict[str, object]:
        self.instructions += steps
        self.calls.append(("run", steps, light_state))
        return {"fault": None, "instructions": self.instructions}

    def display_snapshot(self) -> tuple[int, int, bytes]:
        return 1, 1, b"\0\0\0"

    def close(self) -> None:
        self.calls.append(("close",))


class _Worker(WorkerMixin):
    def __init__(self) -> None:
        self.generation = 1
        self.emulator = None
        self.states: queue.SimpleQueue[tuple[int, dict[str, object]]] = queue.SimpleQueue()
        self.save_errors: queue.SimpleQueue[str] = queue.SimpleQueue()
        self.ui_language = "en"

    def _text(self, key: str) -> str:
        return key


class GuiWorkerCommandDrainTests(unittest.TestCase):
    def _run(self, commands: list[tuple[object, ...]],
             stop_after: int | None = None) -> tuple[list[tuple[object, ...]], list[int]]:
        worker = _Worker()
        stop = threading.Event()
        command_queue: queue.SimpleQueue[tuple[object, ...]] = queue.SimpleQueue()
        for command in commands:
            command_queue.put(command)
        created: list[_Emulator] = []
        stop_after_runs = stop_after or sum(isinstance(command[0], int) for command in commands) or 1
        transition_instructions: list[int] = []

        def make_emulator(config: _Config) -> _Emulator:
            emulator = _Emulator(config)
            created.append(emulator)
            return emulator

        def transition(state: dict[str, object], *_args: object) -> tuple[str, None, bool, bool]:
            transition_instructions.append(int(state["instructions"]))
            return "boot", None, False, False

        with (patch("msm5xxx_emulator.gui.worker.detect_profile",
                    return_value=(_Config(), {})),
              patch("msm5xxx_emulator.gui.worker.GenericMSMEmulator",
                    side_effect=make_emulator),
              patch("msm5xxx_emulator.gui.worker.display_model_name",
                    return_value="test"),
              patch("msm5xxx_emulator.gui.worker.firmware_telemetry",
                    return_value={}),
              patch("msm5xxx_emulator.gui.worker.visible_pixels",
                    return_value=0),
              patch("msm5xxx_emulator.gui.worker._frame_metrics",
                    return_value=("frame", 0)),
              patch("msm5xxx_emulator.gui.worker.telemetry_transition",
                    side_effect=transition),
              patch("msm5xxx_emulator.gui.worker.emit_telemetry")):
            original_run = _Emulator.run

            def stopping_run(emulator: _Emulator, steps: int, *,
                             light_state: bool = False):
                result = original_run(emulator, steps, light_state=light_state)
                if len([call for call in emulator.calls if call[0] == "run"]) >= stop_after_runs:
                    stop.set()
                return result

            with patch.object(_Emulator, "run", stopping_run):
                worker._run(1, stop, command_queue, Path("test.bin"), {})
        return created[0].calls, transition_instructions

    def test_press_release_get_guest_run_between_edges(self) -> None:
        calls, transitions = self._run([(11, True), (11, False)])
        self.assertEqual(calls[:3], [("key", 11, True, None), ("run", 25_000, True),
                                     ("key", 11, False, None)])
        self.assertEqual(transitions, [25_000, 50_000])

    def test_three_key_edges_each_get_an_outer_run(self) -> None:
        calls, transitions = self._run([(11, True), (11, False), (11, True)])
        self.assertEqual(calls[:5], [("key", 11, True, None), ("run", 25_000, True),
                                     ("key", 11, False, None), ("run", 25_000, True),
                                     ("key", 11, True, None)])
        self.assertEqual(transitions, [25_000, 50_000, 75_000])

    def test_stop_does_not_apply_pending_key_edge(self) -> None:
        calls, transitions = self._run([(11, True), (11, False)], stop_after=1)
        self.assertEqual(calls[:2], [("key", 11, True, None), ("run", 25_000, True)])
        self.assertNotIn(("key", 11, False, None), calls)
        self.assertEqual(transitions, [25_000])

    def test_manual_event_preserves_guest_run_between_edges(self) -> None:
        calls, transitions = self._run([(5, True, 0x53), (5, False)])
        self.assertEqual(
            calls[:3],
            [("key", 5, True, 0x53), ("run", 25_000, True),
             ("key", 5, False, None)],
        )
        self.assertEqual(transitions, [25_000, 50_000])

    def test_framebuffer_command_does_not_add_key_edge_run(self) -> None:
        calls, transitions = self._run([("framebuffer-format", "rgb565le")])
        self.assertEqual(calls[:2], [("format", "rgb565le"), ("run", 25_000, True)])
        self.assertEqual(sum(call[0] == "run" for call in calls), 1)
        self.assertEqual(transitions, [25_000])

    def test_prepared_profile_skips_repeated_detection(self) -> None:
        worker = _Worker()
        stop = threading.Event()
        commands: queue.SimpleQueue[tuple[object, ...]] = queue.SimpleQueue()
        config = _Config()
        firmware_data = b"firmware"

        def stop_after_first_run(emulator: _Emulator, steps: int, *,
                                 light_state: bool = False):
            stop.set()
            return {"fault": None, "instructions": steps}

        with TemporaryDirectory() as directory:
            firmware = Path(directory) / "test.bin"
            firmware.write_bytes(firmware_data)
            config.path = str(firmware.resolve())
            config.file_size = len(firmware_data)
            config.firmware_sha256 = hashlib.sha256(firmware_data).hexdigest()
            with (patch("msm5xxx_emulator.gui.worker.detect_profile",
                        side_effect=AssertionError("redetect")),
                  patch("msm5xxx_emulator.gui.worker.GenericMSMEmulator",
                        side_effect=_Emulator),
                  patch("msm5xxx_emulator.gui.worker.display_model_name",
                        return_value="test"),
                  patch("msm5xxx_emulator.gui.worker.firmware_telemetry",
                        return_value={}),
                  patch("msm5xxx_emulator.gui.worker.visible_pixels",
                        return_value=0),
                  patch("msm5xxx_emulator.gui.worker._frame_metrics",
                        return_value=("frame", 0)),
                  patch("msm5xxx_emulator.gui.worker.telemetry_transition",
                        return_value=("boot", None, False, False)),
                  patch("msm5xxx_emulator.gui.worker.emit_telemetry"),
                  patch.object(_Emulator, "run", stop_after_first_run)):
                worker._run(
                    1, stop, commands, firmware, {}, (config, {})
                )

    def test_prepared_profile_requires_current_identity(self) -> None:
        config = _Config()
        with TemporaryDirectory() as directory:
            firmware = Path(directory) / "test.bin"
            firmware.write_bytes(b"firmware")
            config.path = str(firmware)
            config.file_size = 8
            config.firmware_sha256 = hashlib.sha256(b"firmware").hexdigest()
            prepared = (config, {})

            self.assertTrue(_prepared_profile_matches(
                prepared, firmware, {}
            ))
            self.assertFalse(_prepared_profile_matches(
                prepared, firmware, {"width": 128}
            ))
            self.assertFalse(_prepared_profile_matches(
                prepared, firmware.with_name("other.bin"), {}
            ))
            firmware.write_bytes(b"changed!")
            self.assertFalse(_prepared_profile_matches(
                prepared, firmware, {}
            ))


if __name__ == "__main__":
    unittest.main()
