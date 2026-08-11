#!/usr/bin/env python3
"""Run the QEMU PoC while the unchanged emulator GUI decodes LCD writes."""
from __future__ import annotations

import argparse
from pathlib import Path
import queue
import sys
import threading
import tkinter as tk
from tkinter import messagebox


ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(ROOT / "src"))

from qemu_transport import *  # noqa: E402,F403
from msm5xxx_emulator.gui.app import Window, choose_firmware  # noqa: E402
from msm5xxx_emulator.gui.controls import detect_profile  # noqa: E402
from msm5xxx_emulator.gui.locale import display_model_name  # noqa: E402
from msm5xxx_emulator.gui.worker import _prepared_profile_matches  # noqa: E402


class LiveWindow(Window):
    def __init__(self, root: tk.Tk, firmware: Path,
                 qemu: Path, state_dir: Path | None = None,
                 experimental_c80: bool = False) -> None:
        self.qemu = qemu
        self.state_dir = state_dir
        self.experimental_c80 = experimental_c80
        self.transport: Transport | None = None
        self._active_firmware: Path | None = None
        self._active_overrides: dict[str, object] = {}
        super().__init__(
            root, firmware,
            experimental_c80_controller=experimental_c80,
        )
        self.root.after(100, self._refresh_qemu_metrics)
        self.root.after(5, self._forward_qemu_keys)

    def _restart(self) -> None:
        requested_firmware = self.firmware
        requested_overrides = dict(self.overrides)
        prepared = self._prepared_profile
        self._prepared_profile = None
        try:
            if _prepared_profile_matches(
                    prepared, requested_firmware, requested_overrides):
                assert prepared is not None
                config = prepared[0]
                requested_overrides = dict(prepared[1])
            else:
                config, requested_overrides = detect_profile(
                    requested_firmware, requested_overrides
                )
        except Exception as error:
            if self._active_firmware is None:
                raise
            self.firmware = self._active_firmware
            self.overrides = dict(self._active_overrides)
            self.status.set(str(error))
            messagebox.showerror(
                self._text("settings_error"), str(error), parent=self.root
            )
            return

        self.generation += 1
        self.stop.set()
        for callback in self.pending_key_releases.values():
            self.root.after_cancel(callback)
        self.pending_key_releases.clear()
        self.keyboard_bits.clear()
        self.keyboard_sources.clear()
        self.held.clear()
        self.commands = queue.SimpleQueue()
        self._stop_transport()
        self.stop = threading.Event()
        self._render_cache = None
        try:
            transport = Transport(
                self.qemu, requested_firmware, self.state_dir,
                self.experimental_c80, config=config,
            )
        except Exception as error:
            if self._active_firmware is None:
                raise
            self.firmware = self._active_firmware
            self.overrides = dict(self._active_overrides)
            save_error = None
            try:
                self._save_config()
            except (OSError, TimeoutError) as restore_error:
                save_error = restore_error
            try:
                rollback, _cleaned = detect_profile(
                    self.firmware, self.overrides
                )
                transport = Transport(
                    self.qemu, self.firmware, self.state_dir,
                    self.experimental_c80, config=rollback,
                )
            except Exception as rollback_error:
                detail = f"{error}; restore failed: {rollback_error}"
                if save_error is not None:
                    detail += f"; settings restore not saved: {save_error}"
                self.status.set(detail)
                messagebox.showerror(
                    self._text("settings_error"), detail, parent=self.root
                )
                return
            self._activate_transport(
                transport, self.firmware, self.overrides
            )
            detail = f"Settings failed; previous firmware restored: {error}"
            if save_error is not None:
                detail += f"; settings restore not saved: {save_error}"
            self.status.set(detail)
            messagebox.showerror(
                self._text("settings_error"), detail, parent=self.root
            )
            return
        self._activate_transport(
            transport, requested_firmware, requested_overrides
        )

    def _activate_transport(
            self, transport: Transport, firmware: Path,
            overrides: dict[str, object]) -> None:
        self.transport = transport
        self.emulator = transport.decoder
        self.firmware = firmware
        self.overrides = dict(overrides)
        self._active_firmware = firmware
        self._active_overrides = dict(overrides)
        config = transport.config
        self.model.set(display_model_name(
            config.model, config.verified_model, self.ui_language
        ))
        self.device_details.set(
            f"QEMU TCG · {config.chipset} · {config.width}×{config.height}"
        )
        self.status.set("QEMU TCG real-time LCD transport")
        self.worker = threading.Thread(
            target=transport.replay, args=(self.stop,), daemon=False
        )
        self.worker.start()

    def _stop_transport(self) -> None:
        transport = self.transport
        worker = self.worker
        self.transport = None
        self.worker = None
        self.emulator = None
        if transport is None:
            return
        self.stop.set()
        transport.interrupt()
        if worker is not None and worker.is_alive():
            worker.join()
        transport.close()

    def _key_supported(self, bit: int,
                       event_code: int | None = None) -> bool:
        return (self.transport is not None
                and self.transport.can_set_key(bit, event_code))

    def _forward_qemu_keys(self) -> None:
        if self.closing:
            return
        transport = self.transport
        if transport is None:
            self.root.after(5, self._forward_qemu_keys)
            return
        delay = 5
        while True:
            try:
                command = self.commands.get_nowait()
            except queue.Empty:
                break
            if len(command) in (2, 3) and isinstance(command[0], int):
                event_code = int(command[2]) if len(command) == 3 else None
                transport.set_key(
                    int(command[0]), bool(command[1]), event_code
                )
                # Keep a fast click observable across the guest's debounce scan.
                delay = 20
                break
            elif command[0] == "framebuffer-format" and len(command) == 2:
                transport.decoder.set_framebuffer_format(str(command[1]))
                self._active_overrides = dict(self.overrides)
        self.root.after(delay, self._forward_qemu_keys)

    def _refresh_qemu_metrics(self) -> None:
        if self.closing:
            return
        transport = self.transport
        if transport is None:
            self.root.after(100, self._refresh_qemu_metrics)
            return
        emulator = transport.decoder
        width, height, _frame = emulator.display_snapshot()
        self.device_details.set(
            f"QEMU TCG · {emulator.config.chipset} · {width}×{height}"
        )
        self.metric_values["run"].set(f"{transport.instructions:,}")
        self.metric_values["pc"].set(f"0x{transport.pc:08X}")
        self.metric_values["lcd"].set(f"{emulator.lcd_writes:,}")
        self.metric_values["frame"].set(str(emulator.frame_sequence))
        self.root.after(100, self._refresh_qemu_metrics)

    def _close(self) -> None:
        if not self.closing:
            self._stop_transport()
        super()._close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware", nargs="?", type=Path)
    parser.add_argument("--qemu", required=True, type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument(
        "--experimental-static-rex-controller",
        "--experimental-c80-controller",
        dest="experimental_c80_controller", action="store_true",
    )
    args = parser.parse_args()
    firmware = args.firmware
    if firmware is None:
        firmware = choose_firmware()
        if firmware is None:
            return 0
    root = tk.Tk()
    window = LiveWindow(
        root, firmware.resolve(), args.qemu.resolve(),
        args.state_dir.resolve() if args.state_dir is not None else None,
        args.experimental_c80_controller,
    )
    try:
        root.mainloop()
    finally:
        window._close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
