"""Run QEMU with the desktop LCD, input, and settings interface."""
from __future__ import annotations

import argparse
from datetime import datetime
import os
from pathlib import Path
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from PIL import Image, ImageTk


from .transport import *  # noqa: F403
from ..detection.firmware import DEFAULT_STATE_ROOT
from ..gui.app import Window, choose_firmware
from ..gui.controls import detect_profile
from ..gui.locale import display_model_name
from ..gui.worker import _prepared_profile_matches
from .virtual_cell import virtual_cell_scenario


def parse_network_start_time(value: str) -> float | None:
    if not value.strip():
        return None
    parsed = datetime.strptime(value, "%Y-%m-%d %H:%M")
    if parsed.strftime("%Y-%m-%d %H:%M") != value:
        raise ValueError("invalid date format")
    timestamp = parsed.timestamp()
    if datetime.fromtimestamp(timestamp) != parsed:
        raise ValueError("invalid local time")
    virtual_cell_scenario(False, start_time=timestamp)
    return timestamp


class LiveWindow(Window):
    def __init__(self, root: tk.Tk, firmware: Path,
                 qemu: Path, state_dir: Path | None = None,
                 experimental_c80: bool = False) -> None:
        self.qemu = qemu
        self.state_dir = state_dir
        self.persistent_state_enabled = self._load_persistent_state()
        self.experimental_c80 = experimental_c80
        self.virtual_network_enabled = self._load_virtual_network()
        self._active_virtual_network = self.virtual_network_enabled
        self.network_host_time_enabled = self._load_virtual_network("network_host_time")
        self._active_network_host_time = self.network_host_time_enabled
        self.network_start_time = self._load_network_start_time()
        self._active_network_start_time = self.network_start_time
        self.transport: Transport | None = None
        self._active_firmware: Path | None = None
        self._active_overrides: dict[str, object] = {}
        super().__init__(
            root, firmware,
            experimental_c80_controller=experimental_c80,
        )
        self.root.after(100, self._refresh_qemu_metrics)
        self.root.after(5, self._forward_qemu_keys)

    def _build(self) -> None:
        super()._build()
        self.editing_input_mapping = False
        self.settings_button.configure(text=self._text("more"), command=self._show_more)
        self.fold_button = ttk.Button(
            self.controls, text="Fold: unavailable",
            command=self._toggle_fold, state="disabled",
        )
        self.fold_button.grid(row=3, column=0, padx=2, pady=1)
        self.persistent_state_var = tk.BooleanVar(master=self.root, value=self.persistent_state_enabled)
        self.virtual_network_var = tk.BooleanVar(
            master=self.root, value=self.virtual_network_enabled)
        self.network_host_time_var = tk.BooleanVar(
            master=self.root, value=self.network_host_time_enabled)
        self.network_start_time_var = tk.StringVar(master=self.root, value=self.network_start_time)
        self.secondary_window = tk.Toplevel(self.root)
        self.secondary_window.withdraw()
        self.secondary_window.title("Additional display (experimental)")
        self.secondary_window.resizable(True, True)
        self.secondary_window.minsize(112, 104)
        self.secondary_window.protocol("WM_DELETE_WINDOW", self.secondary_window.withdraw)
        self.secondary_view = ttk.Frame(self.secondary_window, padding=8)
        self.secondary_view.pack(fill="both", expand=True)
        self.secondary_image = tk.Canvas(
            self.secondary_view, width=192, height=128,
            background="black", highlightthickness=0,
        )
        self.secondary_image.pack(fill="both", expand=True)
        self.secondary_status = ttk.Label(self.secondary_view)
        self.secondary_status.pack()
        self._secondary_cache = None
        self._secondary_size = None
        self._secondary_owner = None
        self._secondary_auto_open = True
        self.display_menu = tk.Menu(self.root, tearoff=False)
        self.display_menu.add_command(label="Additional display",
                                      command=self._show_secondary_display,
                                      state="disabled")
        self.screen.bind("<Button-3>", self._display_popup)

    def _settings_main_controls(self, page) -> None:
        ttk.Checkbutton(page, text=self._text("persistent_state"),
                        variable=self.persistent_state_var,
                        command=self._set_persistent_state).pack(anchor="w")
        ttk.Button(page, text=self._text("additional_display"),
                   command=self._show_secondary_display).pack(anchor="w", pady=4)
        position = ttk.Frame(page)
        position.pack(anchor="w")
        ttk.Label(position, text=self._text("display_position")).pack(side="left")
        for side in ("left", "right"):
            ttk.Button(position, text=self._text("display_" + side),
                       command=lambda value=side: self._position_secondary(value)).pack(side="left")

    def _set_editing_input(self, enabled: bool) -> None:
        if enabled:
            self._release_all()
            for bit in tuple(self.held):
                self._key(bit, False, f"mouse:{bit}")
        self.editing_input_mapping = enabled
        self.settings_button.configure(text=self._text("done_editing" if enabled else "more"))

    def _show_more(self) -> None:
        if self.editing_input_mapping:
            self._set_editing_input(False)
            return
        running = self.transport is not None
        if hasattr(self, "_more_menu"):
            self._more_menu.destroy()
        menu = tk.Menu(self.root, tearoff=False)
        menu.add_checkbutton(label=self._text("virtual_network_menu"), variable=self.virtual_network_var,
                             command=self._set_virtual_network)
        menu.add_command(label=self._text("start"), command=self._restart, state="disabled" if running else "normal")
        menu.add_command(label=self._text("stop_emulator"), command=self._stop_transport, state="normal" if running else "disabled")
        menu.add_command(label=self._text("reboot_emulator"), command=self._restart, state="normal" if running else "disabled")
        menu.add_command(label=self._text("choose_firmware_menu"), command=self._choose_firmware_from_menu)
        menu.add_command(label=self._text("edit_input"), command=lambda: self._set_editing_input(True),
                         state="normal" if running else "disabled")
        time_menu = tk.Menu(menu, tearoff=False)
        mode = tk.StringVar(master=self.root, value="host" if self.network_host_time_enabled else "fixed")
        self._more_time_var = mode
        time_menu.add_radiobutton(label=self._text("host_time"), variable=mode, value="host",
                                  command=lambda: self._choose_network_time(True))
        time_menu.add_radiobutton(label=self._text("set_time"), variable=mode, value="fixed",
                                  command=lambda: self._choose_network_time(False))
        menu.add_cascade(label=self._text("time"), menu=time_menu)
        menu.add_command(label=self._text("settings") + "…", command=self._settings)
        self._more_menu = menu
        try:
            menu.tk_popup(self.settings_button.winfo_rootx(),
                          self.settings_button.winfo_rooty() + self.settings_button.winfo_height())
        finally:
            menu.grab_release()

    def _choose_firmware_from_menu(self) -> None:
        chosen = filedialog.askopenfilename(parent=self.root, title=self._text("choose_firmware_menu"),
                                            filetypes=(("Firmware", "*.bin *.dump *.img *.mbn *.hex *.hxb"), ("All", "*")))
        if chosen:
            self.firmware = Path(chosen)
            self.overrides = self._load_config()
            self._restart()

    def _choose_network_time(self, host: bool) -> None:
        if host:
            self.network_start_time = ""
            self.network_start_time_var.set("")
        else:
            value = simpledialog.askstring(self._text("set_time"), "YYYY-MM-DD HH:MM",
                                           parent=self.root, initialvalue=self.network_start_time)
            if value is None:
                return
            try:
                if parse_network_start_time(value) is None:
                    raise ValueError("empty time")
            except (ValueError, OverflowError, OSError):
                messagebox.showerror(self._text("settings_error"), self._text("network_time_error"), parent=self.root)
                return
            self.network_start_time = value
            self.network_start_time_var.set(value)
        self.network_host_time_enabled = host
        self.network_host_time_var.set(host)
        if self.transport is not None and self.virtual_network_enabled:
            self._restart()
        self._save_config()

    def _set_persistent_state(self) -> None:
        old = self.persistent_state_enabled
        self.persistent_state_enabled = self.persistent_state_var.get()
        try:
            self._save_config()
        except OSError as error:
            self.persistent_state_enabled = old
            self.persistent_state_var.set(old)
            messagebox.showerror(self._text("settings_save_error"), str(error), parent=self.root)
            return
        if old != self.persistent_state_enabled and self.transport is not None:
            self._restart()

    def _set_virtual_network(self, key: str = "virtual_network") -> None:
        variable = getattr(self, key + "_var")
        requested = variable.get()
        if requested == getattr(self, key + "_enabled"):
            return
        setattr(self, key + "_enabled", requested)
        try:
            # The clock source only matters while the virtual network is on.
            if self.transport is not None and (key == "virtual_network" or self.virtual_network_enabled):
                self._restart()
        finally:
            variable.set(getattr(self, key + "_enabled"))
        if getattr(self, key + "_enabled") == requested:
            try:
                self._save_config()
            except (OSError, TimeoutError) as error:
                messagebox.showerror(
                    self._text("settings_save_error"), str(error), parent=self.root)

    def _set_network_host_time(self) -> None:
        self._set_virtual_network("network_host_time")

    def _set_network_start_time(self, event=None) -> None:
        value = self.network_start_time_var.get()
        if value == self.network_start_time:
            return
        try:
            parse_network_start_time(value)
        except (ValueError, OverflowError, OSError):
            self.network_start_time_var.set(self.network_start_time)
            messagebox.showerror(self._text("settings_save_error"), self._text("network_time_error"), parent=self.root)
            return
        self.network_start_time = value
        if self.virtual_network_enabled:
            self._restart()
        try:
            self._save_config()
        except (OSError, TimeoutError) as error:
            messagebox.showerror(self._text("settings_save_error"), str(error), parent=self.root)

    def _virtual_network_notice(self, transport: Transport) -> str:
        if not self.virtual_network_enabled:
            return ""
        key = ("virtual_network_active" if transport.virtual_cell_status == "configured"
               else "virtual_network_unavailable")
        return " · " + self._text(key)

    def _display_popup(self, event) -> None:
        try:
            self.display_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.display_menu.grab_release()

    def _position_secondary(self, side: str) -> None:
        self.secondary_window.update_idletasks()
        x = (self.root.winfo_x() - self.secondary_window.winfo_reqwidth() - 12
             if side == "left" else self.root.winfo_x() + self.root.winfo_width() + 12)
        x = max(0, min(x, self.root.winfo_screenwidth() - self.secondary_window.winfo_reqwidth()))
        y = max(0, min(self.root.winfo_y(),
                       self.root.winfo_screenheight() - self.secondary_window.winfo_reqheight()))
        self.secondary_window.geometry(f"+{x}+{y}")
        self._show_secondary_display()

    def _show_secondary_display(self) -> None:
        if self._secondary_cache is not None:
            self.secondary_window.deiconify()
            self.secondary_window.lift()

    def _refresh_secondary_display(self, emulator) -> None:
        if emulator is not self._secondary_owner:
            self._secondary_owner = emulator
            self._secondary_cache = None
            self._secondary_auto_open = True
            self.secondary_window.withdraw()
        snapshot = emulator.secondary_display_snapshot()
        if snapshot is None or not snapshot["qualified"]:
            self.secondary_window.withdraw()
            self.display_menu.entryconfigure(0, state="disabled")
            self._secondary_cache = None
            return
        available = (max(1, self.secondary_image.winfo_width()),
                     max(1, self.secondary_image.winfo_height()))
        if snapshot == self._secondary_cache and available == self._secondary_size:
            return
        width, height = snapshot["width"], snapshot["height"]
        frame = (bytes(width * height * 3) if snapshot["enabled"] is False
                 else snapshot["frame"])
        image = Image.frombytes("RGB", (width, height), frame)
        scale = min(available[0] / width, available[1] / height)
        size = (max(1, round(width * scale)), max(1, round(height * scale)))
        self.secondary_photo = ImageTk.PhotoImage(
            image.resize(size, Image.Resampling.NEAREST))
        self.secondary_image.delete("all")
        self.secondary_image.create_image(
            available[0] // 2, available[1] // 2, image=self.secondary_photo,
        )
        power = {True: "On", False: "Off", None: "Power unknown"}[snapshot["enabled"]]
        note = ("Last byte preview · colors/orientation unverified"
                if snapshot.get("encoding") == "unverified-byte-preview"
                else "panel role unverified")
        self.secondary_status.configure(
            text=f"{power} · {width}×{height} · {note}")
        self._secondary_cache = snapshot
        self._secondary_size = available
        self.display_menu.entryconfigure(0, state="normal")
        if self._secondary_auto_open:
            self._secondary_auto_open = False
            self.secondary_window.update_idletasks()
            x = min(self.root.winfo_x() + self.root.winfo_width() + 12,
                    self.root.winfo_screenwidth() - self.secondary_window.winfo_reqwidth())
            y = min(self.root.winfo_y(), self.root.winfo_screenheight()
                    - self.secondary_window.winfo_reqheight())
            self.secondary_window.geometry(f"+{max(0, x)}+{max(0, y)}")
            self._show_secondary_display()

    def _toggle_fold(self) -> None:
        transport = self.transport
        if transport is None or not transport.can_set_fold():
            return
        profile = transport.config.board_status_input
        opened = transport.board_status_snapshot["level"] == profile.default
        if not transport.set_fold(not opened):
            self.status.set(transport.decoder.input_error)

    def _check_for_update(self) -> None:
        # QEMU binaries and their Python transport must update as one bundle.
        pass

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
            self.virtual_network_enabled = self._active_virtual_network
            self.virtual_network_var.set(self.virtual_network_enabled)
            self.network_host_time_enabled = self._active_network_host_time
            self.network_host_time_var.set(self.network_host_time_enabled)
            if hasattr(self, "network_start_time_var"):
                self.network_start_time = self._active_network_start_time
                self.network_start_time_var.set(self.network_start_time)
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
                self.qemu, requested_firmware, self.state_dir if self.persistent_state_enabled else None,
                self.experimental_c80, config=config,
                virtual_cell=virtual_cell_scenario(
                    self.virtual_network_enabled, host_time=self.network_host_time_enabled,
                    start_time=parse_network_start_time(getattr(self, "network_start_time", ""))),
            )
        except Exception as error:
            if self._active_firmware is None:
                raise
            self.firmware = self._active_firmware
            self.overrides = dict(self._active_overrides)
            self.virtual_network_enabled = self._active_virtual_network
            self.virtual_network_var.set(self.virtual_network_enabled)
            self.network_host_time_enabled = self._active_network_host_time
            self.network_host_time_var.set(self.network_host_time_enabled)
            if hasattr(self, "network_start_time_var"):
                self.network_start_time = self._active_network_start_time
                self.network_start_time_var.set(self.network_start_time)
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
                    self.qemu, self.firmware, self.state_dir if self.persistent_state_enabled else None,
                    self.experimental_c80, config=rollback,
                    virtual_cell=virtual_cell_scenario(
                        self.virtual_network_enabled, host_time=self.network_host_time_enabled,
                        start_time=parse_network_start_time(getattr(self, "network_start_time", ""))),
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
        self._last_detected_config = transport.config
        self.firmware = firmware
        self.overrides = dict(overrides)
        self._active_firmware = firmware
        self._active_overrides = dict(overrides)
        self._active_virtual_network = self.virtual_network_enabled
        self._active_network_host_time = self.network_host_time_enabled
        self._active_network_start_time = getattr(self, "network_start_time", "")
        config = transport.config
        self.model.set(display_model_name(
            config.model, config.verified_model, self.ui_language, firmware.stem
        ))
        self.device_details.set(
            f"QEMU TCG · {config.chipset} · {config.width}×{config.height}"
            + self._virtual_network_notice(transport)
        )
        self.status.set("QEMU TCG real-time LCD transport")
        self.worker = threading.Thread(
            target=transport.replay, args=(self.stop,), daemon=False
        )
        self.worker.start()

    def _stop_transport(self) -> None:
        if hasattr(self, "secondary_window"):
            self.secondary_window.withdraw()
            self._secondary_cache = None
            self._secondary_owner = None
            self.display_menu.entryconfigure(0, state="disabled")
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
        supported = transport.can_set_fold()
        self.fold_button.configure(state="normal" if supported else "disabled")
        if supported:
            opened = (transport.board_status_snapshot["level"]
                      == transport.config.board_status_input.default)
            state = "Open" if opened else "Closed"
            self.fold_button.configure(text=f"Fold: {state} (experimental)")
        else:
            self.fold_button.configure(text="Fold: unavailable")
        width, height, _frame = emulator.display_snapshot()
        self.device_details.set(
            f"QEMU TCG · {emulator.config.chipset} · {width}×{height}"
            + self._virtual_network_notice(transport)
        )
        self.metric_values["run"].set(f"{transport.instructions:,}")
        self.metric_values["pc"].set(f"0x{transport.pc:08X}")
        self.metric_values["lcd"].set(f"{emulator.lcd_writes:,}")
        secondary = emulator.secondary_display_snapshot()
        sub_frames = secondary.get("sequence", 0) if secondary else 0
        frames = str(emulator.frame_sequence)
        if sub_frames:
            frames += f" + {sub_frames} sub"
        self.metric_values["frame"].set(frames)
        self.root.after(100, self._refresh_qemu_metrics)

    def _refresh_display(self) -> None:
        super()._refresh_display()
        if self.emulator is not None:
            self._refresh_secondary_display(self.emulator)

    def _close(self) -> None:
        if not self.closing:
            self._stop_transport()
        super()._close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware", nargs="?", type=Path)
    parser.add_argument(
        "--qemu", type=Path,
        default=Path(os.environ.get("MSM5XXX_QEMU",
            Path(__file__).resolve().parents[3] / "bin" /
            ("qemu-system-arm.exe" if os.name == "nt" else "qemu-system-arm"))),
    )
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
    state_dir = args.state_dir or DEFAULT_STATE_ROOT / "qemu-state"
    window = LiveWindow(
        root, firmware.resolve(), args.qemu.resolve(),
        state_dir.resolve(),
        args.experimental_c80_controller,
    )
    try:
        root.mainloop()
    finally:
        window._close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
