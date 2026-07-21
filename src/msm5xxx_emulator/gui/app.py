#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import locale
import logging
import os
from pathlib import Path
import queue
import shutil
import signal
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageTk

from ..probe.boot import boot_event, boot_phase, visible_pixels
from ..core.constants import (BUILD_CODENAME, MAX_NAND_BACKING_SIZE,
                              MAX_NAND_DATA_SIZE, MAX_RAM_SIZE, PAGE)
from ..core.emulator import GenericMSMEmulator
from ..core.errors import HostBackendFault
from ..detection.firmware import (DEFAULT_STATE_ROOT, DISABLEABLE_ADDRESS_FIELDS,
                                  MAX_FLASH_SIZE, detect)
from ..state_io import atomic_write_text, exclusive_path_lock
from ..diagnostics.runtime_log import install_runtime_logging, record_exception
from .controls import (
    ControlsMixin, KEYS, LAYOUT, METRIC_TEXT,
    SETTINGS_ENGLISH, can_apply_live_framebuffer_format,
    merge_settings_overrides, settings_apply_mode,
)
from ..update import (UpdateError, UpdateInfo, application_root, check_for_update,
                      inplace_update_command, installation_status, prepare_update,
                      remember_update)
from .display_view import DisplayViewMixin, frame_repaint_needed
from .worker import WorkerMixin
from .locale import (
    UI_LANGUAGE_CHOICES, UI_TEXT, display_model_name, normalize_ui_language,
    resolve_ui_language, runtime_notice_text, runtime_status_text,
    system_ui_language,
)
from .repro import (create_repro_bundle, finish_repro_bundle,
                    firmware_telemetry)
from .telemetry import (
    TELEMETRY_INSTRUCTION_CADENCE, TELEMETRY_POLL_ESCAPE_CAP,
    TELEMETRY_SCREENSHOT_CADENCE, TELEMETRY_SCREENSHOT_CAP,
    _compact_telemetry, _counter, _frame_metrics, _host_hle_telemetry,
    _mapping, _nonnegative_counter, _phase_state, emit_telemetry,
    hydrate_host_checkpoint, runtime_telemetry, save_telemetry_frame,
    telemetry_artifact_due, telemetry_transition,
)


LOGGER = logging.getLogger("gui")


STATE_ROOT = DEFAULT_STATE_ROOT
LAST_CONFIG = STATE_ROOT / "last_config.json"


class Window(ControlsMixin, DisplayViewMixin, WorkerMixin):
    def __init__(self, root: tk.Tk, firmware: Path) -> None:
        LOGGER.info("window create firmware=%s build=%s", firmware.name, BUILD_CODENAME)
        self.root = root
        self.root.minsize(360, 640)
        self.firmware = firmware
        self.ui_language_preference = self._load_ui_language()
        self.ui_language = resolve_ui_language(self.ui_language_preference)
        self.overrides = self._load_config()
        self.emulator: GenericMSMEmulator | None = None
        self.worker: threading.Thread | None = None
        self.stop = threading.Event()
        self.generation = 0
        self.closing = False
        self.commands: queue.SimpleQueue[tuple[object, ...]] = queue.SimpleQueue()
        self.states: queue.SimpleQueue[tuple[int, dict[str, object]]] = queue.SimpleQueue()
        self.save_errors: queue.SimpleQueue[str] = queue.SimpleQueue()
        self.update_results: queue.SimpleQueue[tuple[str, object]] = queue.SimpleQueue()
        self.update_download_active = False
        self.held: dict[int, set[str]] = {}
        self.keyboard_bits: dict[str, int] = {}
        self.keyboard_sources: set[str] = set()
        self.pending_key_releases: dict[str, str] = {}
        self.photo: ImageTk.PhotoImage | None = None
        self._render_cache: tuple[object, bytes, int, int, int, int] | None = None
        self.status = tk.StringVar(value=self._text("ready"))
        self.model = tk.StringVar(value=self._text("detecting"))
        self.device_details = tk.StringVar(value="")
        self.metric_values = {
            "run": tk.StringVar(value="—"), "pc": tk.StringVar(value="—"),
            "lcd": tk.StringVar(value="—"), "frame": tk.StringVar(value="—"),
        }
        self.metric_titles: dict[str, ttk.Label] = {}
        self._tooltip_after: str | None = None
        self._tooltip_window: tk.Toplevel | None = None
        self._configure_style()
        self._build()
        self._bind_keyboard()
        self._restart()
        self.root.after(50, self._refresh)
        self.root.after(750, self._check_for_update)
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Phone.TFrame", background="#242424")
        style.configure("Phone.TLabel", background="#242424", foreground="#eeeeee")
        style.configure("Device.Phone.TLabel", background="#242424",
                        foreground="#ffffff", font=("TkDefaultFont", 9, "bold"),
                        padding=0)
        style.configure("Detail.Phone.TLabel", background="#242424",
                        foreground="#aeb7c2", font=("TkDefaultFont", 8), padding=0)
        style.configure("MetricName.Phone.TLabel", background="#242424",
                        foreground="#8fa1b5", font=("TkDefaultFont", 8), padding=0)
        style.configure("MetricValue.Phone.TLabel", background="#242424",
                        foreground="#e8edf2", font=("TkFixedFont", 8), padding=0)
        style.configure("Phone.TButton", padding=(4, 1), width=6, anchor="center")
        style.configure("Tool.Phone.TButton", padding=(4, 1), width=10)
        self.root.configure(background="#1b1b1b")

    def _build(self) -> None:
        outer = ttk.Frame(self.root, style="Phone.TFrame", padding=10)
        outer.pack(fill="both", expand=True, padx=8, pady=8)

        self.screen = tk.Canvas(outer, width=1, height=1, background="black",
                                highlightthickness=0, bd=0)
        self.screen.pack(fill="both", expand=True, pady=(0, 6))

        controls = ttk.Frame(outer, style="Phone.TFrame")
        controls.pack()
        self.key_buttons: dict[str, ttk.Button] = {}
        for label, row, column in LAYOUT:
            button = ttk.Button(controls, text=self._key_text(label),
                                style="Phone.TButton", takefocus=False)
            button.grid(row=row, column=column, padx=2, pady=1)
            self.key_buttons[label] = button
            bit = KEYS[label]
            button.bind("<ButtonPress-1>",
                        lambda _event, b=bit: self._key(b, True, f"mouse:{b}"))
            button.bind("<ButtonRelease-1>",
                        lambda _event, b=bit: self._key(b, False, f"mouse:{b}"))

        tools = ttk.Frame(outer, style="Phone.TFrame")
        tools.pack(pady=(2, 4))
        self.settings_button = ttk.Button(tools, text=self._text("settings"),
                                          command=self._settings,
                                          style="Tool.Phone.TButton")
        self.settings_button.grid(row=0, column=0, padx=2)
        self.capture_button = ttk.Button(tools, text=self._text("capture"),
                                         command=self._save_png,
                                         style="Tool.Phone.TButton")
        self.capture_button.grid(row=0, column=1, padx=2)

        ttk.Separator(outer).pack(fill="x", pady=(3, 1))
        self.model_label = ttk.Label(outer, textvariable=self.model, anchor="w",
                                     justify="left", wraplength=330,
                                     style="Device.Phone.TLabel")
        self.model_label.pack(fill="x")
        self.device_details_label = ttk.Label(
            outer, textvariable=self.device_details, anchor="w", justify="left",
            wraplength=330, style="Detail.Phone.TLabel",
        )
        self.device_details_label.pack(fill="x")
        metrics = ttk.Frame(outer, style="Phone.TFrame")
        metrics.pack(fill="x")
        for column in range(2):
            metrics.columnconfigure(column, weight=1, uniform="metric")
        for index, key in enumerate(("run", "pc", "lcd", "frame")):
            cell = ttk.Frame(metrics, style="Phone.TFrame")
            cell.grid(row=index // 2, column=index % 2, sticky="ew", padx=(0, 8))
            title = ttk.Label(cell, text=METRIC_TEXT[self.ui_language][key][0],
                              style="MetricName.Phone.TLabel")
            title.pack(side="left")
            value = ttk.Label(cell, textvariable=self.metric_values[key],
                              style="MetricValue.Phone.TLabel")
            value.pack(side="left", padx=(6, 0))
            self.metric_titles[key] = title
            self._bind_metric_tooltip(title, key)
            self._bind_metric_tooltip(value, key)
        self.status_label = ttk.Label(outer, textvariable=self.status, anchor="w",
                                      justify="left", wraplength=330,
                                      style="Detail.Phone.TLabel")
        self.status_label.pack(fill="x")
        self.status.trace_add("write", self._sync_status_visibility)

        def wrap_status(event: tk.Event) -> None:
            length = max(120, event.width - 24)
            self.model_label.configure(wraplength=length)
            self.device_details_label.configure(wraplength=length)
            self.status_label.configure(wraplength=length)

        outer.bind("<Configure>", wrap_status)
        self._apply_ui_language()

    def _sync_status_visibility(self, *_args: object) -> None:
        if self.status.get():
            if not self.status_label.winfo_manager():
                self.status_label.pack(fill="x")
        else:
            self.status_label.pack_forget()

    def _check_for_update(self) -> None:
        """Check GitHub outside Tk; ``_refresh`` owns all UI actions."""
        def check() -> None:
            try:
                update = check_for_update(application_root(), STATE_ROOT)
            except UpdateError as error:
                LOGGER.info("update check skipped error=%s", error)
                return
            if update is not None:
                self.update_results.put(("available", update))

        threading.Thread(target=check, daemon=True).start()

    def _offer_update(self, update: UpdateInfo) -> None:
        if self.closing or self.update_download_active:
            return
        try:
            remember_update(STATE_ROOT, update.revision)
        except (OSError, UpdateError) as error:
            LOGGER.info("update prompt state not saved error=%s", error)
        try:
            modified = not installation_status(application_root()).clean
        except UpdateError:
            modified = True
        if modified:
            prompt = (
                f"GitHub 최신 commit {update.revision[:12]}를 찾았습니다.\n\n"
                "로컬 source 수정이 있습니다. 로컬 편집을 폐기하고 업데이트할까요?\n"
                "firmware, logs, EEPROM/NOR state는 보존됩니다."
            )
        else:
            prompt = (
                f"GitHub 최신 commit {update.revision[:12]}를 찾았습니다.\n\n"
                "현재 설치 파일을 최신 버전으로 업데이트할까요?"
            )
        if not messagebox.askyesno("업데이트", prompt, parent=self.root):
            return
        self.update_download_active = True
        self.status.set("업데이트 내려받는 중")

        def download() -> None:
            try:
                prepared = prepare_update(update, STATE_ROOT)
                self.update_results.put(("ready", (prepared, update, modified)))
            except (OSError, UpdateError) as error:
                self.update_results.put(("error", error))

        threading.Thread(target=download, daemon=True).start()

    def _launch_update(self, prepared: Path, update: UpdateInfo,
                       discard_modified: bool) -> None:
        try:
            root = application_root()
            command = inplace_update_command(
                prepared, root, STATE_ROOT, self.firmware, update, discard_modified
            )
        except UpdateError as error:
            self.status.set(f"업데이트 준비 실패: {error}")
            self.update_download_active = False
            return
        self._close()
        try:
            subprocess.Popen(command, cwd=root)
        except OSError as error:
            LOGGER.error("updated GUI launch failed error=%s", error)

    def _close(self) -> None:
        if self.closing:
            return
        self.closing = True
        self._hide_metric_tooltip()
        firmware = getattr(self, "firmware", None)
        firmware_name = firmware.name if isinstance(firmware, Path) else "unknown"
        LOGGER.info("window close begin firmware=%s", firmware_name)
        self.generation += 1
        self.stop.set()
        if self.worker and self.worker.is_alive():
            self.worker.join()
        self._show_save_errors()
        try:
            self.root.destroy()
        except tk.TclError:
            pass
        LOGGER.info("window close complete firmware=%s", firmware_name)


def main() -> int:
    session_log = install_runtime_logging("gui")
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware", nargs="?", type=Path)
    args = parser.parse_args()
    firmware = args.firmware
    if firmware is None:
        root = tk.Tk()
        root.withdraw()
        chosen = filedialog.askopenfilename(filetypes=(("Firmware", "*.bin"), ("All", "*")))
        root.destroy()
        if not chosen:
            LOGGER.info("firmware selection cancelled log=%s", session_log)
            return 0
        firmware = Path(chosen)
    root = tk.Tk()

    def callback_exception(error_type: type[BaseException], error: BaseException,
                           trace: object) -> None:
        error = error.with_traceback(trace)  # type: ignore[arg-type]
        record_exception("Tk callback exception", error)
        sys.__excepthook__(error_type, error, trace)

    root.report_callback_exception = callback_exception
    window = Window(root, firmware.resolve())
    LOGGER.info("GUI mainloop start firmware=%s log=%s", firmware.name, session_log.name)

    def close_from_signal(_number: int, _frame: object) -> None:
        LOGGER.info("signal received number=%d", _number)
        root.after_idle(window._close)

    signal.signal(signal.SIGINT, close_from_signal)
    signal.signal(signal.SIGTERM, close_from_signal)
    try:
        root.mainloop()
    finally:
        window._close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
