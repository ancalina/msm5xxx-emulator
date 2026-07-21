from __future__ import annotations

import queue
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageTk

from ..update import UpdateError, UpdateInfo

from .controls import METRIC_TEXT
from .locale import runtime_notice_text


def frame_repaint_needed(
        cache: tuple[object, bytes, int, int, int, int] | None,
        emulator: object, frame: bytes, frame_width: int, frame_height: int,
        canvas_width: int, canvas_height: int) -> bool:
    """Avoid rebuilding Pillow/Tk objects for an immutable displayed frame."""
    return (cache is None or cache[0] is not emulator or cache[1] is not frame
            or cache[2:] != (frame_width, frame_height, canvas_width, canvas_height))


class DisplayViewMixin:
    def _bind_metric_tooltip(self, widget: tk.Widget, key: str) -> None:
        widget.bind("<Enter>", lambda _event: self._queue_metric_tooltip(widget, key))
        widget.bind("<Leave>", lambda _event: self._hide_metric_tooltip())
        widget.bind("<ButtonPress>", lambda _event: self._hide_metric_tooltip())

    def _queue_metric_tooltip(self, widget: tk.Widget, key: str) -> None:
        self._hide_metric_tooltip()
        self._tooltip_after = self.root.after(
            350, lambda: self._show_metric_tooltip(widget, key)
        )

    def _show_metric_tooltip(self, widget: tk.Widget, key: str) -> None:
        self._tooltip_after = None
        if not widget.winfo_exists():
            return
        title, explanation = METRIC_TEXT[self.ui_language][key]
        window = tk.Toplevel(self.root)
        window.overrideredirect(True)
        window.attributes("-topmost", True)
        tk.Label(
            window,
            text=f"{title}\n{explanation}",
            justify="left", padx=9, pady=7,
            background="#fffbd6", foreground="#202020",
            relief="solid", borderwidth=1,
        ).pack()
        window.update_idletasks()
        pointer_x, pointer_y = self.root.winfo_pointerxy()
        x = min(pointer_x + 14,
                self.root.winfo_screenwidth() - window.winfo_reqwidth() - 4)
        y = min(pointer_y + 18,
                self.root.winfo_screenheight() - window.winfo_reqheight() - 4)
        window.geometry(f"+{max(0, x)}+{max(0, y)}")
        self._tooltip_window = window

    def _hide_metric_tooltip(self) -> None:
        if self._tooltip_after is not None:
            self.root.after_cancel(self._tooltip_after)
            self._tooltip_after = None
        if self._tooltip_window is not None:
            self._tooltip_window.destroy()
            self._tooltip_window = None

    def _refresh(self) -> None:
        self._show_save_errors()
        while True:
            try:
                kind, value = self.update_results.get_nowait()
            except queue.Empty:
                break
            if kind == "available" and isinstance(value, UpdateInfo):
                self._offer_update(value)
            elif (kind == "ready" and isinstance(value, tuple)
                  and len(value) == 3 and isinstance(value[0], Path)
                  and isinstance(value[1], UpdateInfo)):
                self._launch_update(value[0], value[1], bool(value[2]))
                return
            elif kind == "error" and isinstance(value, (OSError, UpdateError)):
                self.status.set(f"업데이트 실패: {value}")
                self.update_download_active = False
        latest: dict[str, object] = {}
        while True:
            try:
                generation, state = self.states.get_nowait()
            except queue.Empty:
                break
            if generation == self.generation:
                latest.update(state)
        if latest:
            if "model" in latest:
                self.model.set(str(latest["model"]))
            if "device_details" in latest:
                self.device_details.set(str(latest["device_details"]))
            if "instructions" in latest:
                self.metric_values["run"].set(f"{int(latest['instructions']):,}")
                self.metric_values["pc"].set(str(latest.get("pc", "?")))
                self.metric_values["lcd"].set(
                    f"{int(latest.get('lcd_writes', 0)):,}"
                )
                self.metric_values["frame"].set(
                    str(latest.get("frame_sequence", 0))
                )
                self.status.set(runtime_notice_text(latest, self.ui_language))
            if latest.get("fault"):
                self.status.set(
                    f"{'Stopped' if self.ui_language == 'en' else '중지'}: {latest['fault']}"
                )
            if latest.get("host_backend_fault"):
                self.status.set(
                    f"{'Host backend stopped' if self.ui_language == 'en' else '호스트 backend 중지'}: "
                    f"{latest['host_backend_fault']}"
                )
        emulator = self.emulator
        if emulator is not None:
            frame_width, frame_height, frame = emulator.display_snapshot()
            width = max(1, self.screen.winfo_width())
            height = max(1, self.screen.winfo_height())
            if frame_repaint_needed(
                    self._render_cache, emulator, frame, frame_width, frame_height,
                    width, height):
                image = Image.frombytes("RGB", (frame_width, frame_height), frame)
                scale = min(width / image.width, height / image.height)
                size = (max(1, int(image.width * scale)),
                        max(1, int(image.height * scale)))
                self.photo = ImageTk.PhotoImage(
                    image.resize(size, Image.Resampling.NEAREST)
                )
                self.screen.delete("all")
                self.screen.create_image(width // 2, height // 2, image=self.photo)
                self._render_cache = (
                    emulator, frame, frame_width, frame_height, width, height
                )
        self.root.after(100, self._refresh)

    def _show_save_errors(self) -> None:
        errors: list[str] = []
        while True:
            try:
                errors.append(self.save_errors.get_nowait())
            except queue.Empty:
                break
        if not errors:
            return
        detail = "\n".join(dict.fromkeys(errors))
        self.status.set(f"{self._text('save_failed')}: {detail}")
        messagebox.showerror(self._text("save_failed"), detail, parent=self.root)

    def _save_png(self) -> None:
        emulator = self.emulator
        if emulator is None:
            return
        path = filedialog.asksaveasfilename(defaultextension=".png",
                                            filetypes=(("PNG", "*.png"),))
        if path:
            width, height, frame = emulator.display_snapshot()
            Image.frombytes("RGB", (width, height), frame).save(path)
