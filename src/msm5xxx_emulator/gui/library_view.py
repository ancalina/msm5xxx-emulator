"""Small Tk firmware-library chooser."""
from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import queue
import threading
import tkinter as tk
from PIL import Image, ImageTk
from tkinter import filedialog, messagebox, ttk

from .firmware_library import FirmwareLibrary
from .locale import UI_TEXT
from .controls import LAST_CONFIG
from ..state_io import atomic_write_text, exclusive_path_lock


def format_size(size: int) -> str:
    value = max(0, size)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{value} B"
        value /= 1024


def group_rows(rows: list[dict]) -> list[list[int]]:
    groups: dict[tuple[str, object], list[int]] = {}
    for index, row in enumerate(rows):
        model = row.get('model')
        key = ('model', model.strip().casefold()) if isinstance(model, str) and model.strip() else ('file', index)
        groups.setdefault(key, []).append(index)
    return list(groups.values())


def save_session_settings(path: Path, network: bool, host_time: bool, start_time: str,
                          persistent: bool) -> None:
    from ..qemu.live_display import parse_network_start_time
    if not host_time:
        if not start_time or parse_network_start_time(start_time) is None:
            raise ValueError('invalid network time')
    with exclusive_path_lock(path):
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                data = {}
        except (OSError, ValueError):
            data = {}
        data.update(virtual_network=network, network_host_time=host_time,
                    network_start_time='' if host_time else start_time,
                    persistent_state=persistent)
        atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2) + '\n')


class LibraryDialog:
    def __init__(self, root: tk.Tk, library: FirmwareLibrary, language: str):
        self.root, self.library, self.text = root, library, UI_TEXT[language]
        self.selected: Path | None = None
        self.rows: list[dict] = []
        self.results: queue.SimpleQueue = queue.SimpleQueue()
        self.closed = False
        self.scanning = False
        self.window = tk.Toplevel(root)
        self.window.title(self.text['library_title'] + ' — MSM5XXX Emulator')
        self.window.geometry('680x420')
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        body = ttk.Frame(self.window, padding=10)
        body.pack(fill='both', expand=True)
        self.notice = ttk.Label(body, text=self.text['library_loading'])
        self.notice.pack(anchor='w')
        self.list = ttk.Treeview(body, columns=('chipset', 'size', 'last'), show='tree headings', selectmode='browse')
        self.list.heading('#0', text=self.text['library_model'])
        self.list.heading('chipset', text=self.text['library_chipset'])
        self.list.heading('size', text=self.text['library_size'])
        self.list.heading('last', text=self.text['library_last'])
        self.list.column('#0', width=210)
        self.list.column('chipset', width=120)
        self.list.column('size', width=90)
        self.list.column('last', width=150)
        self.list.pack(fill='both', expand=True)
        self.images: list[ImageTk.PhotoImage] = []
        self.list.bind('<Double-Button-1>', lambda event: self.boot())
        self.list.bind('<Return>', lambda event: self.boot())
        self.list.bind('<Button-3>', self.popup)
        buttons = ttk.Frame(body)
        buttons.pack(fill='x', pady=6)
        self.buttons = []
        for label, callback in (('library_add_folder', self.add_folder),
                                ('library_remove_folder', self.remove_folder),
                                ('library_import', self.add_file),
                                ('library_refresh', self.refresh),
                                ('settings', self.session_settings)):
            button = ttk.Button(buttons, text=self.text[label], command=callback)
            button.pack(side='left', padx=2)
            self.buttons.append(button)
        self.refresh()
        self.window.after(100, self.poll)

    def close(self) -> None:
        self.closed = True
        self.window.destroy()

    def refresh(self) -> None:
        if self.scanning:
            return
        self.scanning = True
        for button in self.buttons:
            button.configure(state='disabled')
        self.notice.configure(text=self.text['library_loading'])
        def scan():
            try:
                self.results.put((self.library.scan(), None))
            except (OSError, ValueError) as error:
                self.results.put(([], str(error)))
        threading.Thread(target=scan, daemon=True).start()

    def poll(self) -> None:
        if self.closed:
            return
        try:
            self.rows, error = self.results.get_nowait()
        except queue.Empty:
            pass
        else:
            self.scanning = False
            for button in self.buttons:
                button.configure(state='normal')
            self.list.delete(*self.list.get_children())
            self.images.clear()
            for group_number, group in enumerate(group_rows(self.rows)):
                parent = ''
                if len(group) > 1:
                    first = self.rows[group[0]]
                    parent = f'group:{group_number}'
                    self.list.insert('', tk.END, iid=parent, text=first['model'].strip(), open=False)
                for index in group:
                    item = self.rows[index]
                    last = item.get('last_booted')
                    timestamp = datetime.fromtimestamp(last).strftime('%Y-%m-%d %H:%M') if last else self.text['library_never']
                    status = '' if item.get('available') else ' · ' + self.text['library_unavailable']
                    thumbnail = ''
                    if item.get('thumbnail'):
                        try:
                            image = Image.open(item['thumbnail'])
                            image.thumbnail((32, 24), Image.Resampling.NEAREST)
                            self.images.append(ImageTk.PhotoImage(image, master=self.window))
                            thumbnail = self.images[-1]
                        except (OSError, ValueError):
                            pass
                    label = Path(item['path']).name if parent else item['name']
                    self.list.insert(parent, tk.END, iid=str(index), text=label + status, image=thumbnail,
                                     values=(item.get('chipset') or '—', format_size(item.get('size', 0)), timestamp))
            self.notice.configure(text=error or ('' if self.rows else self.text['library_empty']))
        self.window.after(100, self.poll)

    def add_folder(self) -> None:
        selected = filedialog.askdirectory(parent=self.window)
        if selected:
            self.library.add_folder(Path(selected))
            self.refresh()

    def remove_folder(self) -> None:
        if not self.library.folders:
            return
        dialog = tk.Toplevel(self.window)
        dialog.title(self.text['library_remove_folder'])
        dialog.transient(self.window)
        folders = tk.Listbox(dialog, width=70, height=min(10, len(self.library.folders)))
        folders.pack(fill='both', expand=True, padx=10, pady=10)
        for folder in self.library.folders:
            folders.insert(tk.END, folder)

        def remove_selected() -> None:
            selection = folders.curselection()
            if selection:
                self.library.remove_folder(Path(folders.get(selection[0])))
                dialog.destroy()
                self.refresh()

        ttk.Button(dialog, text=self.text['library_remove'], command=remove_selected).pack(pady=5)
        dialog.grab_set()

    def add_file(self) -> None:
        selected = filedialog.askopenfilename(parent=self.window)
        if selected:
            self.library.add_file(Path(selected))
            self.refresh()

    def session_settings(self) -> None:
        try:
            data = json.loads(LAST_CONFIG.read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                data = {}
        except (OSError, ValueError):
            data = {}
        dialog = tk.Toplevel(self.window)
        dialog.title(self.text['settings'])
        dialog.transient(self.window)
        frame = ttk.Frame(dialog, padding=12)
        frame.pack(fill='both', expand=True)
        network = tk.BooleanVar(master=dialog, value=data.get('virtual_network', False) is True)
        host = tk.BooleanVar(master=dialog, value=data.get('network_host_time', True) is True)
        persistent = tk.BooleanVar(master=dialog, value=data.get('persistent_state', True) is True)
        start = tk.StringVar(master=dialog, value=data.get('network_start_time', ''))
        ttk.Checkbutton(frame, text=self.text['virtual_network'], variable=network).pack(anchor='w')
        ttk.Checkbutton(frame, text=self.text['network_host_time'], variable=host).pack(anchor='w')
        ttk.Label(frame, text=self.text['time_format']).pack(anchor='w')
        ttk.Entry(frame, textvariable=start).pack(fill='x')
        ttk.Checkbutton(frame, text=self.text['persistent_state'], variable=persistent).pack(anchor='w')

        def apply() -> None:
            try:
                save_session_settings(LAST_CONFIG, network.get(), host.get(), start.get().strip(), persistent.get())
            except (OSError, ValueError, OverflowError) as error:
                messagebox.showerror(self.text['settings_error'], str(error), parent=dialog)
                return
            dialog.destroy()

        ttk.Button(frame, text=self.text['apply'], command=apply).pack(pady=6)
        dialog.grab_set()

    def selected_row(self) -> dict | None:
        selection = self.list.selection()
        return self.rows[int(selection[0])] if selection and selection[0].isdigit() else None

    def boot(self) -> None:
        if self.scanning:
            return
        row = self.selected_row()
        if row is None and self.list.selection():
            item = self.list.selection()[0]
            self.list.item(item, open=not self.list.item(item, 'open'))
        if row and row.get('available'):
            self.selected = Path(row['path'])
            self.close()

    def popup(self, event) -> None:
        if self.scanning:
            return
        index = self.list.identify_row(event.y)
        if not index:
            return
        if not index.isdigit():
            return
        self.list.selection_set(index)
        menu = tk.Menu(self.window, tearoff=False)
        menu.add_command(label=self.text['library_info'], command=self.info)
        menu.add_command(label=self.text['library_remove'], command=self.remove)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def info(self) -> None:
        row = self.selected_row()
        if row:
            messagebox.showinfo(self.text['library_info'],
                f"{self.text['library_model']}: {row.get('name', '')}\n"
                f"{self.text['library_chipset']}: {row.get('chipset') or '—'}\n"
                f"SHA-256: {row.get('sha256', '—')}\n"
                f"{self.text['library_path']}: {row['path']}", parent=self.window)

    def remove(self) -> None:
        row = self.selected_row()
        if row:
            self.library.remove(Path(row['path']))
            self.refresh()


def choose_from_library(root: tk.Tk, library: FirmwareLibrary, language: str) -> Path | None:
    dialog = LibraryDialog(root, library, language)
    root.wait_window(dialog.window)
    return dialog.selected
