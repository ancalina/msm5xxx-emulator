"""Small Tk firmware-library chooser."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import queue
import threading
import tkinter as tk
from PIL import Image, ImageTk
from tkinter import filedialog, messagebox, ttk

from .firmware_library import FirmwareLibrary
from .locale import UI_TEXT


def format_size(size: int) -> str:
    value = max(0, size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{value} B"
        value /= 1024


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
                                ('library_import', self.add_file),
                                ('library_refresh', self.refresh)):
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
            for index, item in enumerate(self.rows):
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
                self.list.insert('', tk.END, iid=str(index), text=item['name'] + status, image=thumbnail,
                                 values=(item.get('chipset') or '—', format_size(item.get('size', 0)), timestamp))
            self.notice.configure(text=error or ('' if self.rows else self.text['library_empty']))
        self.window.after(100, self.poll)

    def add_folder(self) -> None:
        selected = filedialog.askdirectory(parent=self.window)
        if selected:
            self.library.add_folder(Path(selected))
            self.refresh()

    def add_file(self) -> None:
        selected = filedialog.askopenfilename(parent=self.window)
        if selected:
            self.library.add_file(Path(selected))
            self.refresh()

    def selected_row(self) -> dict | None:
        selection = self.list.selection()
        return self.rows[int(selection[0])] if selection else None

    def boot(self) -> None:
        if self.scanning:
            return
        row = self.selected_row()
        if row and row.get('available'):
            self.selected = Path(row['path'])
            self.close()

    def popup(self, event) -> None:
        if self.scanning:
            return
        index = self.list.identify_row(event.y)
        if not index:
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
