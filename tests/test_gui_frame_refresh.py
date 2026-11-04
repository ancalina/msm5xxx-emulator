import unittest
from unittest.mock import patch

from msm5xxx_emulator.gui.display_view import DisplayViewMixin


class FrameRefreshTest(unittest.TestCase):
    def test_changed_frame_reuses_photo_and_unchanged_frame_is_skipped(self):
        class Emulator:
            frame = bytes(12)
            def display_snapshot(self):
                return 2, 2, self.frame
        class Screen:
            def winfo_width(self): return 4
            def winfo_height(self): return 4
            def create_image(self, *args, **kwargs): return 1
            def coords(self, *args): pass
            def itemconfigure(self, *args, **kwargs): pass
        class Root:
            def after(self, *args): pass
        class Photo:
            def __init__(self, image): self.pastes = 0
            def width(self): return 4
            def height(self): return 4
            def paste(self, image): self.pastes += 1
        view = DisplayViewMixin()
        view.emulator, view.screen, view.root = Emulator(), Screen(), Root()
        view.photo = view._screen_item = view._render_cache = None
        with patch('msm5xxx_emulator.gui.display_view.ImageTk.PhotoImage', Photo):
            view._refresh_display()
            photo = view.photo
            view._refresh_display()
            self.assertEqual(photo.pastes, 0)
            view.emulator.frame = bytes([1] * 12)
            view._refresh_display()
            self.assertIs(view.photo, photo)
            self.assertEqual(photo.pastes, 1)
