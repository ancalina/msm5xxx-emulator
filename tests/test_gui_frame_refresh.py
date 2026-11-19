import unittest
from unittest.mock import patch

from PIL import Image

from msm5xxx_emulator.gui.display_view import DisplayViewMixin, _resize_rgb_nearest


def image_pixels(image):
    return [image.getpixel((x, y))
            for y in range(image.height) for x in range(image.width)]


class FrameRefreshTest(unittest.TestCase):
    def test_nearest_fallback_scales_rgb_up_and_down(self):
        colors = [(0, 0, 0), (255, 0, 0), (0, 255, 0), (0, 0, 255)]
        checkerboard = Image.new("RGB", (2, 2))
        checkerboard.putdata(colors)
        with patch.object(
                Image.Image, "resize",
                side_effect=SystemError(
                    "<method 'resize' of 'ImagingCore' objects> returned NULL "
                    "without setting an exception")):
            enlarged = _resize_rgb_nearest(checkerboard, (4, 4))
        expected_enlarged = [
            colors[0], colors[0], colors[1], colors[1],
            colors[0], colors[0], colors[1], colors[1],
            colors[2], colors[2], colors[3], colors[3],
            colors[2], colors[2], colors[3], colors[3],
        ]
        self.assertEqual(image_pixels(enlarged), expected_enlarged)

        grid = Image.new("RGB", (4, 4))
        grid.putdata([(value, value, value) for value in range(16)])
        with patch.object(
                Image.Image, "resize",
                side_effect=SystemError(
                    "<method 'resize' of 'ImagingCore' objects> returned NULL "
                    "without setting an exception")):
            reduced = _resize_rgb_nearest(grid, (2, 2))
        self.assertEqual(image_pixels(reduced), [
            (5, 5, 5), (7, 7, 7), (13, 13, 13), (15, 15, 15),
        ])

    def test_nearest_fallback_propagates_unrelated_system_error(self):
        image = Image.new("RGB", (2, 2))
        with patch.object(Image.Image, "resize", side_effect=SystemError("other failure")):
            with self.assertRaisesRegex(SystemError, "other failure"):
                _resize_rgb_nearest(image, (4, 4))

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
