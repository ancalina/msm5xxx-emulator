"""Domain-owned boot captures over shared evidence."""

from .rules import detect_lcd_width_hint
from .rules import find_page_plane_width
def capture_hint(layout):
    width, height = 176, 220
    page_width = find_page_plane_width(layout.primary_image)
    if page_width is not None:
        if detect_lcd_width_hint(layout.primary_image) == page_width:
            layout.detection_notes.append(
                f"experimental paired-page descriptor width={page_width}; "
                "two-plane inference; physical packing and panel role unverified"
            )
        else:
            layout.detection_notes.append("paired-page descriptor width not applied: existing metadata retained")
    return (width, height,)

from .rules import find_framebuffer_layout
from .paired_page128 import find_paired_page128
def capture_framebuffer(layout, runtime_position, width, height):
    framebuffer = find_framebuffer_layout(layout.primary_image)
    framebuffer_address = None
    framebuffer_stride = 0
    framebuffer_format = "none"
    framebuffer_flush_address = None
    framebuffer_rect_flush_address = None
    page_panel = find_paired_page128(layout.primary_image) if framebuffer is None else None
    if page_panel is not None:
        width, height = page_panel["width"], page_panel["height"]
        layout.detection_notes.append("interleaved two-plane page driver establishes 128x128 geometry")
    if framebuffer is not None:
        width, height, framebuffer_address, framebuffer_stride, row, rect = framebuffer
        framebuffer_format = "rgb565le"
        framebuffer_flush_address = runtime_position("framebuffer_flush_address", row)
        framebuffer_rect_flush_address = runtime_position("framebuffer_rect_flush_address", rect)
    return (width, height, framebuffer, framebuffer_address, framebuffer_stride, framebuffer_format, framebuffer_flush_address, framebuffer_rect_flush_address,
        page_panel,)
