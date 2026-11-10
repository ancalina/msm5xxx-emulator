"""Projection of captured evidence into firmware configuration."""

def configuration_fields(layout, drivers, storage):
    return {'width': drivers.width, 'height': drivers.height, 'display_geometry_source': 'framebuffer-descriptor' if drivers.framebuffer is not None else
        'interleaved-page-driver' if drivers.page_panel is not None else 'auto-default', 'framebuffer_address': drivers.framebuffer_address,
        'framebuffer_stride': drivers.framebuffer_stride, 'framebuffer_format': drivers.framebuffer_format, 'framebuffer_flush_address': drivers.framebuffer_flush_address,
        'framebuffer_rect_flush_address': drivers.framebuffer_rect_flush_address}

from .selector_lcd import find_selector_lcd_profile

def bind_geometry(config, image):
    if config.load_address == 0 and config.image_kind == "firmware":
        selector_panel, _ = find_selector_lcd_profile(image)
        if selector_panel is not None and config.display_geometry_source == "auto-default":
            config.width = selector_panel["width"]
            config.height = selector_panel["height"]
            config.display_geometry_source = "source-selector-window-clear"

def apply_overrides(config, overrides):
    if (getattr(overrides, "width", None) is not None or getattr(overrides, "height", None) is not None):
        config.display_geometry_source = "override"
    if (getattr(overrides, "framebuffer_stride", None) is None and config.framebuffer_address is not None and (getattr(overrides, "width", None) is not None or
        config.framebuffer_stride <= 0)):
        config.framebuffer_stride = ((config.width + 7) // 8) * 16
    if (getattr(overrides, "framebuffer_address", None) is not None and getattr(overrides, "framebuffer_format", None) is None):
        config.framebuffer_format = "rgb565le"
    if (getattr(overrides, "framebuffer_address", None) == 0 or getattr(overrides, "framebuffer_format", None) == "none"):
        config.framebuffer_address = None
        config.framebuffer_stride = 0
        config.framebuffer_format = "none"
        config.framebuffer_flush_address = None
        config.framebuffer_rect_flush_address = None
