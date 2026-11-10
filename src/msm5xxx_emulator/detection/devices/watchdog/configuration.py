"""Projection of captured evidence into firmware configuration."""

def configuration_fields(layout, drivers, storage):
    return {'watchdog': None}

from .rules import find_watchdog_profile

def bind_configuration(config, image):
    watchdog_image = image[:config.flash_size]
    config.watchdog, watchdog_reason = find_watchdog_profile(watchdog_image)
    if config.watchdog is not None or b"dog.c\0" in watchdog_image:
        config.detection_notes.append(
            "watchdog admitted: unique service/pulse/task linkage"
            if config.watchdog is not None
            else f"watchdog rejected: {watchdog_reason}"
        )
