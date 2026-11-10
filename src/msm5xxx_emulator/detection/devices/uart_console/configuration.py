"""Projection of captured evidence into firmware configuration."""

def configuration_fields(layout, drivers, storage):
    return {'uart_console': drivers.uart_console}

def capture(layout, ready_poll):
    from . import find_uart_console_profile, detection_note
    profile, reason = find_uart_console_profile(layout.primary_image, ready_poll, chipset=layout.chipset)
    if note := detection_note(profile, reason, ready_poll):
        layout.detection_notes.append(note)
    return profile
