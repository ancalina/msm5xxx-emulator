"""Projection of captured evidence into firmware configuration."""

def configuration_fields(layout, drivers, storage):
    return {'ready_poll': drivers.ready_poll}

def capture(layout):
    from . import capture_profile
    profile, notes = capture_profile(layout.primary_image, unresolved_startup_mapping=layout.ram_bootstrap_profile is not None)
    layout.detection_notes.extend(notes)
    return profile
