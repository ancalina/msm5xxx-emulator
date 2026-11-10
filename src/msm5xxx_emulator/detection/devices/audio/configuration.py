"""Projection of captured evidence into firmware configuration."""

def configuration_fields(layout, drivers, storage):
    return {'audio_play_address': drivers.audio_address, 'ma2_silent_boot_address': drivers.ma2_silent_boot_address, 'audio_transport': drivers.audio_transport}
