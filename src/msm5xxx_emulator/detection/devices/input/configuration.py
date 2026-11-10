"""Projection of captured evidence into firmware configuration."""

def configuration_fields(layout, drivers, storage):
    return {'board_status_input': drivers.board_status_input, 'sd810_gpio_profile': drivers.sd810_profile, 'key_register': None, 'key_active_low': True,
        'guest_owned_status_72c': drivers.guest_owned_status_72c, 'boot_keysense_release': drivers.boot_keysense_release}
