"""Projection of captured evidence into firmware configuration."""

def configuration_fields(layout, drivers, storage):
    return {'rex_idle_address': drivers.rex_idle_address, 'rex_tick_address': drivers.rex_tick_address, 'rex_irq_wrapper_address': drivers.rex_irq_route[0] if
        drivers.rex_irq_route else None, 'rex_irq_handler_address': drivers.rex_irq_route[1] if drivers.rex_irq_route else None, 'rex_irq_handler_slot': drivers.rex_irq_route[2]
        if drivers.rex_irq_route else None, 'rex_irq_callback_slot': drivers.rex_irq_route[3] if drivers.rex_irq_route else None, 'rex_irq_status_address':
        drivers.rex_irq_route[4] if drivers.rex_irq_route else None, 'rex_irq_enable_address': drivers.rex_irq_route[5] if drivers.rex_irq_route else None,
        'rex_irq_arm_address': drivers.rex_irq_arm_address, 'rex_irq_mask': drivers.rex_irq_route[6] if drivers.rex_irq_route else 0, 'rex_tick_ms': drivers.rex_tick_ms,
        'rex_static_controller_candidate': drivers.rex_static_controller_candidate, 'rex_static_c40_controller_observation': drivers.rex_static_c40_controller_observation,
        'rex_basic_irq_profile': drivers.rex_basic_irq_profile, 'uis_idle_entry_address': drivers.uis_idle_entry_address, 'uis_idle_body_address': drivers.uis_idle_body_address}
