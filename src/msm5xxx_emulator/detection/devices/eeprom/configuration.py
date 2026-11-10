"""Projection of captured evidence into firmware configuration."""

def configuration_fields(layout, drivers, storage):
    return {'eeprom_read_address': storage.eeprom_read_address, 'eeprom_write_address': storage.eeprom_write_address, 'eeprom_geometry_address': storage.eeprom_geometry_address,
        'eeprom_static_capacity': storage.eeprom_static_capacity}

from . import capture_entries as _required_eeprom_capture_entries
def capture_entries(layout, drivers):
    eeprom_entries = _required_eeprom_capture_entries(layout.primary_image)
    eeprom_read_address = (drivers.runtime_position('eeprom_read_address', eeprom_entries.read) if eeprom_entries.read is not None else None)
    eeprom_write_address = (drivers.runtime_position('eeprom_write_address', eeprom_entries.write) if eeprom_entries.write is not None else None)
    eeprom_geometry_address = eeprom_entries.geometry
    eeprom_static_capacity = eeprom_entries.capacity
    layout.detection_notes.extend(eeprom_entries.notes)
    return (eeprom_read_address, eeprom_write_address, eeprom_geometry_address, eeprom_static_capacity,)
