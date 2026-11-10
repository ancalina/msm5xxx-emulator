"""Projection of captured evidence into firmware configuration."""

def configuration_fields(layout, drivers, storage):
    return {'dmd_download_address': storage.dmd_download_address}

from . import detect_dmd_download_5500 as _required_dmd_detect_dmd_download_5500
from . import download_signature_position as _required_dmd_download_signature_position
def capture_entry(layout, drivers):
    dmd_5500_position = _required_dmd_detect_dmd_download_5500(layout.primary_image)
    if dmd_5500_position is not None:
        dmd_download_address = drivers.runtime_position("dmd_download_address", dmd_5500_position)
    else:
        dmd_position = _required_dmd_download_signature_position(layout.primary_image)
        dmd_download_address = (drivers.runtime_position("dmd_download_address", dmd_position) if dmd_position is not None else None)
    return dmd_download_address
