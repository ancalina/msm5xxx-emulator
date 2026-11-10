"""Network scenario API backed by the baseband protocol package."""
from msm5xxx_emulator.detection.registry import device_domain

_cell = device_domain("baseband.virtual_cell")
DEFAULT_NETWORK_TIME = _cell.DEFAULT_NETWORK_TIME
DEFAULT_LTM_OFF = _cell.DEFAULT_LTM_OFF
_crc30 = _cell._crc30
_long_code_state = _cell._long_code_state
_leap_seconds = _cell._leap_seconds
sync_message_hex = _cell.sync_message_hex
network_sync_message_hex = _cell.network_sync_message_hex
host_sync_message_hex = _cell.host_sync_message_hex
virtual_cell_scenario = _cell.virtual_cell_scenario
