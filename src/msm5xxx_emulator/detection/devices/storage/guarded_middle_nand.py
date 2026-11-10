"""Copied small-page NAND driver with a shared boot and ready GPIO byte."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import struct
from msm5xxx_emulator.detection.devices.storage.middle_nand import _middle_reset

_STATUS = bytes.fromhex('00200321c9050d22520580b4702717700b78c02b08d0c12b03d0044b01309842' 'f5d3022080bc70470120fbe7')
_READY = bytes.fromhex('90b406480021064a012743681c88a30802d217701170f8e790bc7047')
_BAD_PREFIX = bytes.fromhex('f8b5010a0406240e00270d062d0e5026')
_BAD_TRANSFER = bytes.fromhex('0d20400506700220192109050870201c384308700d70')
_SWEEP_PREFIX = bytes.fromhex('f0b500270125074c0026257026707801')
_SWEEP_TAIL = bytes.fromhex('01370123db029f42f5dbf0bc08bc1847')

def find_guarded_middle_nand_profile(image: bytes) -> dict | None:
    """Close the copied RESET/status/ready and spare-read instruction graph."""
    if find_cold_power_guard(image) is None:
        return None
    found = []
    for table in range(0, min(0x10000, len(image) - 12), 4):
        source, target, size = struct.unpack_from('<III', image, table)
        if ((source | target | size) & 3 or source < table + 12 or target != 0x03800000 or not 0x1000 <= size <= 0x20000 or source + size > len(image)):
            continue
        end = source + size
        at = source
        while (at := image.find(_STATUS, at, end)) >= 0:
            status = at
            at += 2
            reset = status + 0x30
            ready = reset + 10
            spare = reset + 0x30
            sweep = reset + 0x104
            if (not _middle_reset(image, reset, end) or image[ready:ready + len(_READY)] != _READY or facts_for(image).thumb_literal_value(ready + 2, 0) !=
                0x017f0000 or facts_for(image).thumb_literal_value(ready + 6, 2) != 0x03001080 or image[spare:spare + len(_BAD_PREFIX)] != _BAD_PREFIX or
                facts_for (image).thumb_call_target(spare + 0x10) != reset or image[spare + 0x14:spare + 0x14 + len(_BAD_TRANSFER)] != _BAD_TRANSFER or
                facts_for(image).thumb_call_target(spare + 0x2a) != ready or image[sweep:sweep + len(_SWEEP_PREFIX)] != _SWEEP_PREFIX or facts_for(image).thumb_literal_value
                (sweep + 6, 4) != 0x03001080 or facts_for(image).thumb_call_target(sweep + 0x10) != reset + 0x19a or image[sweep + 0x14:sweep + 0x14 + len(_SWEEP_TAIL)]
                != _SWEEP_TAIL):
                continue
            found.append(dict(signature='guarded-copied-middle-x16-v1', data=0x01800000, address=0x01900000, command=0x01a00000, data_size=0x2000000, page_size=512,
                pages_per_block=32, bus_width=2, ready_address=0x03000720, ready_mask=2, ready_width=2, source_interval=(source, end), copy_target=target, reset=reset,
                code_intervals=((table, table + 12), (status, spare + 0x30), (sweep, sweep + 0x28))))
    return found[0] if len(found) == 1 else None

# Required evidence providers are bound by registry discovery.
REQUIRES = {'find_cold_power_guard': ('external_bus.cold_power_guard', 'find_cold_power_guard')}
