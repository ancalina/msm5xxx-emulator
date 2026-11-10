"""Static MA5 GPIO/parent route discovery; runtime admission stays off."""
from msm5xxx_emulator.detection.facts import facts_for
import hashlib
import re
import struct
from msm5xxx_emulator.detection.arm import thumb_bl_target, thumb_literal_value
from msm5xxx_emulator.detection.devices.audio.rules import find_ma5_readback_candidate
from .contracts import (_SPANS, _HASH_SPANS, _Reject, _span, _scan, _boot_copy, _layouts, _mapping, _check, _one, _pointer, _indirect_call_chain,
    _direct_accessor)
from .routing import _route, find_ma5_gpio_irq_candidate
