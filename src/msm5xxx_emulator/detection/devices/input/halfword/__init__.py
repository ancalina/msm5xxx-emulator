"""Exact indirect halfword matrix candidates; runtime admission is separate."""
from msm5xxx_emulator.detection.facts import facts_for
import re
import struct
from msm5xxx_emulator.detection.arm import thumb_literal_value, thumb_bl_target, _thumb_successors, _thumb_reachable_preserving_register
from msm5xxx_emulator.detection.signatures import find_all
from msm5xxx_emulator.detection.devices.input.matrix import classify_matrix_event_sink
from msm5xxx_emulator.detection.devices.input.semantics import detect_keyemu_semantics
from .scanners import (TAIL, interrupt_helper, row_arms, find_indirect_matrix_scanners, _mapped_irq, _mapped_ring4, _mapped_descriptor_copy, _mapped_scan_gates,
    find_mapped_row_scanners, _loop_descriptor_copy)
from .mapping import (find_loop_row_scanners, _LOOP_CONFIRM_RULE, _LOOP_CONFIRM_SHAPES, _loop_functional_confirm, _mapped_physical_menu, _MAPPED_CONFIRM_RULE,
    _MAPPED_CONFIRM_SHAPES)
from .navigation import _mapped_functional_confirm, resolve_indirect_matrix_input
from msm5xxx_emulator.detection.contracts import _normalized_thumb_sha256 as _normalized_thumb_sha256
