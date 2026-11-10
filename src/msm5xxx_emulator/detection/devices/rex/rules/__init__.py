"""Firmware REX timer, IRQ, and idle detection."""
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.contracts import _normalized_thumb_sha256
import hashlib
import re
import struct
from msm5xxx_emulator.detection.arm import arm_b_word_target, thumb_bl_target, thumb_literal_value
from msm5xxx_emulator.detection.devices.rex.vector_chain import find_nor_veneer_vector_copy
from .timer_shapes import (REX_TICK_SIGNATURE, REX_5MS_WRAPPER_ANCHOR, REX_5MS_CALLBACK_SIZE, REX_TIMER_ADVANCE_SIZE, REX_LEGACY_5MS_CALLBACK_SIZE,
    REX_TIMER_CALLBACK_DRAIN_SIZE, UIS_IDLE_ENTRY_PREFIX, UIS_IDLE_BODY_PREFIX, UIS_IDLE_BODY_DELTA, UIS_IDLE_COMPACT_ENTRY_PREFIX, UIS_IDLE_COMPACT_BODY_PREFIX,
    UIS_IDLE_COMPACT_BODY_DELTA, UIS_IDLE_DRAW_MARKER, UIS_IDLE_DRAW_BODY_DELTAS, UIS_IDLE_BODY_DELTAS, REX_IRQ_WRAPPER_SIGNATURE, REX_IRQ_WRAPPER_RUNTIME_SIZE,
    REX_IRQ_HANDLER_RUNTIME_SIZE, TRAMPM5_CONSUMER_SIZE, REX_INTLOCK_SIGNATURE, REX_INTFREE_SIGNATURE, REX_IRQ_DRAIN_PATTERN, THUMB_BL_PATTERN,
    REX_5MS_REGISTRATION_PATTERN, REX_5MS_ARM_PATTERN, rex_5ms_registration_targets, rex_timer_advance_at, legacy_rex_timer_advance_at,
    _controller_timer_advance_at, _controller_two_bank_handler_at, _controller_registrar_at, _controller_callback_advance, _c80_full_handler_span, _ram_contains,
    _legacy_620_vector_copy)
from .controller import _find_rex_620_static_controller_callback_candidate, _nand_backed_veneer_chain
from .controller_routes import find_rex_static_controller_callback_candidate, _find_rex_direct_c40_controller_observation
from .copied_routes import (_copied_c40_handler_slots, _copied_c40_delta5_callback_at, _copied_c40_time_tick_registrations,
    _find_rex_copied_c40_controller_observation, find_rex_static_c40_controller_observation, legacy_software_timer_advance_at, _legacy_rex_timer_target,
    _legacy_software_timer_target, rex_legacy_5ms_callback_shape_at, rex_legacy_5ms_callback_at, rex_timer_callback_drain_at, rex_5ms_callback_at,
    rex_sleep_call_at, trampm5_consumer_at, find_trampm5_consumer, find_rex_5ms_irq_arm)
from .timer_routes import (find_rex_5ms_irq_route, find_rex_5ms_sleep_timer, _legacy_timer_registration_at, find_rex_legacy_5ms_timer_bridge,
    _relocated_thumb_file_target)
from .idle import (find_rex_legacy_5ms_irq_route, find_rex_static_overlay_controller_callback_candidate, _thumb_adr_target, _uis_idle_event_prefix_at,
    _uis_idle_draw_prefix_at, _uis_idle_draw_pair, find_uis_idle_pair)
from .row0 import find_rex_idle_address, _ROW0_BODIES, _row0_thumb, _row0_arm_literal, _row0_positions, find_rex_legacy_row0_profile
REQUIRES = {'find_static_middle_nand_profile': ('storage.static_middle_nand', 'find_static_middle_nand_profile')}
