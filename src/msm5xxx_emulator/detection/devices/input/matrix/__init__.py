"""Exact direct-MMIO keypad matrix detection."""
from msm5xxx_emulator.detection.facts import facts_for
import hashlib
import json
import re
import struct
from msm5xxx_emulator.detection.arm import (arm_b_target, _thumb_callable_entry, _thumb_fingerprint, _thumb_function_start, _thumb_path_preserves_register,
    _thumb_reachable, _thumb_reachable_preserving_register, _thumb_successors, thumb_bl_target, thumb_literal_value)
from msm5xxx_emulator.detection.signatures import find_all
from msm5xxx_emulator.detection.devices.input.semantics import (KEYEMU_GRAMMAR_FINGERPRINT, KEYEMU_PASSTHROUGH, KeyemuSemantics, detect_keyemu_semantics)
from .sideband import (DIRECT_MATRIX_TAIL, THUMB_BL, MAX_DIRECT_MATRIX_TAILS, DIRECT_MATRIX_SEMANTICS, DIRECT_MATRIX_FINGERPRINT, SAMSUNG_RING32,
    SAMSUNG_DUAL_PLANE_RING32, LG_RING256, UNCLASSIFIED, ASCII_KEY_EVENTS, SINGLE_KEY_COLUMN_SENSE, PRODUCER_FEATURES, SAMSUNG_RAW_ENQUEUE_TAIL,
    SAMSUNG_RAW_DEQUEUE, SAMSUNG_RAW_RECEIVER_TAIL, SAMSUNG_RAW_R7_MOVE, SAMSUNG_RAW_CONSUMER_EVIDENCE, SAMSUNG_RAW_R7_CONSUMER_EVIDENCE,
    SAMSUNG_RAW_SAVED_CONSUMER_EVIDENCE, _SAMSUNG_CONSUMER_ROUTE_EVENTS, _SAMSUNG_CONSUMER_ROUTE_EVIDENCE, _SAMSUNG_CONSUMER_ROUTE_LIMIT, N330_5X6_ENTRY,
    N330_PRESS_PREFIX, N330_RELEASE_PREFIX, N330_GLOBAL_SENSE, N330_ROW_SENSE, N330_5X6_SEMANTICS, N330_5X6_FINGERPRINT, _matches_relocated_thumb_bl,
    SAMSUNG_SIDEBAND_51_WORDS, _accepted_samsung_sideband_51, _samsung_sideband_51_metadata, _SAMSUNG_FLAG_SIDEBAND_CONTRACTS, _SAMSUNG_FLAG_SIDEBAND_SINK,
    _samsung_flags_sideband_51_metadata, _thumb_immediate_byte_stores, _samsung_sideband_51_family_metadata)
from .confirm import (_same_image_keyemu_ok_mapping, _SAMSUNG_CONFIRM_CONVERTER, _SAMSUNG_CONFIRM_PRESS, _SAMSUNG_CONFIRM_MESSAGE_SINK,
    _SAMSUNG_CONFIRM_NAMESPACE, _SAMSUNG_CONFIRM_RULE, _SAMSUNG_CONFIRM_FINGERPRINT, _SAMSUNG_CONFIRM_STATE_CONVERTER, _SAMSUNG_CONFIRM_STATE_RULE,
    _SAMSUNG_CONFIRM_CLOCK_CONTRACTS, _SAMSUNG_CONFIRM_CLOCK_RAW_CONTRACTS, _SAMSUNG_CONFIRM_STATE_FINGERPRINT, _confirm_clock_code_matches,
    _confirm_saved_state_clock_closed, _same_image_ring32_confirm_mapping, _SAMSUNG_SELECTED_CONFIRM_CONTRACTS, _SAMSUNG_SELECTED_CONFIRM_CALLS,
    _SAMSUNG_SELECTED_CONFIRM_R7_CONTRACTS, _SAMSUNG_SELECTED_CONFIRM_R7_CALLS)
from .queue import (_same_image_selected_confirm_mapping, _producer_feature_names, _thumb_linear_return, classify_matrix_event_sink, validate_matrix_event_sink,
    _samsung_raw_consumer_metadata, _samsung_raw_r7_consumer_metadata)
from .consumers import (_samsung_raw_saved_consumer_metadata, _samsung_consumer_route_handler, _samsung_route_match, _samsung_consumer_route_metadata,
    _thumb_inbound_entries, _find_n330_5x6_scanners, find_direct_matrix_scanners, resolve_direct_matrix_input, detect_direct_matrix_input, _distributed_word)
from .scanners import (_distributed_ram, _distributed_irq, _distributed_branch, _distributed_hop, _distributed_gpio_arm, _distributed_clear, _distributed_ring32,
    _distributed_control_profile, _DISTRIBUTED_NAVIGATION_SPANS, _DISTRIBUTED_NAVIGATION_DIVISION, _distributed_navigation_profile, _DISTRIBUTED_BACK_SPAN,
    _distributed_back_profile, _DISTRIBUTED_CALL_SPANS)
from .distributed import _distributed_call_profile, resolve_distributed_matrix_input
