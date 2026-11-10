"""Read-only structural evidence for auxiliary builders and search result consumers.

This does not model a modem, result values, IRQs, timing, or service state.
The caller supplies a previously proven Thumb entry point; ambiguity stays a
native fallback.
"""
from msm5xxx_emulator.detection.facts import facts_for
from dataclasses import dataclass
import re
import struct
from msm5xxx_emulator.detection.arm import (_thumb_path_preserves_register, _thumb_reachable, _thumb_writes_register, _thumb_function_start, thumb_bl_target)
from .auxiliary import (_MAX_FUNCTION_BYTES, _SEMANTIC_LIMIT, AuxSelector, AuxLoad, AuxCompletionEvidence, _reject, _u16, _add_imm3, _add_reg, _add_imm8,
    _mov_imm, _mul, _cmp_reg, _shift_lsl_reg, _literal, _is_bl, _conditional_target, _load_store, _function, detect_aux_completion_shape,
    detect_search2_result_shape, _search2_task_tail)
from .search import (find_search2_transport_profile, _search1_result_at, _find_search1_result, _find_search1_writer, _S1_SITES, _S1_OFFSETS, _S1_OPS, _S1_BLOCKS,
    _find_conditional_search1_writer, find_search1_transport_profile, _finger_quality_at, _find_finger_quality, find_finger_transport_profile,
    find_decoder_init_profile)
from .decoder import (find_combiner_clock_profile, find_paging_decoder_profile, find_search1_abort_profile, _TX_INIT_CALLBACK_SHAPES, _TX_INIT_CONTROL_SHAPE,
    _tx_init_code_matches, find_tx_init_profile, _TX_FRAME_DATA_SHAPE, _TX_FRAME_TABLE, _TX_FRAME_FIXED_WRITER, find_tx_frame_profile, _TRAFFIC_READER_SHAPE,
    _TRAFFIC_METRICS_SHAPE, _TRAFFIC_INIT_SHAPE, _TRAFFIC_REGISTRATION_SHAPE)
from .traffic import (_TRAFFIC_CALLBACK_SHAPE, _TRAFFIC_DATA_CALL_SHAPE, _TRAFFIC_EMIT_SHAPE, _TRAFFIC_QUALITY_SHAPE, _TRAFFIC_ORDINARY_SHAPE,
    _TRAFFIC_VARIANT_SHAPE, _TRAFFIC_COEFFICIENTS_SHAPE, _TRAFFIC_SELECTORS_SHAPE, find_traffic_decoder_profile, find_legacy_cdma_profile)
REQUIRES = {'find_rex_5ms_irq_route': ('rex.rules', 'find_rex_5ms_irq_route'), 'rex_5ms_registration_targets': ('rex.rules', 'rex_5ms_registration_targets')}
