"""Evidence-gated Yamaha audio transport detection."""
from msm5xxx_emulator.detection.facts import facts_for
from collections import defaultdict
from bisect import bisect_right
import hashlib
import re
import struct
from msm5xxx_emulator.detection.arm import _thumb_writes_register, thumb_bl_target, thumb_literal_value
from msm5xxx_emulator.detection.devices.audio.irq import find_audio_irq_candidate
from msm5xxx_emulator.detection.layout_queries import find_linker_layout
from .accesses import (_STRONG_MARKERS, _BASE_PREFIX, _THUMB_BL, _MMIO_MIN, _MMIO_MAX, _SEARCH_BYTES, _CLUSTER_GAP, _MARKER_CHUNK, _MARKER_OVERLAP,
    _marker_families, _synthesized_base_accesses, _has_backedge, _transport_clusters, _command_status_candidates, _repeated_status_candidates, _SEQUENCE_SPANS,
    _sequence_span, _unique_sequence_span, _sequence_clear_profile, _sequence_status_profile, _MA5_READBACK_SPANS)
from .ma5 import (_ma5_readback_span, _ma5_readback_transport, _ma5_timed_transport, _ma5_alternate_readback, find_ma5_readback_candidate,
    _ma2_callback_irq_profile, _thumb_short_branch_target, _thumb_condition, _thumb_bl_targets)
from .ma3 import (_thumb_readback_verifiers, _thumb_ma3_014_wrappers, _thumb_ma3_014_fifo_writer, find_ma3_indexed_candidate, _SV130_MA3_SITES,
    _KP6200_MA3_SITES, find_ma3_kp6200_candidate, find_ma3_packetized_candidate, find_ma3_readback_candidate)
from .transport import find_audio_transport
