"""Static descriptor-keypad evidence; deliberately no runtime transport."""
from msm5xxx_emulator.detection.facts import facts_for
import re
import struct
from collections import defaultdict
from msm5xxx_emulator.detection.arm import (_thumb_callable_entry, _thumb_fingerprint, _thumb_function_start, _thumb_path_preserves_register, _thumb_reachable,
    _thumb_successors, thumb_bl_target, thumb_literal_value)
from msm5xxx_emulator.detection.devices.input.matrix import ASCII_KEY_EVENTS, _thumb_inbound_entries
from .scanners import (LG_DESCRIPTOR_RAW, LG_DESCRIPTOR_RAW_FINGERPRINT, RAW_CONSUMER_EVIDENCE, LG_OBSERVED_SEMANTIC_FINGERPRINT, LG_OBSERVED_KEY_EVENTS,
    RAW_RING_STORE, RAW_DEQUEUE_HEAD, RAW_THUMB_BL, DESCRIPTOR_SCAN_ANCHORS, DESCRIPTOR_MMIO_ROLES, find_descriptor_scan_anchors,
    find_lg_descriptor_scan_anchors, _last_literal, _descriptor_pointer, _observed_lg_mappings, _raw_consumer_metadata, _descriptor_mmio_provenance,
    _low5_senses, _descriptor_senses, _row_bounds, _descending_row_register, find_descriptor_ram_scan_shapes, _table_base, _event_table, _row_order)
from .provenance import _row_state, _sense_roles, _row_register, find_lg_descriptor_keypad_candidates, resolve_lg_descriptor_input
