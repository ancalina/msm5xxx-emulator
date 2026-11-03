"""Source-closed KP2600 keypad matrix and timer registration."""
from __future__ import annotations

import struct

from .arm import thumb_bl_target, thumb_literal_value
from .input_descriptor import _descriptor_mmio_provenance
from .input_matrix import ASCII_KEY_EVENTS


def find_kp2600_scanner(image: bytes, config: object) -> dict[str, object] | None:
    """Recover the KP2600 numeric contacts without assigning special keys."""
    if (getattr(config, 'model', None) != 'LG-KP2600'
            or getattr(config, 'load_address', None) != 0
            or getattr(config, 'flash_size', 0) < 0x77c254
            or len(image) < 0x77c254):
        return None
    image = image[:config.flash_size]
    provenance = _descriptor_mmio_provenance(image, 0x019462c4)
    if (provenance is None or provenance['kind'] != 'validated-scatter'
            or provenance['source'] != 0x77c21c):
        return None
    ops = {
        0x6d554: 0x7990, 0x6d556: 0x2800, 0x6d55e: 0x7800, 0x6d560: 0x2801,
        0x6d572: 0x6b40, 0x6d574: 0x8800, 0x6d576: 0x2310, 0x6d578: 0x4018,
        0x6d5d0: 0x6b60, 0x6d5d2: 0x8800, 0x6d5d4: 0x0940, 0x6d5d6: 0xd201,
        0x6d5d8: 0x2751, 0x6d5e0: 0x6b61, 0x6d5e2: 0x1c20, 0x6d5e4: 0x8809,
        0x6d5e6: 0x06c9, 0x6d5e8: 0x0ec9, 0x6d5ea: 0x291f,
        0x6d608: 0x2c04, 0x6d610: 0x8db1, 0x6d612: 0x231e, 0x6d614: 0x4399,
        0x6d616: 0x1c62, 0x6d618: 0x2301, 0x6d61a: 0x4093, 0x6d626: 0x4311,
        0x6d628: 0x85b1, 0x6d62c: 0x6a32, 0x6d62e: 0x8011,
        0x6d690: 0x8db1, 0x6d692: 0x0849, 0x6d694: 0x0049, 0x6d696: 0x85b1,
        0x6d6f8: 0x8bb1, 0x6d6fa: 0x2301, 0x6d6fc: 0x039b, 0x6d6fe: 0x4399,
        0x6d700: 0x83b1, 0x6d704: 0x6932, 0x6d706: 0x8011,
        0x6d710: 0x6b70, 0x6d712: 0x8800, 0x6d714: 0x06c0, 0x6d716: 0x0ec0,
        0x6d718: 0x281f, 0x6d720: 0x5c08, 0x6d728: 0x2306, 0x6d72c: 0x4358,
        0x6d72e: 0x391e, 0x6d730: 0x1840, 0xc672: 0x2002, 0xc674: 0x7008,
        0xc678: 0x201e, 0x6d9ee: 0x2219, 0x6d9f0: 0x2319,
        0x6e51e: 0x2319, 0x6e520: 0x2219,
    }
    if any(struct.unpack_from('<H', image, pos)[0] != value for pos, value in ops.items()):
        return None
    literals = ((0x6d56e, 0, 0x019462c4), (0x6d5ce, 4, 0x019462c4),
                (0x6d71c, 1, 0x271756), (0x6d72a, 1, 0x271756),
                (0xc670, 1, 0x030007a0), (0xc676, 1, 0xc605),
                (0x6d9f4, 1, 0x6d551), (0x6e522, 1, 0x6d551))
    if any(thumb_literal_value(image, pos, reg) != value for pos, reg, value in literals):
        return None
    calls = ((0x6d9f6, 0xc822), (0x6e526, 0xc822), (0xc67a, 0xa4a00),
             (0x6d78e, 0x6cd7c), (0x6d5dc, 0x6cf6a))
    if any(thumb_bl_target(image, pos) != target for pos, target in calls):
        return None
    candidate = getattr(config, 'rex_static_controller_candidate', None)
    required = {'accepted': True, 'controller_class': 'legacy-c80-index1e-delta5-controller-candidate-v1',
                'status': 0x03000c80, 'enable': 0x03000c94, 'mask': 0x200,
                'wrapper_file_offset': 0x3824, 'handler_file_offset': 0xa47a8,
                'handler_slot': 0x019fb0ec, 'callback_slot': 0x01949048,
                'callback_file_offset': 0xc604, 'vector_target': 0x01800000}
    if not isinstance(candidate, dict) or any(candidate.get(k) != v for k, v in required.items()):
        return None
    raw = list(image[0x271738:0x271756])
    columns = image[0x271756:0x271776]
    if any(raw.count(event) != 1 for event in ASCII_KEY_EVENTS):
        return None
    try:
        senses = [next(s for s in (30, 29, 27, 23, 15) if columns[s] == col)
                  for col in range(5)]
    except StopIteration:
        return None
    if len(set(senses)) != 5:
        return None
    # Scanner rows 0..4 drive bits 1,2,3,4,0; native rows use bits 0..4.
    order = (4, 0, 1, 2, 3, 5)
    events = [raw[column * 6 + row] for column in range(5) for row in order]
    return {'grammar': 'lg-descriptor-low5-6x5-raw-v1',
            'family': 'lg-kp2600-numeric-v1', 'event_sink_family': 'lg-kp2600-numeric-v1',
            'function': 0x6d550, 'descriptor_pointer': 0x019462c4,
            'descriptor_mmio_provenance': provenance['kind'],
            'raw_enqueue': 0x6cd7c, 'event_sink_validation': 'validated-raw-enqueue-callsites',
            'rows': 6, 'columns': 5, 'no_key': 31, 'sense_bits': 5,
            'register': 0x0300072c, 'event_codes': events,
            'single_key_column_sense': senses,
            'provisional_mappings': {bit: {'event': event, 'rule': 'ascii-table-entry'}
                                     for bit, event in zip(range(11, 23), ASCII_KEY_EVENTS)}}
