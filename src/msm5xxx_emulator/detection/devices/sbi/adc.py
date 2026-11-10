"""SBI board ADC reader and selector-2 policy evidence."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import struct
from ...contracts import _normalized_thumb_sha256
from ...facts import facts_for
from ...signatures import find_all

BOARD_ADC_SIGNATURE = bytes.fromhex("f1b584b00027049a002521492e1c009700200024895cd2000392ca1f033a0a31")
BOARD_ADC_READER_READ_OFFSET = 0x7E
BOARD_ADC_READER_PREFIX = bytes.fromhex("90b5071c")
BOARD_ADC_READER_BODY = bytes.fromhex("1e48802301781943017001789f2319400170022f03d10178402319430ae0"
    "032f03d101786023194304e0002f03d101782023194301700178071c0a20")
BOARD_ADC_READER_MID_BODY = bytes.fromhex("387880239843387039780a20")
BOARD_ADC_READER_TAIL = bytes.fromhex("0548808907063f0e002c01d1")
BOARD_ADC_READER_BL_OFFSETS = (0x04, 0x0C, 0x12, 0x52, 0x56, 0x5A, 0x6A, 0x6E, 0x74, 0x78, 0x88)
BOARD_ADC_READER_SIZE = 0x98
BOARD_ADC_READER_LITERAL = 0x03000780
BOARD_ADC_READER_DATA_ADDRESS = BOARD_ADC_READER_LITERAL + 0x0C
BOARD_ADC_READER_VARIANT_SIZE = BOARD_ADC_READER_SIZE + 4
BOARD_ADC_READER_VARIANT_BL_OFFSETS = (0x04, 0x0C, 0x12, 0x4E, 0x52, 0x56, 0x68, 0x6C, 0x72, 0x76, 0x86)
BOARD_ADC_READER_ANCHOR = bytes.fromhex("0404240c")
BOARD_ADC_READER_VARIANT_FIXED = ((0, BOARD_ADC_READER_PREFIX), (8, BOARD_ADC_READER_ANCHOR), (0x10, bytes.fromhex("2a20")), (0x16, bytes.fromhex("1f48802201781143017001789f2319400170022f02d10178202208e0"
    "032f02d10178602203e0002f03d10178402211430170071c01780a20")), (0x5A, bytes.fromhex("3878802398430106090e38700a20")), (0x70, bytes.fromhex("0b20")), (0x7A,
    bytes.fromhex("0748808907063f0e002c01d1")), (0x8A, bytes.fromhex("381c90bc08bc1847")),)
BOARD_ADC_READER_REORDERED_FIXED = ((0x2E, b"\x40"), (0x42, b"\x20"), (0, BOARD_ADC_READER_PREFIX), (8, BOARD_ADC_READER_ANCHOR), (0x10, bytes.fromhex("2a20")),
    (0x16, bytes.fromhex("1f48802201781143017001789f2319400170022f02d10178402208e0" "032f02d10178602203e0002f03d10178202211430170071c01780a20")), (0x5A, bytes.fromhex("3878802398430106090e38700a20")),
    (0x70, bytes.fromhex("0b20")), (0x7A, bytes.fromhex("0748808907063f0e002c01d1")), (0x8A, bytes.fromhex("381c90bc08bc1847")),)
BOARD_ADC_READER_EXTENDED_SIZE = BOARD_ADC_READER_VARIANT_SIZE + 12
BOARD_ADC_READER_EXTENDED_BL_OFFSETS = (0x04, 0x0C, 0x12, 0x4E, 0x52, 0x56, 0x68, 0x6C, 0x74, 0x78, 0x7E, 0x82, 0x92,)
BOARD_ADC_READER_EXTENDED_FIXED = ((0, BOARD_ADC_READER_PREFIX), (8, BOARD_ADC_READER_ANCHOR), (0x10, bytes.fromhex("2a20")), (0x16, bytes.fromhex("2248802201781143017001789f2319400170022f02d10178202208e0"
    "032f02d10178602203e0002f03d10178402211430170071c01780a20")), (0x5A, bytes.fromhex("3878802398430106090e38700a20")), (0x70, bytes.fromhex("80210c20")), (0x7C,
    bytes.fromhex("0b20")), (0x86, bytes.fromhex("0748808907063f0e002c01d1")), (0x96, bytes.fromhex("381c90bc08bc1847")),)
BOARD_ADC_READER_FIXED = ((0, BOARD_ADC_READER_PREFIX), (8, BOARD_ADC_READER_ANCHOR), (0x10, bytes.fromhex("2a20")), (0x16, BOARD_ADC_READER_BODY), (0x5E,
    BOARD_ADC_READER_MID_BODY), (0x72, bytes.fromhex("0b20")), (0x7C, BOARD_ADC_READER_TAIL), (0x8C, bytes.fromhex("381c90bd")),)
DC0_BOARD_ADC_SCALE_PREFIX = bytes.fromhex("88b569461520")
DC0_BOARD_ADC_SCALE_SHAPE = ("e5621ef56171f9454c9ce7e229f69400a217419ccd18f07410960033ba863af5", (0x06, 0x1A, 0x36),)
DC0_BOARD_ADC_GETTER_SHAPE = ("5518153f5d945817368f2ff4faddb98c18e50956cf987f966883943b3026aa7b", (0x12,),)
DC0_BOARD_ADC_SERVICE_SHAPE = ("0b27f75b80031a871db2964a6d942894fc7f8214c2cabf88549b1352ed4856fe", (0x04, 0x10, 0x3E, 0x5C, 0x70, 0x7A, 0x80, 0x92, 0xAA, 0xB2),)
DC0_BOARD_ADC_SEND_SHAPE = ("1346c57a455f6cde6eacdd0af0101d755515b61e6d4fcb467fd8ba8e3693cbc1", (0x5E,),)
DC0_BOARD_ADC_RECEIVE_SHAPE = ("2ae667b7657c17780af982024b29ecb9be362d0bda978ee98e6a794d3d96c069", (0x64,),)
DC0_BOARD_ADC_FILTER_SHAPE = ("e0682467707ce4f868e0d6779bab9834c97f7fe433a02ecf574dde949a68f430", (0x12, 0x74, 0x7A, 0x94, 0x9E, 0xBC, 0xC2, 0xD6, 0xE0, 0xFE,
    0x104, 0x112, 0x12E, 0x13A, 0x144, 0x148, 0x162),)

def board_adc_reader_read_offset_at(image: bytes, position: int) -> int | None:
    """Return the data-read PC offset for one pristine reader layout."""
    if position & 1 or position < 0:
        return None
    if (position + BOARD_ADC_READER_SIZE <= len(image) and not any(image[position + offset:position + offset + len(expected)] != expected for offset, expected
        in BOARD_ADC_READER_FIXED) and struct.unpack_from("<I", image, position + 0x94)[0] == BOARD_ADC_READER_LITERAL):
        return 0x7E
    if (position + BOARD_ADC_READER_VARIANT_SIZE <= len(image) and not any(image[position + offset:position + offset + len(expected)] != expected for offset,
        expected in BOARD_ADC_READER_VARIANT_FIXED) and struct.unpack_from("<I", image, position + 0x98)[0] == BOARD_ADC_READER_LITERAL):
        return 0x7C
    if (position + BOARD_ADC_READER_VARIANT_SIZE <= len(image) and not any(image[position + offset:position + offset + len(expected)] != expected for offset,
        expected in BOARD_ADC_READER_REORDERED_FIXED) and struct.unpack_from("<I", image, position + 0x98)[0] == BOARD_ADC_READER_LITERAL):
        return 0x7C
    if (position + BOARD_ADC_READER_EXTENDED_SIZE <= len(image) and not any(image[position + offset:position + offset + len(expected)] != expected for offset,
        expected in BOARD_ADC_READER_EXTENDED_FIXED) and struct.unpack_from("<I", image, position + 0xA4)[0] == BOARD_ADC_READER_LITERAL):
        return 0x88
    return None

def _reader_targets_in_image(image: bytes, position: int, offsets: tuple[int, ...]) -> bool:
    return all((target := facts_for(image).thumb_call_target(position + offset)) is not None and 0 <= target < len(image) for offset in offsets)

def board_adc_reader_at(image: bytes, position: int) -> bool:
    """Validate one shared ADC reader without matching unrelated MMIO users."""
    offset = board_adc_reader_read_offset_at(image, position)
    offsets = { 0x7E: BOARD_ADC_READER_BL_OFFSETS, 0x7C: BOARD_ADC_READER_VARIANT_BL_OFFSETS, 0x88: BOARD_ADC_READER_EXTENDED_BL_OFFSETS, }.get(offset)
    return (offsets is not None and _reader_targets_in_image(image, position, offsets))

def find_board_adc_reader(image: bytes) -> int | None:
    """Return unique shared Thumb ADC reader, never loose ADC MMIO literal hits."""
    matches = [anchor - 8 for anchor in find_all(image, BOARD_ADC_READER_ANCHOR) if anchor >= 8 and board_adc_reader_at(image, anchor - 8)]
    return matches[0] if len(matches) == 1 else None

def _dc0_board_adc_profile_at(image: bytes, scale: int,) -> tuple[dict[str, object] | None, str]:
    """Close one selector-2 raw-byte path through its battery policy."""
    def exact_shape(position: int, size: int, expected: tuple[str, tuple[int, ...]]) -> bool:
        return (_normalized_thumb_sha256(image, position, size) == expected and all((target := facts_for(image).thumb_call_target(position + offset)) is not
            None and 0 <= target < len(image) for offset in expected[1]))
    if not exact_shape(scale, 0x4C, DC0_BOARD_ADC_SCALE_SHAPE):
        return None, "selector2-helper-not-unique"
    getter = facts_for(image).thumb_call_target(scale + 0x1A)
    if (image[scale + 0x18:scale + 0x1A] != b"\x02\x20" or getter is None or not exact_shape(getter, 0x1C, DC0_BOARD_ADC_GETTER_SHAPE)):
        return None, "raw-getter/service-grammar-mismatch"
    service = facts_for(image).thumb_call_target(getter + 0x12)
    if (service is None or not exact_shape(service, 0xBE, DC0_BOARD_ADC_SERVICE_SHAPE)):
        return None, "raw-getter/service-grammar-mismatch"
    cache_roots = (facts_for(image).thumb_literal_value(getter + 0x04, 3), facts_for(image).thumb_literal_value (service + 0x14, 1), facts_for(image).thumb_literal_value(service
        + 0x66, 0), facts_for(image).thumb_literal_value(service + 0x96, 1),)
    if (cache_roots[0] is None or not 0x01000000 <= cache_roots[0] < 0x02000000 or len(set(cache_roots)) != 1):
        return None, "raw-getter/service-grammar-mismatch"
    send = facts_for(image).thumb_call_target(service + 0x5C)
    receive = facts_for(image).thumb_call_target(service + 0x92)
    if (send is None or receive is None or not exact_shape(send, 0x74, DC0_BOARD_ADC_SEND_SHAPE) or not exact_shape(receive, 0xAE, DC0_BOARD_ADC_RECEIVE_SHAPE)):
        return None, "dc0-receive-mmio-mismatch"
    if (facts_for(image).thumb_literal_value(receive + 0x04, 1) != 0x8840 or any(facts_for(image).thumb_literal_value(receive + offset, 4) != 0x03000DC0 for
        offset in (0x2E, 0x7E, 0x8A, 0x96)) or facts_for(image).thumb_literal_value(receive + 0x0A, 0) != 0x03000DC0 or any(facts_for(image).thumb_literal_value(receive
        + offset, 0) != 0x03000C80 for offset in (0x44, 0x68))):
        return None, "dc0-receive-mmio-mismatch"
    # These legacy image offsets are deliberately analyzed in the same
    # base-zero coordinate space as thumb_bl_target above.
    calls = facts_for(image, base=0).call_candidates('thumb')
    callers = [site for site, target in calls if not site & 1 and target == scale and facts_for(image).thumb_call_target(site + 4) is not None]
    filter_addresses = { facts_for(image).thumb_call_target(caller + 4) for caller in callers }
    if len(callers) != 2 or len(filter_addresses) != 1:
        return None, "battery-filter-consumer-not-unique"
    filter_address = filter_addresses.pop()
    if not exact_shape(filter_address, 0x1B4, DC0_BOARD_ADC_FILTER_SHAPE):
        return None, "battery-filter-policy-mismatch"
    filter_calls = { offset: facts_for(image).thumb_call_target(filter_address + offset) for offset in DC0_BOARD_ADC_FILTER_SHAPE[1] }
    same_targets = ((0x12, 0x148), (0x7A, 0xC2, 0x104), (0x94, 0xD6, 0x112), (0x9E, 0xE0), (0xBC, 0xFE),)
    if (any(len({filter_calls[offset] for offset in group}) != 1 for group in same_targets) or facts_for(image).thumb_literal_value(filter_address + 0x9C, 0) !=
        0x4000001B or facts_for(image).thumb_literal_value(filter_address + 0xDE, 0) != 0x4000001A):
        return None, "battery-filter-policy-mismatch"
    return { "signature": "static-dc0-selector2-battery-policy-v1", "accepted": True, "scope": "temporary-evidence-gated", "transport":
        "dc0-887e-b200-start01-lowbyte-v1", "selector": 2, "response_raw": 0xFF, "low_thresholds":[0xC8, 0xDE], "scale_offset": scale, "raw_getter_offset":
        getter, "service_offset": service, "receive_offset": receive, "filter_offset": filter_address, "caller_offsets": callers, }, ""

def find_dc0_board_adc_profile(image: bytes) -> dict[str, object] | None:
    """Return one fail-closed virtual full-battery policy, never a model gate."""
    scales = [position for position in find_all(image, DC0_BOARD_ADC_SCALE_PREFIX) if not position & 1]
    if not scales:
        return None
    profiles: list[dict[str, object]] = []
    reasons: list[str] = []
    for scale in scales:
        profile, reason = _dc0_board_adc_profile_at(image, scale)
        if profile is not None:
            profiles.append(profile)
        else:
            reasons.append(reason)
    if len(profiles) == 1:
        return profiles[0]
    return { "signature": "static-dc0-selector2-battery-policy-v1", "accepted": False, "reject_reason": ("battery-policy-ambiguous" if profiles else reasons[0]
        if len(scales) == 1 else "selector2-helper-not-unique"), }
