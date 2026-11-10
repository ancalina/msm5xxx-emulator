"""Source closure for the SV130 keypad and relocated interrupt handler."""
from __future__ import annotations
from msm5xxx_emulator.detection.contracts import fields_match
from msm5xxx_emulator.detection.facts import facts_for
import struct
from msm5xxx_emulator.detection.arm import arm_b_target, arm_b_word_target
from msm5xxx_emulator.detection.devices.input.descriptor import _descriptor_mmio_provenance
from msm5xxx_emulator.detection.devices.input.matrix import ASCII_KEY_EVENTS

def sv130_keypad_source(image: bytes, config: object, profile: dict[str, object] | None) -> bool:
    """Verify the keypad, timer, vector, and copied dispatcher as one source."""
    image = image[:getattr(config, "flash_size", len(image))]
    if (profile is None or getattr(config, 'board_status_input', None) is not None or getattr(config, 'load_address', None) != 0 or (not fields_match(profile, (('grammar',
        'lg-descriptor-low5-6x5-raw-v1'), ('function', 532844), ('descriptor_pointer', 25396212), ('row_order',[0, 1, 2, 3, 4, 5]), ('event_sink_validation',
        'validated-raw-enqueue-callsites'))))):
        return False
    provenance = _descriptor_mmio_provenance(image, 0x018383f4)
    if provenance is None or provenance["kind"] != profile.get("descriptor_mmio_provenance"):
        return False
    if (provenance["source"] + 8 > len(image) or struct.unpack_from("<I", image, provenance["source"] + 4)[0] != 0x03000720):
        return False
    events = profile.get("event_codes")
    if not isinstance(events, (list, tuple)) or any(events.count(x) != 1 for x in ASCII_KEY_EVENTS):
        return False
    bridge = profile.get("timer_bridge")
    if not isinstance(bridge, dict):
        return False
    wanted = {"scanner": 0x8216c, "outer_callback": 0xe3a4, "registrar": 0xe5c2, "initial": 25, "reload": 25, "timer_object": 0x01a33958}
    if any(bridge.get(k) != v for k, v in wanted.items()):
        return False
    route = bridge.get("irq_route")
    required = {"controller_class": "legacy-c80-three-bank-group14-v1", "outer_callback": 0xe3a4, "wrapper": 0x3460, "handler": 0x03800068,
        "handler_file_offset": 0x00de5d00, "handler_slot": 0x01a3c398, "callback_slot": 0x0183c548, "status": 0x03000c80, "enable": 0x03000c94, "mask": 0x200,
        "vector_target": 0x01800000, "index": 43}
    if not isinstance(route, dict) or any(route.get(k) != v for k, v in required.items()):
        return False
    if (getattr(config, "rex_tick_address", None) != route["outer_callback"] or getattr(config, "rex_irq_handler_address", None) != route["handler"] or getattr(config,
        "rex_irq_status_address", None) != route["status"] or getattr(config, "rex_irq_enable_address", None) != route["enable"]):
        return False
    if (len(image) <= 0x00de5d00 + 0x27c or arm_b_target(image, 0x18) != 0x01800000 or arm_b_word_target(struct.unpack_from("<I", image, 0x00da1530)[0],
        0x01800000) != 0x3460 or struct.unpack_from("<3I", image, 0x6064) != (0x00da1530, 0x01800000, 0x140)):
        return False
    overlays = getattr(config, "overlays", ())
    overlaps = [item for item in overlays if item.target < 0x038002e4 and item.target + item.size > 0x03800068]
    if (len(overlaps) != 1 or (overlaps[0].source, overlaps[0].target, overlaps[0].size) != (0x00de5c98, 0x03800000, 0x170e0)):
        return False
    if (facts_for(image).thumb_literal_value(0xe410, 1) != 0x030007a0 or struct.unpack_from("<2H", image, 0xe412) != (0x2002, 0x7008) or facts_for(image).thumb_literal_value(0xe416,
        1) != 0xe3a5 or struct.unpack_from ("<H", image, 0xe418)[0] != 0x202b or facts_for(image).thumb_call_target(0x8218c) != 0x8208e or facts_for(image).thumb_literal_value(0x82190,
        5) != 0x018383f4 or facts_for(image).thumb_literal_value(0x82094, 7) != 0x018383f4):
        return False
    scanner = {0x82192: 0x6b68, 0x82194: 0x8800, 0x822b8: 0x6b68, 0x822ba: 0x8800, 0x822bc: 0x06c0, 0x822be: 0x0ec0, 0x822d4: 0x6b68, 0x822d6: 0x8800, 0x822d8:
        0x0940, 0x822da: 0xd203}
    restore = {0x82096: 0x8db9, 0x82098: 0x0949, 0x8209a: 0x0149, 0x8209c: 0x85b9, 0x820a0: 0x6a3a, 0x820b0: 0x89b9, 0x820b2: 0x2310, 0x820b4: 0x4399, 0x820b6:
        0x81b9, 0x820bc: 0x8011}
    return all(struct.unpack_from("<H", image, pos)[0] == word for pos, word in {**scanner, **restore}.items())
