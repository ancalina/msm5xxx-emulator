from __future__ import annotations
import hashlib
import json
from .sideband import ASCII_KEY_EVENTS

def _same_image_keyemu_ok_mapping(profile: dict[str, object], semantics: KeyemuSemantics,) -> dict[int, dict[str, object]]:
    """Bind OK only when matrix and exact native KEYEMUL share event ABI."""
    from . import KEYEMU_GRAMMAR_FINGERPRINT, KEYEMU_PASSTHROUGH
    if (semantics.confidence != "exact-native" or semantics.grammar_fingerprint != KEYEMU_GRAMMAR_FINGERPRINT):
        return {}
    semantic_events = dict(semantics.event_map)
    if (semantic_events.get("O") != (0x53,) or semantic_events.get("release") != (0xFF,)):
        return {}
    events = list(profile.get("event_codes", ()))
    shared = (*map(ord, KEYEMU_PASSTHROUGH), 0x53)
    if any(events.count(event) != 1 for event in shared):
        return {}
    return {5: { "event": 0x53, "rule": "same-image-exact-keyemul-O-unique-cell", "evidence": ("exact-keyemul-semantics+unique-matrix-event-namespace"),
        "semantic_grammar_fingerprint": KEYEMU_GRAMMAR_FINGERPRINT, }}

_SAMSUNG_CONFIRM_CONVERTER = bytes.fromhex("512834d021dc342848d00edc312841d006dc23284ed02a284ad030285ed1f7463228"
    "39d0332859d1f74638283cd006dc352835d0362835d037284fd1f746392834d05028" "4ad1be20f7465f2840d010dc552841d007dc52282ed0532830d054283cd1c220f746"
    "5b2828d05e2836d1bf20f746652828d007dc60282bd0632821d064282bd19220f746" "66281fd0872825d19420f7463120f7463220f7463420f7463520f7463620f7463820"
    "f7463920f7462a20f7462320f7460820f7468120f7468320f7468d20f7468e20f746" "9120f746c020f746c120f746c320f7460123db031843f746")
_SAMSUNG_CONFIRM_PRESS = bytes.fromhex("00b582b0012100ab197059705880684600f000f802b000bd")
_SAMSUNG_CONFIRM_MESSAGE_SINK = bytes.fromhex("80b410490cc908399a1a402a17da0e4a402b06da5f1cdb004f609f180cc80cc708e0"
    "5f1cdb009a184f60d71fff3f0cc8fa3f0cc748680968401a80bcf7460020c043fae7")
_SAMSUNG_CONFIRM_NAMESPACE = (*ASCII_KEY_EVENTS, 0x53, 0x54, 0x55, 0x5B, 0x63, 0x64, 0x65, 0x66,)
_SAMSUNG_CONFIRM_RULE = "same-image-ring32-confirm-consumer-v1"
_SAMSUNG_CONFIRM_FINGERPRINT = hashlib.sha256(_SAMSUNG_CONFIRM_CONVERTER + _SAMSUNG_CONFIRM_PRESS + _SAMSUNG_CONFIRM_MESSAGE_SINK + bytes(_SAMSUNG_CONFIRM_NAMESPACE)
    + b"raw-dequeue-delta:0x60;paired-raw-guards+saved-r7-press-v1").hexdigest()
_SAMSUNG_CONFIRM_STATE_CONVERTER = bytes.fromhex("522852d022dc352850d010dc312846d006dc232854d02a2850d030285ed1f7463228"
    "3ed033283ed0342857d1f746392842d006dc36283bd037283bd038284dd1f7465028" "4bd0512848d14ae063283fd012dc5b2838d007dc532837d0542844d055283bd1c320"
    "f7465e283ad05f283ad0602833d1c120f7460021c943792836d007dc642828d06528" "24d0662826d19120f7467a282bd0872820d19420f7463120f7463220f7463320f746"
    "0be03520f7463620f7463720f7463920f7462a20f7462320f7460820f7468120f746" "8320f7468d20f7468e20f7469220f74609e0be20f746bf20f746c020f746c220f746"
    "081cf7460123db031843f746")
_SAMSUNG_CONFIRM_STATE_RULE = "same-image-ring32-confirm-saved-state-v1"
_SAMSUNG_CONFIRM_CLOCK_CONTRACTS = { "clock": (130, "fa8ec97207aa8b5c1f7825c4b80878c6f96a6b0e037c5e33774b4a4cd63f7aa0"), "hardware": (64,
    "91a7e5a29998704101222fab0e80895d9f83e7678423c38fd25c005c6b82c7d8"), "copy": (14, "382df184ea60a0c8346efe76cf05e08520406e57bdd881dd782c65a8ae140571"),
    "assign": (12, "c4be156fe24ce917ee6573eb030476ef39f44a9966ac68d9bf055ffa82899089"), "add": (34,
    "84e1145cff7f91a33235d0e682fabe9fbdb609262463ece765910670f762f0ba"), "sum": (92, "812185ab79eb3b4c33af50ea4da425d621e07e9cb8d6e9505285b36009eb244e"),
    "multiply": (64, "4d2b12f5d49fbd1520a1537fb0fcc5090f193023a79fb297ef3234c39aad89c3"), "divide": (72,
    "8ad910c95849e7e5858cef1d53832b0e6f474c6f191398c9c049f089ff5d69a8"), }
_SAMSUNG_CONFIRM_CLOCK_RAW_CONTRACTS = { "lock": (28, "05bb1a2e651a889ae08f19e98607f956161b40424ed99b20b412b687a6667f10"), "unlock": (28,
    "d961305ca13c6c8a3d2a5bd54d508f2977a58483bff33d6de0ae24fa06c4fe82"), "scalar": (72, "ca730b18f8ed52cbcee991280aafffbb0d5520734787dba42d7fa265689aa3d9"), }
_SAMSUNG_CONFIRM_STATE_FINGERPRINT = hashlib.sha256(_SAMSUNG_CONFIRM_STATE_CONVERTER + _SAMSUNG_CONFIRM_PRESS + _SAMSUNG_CONFIRM_MESSAGE_SINK + bytes(_SAMSUNG_CONFIRM_NAMESPACE)
    + json.dumps(_SAMSUNG_CONFIRM_CLOCK_CONTRACTS, sort_keys=True).encode() + json.dumps(_SAMSUNG_CONFIRM_CLOCK_RAW_CONTRACTS, sort_keys=True).encode() +
    b"raw-dequeue-delta:0x66;saved-state+0x20;aligned-clock-output+0x18").hexdigest()

def _confirm_clock_code_matches(image: bytes, at: int, size: int, digest: str, *, raw: bool = False) -> bool:
    from . import hashlib, struct
    if at < 0 or at & 1 or at + size > len(image):
        return False
    block = bytearray(image[at:at + size])
    if not raw:
        offset = 0
        while offset + 2 <= size:
            word = struct.unpack_from("<H", block, offset)[0]
            if (word & 0xF800 == 0xF000 and offset + 4 <= size and struct.unpack_from("<H", block, offset + 2)[0] & 0xF800 == 0xF800):
                block[offset:offset + 4] = bytes.fromhex("00f000f8")
                offset += 4
                continue
            if word & 0xF800 == 0x4800:
                block[offset] = 0
            offset += 2
    return hashlib.sha256(block).hexdigest() == digest

def _confirm_saved_state_clock_closed(image: bytes, call: int, raw_call: int) -> bool:
    """Preserve saved payload under aligned task-stack/callee-saved ABI."""
    from . import _SAMSUNG_CONFIRM_CLOCK_CONTRACTS, _SAMSUNG_CONFIRM_CLOCK_RAW_CONTRACTS, _confirm_clock_code_matches, _thumb_path_preserves_register, arm_b_target, facts_for
    if not _thumb_path_preserves_register(image, raw_call - 0xA, raw_call + 0xA, raw_call + 0xC, 4):
        return False
    clock = facts_for(image).thumb_call_target(call + 0x10)
    if clock is None or not _confirm_clock_code_matches(image, clock, *_SAMSUNG_CONFIRM_CLOCK_CONTRACTS["clock"]):
        return False
    nodes = {"clock": clock}
    for name, offset in (("lock", 0xA), ("copy", 0x20), ("hardware", 0x26), ("unlock", 0x2E), ("assign", 0x4A), ("multiply", 0x56), ("add", 0x60), ("sum", 0x6A)):
        target = facts_for(image).thumb_call_target(clock + offset)
        if target is None:
            return False
        nodes[name] = target
    if facts_for(image).thumb_call_target(clock + 0x7A) != nodes["add"]:
        return False
    if nodes["lock"] & 3 or nodes["unlock"] & 3:
        return False
    divide = facts_for(image).thumb_call_target(nodes["hardware"] + 0x2E)
    stub = facts_for(image).thumb_call_target(nodes["multiply"] + 0x20)
    if (divide is None or stub is None or stub < 0 or stub & 3 or image[stub:stub + 8] != bytes.fromhex("784700000030a0e3")):
        return False
    scalar = arm_b_target(image, stub + 8)
    if scalar is None or scalar & 3:
        return False
    nodes.update(divide=divide, scalar=scalar)
    if any(not _confirm_clock_code_matches(image, nodes[name], *contract) for name, contract in _SAMSUNG_CONFIRM_CLOCK_CONTRACTS.items()):
        return False
    if any(not _confirm_clock_code_matches(image, nodes[name], *contract, raw=True) for name, contract in _SAMSUNG_CONFIRM_CLOCK_RAW_CONTRACTS.items()):
        return False
    state = facts_for(image).thumb_literal_value(raw_call + 8, 5)
    destination = facts_for(image).thumb_literal_value(raw_call - 0xC, 4)
    hardware = nodes["hardware"]
    flag = facts_for(image).thumb_literal_value(hardware + 8, 2)
    inputs = (facts_for(image).thumb_literal_value(clock + 6, 6), facts_for(image).thumb_literal_value(clock + 0x10, 0), facts_for(image).thumb_literal_value(clock
        + 0x6E, 0))
    return (state is not None and destination is not None and flag is not None and 0x01000000 <= state <= 0x04000000 - 0x24 and not state & 3 and destination ==
        state + 0x18 and 0x01000000 <= flag < 0x04000000 and not destination <= flag < state + 0x24 and all(value is not None and not value & 3 and 0x01000000
        <= value <= 0x04000000 - 0x5C for value in inputs) and facts_for(image).thumb_literal_value(hardware + 2, 1) == 0x030006E0 and facts_for(image).thumb_literal_value(hardware
        + 0x28, 3) == 0x3C1)

def _same_image_ring32_confirm_mapping(image: bytes, profile: dict[str, object], load_address: int,) -> tuple[dict[int, dict[str, object]], dict[str, object]]:
    """Bind one provisional confirm class to its physical scanner's raw ring."""
    from . import SAMSUNG_RAW_CONSUMER_EVIDENCE, SAMSUNG_RAW_R7_CONSUMER_EVIDENCE, SAMSUNG_RAW_SAVED_CONSUMER_EVIDENCE, SAMSUNG_RING32, THUMB_BL, _SAMSUNG_CONFIRM_CONVERTER, _SAMSUNG_CONFIRM_FINGERPRINT, _SAMSUNG_CONFIRM_MESSAGE_SINK, _SAMSUNG_CONFIRM_NAMESPACE, _SAMSUNG_CONFIRM_PRESS, _SAMSUNG_CONFIRM_RULE, _SAMSUNG_CONFIRM_STATE_CONVERTER, _SAMSUNG_CONFIRM_STATE_FINGERPRINT, _SAMSUNG_CONFIRM_STATE_RULE, _confirm_saved_state_clock_closed, _matches_relocated_thumb_bl, _thumb_path_preserves_register, _thumb_successors, facts_for, find_all, struct
    def reject(reason: str):
        return {}, { "ok_mapping_status": "rejected", "ok_mapping_reject_reasons":[reason], }
    dequeue = profile.get("raw_dequeue")
    ring = profile.get("raw_ring")
    if (profile.get("event_sink_family") != SAMSUNG_RING32 or type(dequeue) is not int or type(ring) is not int or not 0x01000000 <= ring < 0x04000000 or
        profile.get("raw_consumer_evidence") not in (SAMSUNG_RAW_CONSUMER_EVIDENCE, SAMSUNG_RAW_R7_CONSUMER_EVIDENCE, SAMSUNG_RAW_SAVED_CONSUMER_EVIDENCE,)):
        return reject("raw-consumer-not-closed")
    dequeue -= load_address
    if dequeue & 1 or not 0 <= dequeue <= len(image) - 2:
        return reject("raw-consumer-not-closed")
    events = list(profile.get("event_codes", ()))
    if any(events.count(event) != 1 for event in _SAMSUNG_CONFIRM_NAMESPACE):
        return reject("namespace-not-unique")
    converters = [position for position in find_all(image, _SAMSUNG_CONFIRM_CONVERTER) if not position & 1]
    saved_state = not converters
    if saved_state:
        converters = [position for position in find_all(image, _SAMSUNG_CONFIRM_STATE_CONVERTER) if not position & 1]
    if len(converters) != 1:
        return reject("exact-converter-missing-or-ambiguous")
    converter = converters[0]
    calls = []
    for match in THUMB_BL.finditer(image):
        call = match.start()
        if not call & 1 and facts_for(image).thumb_call_target(call) == converter:
            calls.append(call)
            if len(calls) > 1:
                break
    if len(calls) != 1:
        return reject("converter-caller-not-unique")
    call = calls[0]
    raw_call = call - (0x66 if saved_state else 0x60)
    end = min(len(image), call + 0x100)
    if (raw_call < (0xC if saved_state else 0) or call + (0x1A if saved_state else 0x18) > len(image) or facts_for(image).thumb_call_target(raw_call) != dequeue):
        return reject("dequeue-call-mismatch")
    def word(at: int) -> int:
        return struct.unpack_from("<H", image, at)[0]
    if word(raw_call + 4) != 0x2800 or word(raw_call + 6) & 0xFF00 != 0xD000:
        return reject("raw-release-guard-unclosed")
    empty = set(_thumb_successors(image, raw_call + 6, end)) - {raw_call + 8}
    raw_guard = None
    if (saved_state and word(raw_call + 8) & 0xFF00 == 0x4D00 and word(raw_call + 0xA) == 0x1C26 and word(raw_call + 0xC) == 0x28FF):
        raw_guard = raw_call + 0xE
        shape = "saved-state-timestamp"
    elif not saved_state and word(raw_call + 8) == 0x28FF:
        raw_guard = raw_call + 0xA
        shape = "valid-event-timestamp"
    elif (not saved_state and word(raw_call + 8) & 0xFF00 == 0x4D00 and word(raw_call + 0xA) == 0x28FF):
        raw_guard = raw_call + 0xC
        shape = "conditional-timestamp"
    if (raw_guard is None or word(raw_guard) & 0xFF00 != 0xD100 or set(_thumb_successors(image, raw_guard, end)) != {raw_guard + 2, call}):
        return reject("raw-release-guard-unclosed")
    if shape == "saved-state-timestamp":
        press_call = call + 0x16
        skip = set(_thumb_successors(image, call + 0xC, end)) - {call + 0xE}
        valid = (image[call + 4:call + 0xC] == bytes.fromhex("01232c1cd8422862") and word(call + 0xC) & 0xFF00 == 0xD000 and len(skip) == 1 and press_call + 4
            <= next(iter(skip)) < end and word(call + 0xE) == 0x1C30 and word(call + 0x14) == 0x6A20)
        if valid and not _confirm_saved_state_clock_closed(image, call, raw_call):
            return reject("saved-state-clock-unclosed")
    elif shape == "valid-event-timestamp":
        press_call = call + 0x14
        skip = set(_thumb_successors(image, call + 0xA, end)) - {call + 0xC}
        valid = (image[call + 4:call + 0xA] == bytes.fromhex("0123071cd842") and word(call + 0xA) & 0xFF00 == 0xD000 and len(skip) == 1 and press_call + 4 <=
            next(iter(skip)) < end and word(call + 0xC) & 0xFF00 == 0x4800 and facts_for(image).thumb_call_target(call + 0xE) is not None and word(call + 0x12)
            == 0x1C38)
    else:
        press_call = call + 0x12
        valid = (image[call + 4:call + 8] == bytes.fromhex("071cbf28") and word(call + 8) & 0xFF00 == 0xD100 and set(_thumb_successors(image, call + 8, end)) ==
            {call + 0xA, call + 0x10} and word(call + 0xA) & 0xFF00 == 0x4800 and facts_for(image).thumb_call_target(call + 0xC) is not None and word(call +
            0x10) == 0x1C38)
    if (not valid or (not saved_state and not _thumb_path_preserves_register(image, call + 8, press_call, press_call + 4, 7))):
        return reject("translated-press-shape-unclosed")
    if len(empty) != 1 or not press_call + 4 <= next(iter(empty)) < end:
        return reject("raw-release-guard-unclosed")
    press = facts_for(image).thumb_call_target(press_call)
    if (press is None or not _matches_relocated_thumb_bl(image, press, _SAMSUNG_CONFIRM_PRESS, 0x10)):
        return reject("press-message-abi-mismatch")
    sink = facts_for(image).thumb_call_target(press + 0x10)
    if (sink is None or sink < 0 or image[sink:sink + len(_SAMSUNG_CONFIRM_MESSAGE_SINK)] != _SAMSUNG_CONFIRM_MESSAGE_SINK or any(value is None or not
        0x01000000 <= value < 0x04000000 for value in (facts_for(image).thumb_literal_value(sink + 2, 1), facts_for(image).thumb_literal_value(sink + 0xE, 2)))):
        return reject("message-sink-unclosed")
    mapping = {5: { "event": 0x53, "semantic_status": "provisional-cross-firmware-class", "rule": _SAMSUNG_CONFIRM_RULE, "evidence": ("scanner-linked-dequeue+exact-converter+press-message"
        "+cross-firmware-selection"), "semantic_grammar_fingerprint": _SAMSUNG_CONFIRM_FINGERPRINT, "raw_dequeue": load_address + dequeue, "converter_callsite":
        load_address + call, "converter": load_address + converter, "press_callsite": load_address + press_call, "press_message_sink": load_address + sink, }}
    if saved_state:
        mapping[5].update(semantic_status="temporary-evidence-gated-provisional", rule= _SAMSUNG_CONFIRM_STATE_RULE, evidence=
            "scanner-linked-dequeue+exact-converter+saved-state-aligned-clock+selection", semantic_grammar_fingerprint=_SAMSUNG_CONFIRM_STATE_FINGERPRINT,)
    return mapping, { "ok_mapping_status": "accepted-provisional", "ok_mapping_reject_reasons":[], }

_SAMSUNG_SELECTED_CONFIRM_CONTRACTS = { "forward": (0x22, "a82a693082c37767e527ac1df24d750dc40815274f994d7e43903c9a15772c39"), "producer": (0x56,
    "09a173fa9dd25688356d81a519adf2c8b617f1d57d2abb4ca30afebe41f854e5"), "secondary": (0x48, "a47287de448513c662e1ac63fa5e3ec7d2f9535a4f8f2eb7d3ee9fefee362bca"),
    "app_entry": (0xa, "ccdcc5ee91d181ce899800e591373fffd5343c5de39a96256c7da02f77a09143"), "publication": (0x20,
    "581dea6532be030c7209cddb7b32e3be90b7720985576e00c2c2ad9da870bf90"), "global_read": (0x6, "7397c36f60ea6cc51accecc3a8ba91bf7749ab0af2d290d872f8088f84c7a815"),
    "outer_state": (0x3e, "5e65b75af7973fedf6c5e0db52b3dd4b7bd8ff0df3a632dea2bbd8eebdffcf67"), "outer_switch": (0x10,
    "900b91635772354d9306a1ea8110f6c36b8e8d138fdb33087affd0d2817e1e2d"), "selected_call": (0x6,
    "b66c8ed91a4020eaec181945b26894b4f3a2db40b912cb11e85ef95abc43048d"), "handler_entry": (0x176,
    "6ba42eae5c8c331857328c00db03feb74b891c434e35932716d319ad2024d7b8"), "raw_arm": (0x6c, "18d6524c531bf14a34a53358b33318be95a31a18d8d78d17a3e71d34e4a6e2d3"),
    "selection": (0x76, "6c43208e6c0aa4b60053e00d2c9cae4608738d43d21be9bf7bd0c0769723eddb"), "tail": (0x4,
    "4675585148c0fb1462e06481e2d1b0af350d646c8f72a3667e90cfa6987b707b"), "tail_return": (0x14,
    "d9911698f6ab57051a34c8f10416968e9620c51bfd36cd7beb731f16e0d04a25"), "state_bridge": (0x22,
    "03345c7c07e1e841d9d9221facf9524a4815f84677c0f6a5d2c2d94d9f5ead36"), "selected_entry": (0x70,
    "fbc78c769cde05a0d034efe7d9c987dcb51f6a0a83f1304d6a7390d0d7acf884"), "child": (0x1b6, "d0289a434aa3bf903d0a4e568e7dbb13ea0384487431e050efa9cad1d72b896f"), }
_SAMSUNG_SELECTED_CONFIRM_CALLS = { 'selected_entry': ((20, 184492), (76, -100084), (100, -720), (108, 91880)), 'handler_entry': ((60, -5692), (370, 31610)),
    'outer_state': ((4, 11486), (16, 793034), (22, 3990), (34, 793034)), 'forward': ((30, -16860),), 'producer': ((38, -266836),), 'secondary': ((42, 288614), (54,
    198054)), 'publication': ((6, 538862), (22, 7294)), 'selected_call': ((0, -103832),), 'raw_arm': ((8, 3226), (18, 1860), (90, 29718)), 'selection': ((28,
    5300), (114, 30150)), 'tail_return': ((6, -31236),), 'state_bridge': ((28, 31214),), 'child': ((0, -87088), (116, 11596), (158, -87088), (214, -36672), (372,
    -36408), (414, - 843540)), }
_SAMSUNG_SELECTED_CONFIRM_R7_CONTRACTS = { "forward": (0xe, "da9d79d109f0c671b2046c34cff9d24a958f9dbae15e6bef145518cec1578282"), "producer": (0x56,
    "d662f2637720591872248a9c5caa11c30fa4a85d0029ef6994d61d48e89ac7d0"), "secondary": (0x48, "d18fec36b09b8112a88fffd688dc8c68d6447ceae40257c4378c275cf5892b99"),
    "app_entry": (0xc, "18e4e0a4812bef75cb9a4cd963b0edd98c1874927a064e0b9ec1788d11cb5061"), "app_global": (0x52,
    "ab431ddae520ae2001acd7045bb3ea7f14859628f4f56e4d8b579f12ebdec0c1"), "publication": (0x24,
    "5014d8f335d44c9bc6c59ad2c6840fa1a021b11c6b8ed2f29d3d4dd0ff38e3a3"), "global_read": (0x8, "05e12fb1e0c6013e95fc8ab523e344af782ee15562d1d5fffb4ea30a16309822"),
    "outer_state": (0x18, "c38bb314d9f9cf349e4928e1fb8471297c1505a73f5da8b63895cc0f1590a267"), "selected_call": (0x6,
    "9654c47d0ebf7cfcf984272cc39e85a6aa18be447ee7398387b0a93a8d05cb16"), "handler_entry": (0x144,
    "36117dd5d08324edbf15fbbee6c670712111a0bc70b5f5ff80bc9bba1fa55f9b"), "raw_arm": (0x6a, "369b7934df1c1341ac2d625f1e65cb70bd1949274cacd465d107247769313b53"),
    "selection": (0x9e, "24ca207bd734c98b28ac8b86445496d2e50063c5c380a4a57adf9651175263a8"), "tail_return": (0x14,
    "9ed889db0586d19de2470b8cbbb2f0d8598bb6be4fe3d94571b1130a113c9e8b"), "state_bridge": (0x20,
    "6929f319ffdad8ba5828b88adcf80e5052debb2e3906685a64581362f0957a7a"), "selected_entry": (0x64,
    "d234c08652ef27d94c9f5f9ecbc81bcdc5e3c7b6acb8931e35f7a94d6b00a36d"), "child": (0x206, "e07e4b74ddfa1ebe1c7c39f4d2a5c48a3c5836201f3e754dee9652cfc926f9c0"), }
_SAMSUNG_SELECTED_CONFIRM_R7_CALLS = {'forward': ((10, -16104),), 'producer': ((38, -259788),), 'secondary': ((42, 248016), (54, 188048)), 'app_global': ((12, -813002),
    (46, -166444), (68, 498846)), 'publication': ((14, 488656), (28, 8028)), 'selected_call': ((0, -102116),), 'handler_entry': ((56, -5904), (320, 33884)),
    'raw_arm': ((16, 1914), (64, 30214)), 'selection': ((28, 18232), (154, 29898)), 'tail_return': ((6, -33560),), 'state_bridge': ((28, 33548),),
    'selected_entry': ((64, -91922), (88, -618), (96, 90182)), 'child': ((0, -73500), (130, 26664), (224, -73500), (286, -31224), (296, 18812), (438, -30960), (482,
    -811088))}
