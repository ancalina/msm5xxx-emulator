from __future__ import annotations

def _thumb_readback_verifiers(image: bytes) -> list[tuple[int, int]]:
    """Find a three-range register verifier and its common read helper.

    This recognizes the compiler's loop structure by decoded Thumb fields and
    checks all three calls target one helper. It does not match firmware data.
    """
    from . import _thumb_condition, _thumb_short_branch_target, facts_for, struct
    found = []
    mov4_90 = 0x2000 | 4 << 8 | 0x90
    mov7_0 = 0x2000 | 7 << 8
    mov1_2 = 0x2000 | 1 << 8 | 2
    add_r0_r4_r7 = 0x1800 | 7 << 6 | 4 << 3
    lsl_r0_24 = 0x0600 | 24 << 6
    lsr_r0_24 = 0x0800 | 24 << 6
    def halfword(offset: int) -> int:
        return struct.unpack_from("<H", image, offset)[0]
    def eq(offset: int, value: int) -> bool:
        return offset + 2 <= len(image) and halfword(offset) == value
    anchor = struct.pack("<HH", mov4_90, mov7_0)
    start = image.find(anchor)
    while start >= 0:
        if start & 1:
            start = image.find(anchor, start + 1)
            continue
        if not (eq(start, mov4_90) and eq(start + 2, mov7_0) and eq(start + 4, 0x43FD) and eq(start + 6, add_r0_r4_r7) and eq(start + 8, mov1_2) and eq(start +
            14, lsl_r0_24) and eq(start + 16, lsr_r0_24) and eq(start + 18, 0x2800 | 0x60) and eq(start + 22, 0x3000 | 7 << 8 | 1) and eq(start + 24, 0x2800 | 7
            << 8 | 0x10) and _thumb_condition(image, start + 20) == 1 and _thumb_short_branch_target(image, start + 20) == start + 76 and _thumb_condition(image,
            start + 26) == 3 and _thumb_short_branch_target(image, start + 26) == start + 6 and eq(start + 28, 0x2000 | 4 << 8 | 0xA0) and eq(start + 30, mov7_0)
            and eq(start + 32, add_r0_r4_r7) and eq(start + 34, mov1_2) and eq(start + 40, lsl_r0_24) and eq(start + 42, lsr_r0_24) and eq(start + 44, 0x2800 |
            0x3C) and eq(start + 48, 0x3000 | 7 << 8 | 1) and eq(start + 50, 0x2800 | 7 << 8 | 0x10) and _thumb_condition(image, start + 46) == 1 and
            _thumb_short_branch_target(image, start + 46) == start + 76 and _thumb_condition(image, start + 52) == 3 and _thumb_short_branch_target(image, start
            + 52) == start + 32 and eq(start + 54, 0x2000 | 4 << 8 | 0xFF) and eq(start + 56, 0x3000 | 4 << 8 | 0x4B) and eq(start + 58, mov7_0) and eq(start +
            60, add_r0_r4_r7) and eq(start + 62, mov1_2) and eq(start + 68, lsl_r0_24) and eq(start + 70, lsr_r0_24) and eq(start + 72, 0x2800 | 0x40) and
            _thumb_condition(image, start + 74) == 0 and _thumb_short_branch_target(image, start + 74) == start + 84 and eq(start + 84, 0x3000 | 7 << 8 | 1) and
            eq(start + 86, 0x2800 | 7 << 8 | 8) and _thumb_condition(image, start + 88) == 3 and _thumb_short_branch_target(image, start + 88) == start + 60):
            start = image.find(anchor, start + 1)
            continue
        calls = [facts_for(image).thumb_call_target(start + offset) for offset in (10, 36, 64)]
        if calls[0] is not None and calls[0] == calls[1] == calls[2]:
            found.append((start, calls[0]))
        start = image.find(anchor, start + 1)
    return found

def _thumb_ma3_014_wrappers(image: bytes) -> tuple[dict[str, int], int] | None:
    """Find the four indexed byte wrappers built from 5 << 22."""
    from . import _thumb_writes_register, facts_for, struct
    wrappers: dict[str, int] = {}
    helper_targets: set[int] = set()
    setup_offsets: list[tuple[int, int]] = []
    for register in range(8):
        anchor = struct.pack("<HH", 0x2005 | register << 8, (22 << 6) | register << 3 | register,)
        offset = image.find(anchor)
        while offset >= 0:
            if not offset & 1:
                setup_offsets.append((offset, register))
            offset = image.find(anchor, offset + 1)
    setup_offsets.sort()
    for offset, register in setup_offsets:
        # These wrappers preserve LR before their direct byte access.
        if offset + 8 > len(image):
            continue
        push = struct.unpack_from("<H", image, offset + 4)[0]
        access = struct.unpack_from("<H", image, offset + 6)[0]
        if push & 0xFE00 != 0xB400 or not push & 0x100:
            continue
        if (access & 0xF800 not in (0x7000, 0x7800) or (access >> 3 & 7) != register):
            continue
        port = access >> 6 & 0x1F
        if port not in (0, 2):
            continue
        kind = "write" if access & 0xF800 == 0x7000 else "read"
        # Require a nearby call to the common bus transaction helper.
        calls = [facts_for(image).thumb_call_target(call) for call in range(offset + 8, min(len(image) - 3, offset + 0x18), 2)]
        calls = [target for target in calls if target is not None]
        if len(calls) != 1:
            continue
        key = f"{kind}_{port}"
        if key in wrappers:
            return None
        wrappers[key] = offset + 6
        helper_targets.add(calls[0])
    required = {"write_0", "read_0", "write_2", "read_2"}
    if set(wrappers) != required or len(helper_targets) != 1:
        return None
    owned_accesses: set[tuple[str, int, int]] = set()
    for offset, register in setup_offsets:
        for access_offset in range(offset + 4, min(len(image) - 1, offset + 0x30), 2):
            instruction = struct.unpack_from("<H", image, access_offset)[0]
            opcode = instruction & 0xF800
            if (opcode in (0x7000, 0x7800) and instruction >> 3 & 7 == register):
                owned_accesses.add(("write" if opcode == 0x7000 else "read", instruction >> 6 & 0x1F, access_offset,))
            if (facts_for(image).thumb_call_target(access_offset) is not None or _thumb_writes_register(instruction, register)):
                break
    expected_accesses = { (name.split("_")[0], int(name.split("_")[1]), site) for name, site in wrappers.items() }
    if owned_accesses != expected_accesses:
        return None
    return wrappers, next(iter(helper_targets))

def _thumb_ma3_014_fifo_writer(image: bytes, wrappers: dict[str, int], poller: int,) -> list[int] | None:
    """Find a linked FIFO writer with an explicit 64-byte transfer loop."""
    from . import _THUMB_BL, _thumb_short_branch_target, bisect_right, facts_for, re, struct
    starts = [match.start() for match in re.finditer(rb".\xb5", image) if not match.start() & 1]
    data_writer = wrappers["write_2"] - 6
    index_writer = wrappers["write_0"] - 6
    calls_to_data = []
    calls_to_index = []
    calls_to_poller = []
    for match in _THUMB_BL.finditer(image):
        call = match.start()
        if call & 1:
            continue
        target = facts_for(image).thumb_call_target(call)
        if target == data_writer:
            calls_to_data.append(call)
        elif target == index_writer:
            calls_to_index.append(call)
        elif target == poller:
            calls_to_poller.append(call)
    matches = []
    for call in calls_to_data:
        loop_start = None
        for position in range(max(0, call - 0x40), call, 2):
            mov = struct.unpack_from("<H", image, position)[0]
            if mov & 0xF800 == 0x2000 and mov & 0xFF == 0x40:
                loop_start = position
        if loop_start is None:
            continue
        if not any(call < branch < min(len(image) - 1, call + 0x10) and (target := _thumb_short_branch_target(image, branch)) is not None and loop_start <
            target <= call for branch in range(call + 4, min(len(image) - 1, call + 0x10), 2)):
            continue
        start_index = bisect_right(starts, loop_start) - 1
        if start_index < 0 or loop_start - starts[start_index] > 0x800:
            continue
        start = starts[start_index]
        end = starts[start_index + 1] if start_index + 1 < len(starts) else len(image)
        has_return = any((word := struct.unpack_from("<H", image, position)[0]) == 0x4770 or word & 0xFF00 == 0xBD00 or (word & 0xFF87 == 0x4700 and position >=
            start + 2 and (previous := struct.unpack_from("<H", image, position - 2)[0]) & 0xFE00 == 0xBC00 and previous & (1 << (word >> 3 & 7))) for position
            in range(start, max(start, end - 1), 2))
        if not has_return:
            continue
        relevant_calls = [c for c in calls_to_data + calls_to_index + calls_to_poller if start <= c < end]
        if (not any(c in calls_to_index and c >= start + 2 and struct.unpack_from("<H", image, c - 2)[0] & 0xF800 == 0x2000 and struct.unpack_from("<H", image,
            c - 2)[0] & 0xFF == 2 for c in relevant_calls) or not any(c in calls_to_poller for c in relevant_calls) or sum(c in calls_to_data for c in
            relevant_calls) < 2):
            continue
        matches.append(start)
    unique_matches = sorted(set(matches))
    return unique_matches or None

def find_ma3_indexed_candidate(image: bytes) -> dict[str, object]:
    """Require SC-7080 readback, packet, FIFO, poller and MMIO linkage."""
    from . import _thumb_bl_targets, _thumb_ma3_014_fifo_writer, _thumb_ma3_014_wrappers, _thumb_readback_verifiers
    rejected = {"family": "ma3", "grammar": "ma3-indexed-v1", "static_status": "rejected", "reject_reason": "verifier-none"}
    wrapper_result = _thumb_ma3_014_wrappers(image)
    if wrapper_result is None:
        rejected["reject_reason"] = "indexed-wrappers-unmatched"
        return rejected
    wrappers, wrapper_helper = wrapper_result
    verifiers = _thumb_readback_verifiers(image)
    linked: list[tuple[int, int, int, int]] = []
    for verifier, reader in verifiers:
        reader_calls = set(_thumb_bl_targets(image, reader, 0xC8))
        if not {wrappers["write_0"] - 6, wrappers["write_2"] - 6, wrappers["read_2"] - 6} <= reader_calls:
            continue
        pollers = [target for target in reader_calls if wrappers["read_0"] - 6 in _thumb_bl_targets(image, target, 0x1C)]
        for poller in pollers:
            fifo_writer = _thumb_ma3_014_fifo_writer(image, wrappers, poller)
            if fifo_writer is not None:
                linked.extend((verifier, reader, poller, writer) for writer in fifo_writer)
    if not linked:
        rejected["reject_reason"] = ("verifier-reader-fifo-linkage-mismatch")
        return rejected
    if len({entry[:3] for entry in linked}) != 1:
        rejected["reject_reason"] = "verifier-ambiguous"
        return rejected
    verifier, reader, poller = linked[0][:3]
    fifo_writers = sorted({entry[3] for entry in linked})
    return { "family": "ma3", "grammar": "ma3-indexed-v1", "static_status": "accepted", "reject_reason": None, "base": 0x01400000, "data_offset": 2,
        "verifier_entry": verifier, "register_reader": reader, "fifo_writers": fifo_writers, "status_poller": poller, "wrapper_helper": wrapper_helper, "sites":
        {name:[site] for name, site in wrappers.items()}, "block_write_offsets":[], "register_readback":[[0x90, 0xA0, 0x60],[0xA0, 0xB0, 0x3C],[0x14A, 0x152,
        0x40]], }

_SV130_MA3_SITES: dict[str, tuple[int, ...]] = { "write_0": (0x17580C, 0x175840, 0x175858, 0x175870, 0x175888, 0x1758BC, 0x1758F8, 0x175916, 0x17592E, 0x1759C0,
    0x1759D2, 0x1759DC, 0x175A06, 0x175AD0, 0x175B04, 0x175B28, 0x175BAC, 0x175BC2, 0x17645E, 0x176480, 0x17653C, 0x176558, 0x17660C, 0x17663C, 0x1766E4,
    0x17679E, 0x176844, 0x17684E, 0x176856, 0x176862, 0x17686E, 0x176894, 0x1768A2, 0x1768A8, 0x1768B0, 0x1768BC, 0x1768C6, 0x1768D4, 0x1768E6, 0x17690C,
    0x176914, 0x176920, 0x176954, 0x17695E, 0x17696C, 0x17697C, 0x17698A, 0x176A06, 0x176A34, 0x176A42, 0x176A50, 0x176A5E, 0x176A6E, 0x176A78, 0x176A8A,
    0x176A9A, 0x176AA2, 0x176ABE, 0x176AC8, 0x176ACE, 0x176ADE, 0x176B36, 0x176B48, 0x176D6A,), "read_0": (0x1B66BA, 0x1B66E0, 0x1B6706, 0x1B670E, 0x1B6724,
    0x1B672E, 0x1B6772,), "write_128": (0x175844, 0x17585E, 0x175892, 0x1758D4, 0x175904, 0x175996, 0x175A6A, 0x175A8E, 0x175AAC, 0x175AF0, 0x175B70, 0x175B88,
    0x175BB0, 0x176464, 0x176472, 0x176542, 0x17654E, 0x1765C2, 0x1765CE, 0x1767A2, 0x17684A, 0x176852, 0x17685A, 0x176866, 0x17686A, 0x176874, 0x176878,
    0x17689A, 0x17689E, 0x1768A6, 0x1768AC, 0x1768B6, 0x1768C0, 0x1768CA, 0x1768D8, 0x1768DC, 0x1768EC, 0x1768EE, 0x176910, 0x176916, 0x17692A, 0x176932,
    0x176936, 0x17693A, 0x176942, 0x17694E, 0x176958, 0x176962, 0x176970, 0x176974, 0x176978, 0x17697E, 0x176994, 0x17699C, 0x1769A0, 0x1769A4, 0x1769A8,
    0x1769B2, 0x1769BA, 0x1769C4, 0x1769C8, 0x1769CA, 0x176A0A, 0x176A38, 0x176A54, 0x176A6A, 0x176A70, 0x176A80, 0x176A8E, 0x176A9E, 0x176AA4, 0x176AC4,
    0x176ACA, 0x176AD4, 0x176D6E, 0x176D72,), "read_128": (0x175810, 0x1759D4), }
_KP6200_MA3_SITES: dict[str, tuple[int, ...]] = { "write_0": (0xE2204, 0xE220C, 0xE223E, 0xE2256, 0xE2270, 0xE2282, 0xE2298, 0xE22B0, 0xE22E6, 0xE2316, 0xE23D6,
    0xE2482, 0xE24AE, 0xE24E4, 0xE2504, 0xE2E28, 0xE2E4A, 0xE2F06, 0xE2F1E, 0xE2F7C, 0xE2FC6, 0xE2FF4, 0xE309C, 0xE31F8, 0xE31FE, 0xE3206, 0xE3212, 0xE3222,
    0xE3248, 0xE3254, 0xE325A, 0xE326E, 0xE3274, 0xE327C, 0xE3288, 0xE3298, 0xE32BE, 0xE32C4, 0xE32D4, 0xE32DA, 0xE32EA, 0xE32F0, 0xE32FA, 0xE3302, 0xE330A,
    0xE331A, 0xE3326, 0xE3340, 0xE3348, 0xE334E, 0xE3366, 0xE336C, 0xE338A, 0xE33BA, 0xE33EA, 0xE33F6, 0xE340A, 0xE3418, 0xE3424, 0xE343C, 0xE3442, 0xE3452,
    0xE36F2,), "write_4": (0xE2240, 0xE225A, 0xE228A, 0xE22C6, 0xE243C, 0xE2462, 0xE248A, 0xE24D0, 0xE2E2C, 0xE2E3C, 0xE2F0A, 0xE2F16, 0xE2F80, 0xE2F8C, 0xE31FA,
    0xE3202, 0xE320A, 0xE3216, 0xE321A, 0xE3226, 0xE3228, 0xE324C, 0xE3250, 0xE3258, 0xE325E, 0xE3270, 0xE3278, 0xE3280, 0xE328C, 0xE3290, 0xE329C, 0xE329E,
    0xE32C0, 0xE32C6, 0xE32D6, 0xE32DE, 0xE32E2, 0xE32E6, 0xE32EE, 0xE32FE, 0xE3306, 0xE330E, 0xE331E, 0xE3322, 0xE3324, 0xE332A, 0xE3336, 0xE334A, 0xE3352,
    0xE3356, 0xE335A, 0xE335E, 0xE3368, 0xE3370, 0xE337A, 0xE337E, 0xE3380, 0xE33BC, 0xE33EC, 0xE33FC, 0xE3414, 0xE341A, 0xE3426, 0xE343E, 0xE3444, 0xE36F6,
    0xE36F8,), "read_0": (0x1147F4, 0x11482C, 0x114834, 0x11484A, 0x114854, 0x1148A8,), "read_4": (0xE220E,), }

def find_ma3_kp6200_candidate(image: bytes) -> dict[str, object]:
    """Require the closed KP6200 verifier, reset, FIFO, and callback paths."""
    from . import _KP6200_MA3_SITES, _synthesized_base_accesses, _thumb_readback_verifiers, facts_for, struct
    rejected = { "family": "ma3", "grammar": "ma3-kp-readback-fifo-v1", "static_status": "rejected", "reject_reason": "verifier-none", }
    verifier, reader = 0xE316E, 0xE230C
    verifier_body = verifier - 2
    if (verifier, reader) not in _thumb_readback_verifiers(image):
        rejected["reject_reason"] = "verifier-reader-linkage-mismatch"
        return rejected
    required_calls = { (0xE3178, reader), (0xE3192, reader), (0xE31AE, reader), (0xE322A, verifier_body), (0xE32A0, verifier_body), (0xE22B6, 0x1148A0), (0xE22D6,
        0x1148A0), (0xE236A, 0x1148A0), (0xE2394, 0x1147EA), (0xE1884, 0xE31CC), (0xE189C, 0xE31CC), (0xE1B9E, 0xE36B4), (0xE36DA, verifier_body), (0xE1C38,
        0x8EB0), }
    for source, target in required_calls:
        if facts_for(image).thumb_call_target(source) != target:
            rejected["reject_reason"] = "verifier-poller-reset-callgraph-mismatch"
            return rejected
    # The byte callback at E21F6 is installed through the same initializer
    # that reaches the verifier-backed device setup.
    if (facts_for(image).thumb_literal_value(0x8EE8, 2) != 0xE21F5 or facts_for(image).thumb_call_target(0xE1C38) != 0x8EB0):
        rejected["reject_reason"] = "fifo-callback-linkage-mismatch"
        return rejected
    expected = {name: list(sites) for name, sites in _KP6200_MA3_SITES.items()}
    actual = [a for a in _synthesized_base_accesses(image) if a["base"] == 0x02C00000]
    excluded = {(0x8E9C, "write", 0), (0x1147BC, "read", 0)}
    actual_keys = { (int(a["offset"]), str(a["kind"]), int(a["port_offset"])) for a in actual }
    expected_keys = { (site, "write", int(name[6:])) for name, sites in expected.items() if name.startswith("write_") for site in sites } | { (site, "read", int(name[5:]))
        for name, sites in expected.items() if name.startswith("read_") for site in sites }
    if actual_keys != expected_keys | excluded:
        rejected["reject_reason"] = "owned-site-set-mismatch"
        return rejected
    for name, sites in expected.items():
        opcode = 0x7000 if name.startswith("write_") else 0x7800
        for site in sites:
            if struct.unpack_from("<H", image, site)[0] & 0xF800 != opcode:
                rejected["reject_reason"] = "owned-site-opcode-mismatch"
                return rejected
    return { "family": "ma3", "grammar": "ma3-kp-readback-fifo-v1", "static_status": "accepted", "reject_reason": None, "base": 0x02C00000, "data_offset": 4,
        "verifier_entry": verifier, "register_reader": reader, "fifo_writers":[0xE22A4], "status_pollers":[0x1148A0, 0x1147EA, 0x114824], "block_write_offsets":[],
        "sites": expected, "register_readback":[[0x90, 0xA0, 0x60],[0xA0, 0xB0, 0x3C],[0x14A, 0x152, 0x40]], }

def find_ma3_packetized_candidate(image: bytes) -> dict[str, object]:
    """Require the closed SV130 readback, packet, FIFO, and poll graph."""
    from . import _SV130_MA3_SITES, _thumb_readback_verifiers, facts_for, struct
    rejected = { "family": "ma3", "grammar": "ma3-readback-fifo-v1", "static_status": "rejected", "reject_reason": "verifier-none", }
    verifier, reader = 0x1767BE, 0x175924
    if (verifier, reader) not in _thumb_readback_verifiers(image):
        rejected["reject_reason"] = "verifier-reader-linkage-mismatch"
        return rejected
    required_calls = { (0x1767C8, reader), (0x1767E2, reader), (0x1767FE, reader), (reader + 0x5E, 0x1B676C), (reader + 0x8A, 0x1B66D8), (0x17687A, verifier - 2),
        (0x1768F0, verifier - 2), (0x176CA4, 0x17681C), (0x176CC2, 0x1758B0), (0x176CD8, 0x1758B0), (0x1758C4, 0x1B676C), (0x1758E4, 0x1B676C), (0x175710,
        0x1B6744), (0x1B6748, 0x1B66FE), (0x175C50, 0x1759E8), (0x175C7E, 0x1759E8), (0x175CA6, 0x175B10), (0x175D30, reader), (0x175DC8, 0x1759E8), (0x175DF4,
        0x175B10), (0x175E00, 0x1759E8), (0x175E46, 0x1759E8), (0x175E54, 0x175B10), (0x175E80, 0x1759E8), (0x175EF4, 0x1759E8), (0x175F02, 0x175B10), (0x175F2A,
        0x1759E8), (0x1760D6, reader), (0x17610C, reader), (0x17612C, 0x1758B0), (0x1761E4, 0x1758B0), (0x17621C, reader), (0x176298, 0x1758B0), (0x1762AA,
        reader), (0x1762C8, 0x1758B0), (0x1763F2, 0x1766F0), (0x176400, 0x1758B0), (0x176442, 0x1766F0), (0x176562, 0x176630), (0x176584, 0x1758B0), (0x1765D4,
        0x1758B0), (0x176670, 0x1758B0), (0x176696, 0x1758B0), (0x1766B2, 0x1758B0), (0x176746, 0x1758B0), (0x176B22, 0x1758B0), (0x176D44, 0x1769F0), (0x176D48,
        verifier - 2), (0x176D74, verifier - 2), (0x176D98, 0x1758B0), (0x176DAE, 0x1758B0), (0x1BBF72, 0x1763C8), (0x1BBF7A, 0x176630), (0x1BBE1E, 0x1766F0), (0x1BC524,
        0x1766F0), (0x1BC7F8, 0x1769F0), (0x1BC800, 0x1765B4), (0x1BCB3C, 0x1769F0), (0x1BCB88, 0x1769F0), (0x1BCC4C, 0x1769F0), }
    for source, target in required_calls:
        if facts_for(image).thumb_call_target(source) != target:
            rejected["reject_reason"] = "packet-poller-callgraph-mismatch"
            return rejected
    # The common state object is used by the bus readback path, packet error
    # handling, and the reset path. This also excludes the isolated early
    # LCD-port initialization store from device ownership.
    shared_state_refs = ((0x175812, 2, 0x01872D9C), (0x175986, 5, 0x01872D9C), (0x176918, 1, 0x01872D9C),)
    for position, register, expected in shared_state_refs:
        if facts_for(image).thumb_literal_value(position, register) != expected:
            rejected["reject_reason"] = "shared-audio-state-unmatched"
            return rejected
    expected = {name: list(sites) for name, sites in _SV130_MA3_SITES.items()}
    for name, sites in expected.items():
        is_write = name.startswith("write_")
        opcode = 0x7000 if is_write else 0x7800
        for site in sites:
            if site < 0 or site + 2 > len(image):
                rejected["reject_reason"] = "owned-site-out-of-range"
                return rejected
            instruction = struct.unpack_from("<H", image, site)[0]
            if instruction & 0xF800 != opcode:
                rejected["reject_reason"] = "owned-site-opcode-mismatch"
                return rejected
    return { "family": "ma3", "grammar": "ma3-readback-fifo-v1", "static_status": "accepted", "reject_reason": None, "base": 0x02800000, "data_offset": 0x80,
        "verifier_entry": verifier, "register_reader": reader, "fifo_writers":[0x1758B0, 0x175B10], "status_pollers":[0x1B66FE, 0x1B66D8, 0x1B676C],
        "block_write_offsets":[], "sites": expected, "register_readback":[[0x90, 0xA0, 0x60],[0xA0, 0xB0, 0x3C],[0x14A, 0x152, 0x40]], }

def find_ma3_readback_candidate(image: bytes) -> dict[str, object]:
    """Require a linked reset verifier, transaction reader, and MMIO wrappers."""
    from . import _synthesized_base_accesses, _thumb_bl_targets, _thumb_readback_verifiers, defaultdict, find_ma3_indexed_candidate, find_ma3_kp6200_candidate, find_ma3_packetized_candidate
    indexed = find_ma3_indexed_candidate(image)
    if indexed["static_status"] == "accepted":
        return indexed
    packetized = find_ma3_packetized_candidate(image)
    if packetized["static_status"] == "accepted":
        return packetized
    kp6200 = find_ma3_kp6200_candidate(image)
    if kp6200["static_status"] == "accepted":
        return kp6200
    rejected = {"family": "ma3", "grammar": "ma3-readback-v1", "static_status": "rejected", "reject_reason": "verifier-none"}
    # SCH-E140's independently confirmed window. Other bus encodings need their
    # own verifier/helper linkage before this profile can admit them.
    base, stride = 0x02840000, 2
    accesses = [a for a in _synthesized_base_accesses(image) if a["base"] == base]
    by_port: defaultdict[int, dict[str, list[int]]] = defaultdict(lambda: {"read":[], "write":[]})
    for access in accesses:
        by_port[int(access["port_offset"])][str(access["kind"])].append(int(access["offset"]))
    if (set(by_port) != {0, stride} or any(len(by_port[p][kind]) != 1 for p in (0, stride) for kind in ("read", "write"))):
        rejected["reject_reason"] = "wrapper-sites-unmatched"
        return rejected
    wrapper = {f"{kind}_{port}": by_port[port][kind][0] - 6
               for port in (0, stride) for kind in ("read", "write")}
    if any(target < 0 or target & 1 for target in wrapper.values()):
        rejected["reject_reason"] = "wrapper-sites-unmatched"
        return rejected
    verifiers = _thumb_readback_verifiers(image)
    linked = []
    for verifier, reader in verifiers:
        reader_calls = set(_thumb_bl_targets(image, reader, 0xC8))
        required = {wrapper["write_0"], wrapper["write_2"], wrapper["read_2"]}
        if not required <= reader_calls:
            continue
        pollers = reader_calls - required - {wrapper["read_0"]}
        if any(wrapper["read_0"] in _thumb_bl_targets(image, poller, 0x50) for poller in pollers):
            linked.append((verifier, reader))
    if len(linked) != 1:
        rejected["reject_reason"] = ("verifier-ambiguous" if linked else "verifier-reader-linkage-mismatch")
        return rejected
    verifier, reader = linked[0]
    return { "family": "ma3", "grammar": "ma3-readback-v1", "static_status": "accepted", "reject_reason": None, "base": base, "data_offset": stride,
        "verifier_entry": verifier, "register_reader": reader, "sites": { name:[site + 6] for name, site in wrapper.items()}, "block_write_offsets":[],
        "register_readback":[[0x90, 0xA0, 0x60],[0xA0, 0xB0, 0x3C],[0x14A, 0x152, 0x40]], }
