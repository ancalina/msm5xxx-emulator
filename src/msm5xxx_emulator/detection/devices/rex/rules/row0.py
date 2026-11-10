from __future__ import annotations
from msm5xxx_emulator.detection.fact_bodies import thumb_body
from msm5xxx_emulator.detection.contracts import BodySpec

def find_rex_idle_address(image: bytes) -> int | None:
    """Find the final idle BL in one validated Qualcomm REX signal loop."""
    from . import THUMB_BL_PATTERN, facts_for, struct
    candidates: list[int] = []
    def unconditional_target(address: int, word: int) -> int | None:
        if word & 0xF800 != 0xE000:
            return None
        displacement = (word & 0x7FF) * 2
        if displacement & 0x800:
            displacement -= 0x1000
        return address + 4 + displacement
    fixed = { 0: 0x0BC1, 1: 0xD306, 2: 0x2108, 6: 0x2101, 7: 0x0389, 8: 0xE007, 9: 0x0B81, 10: 0xD309, 11: 0x2108, 15: 0x2101, 16: 0x0349, 21: 0x0A80, 22:
        0xD302, }
    anchor = struct.pack("<3H", fixed[0], fixed[1], fixed[2])
    offset = 0
    while (offset := image.find(anchor, offset)) >= 0:
        if offset & 1 or offset + 52 > len(image):
            offset += 1
            continue
        words = struct.unpack_from("<26H", image, offset)
        if any(words[index] != value for index, value in fixed.items()):
            offset += 2
            continue
        if any(words[index] & 0xFFC7 != 0x1C00 for index in (3, 12, 17)):
            offset += 2
            continue
        def backward_branch(index: int) -> bool:
            target = unconditional_target(offset + index * 2, words[index])
            return target is not None and target <= offset
        if not all(backward_branch(index) for index in (20, 25)):
            offset += 2
            continue
        if any(not (words[index] & 0xF800 == 0xF000 and words[index + 1] & 0xF800 == 0xF800) for index in (4, 13, 18, 23)):
            offset += 2
            continue
        idle = offset + 52
        last_bl: int | None = None
        for address in range(idle, min(len(image), idle + 0x80), 2):
            word = struct.unpack_from("<H", image, address)[0]
            following = (struct.unpack_from("<H", image, address + 2)[0] if address + 4 <= len(image) else 0)
            if word & 0xF800 == 0xF000 and following & 0xF800 == 0xF800:
                last_bl = address
                continue
            if word & 0xF800 != 0xE000:
                continue
            displacement = (word & 0x7FF) * 2
            if displacement & 0x800:
                displacement -= 0x1000
            if address + 4 + displacement <= offset:
                if last_bl is not None and last_bl + 4 == address:
                    candidates.append(last_bl)
                break
        offset += 2
    # Newer MSM5500 REX uses a distinct four-stage signal loop. Require its
    # complete setup, bit 1/15/14/10 stages, and every same-loop backedge.
    setup_fixed = { 0: 0xB5B0, 1: 0x4D21, 2: 0x4C21, 3: 0x2201, 4: 0x1C29, 5: 0x1C20, 8: 0x2201, 9: 0x0252, 10: 0x1DE0, 11: 0x3015, 12: 0x491B, 15: 0x1DE0, 16:
        0x3015, 21: 0x1C22, 22: 0x210F, 23: 0x2001, 26: 0x27FF, 27: 0x37A0, 28: 0xE007, 29: 0x1C28, 32: 0x0841, 33: 0xD307, 34: 0x200F, 37: 0x1C39, 38: 0x1C20,
        }
    stage_fixed = { 0: 0x0BC1, 1: 0xD304, 4: 0x2101, 5: 0x0389, 7: 0x0B81, 8: 0xD307, 11: 0x2101, 12: 0x0349, 13: 0x1C28, 17: 0x0A80, 18: 0xD302, }
    anchor = struct.pack("<2H", stage_fixed[0], stage_fixed[1])
    offset = 0
    while (offset := image.find(anchor, offset)) >= 0:
        function = offset - 84
        if offset & 1 or function < 0 or offset + 50 > len(image):
            offset += 1
            continue
        setup = struct.unpack_from("<42H", image, function)
        stages = struct.unpack_from("<25H", image, offset)
        def bl(words: tuple[int, ...], index: int) -> bool:
            return (words[index] & 0xF800 == 0xF000 and words[index + 1] & 0xF800 == 0xF800)
        if (any(setup[index] != value for index, value in setup_fixed.items()) or any(stages[index] != value for index, value in stage_fixed.items()) or not all(bl(setup,
            index) for index in (6, 13, 17, 19, 24, 30, 35, 39)) or not all(bl(stages, index) for index in (2, 9, 14, 19, 22))):
            offset += 2
            continue
        loop = offset - 26
        if (unconditional_target(function + 82, setup[41]) != loop or unconditional_target(offset + 12, stages[6]) != offset + 26 or any(unconditional_target(offset
            + index * 2, stages[index]) != loop for index in (16, 21, 24))):
            offset += 2
            continue
        idle = offset + 44
        target = facts_for(image).thumb_call_target(idle)
        if target is None or not 0 <= target < len(image):
            offset += 2
            continue
        callers = [match.start() for match in THUMB_BL_PATTERN.finditer(image) if not match.start() & 1 and facts_for(image).thumb_call_target(match.start()) ==
            target]
        if callers ==[idle]:
            candidates.append(idle)
        offset += 2
    candidates = sorted(set(candidates))
    return candidates[0] if len(candidates) == 1 else None

_ROW0_BODIES = { "callback": bytes.fromhex("80b5d54501daf9f009fdf9f0a9fc07043f0c0f480521fff757fd0e48d8f03afd0223184004d00c4801680539016003e0"
    "0a480168053901600520d8f07ffd08480521fff773fb002f01d1f9f097fc80bd"), "arm": bytes.fromhex("00b5d54501daf9f0d7fc08480022002169f05eff0020064908608880022005490870054900208ef043f800bd"),
    "registrar": bytes.fromhex("f0b5d54501da6bf07ffc041c0f1c6bf01dfc061c414d002f00d12f1c404841491b2c47d201a31b5d5b009f440d0f1113"
    "1517191b1d1f21232527292b2d2f313d3b393735333f4100876345e0c76343e0076441e047643fe087643de007653be0"
    "476539e0876537e0c76535e0076633e0476631e087662fe0c7662de007672be0476729e0876727e0c76725e00f6023e0"
    "4f6021e0cf611fe08f611de04f611be00f6119e0cf6017e08f6015e00f6213e04f6211e065f738f91b480088042807dc"
    "042805dc211c194800230022cbf7a4f8174918489ff714fa200117494018af4206d1c1680289d2430b881a400a800be0"
    "c1680a8801890a4006d102681180c16802890b881a430a80c168098840680180002e01d16bf0a8fbf0bd"), "init": bytes.fromhex("f0b5d54501da6bf0cffc6bf06ffc061c6bf06cfc0027134d2f81134c2785002801d16bf071fc6bf061fc6f81a7850028"
    "01d16bf069fc27870c482084a084002e01d16bf061fc0a4900204af0bdfe094901204af0b9fe00206bf064fc064855f0" "97fff0bd"), "copy": bytes.fromhex("80b4012224490a7000200870234b1f68234e3668be19234f3d681c68b44206d202e004350434f9e72b682360f9e70a70"
    "08701d4b1f681d4e3668be191c68b44204d201e00434fae72060fbe70a700870174b1f68174e3668be19174f3d681c68"
    "b44206d202e004350434f9e72b682360f9e70a700870114b1f68114e3668be191c68b44204d201e00434fae72060fbe7" "0a70087080bcf746"), "core": bytes.fromhex("04e04ee293f021e308d04de200102de910d04de20f002de90d10a0e192f021e328e081e560a29fe500a09ae55c329fe5"
    "003093e5010013e354e29f1554e29f0513ff2fe17847000000c04fe193f021e344129fe5001091e540229fe5000092e5"
    "000051e10700001a0cf068e10cf061e104a090e50f00bde810d08de20010bde804d08de20080fde8001082e504d04de2"
    "00d080e500c08de528e08de524d08de2f0000de904a091e500d091e50010bde80cf068e10cf061e1ffd0fde8"), "walker": bytes.fromhex("f0b5d54501da20f06bff071c0d4804680d4d0026ac4214d001e02468fae7a068b8420bd8a66020686168086060682168"
    "48602169e068fff76bff01e0c01ba060ebe7f0bd"), "signal": bytes.fromhex("f0b5d54501da20f0e3ff071c0c1c20f081ff051cf868061c2043f860386920400ad00020386179690648826852699142"
    "02d9876020f020ff002d01d120f078ff301cf0bd"), "scheduler": bytes.fromhex("7847000001e08ee300200fe1800082e300f021e11f0002e2120050e31a00000a88119fe5001091e584319fe5000093e5"
    "000051e11400000a001083e50030a0e1080091e5010080e2080081e500402de908d04de2f0002de910d04de2202082e3"
    "04002de900d083e50100a0e104a090e500d090e50100bde800f068e100f061e10d00a0e12cd08de2ffd0d0e802f028e1" "02f021e11eff2fe14b4b1847"), "accumulator": bytes.fromhex("0904090c8288511881807d22d2008188914207db7d23db00c91a8180016801310160f4e7f746"),
    "software": bytes.fromhex("f0b5d54501dafaf073f9071c0d1c81b0faf010f90004000c00907c68002c25d0a068401ba060a06801281fda7c682069"
    "a168451a201cfff7bdffe6686069002809d02061a060207e002801d100206061201cfff777ff26636563e01d15308ef0" "75fd7c68002c00d100e0dce70098002801d1faf0edf801b0f0bd"),
    "handler_prefix": bytes.fromhex("f0b5d54501da6bf077fecc4ccc4fcd4dcd4e3088cd4a118c08400004000c288504239843011c7088928c10400004000c" "6885084373d0288dff21"),
    "handler_row": bytes.fromhex("0121490201400cd0a06b66f736feb8890130b881012040028c4a00e004e1108401e1"), "handler_end": bytes.fromhex("fff751fe002800d06ee6388801303880f0bd"),
    "setter": bytes.fromhex("034a002801d1d16000e01161f7460000"), "default": bytes.fromhex("0248418f01314187f746"), "drain": bytes.fromhex("90b5d54501da6bf08ffe084856f0a6f9071c0024002806d0b869796966f7c8fe3c74012090bd201cfce7"),
    }

_ROW0_BODIES.update({ "zero64": bytes.fromhex("0270130a4370130c8370130ec37001710b0a43710b0c83710b0ec371f746"), "irq_enable": bytes.fromhex("7847000001e08ee300100fe1000050e38010c1034010c11301f021e11eff2fe1"),
    "drain_compact": bytes.fromhex("90b5d54501da5af03ff8084847f06cfc071c0024002806d0f868b96863f73efd3c71012090bd201cfce7"), "registrar_compact": bytes.fromhex("f0b5d54501da59f041fe041c0f1c59f0dffd061c3b4d002f00d12f1c3a483b491b2c47d201a31b5d5b009f440d0f1113"
    "1517191b1d1f21232527292b2d2f313d3b393735333f4100876339e0c76337e0076435e0476433e0876431e007652fe0"
    "47652de087652be0c76529e0076627e0476625e0876623e0c76621e007671fe047671de087671be0c76719e00f6017e0"
    "4f6015e0cf6113e08f6111e04f610fe00f610de0cf600be08f6009e00f6207e04f6205e061f78cff15a11848a6f7acfb"
    "200117494018af4206d1c1680289d2430b881a400a800be0c1680a8801890a4006d102681180c16802890b881a430a80" "c168098840680180002e01d159f076fdf0bd"),
    "software_compact": bytes.fromhex("f0b5d54501dae0f037ff071c0d1c81b0e0f0d4fe0004000c00907c68002c25d0a068401ba060a06801281fda7c682069"
    "a168451a201cfff7bdffe6686069002809d02061a060207e002801d100206061201cfff777ff6662a562e01d153087f0" "57f97c68002c00d100e0dce70098002801d1e0f0b1fe01b0f0bd"),
    })

_ROW0_BODIES.update({ "expiry_insert": bytes.fromhex("80b5d54501dafaf0d1f9071cfaf070f90104090c14484068002818d001e04068fae7bb68826893420eda026857600268"
    "3a60786007608268bb68d21a8260002901d1faf063f980bd9a1aba60e7e70748826b5760826b3a6000227a6087630029" "01d1faf053f9eee7"), "expiry_remove": bytes.fromhex("80b5d54501dafaf099f9071cfaf038f90204120c39687868002900d04860002805d001608168bb68c918816003e00029"
    "01d005488163002078603860002a01d1faf02cf980bd"), "submit": bytes.fromhex("90b5d54501da6bf0cdfb071c6bf06cfb0404240c387c002814d012480088032807dc032805dc1048002300220021cbf7"
    "41f80e490e489ff79ff9002c01d16bf061fb90bd01203874002c01d16bf05afb391c381c55f0a1fe391c064855f0a4fe" "efe7"), "queue_init": bytes.fromhex("0060406000218160c1600182f746"),
    "link_init": bytes.fromhex("00220a604a608860ca60081cf746"), "push": bytes.fromhex("90b5d54501da15f0f9fc071c0c1c15f097fc2760e7607968616079680c607c60398a01313982002801d115f097fc90bd"),
    "pop": bytes.fromhex("90b5d54501da15f0e1fc071c15f080fc3c68398a002908dd2168396021684f60398a013939820021e160002801d115f0" "7dfca06890bd"),
    "expiry_insert_compact": bytes.fromhex("80b5d54501dae0f095ff071ce0f034ff0104090c14484068002818d001e04068fae7bb68826893420eda026857600268"
    "3a60786007608268bb68d21a8260002901d1e0f027ff80bd9a1aba60e7e70748c26a5760c26a3a6000227a60c7620029" "01d1e0f017ffeee7"), "expiry_remove_compact": bytes.fromhex("80b5d54501dae0f05dff071ce0f0fcfe0204120c39687868002900d04860002805d001608168bb68c918816003e00029"
    "01d00548c162002078603860002a01d1e0f0f0fe80bd"), "submit_compact": bytes.fromhex("90b5d54501da59f0affd071c59f04efd0404240c3879002809d0794632390b48a6f756fb002c01d159f04efd90bd0120"
    "3871002c01d159f047fd391c381c47f0aaf9391c024847f0aaf9efe7"), "queue_init_compact": bytes.fromhex("0060406000210181f746"), "link_init_compact": bytes.fromhex("081c00210160f746"),
    "push_compact": bytes.fromhex("90b5d54501da12f0e0fb071c0c1c12f07efb276079680c607c60398901313981002801d112f081fb90bd"), "pop_compact": bytes.fromhex("90b5d54501da12f0cbfb071c002412f069fb011c38683a89002a0add03683b600368bb4200d17f60013a3a8100220260"
    "041c002901d112f063fb201c90bd"), })

def _row0_thumb(image: bytes, at: int, shape: str):
    from . import _ROW0_BODIES, facts_for
    body = _ROW0_BODIES[shape]
    template = thumb_body(facts_for(body), 0, len(body), literal_offsets=())
    spec = BodySpec.thumb_body(body, tuple(offset for offset, _ in template.calls), template.literal_sites)
    found = spec.match(facts_for(image), at)
    return (found.targets, found.values) if found is not None else None

def _row0_arm_literal(image: bytes, at: int, register: int) -> int | None:
    from . import struct
    if at < 0 or at & 3 or at + 4 > len(image):
        return None
    word = struct.unpack_from('<I', image, at)[0]
    literal = at + 8 + (word & 0xFFF)
    if (word & 0x0FFFF000 != 0x059F0000 | register << 12 or literal > len(image) - 4):
        return None
    return struct.unpack_from('<I', image, literal)[0]

def _row0_positions(image: bytes, shape: str):
    from . import _ROW0_BODIES, _row0_thumb
    prefix = _ROW0_BODIES[shape][:4]
    start = 0
    while (at := image.find(prefix, start)) >= 0:
        start = at + 1
        matched = _row0_thumb(image, at, shape)
        if matched is not None:
            yield at, matched

def find_rex_legacy_row0_profile(image: bytes, ram_base: int, ram_size: int, overlays=(),) -> tuple[dict | None, str]:
    """Close one copied-vector, typed row0 IRQ route; no idle injection hook.

    Five logical units with a 1000-unit carry support a virtual 5 ms policy,
    not a physical oscillator measurement. The caller enforces primary load0.
    """
    from . import REX_INTFREE_SIGNATURE, REX_INTLOCK_SIGNATURE, _ROW0_BODIES, _legacy_620_vector_copy, _ram_contains, _row0_arm_literal, _row0_positions, _row0_thumb, struct
    if (type(ram_base) is not int or type(ram_size) is not int or not _ram_contains(ram_base, 4, ram_base, ram_size)):
        return None, 'row0-ram-range-invalid'
    overlays = tuple(overlays)
    if any(any(type(getattr(item, name, None)) is not int for name in ('source', 'target', 'size')) or item.source < 0 or item.target < 0 or item.size <= 0 for
        item in overlays):
        return None, 'row0-overlay-invalid'
    callbacks = list(_row0_positions(image, 'callback'))
    if not callbacks:
        return None, 'row0-callback-none'
    copied = _legacy_620_vector_copy(image, ram_base=ram_base, ram_size=ram_size)
    if copied is None:
        return None, 'row0-vector-copy-unclosed'
    source, target, size, core = copied
    if (core & 3 or image[core:core + len(_ROW0_BODIES['core'])] != _ROW0_BODIES['core']):
        return None, 'row0-core-unclosed'
    tuple_bytes = struct.pack('<4I', source, target, size, target + size)
    fields, start = [], 0
    while (position := image.find(tuple_bytes, start)) >= 0:
        start = position + 1
        if not position & 3:
            fields.append(position)
    if len(fields) != 1:
        return None, 'row0-copy-fields-ambiguous'
    field = fields[0]
    producers = [at for at, (_, values) in _row0_positions(image, 'copy') if (values.get(0x50), values.get(0x54), values.get(0x5A)) == (field + 4, field + 8,
        field)]
    if len(producers) != 1:
        return None, 'row0-copy-producer-unclosed'
    def ram(address, length=4):
        return type(address) is int and _ram_contains(address, length, ram_base, ram_size)
    def copied_offset(address, length):
        if not ram(address, length) or not target <= address <= target + size - length:
            return None
        # Supplied CopyLayouts take precedence over the fallback tuple map.
        covering = [item for item in overlays if item.target < address + length and address < item.target + item.size]
        if covering and (len(covering) != 1 or covering[0].target > address or address + length > covering[0].target + covering[0].size or covering[0].source +
            address - covering[0].target != source + address - target):
            return None
        return source + address - target
    if copied_offset(target, 4) is None:
        return None, 'row0-overlay-copy-conflict'
    arms = list(_row0_positions(image, 'arm'))
    initializers = list(_row0_positions(image, 'init'))
    results = []
    reason = 'row0-callback-links-unclosed'
    for callback, (calls, literals) in callbacks:
        guard, lock, free = calls[6], calls[0xA], calls[0x4A]
        if (image[lock:lock + 28] != REX_INTLOCK_SIGNATURE + bytes.fromhex('1eff2fe1') or image[free:free + 28] != REX_INTFREE_SIGNATURE + bytes.fromhex('1eff2fe1')
            or image[calls[0x16]:calls[0x16] + 38] != _ROW0_BODIES['accumulator'] or image[calls[0x1C]:calls[0x1C] + 4] != bytes.fromhex('c068f746') or any(not
            ram(value, 16 if offset == 0x1A else 8) for offset, value in literals.items())):
            continue
        walker_at, software_at = calls[0x3A], calls[0x42]
        walker = _row0_thumb(image, walker_at, 'walker')
        software_shape = ('software' if _row0_thumb(image, software_at, 'software') is not None else 'software_compact')
        software = _row0_thumb(image, software_at, software_shape)
        if (walker is None or software is None or walker[0][6] != guard or software[0][6] != guard or software[0][0x10] != lock or software[0][0x72] != free or
            any(not ram(value) for value in walker[1].values())):
            continue
        compact = software_shape == 'software_compact'
        suffix = '_compact' if compact else ''
        remove = _row0_thumb(image, software[0][0x36], 'expiry_remove' + suffix)
        insert = _row0_thumb(image, software[0][0x52], 'expiry_insert' + suffix)
        context = literals[0x3E]
        if (remove is None or insert is None or remove[0][6] != guard or insert[0][6] != guard or remove[0][0xC] != lock or insert[0][0xC] != lock or remove[0][0x40]
            != free or any(insert[0][offset] != free for offset in (0x42, 0x62)) or (remove[1][0x32], insert[1][0x14], insert[1][0x4E]) != (context, context,
            context) or context & 3 or not ram(context, 0x30 if compact else 0x3C)):
            continue
        signal = _row0_thumb(image, walker[0][0x36], 'signal')
        if (signal is None or signal[0][6] != guard or signal[0][0xE] != lock or signal[0][0x3C] != free):
            continue
        state = signal[1][0x28]
        scheduler = signal[0][0x34]
        if (not ram(state, 20) or image[scheduler:scheduler + len(_ROW0_BODIES['scheduler'])] != _ROW0_BODIES['scheduler'] or _row0_arm_literal(image, scheduler
            + 0x20, 1) != state + 8 or _row0_arm_literal(image, scheduler + 0x28, 3) != state + 4 or _row0_arm_literal(image, core + 0x24, 10) != state or
            _row0_arm_literal(image, core + 0x2C, 3) != state + 12 or _row0_arm_literal(image, core + 0x38, 14) != core + 0x44 or _row0_arm_literal(image, core
            + 0x3C, 14) != core + 0x48 or _row0_arm_literal(image, core + 0x50, 1) != state + 8 or _row0_arm_literal(image, core + 0x58, 2) != state + 4):
            continue
        for arm_at, (arm_calls, arm_literals) in arms:
            if (arm_calls[6] != guard or image[arm_calls[0x10]:arm_calls[0x10] + 30] != _ROW0_BODIES['zero64'] or arm_literals[0x22] != callback | 1 or
                arm_literals[0x1E] != 0x030006E0 or arm_literals[0x16] != literals[0x12] or not ram(arm_literals[0xA], 8)):
                continue
            registrar_at = arm_calls[0x26]
            compact = software_shape == 'software_compact'
            registrar_shape = 'registrar_compact' if compact else 'registrar'
            registrar = _row0_thumb(image, registrar_at, registrar_shape)
            descriptor_literal, free_call = (0xC2, 0xFC) if compact else (0xDA, 0x114)
            if (registrar is None or registrar[0][6] != guard or registrar[0][0xE] != lock or registrar[0][free_call] != free):
                continue
            values = registrar[1]
            descriptors, slots, short, default = (values[descriptor_literal], values[0x1C], values[0x1E], values[0x14])
            slot = slots + 0x38
            descriptor_offset = copied_offset(descriptors, 27 * 16)
            slot_offset = copied_offset(slot, 4)
            default_body = _row0_thumb(image, default & ~1, 'default')
            if (descriptors & 3 or slots != descriptors + 0x178 or short != descriptors + 0x1F8 or descriptor_offset is None or slot_offset is None or not
                default & 1 or default_body is None or not ram(default_body[1][0], 0x3C) or struct.unpack_from('<I', image, slot_offset)[0] != default):
                reason = 'row0-descriptor-copy-unclosed'
                continue
            records = [struct.unpack_from('<4I', image, descriptor_offset + index * 16) for index in range(27)]
            expected = (0x03000620, 0x03000628, 0x200, descriptors - 8)
            if (records[0] != expected or not ram(descriptors - 8, 6) or[i for i, record in enumerate(records) if record[:3] == expected[:3]] !=[0]):
                reason = 'row0-descriptor-tuple-ambiguous'
                continue
            for initializer_at, (init_calls, init_literals) in initializers:
                handler = init_literals[0x46] & ~1
                setter = _row0_thumb(image, init_calls[0x4A], 'setter')
                prefix = _row0_thumb(image, handler, 'handler_prefix')
                row = _row0_thumb(image, handler + 0x102, 'handler_row')
                end = _row0_thumb(image, handler + 0x32A, 'handler_end')
                if (init_calls[6] != guard or init_calls[0xA] != lock or init_calls[0x10] != lock or init_calls[0x26] != lock or any(init_calls[offset] != free
                    for offset in (0x22, 0x32, 0x42)) or init_calls[0x4A] != init_calls[0x52] or image[init_calls[0x58]:init_calls[0x58] + 32] != _ROW0_BODIES['irq_enable']
                    or init_literals[0x1A] != 0x03000600 or init_literals[0x38] != 0xFFFF or not ram(init_literals[0x16], 12) or not ram(init_literals[0x5C],
                    0xA if compact else 0x14) or not init_literals[0x4E] & 1 or not 0 <= init_literals[0x4E] & ~1 < len(image) or setter is None or setter[1][0]
                    != state or not init_literals[0x46] & 1 or prefix is None or prefix[0][6] != guard or (prefix[1][0xA], prefix[1][0xE], prefix[1][0x10],
                    prefix[1][0x14]) != (slots, short, descriptors - 8, 0x03000600) or not ram(prefix[1][0xC], 0x3C) or row is None or image[row[0][0xA]:row[0][0xA]
                    + 2] != b'\x00\x47' or row[1][0x18] != 0x03000600 or end is None):
                    continue
                drain = _row0_thumb(image, end[0][0], 'drain_compact' if compact else 'drain')
                if (drain is None or drain[0][6] != guard or image[drain[0][0x1C]:drain[0][0x1C] + 2] != b'\x08\x47' or not ram(drain[1][0xA], 8)):
                    continue
                submit = _row0_thumb(image, software[0][0x5E], 'submit' + suffix)
                pop = _row0_thumb(image, drain[0][0xC], 'pop' + suffix)
                queue_init = _row0_thumb(image, init_calls[0x5E], 'queue_init' + suffix)
                if submit is None or pop is None or queue_init is None:
                    continue
                link_call, push_call, queue_literal = ((0x3E, 0x46, 0x44) if compact else (0x54, 0x5C, 0x5A))
                link_init = _row0_thumb(image, submit[0][link_call], 'link_init' + suffix)
                push = _row0_thumb(image, submit[0][push_call], 'push' + suffix)
                queue = drain[1][0xA]
                if (link_init is None or push is None or submit[0][6] != guard or submit[0][0xC] != lock or any(submit[0][offset] != free for offset in ((0x28,
                    0x36) if compact else (0x3E, 0x4C))) or push[0][6] != guard or push[0][0xE] != lock or push[0][0x24 if compact else 0x2A] != free or pop[0][6]
                    != guard or pop[0][0xE if compact else 0xC] != lock or pop[0][0x36 if compact else 0x2E] != free or (submit[1][queue_literal], init_literals[0x5C])
                    != (queue, queue) or queue & 3 or not ram(queue, 0xA if compact else 0x14)):
                    continue
                results.append({ 'class_name': 'legacy-row0-stackchecked-irq-v1', 'callback_file_offset': callback, 'timer_walker_file_offset': walker_at,
                    'route': (core, handler, state + 12, slot, 0x03000620, 0x03000628, 0x200), 'arm_address': 0x030006E0, 'mask': 0x200, 'logical_delta': 5,
                    'logical_carry': 1000, 'virtual_interval_ns': 5_000_000, 'idle_address': None, 'links': { 'arm_file_offset': arm_at, 'registrar_file_offset':
                    registrar_at, 'initializer_file_offset': initializer_at, 'descriptor_file_offset': descriptor_offset, 'descriptor_address': descriptors,
                    'copy_file_offset': producers[0], 'copy_source': source, 'copy_target': target, 'copy_size': size, 'software_walker_file_offset':
                    software_at, 'accumulator_file_offset': calls[0x16], 'expiry_layout': 'compact' if compact else 'extended', 'expiry_context': context,
                    'deferred_queue': queue, 'remove_file_offset': software[0][0x36], 'insert_file_offset': software[0][0x52], 'submit_file_offset': software[0][0x5E],
                    'pop_file_offset': drain[0][0xC], 'queue_init_file_offset': init_calls[0x5E]}, })
    if len(results) != 1:
        return None, 'row0-profile-ambiguous' if results else reason
    return results[0], 'accepted'
