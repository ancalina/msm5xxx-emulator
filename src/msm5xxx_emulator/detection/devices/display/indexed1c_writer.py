"""Source proof for indexed halfword GRAM streaming on a 1C bus."""
from __future__ import annotations

from capstone import arm as a

from msm5xxx_emulator.detection.facts import CodeAddress, facts_for


# Candidate filter only.  The instructions at every hit are decoded and their
# typed accesses, loop control, and direct call linkage are verified below.
_COPY_STEP = bytes.fromhex('11880232a980')
_WINDOW_COMMANDS = (0x220, 0x222, 0x224, 0x226)


def _instructions_span(facts, function):
    if not function.instructions:
        return None
    start = min(pc.address for pc in function.instructions)
    end = max(pc.address + (facts.decode(pc).size if facts.decode(pc) else 0)
              for pc in function.instructions)
    if end <= start:
        return None
    return {'span': (start, end - start), 'extra_spans': tuple(
        (literal.pool, 4) for literal in function.literals)}


def _thumb_mov_imm(ins, register):
    return (ins is not None and ins.id in (a.ARM_INS_MOV, a.ARM_INS_MOVS)
            and len(ins.operands) == 2
            and ins.operands[0].type == a.ARM_OP_REG
            and ins.operands[0].reg == register
            and ins.operands[1].type == a.ARM_OP_IMM)


def _stream_shape(facts, function, candidate):
    """Return source-derived port and raster counts for one code body."""
    instructions = set(function.instructions)
    if CodeAddress(candidate, 'thumb') not in instructions:
        return None
    data = [use for use in function.accesses
            if use.operation == 'write' and use.width == 2
            and use.address is not None and use.value is None
            and use.instruction in instructions]
    # The discovered source copies a halfword loaded from its row pointer to
    # the data aperture.  Do not treat constant register writes as pixels.
    ports = {use.address for use in data if use.address >= 4 and use.address % 4 == 0}
    for data_port in sorted(ports):
        command_port = data_port - 4
        if not 0 <= command_port <= 0xfffffffc:
            continue
        pixel_writes = [use for use in data if use.address == data_port]
        if not pixel_writes:
            continue
        for branch_address, target_address in function.back_edges:
            branch_pc = CodeAddress(branch_address, 'thumb')
            branch = facts.decode(branch_pc)
            back = [use for use in pixel_writes
                    if target_address <= use.instruction.address <= branch_address]
            if (not back or branch is None or branch.id != a.ARM_INS_B
                    or branch.cc != a.ARM_CC_AL):
                continue
            # A decrement and lower-than exit implement the counted row loop;
            # the initial count must branch to this decrement before row one.
            decrement_pc = CodeAddress(branch_address - 4, 'thumb')
            exit_pc = CodeAddress(branch_address - 2, 'thumb')
            decrement, exit_branch = facts.decode(decrement_pc), facts.decode(exit_pc)
            if (decrement is None or decrement.id != a.ARM_INS_SUB
                    or len(decrement.operands) != 2
                    or decrement.operands[0].type != a.ARM_OP_REG
                    or decrement.operands[1].type != a.ARM_OP_IMM
                    or decrement.operands[1].imm != 1
                    or exit_branch is None or exit_branch.id != a.ARM_INS_B
                    or exit_branch.cc != a.ARM_CC_LO
                    or not exit_branch.operands
                    or exit_branch.operands[0].type != a.ARM_OP_IMM
                    or exit_branch.operands[0].imm != branch_address + 2):
                continue
            row_reg = decrement.operands[0].reg
            height = None
            ordered = sorted(function.instructions, key=lambda pc: pc.address)
            for index, pc in enumerate(ordered[:-1]):
                if pc.address >= target_address:
                    break
                mov = facts.decode(pc)
                jump = facts.decode(ordered[index + 1])
                if (not _thumb_mov_imm(mov, row_reg) or jump is None
                        or jump.id != a.ARM_INS_B or jump.cc != a.ARM_CC_AL
                        or len(jump.operands) != 1
                        or jump.operands[0].type != a.ARM_OP_IMM
                        or jump.operands[0].imm != decrement_pc.address):
                    continue
                value = mov.operands[1].imm
                if 0 < value <= 512:
                    height = value
            if height is None:
                continue

            width = len(back)
            if width < 2 or width > 512:
                continue
            valid_stores = True
            for use in back:
                store = facts.decode(use.instruction)
                load = facts.decode(CodeAddress(use.instruction.address - 4, 'thumb'))
                step = facts.decode(CodeAddress(use.instruction.address - 2, 'thumb'))
                adjacent_load = (step is not None and step.id == a.ARM_INS_LDRH
                    and len(step.operands) == 2
                    and step.operands[0].type == a.ARM_OP_REG
                    and store is not None and len(store.operands) == 2
                    and store.operands[0].type == a.ARM_OP_REG
                    and step.operands[0].reg == store.operands[0].reg)
                if (store is None or store.id != a.ARM_INS_STRH
                        or len(store.operands) != 2
                        or store.operands[0].type != a.ARM_OP_REG
                        or store.operands[1].type != a.ARM_OP_MEM
                        or store.operands[1].mem.disp != 4
                        or not (adjacent_load or (load is not None
                            and load.id == a.ARM_INS_LDRH
                            and len(load.operands) == 2
                            and load.operands[0].type == a.ARM_OP_REG
                            and load.operands[0].reg == store.operands[0].reg
                            and load.operands[1].type == a.ARM_OP_MEM
                            and step is not None and step.id == a.ARM_INS_ADD))):
                    valid_stores = False
                    break
            if not valid_stores:
                continue
            commands = [use for use in function.accesses
                        if use.operation == 'write' and use.address == command_port
                        and use.width == 2 and use.value == 0x28
                        and use.instruction.address < min(
                            item.instruction.address for item in back)]
            if not commands:
                continue
            return {'command_port': command_port, 'data_port': data_port,
                    'width': width, 'height': height,
                    'pixel_format': 'rgb565', 'command_site': commands[0].instruction}
    return None


def _window_shape(facts, context_start, context_end, command_port,
                  data_port, width, height):
    """Find a source body programming origin and inclusive window endpoints."""
    for at in range(context_start, context_end - 1, 2):
        ins = facts.decode(CodeAddress(at, 'thumb'))
        if ins is None or ins.id != a.ARM_INS_PUSH:
            continue
        function = facts.function(CodeAddress(at, 'thumb'), budget=1536)
        if function.truncated:
            continue
        writes = [use for use in function.accesses
                  if use.operation == 'write' and use.width == 2
                  and use.address in (command_port, data_port)]
        commands = [(index, use) for index, use in enumerate(writes)
                    if use.address == command_port and use.value in _WINDOW_COMMANDS]
        for first, command in commands:
            if command.value != _WINDOW_COMMANDS[0]:
                continue
            wanted = ((0x220, 0), (0x222, 0),
                      (0x224, width - 1), (0x226, height - 1))
            found = []
            cursor = first
            for expected_command, expected_value in wanted:
                if cursor >= len(writes):
                    break
                current = writes[cursor]
                if (current.address != command_port or current.value != expected_command
                        or cursor + 1 >= len(writes)):
                    break
                value = writes[cursor + 1]
                if value.address != data_port or value.value != expected_value:
                    break
                found.extend((current, value))
                cursor += 2
            if len(found) != 8:
                continue
            last = max(item.instruction.address for item in found)
            if any(item.address <= last for item in function.unresolved):
                continue
            evidence = _instructions_span(facts, function)
            if evidence is None:
                continue
            return function, evidence
    return None


def _profile_in_context(facts, context_start, context_end, candidate):
    call_sites = facts.call_candidates('thumb')
    targets = sorted({target for _, target in call_sites
                      if context_start <= target < context_end})
    profiles = []
    for target in targets:
        stream = facts.function(CodeAddress(target, 'thumb'), budget=2048)
        shape = _stream_shape(facts, stream, candidate)
        if shape is None:
            continue
        window = _window_shape(facts, context_start, context_end,
                               shape['command_port'], shape['data_port'],
                               shape['width'], shape['height'])
        if window is None:
            continue
        initializer, init_evidence = window
        stream_evidence = _instructions_span(facts, stream)
        if stream_evidence is None:
            continue
        caller_evidence = []
        for site, called in call_sites:
            if called == target:
                caller_evidence.append({'span': (site, 4)})
        if not caller_evidence:
            continue
        profiles.append({
            'protocol': 'indexed1c-halfword-stream',
            'command_port': shape['command_port'],
            'data_port': shape['data_port'],
            'width': shape['width'], 'height': shape['height'],
            'pixel_format': shape['pixel_format'],
            'evidence': [stream_evidence, init_evidence, *caller_evidence],
        })
    unique = {(item['command_port'], item['data_port'], item['width'],
               item['height'], item['pixel_format']) for item in profiles}
    return profiles[0] if len(unique) == 1 else None


def find_indexed1c_profile(image: bytes):
    """Recognize a called halfword GRAM streamer plus its source window setup.

    The byte sequence only narrows candidate locations; positive selection is
    based on decoded instructions, typed MMIO accesses, loop structure, and
    direct call linkage.  The indexed register/window contract selects the
    controller's packed 16-bit RGB transfer mode.
    """
    if not isinstance(image, bytes) or not image:
        return None
    cursor = 0
    profiles = []
    candidates = {}
    while True:
        candidate = image.find(_COPY_STEP + _COPY_STEP, cursor)
        if candidate < 0:
            break
        cursor = candidate + len(_COPY_STEP)
        candidates.setdefault(candidate >> 12, candidate)
    for candidate in candidates.values():
        context_start = max(0, candidate - 0x1000) & ~1
        context_end = min(len(image), candidate + 0x3000)
        context = image[context_start:context_end]
        facts = facts_for(context, base=context_start)
        profile = _profile_in_context(facts, context_start, context_end, candidate)
        if profile is not None:
            profiles.append(profile)
    unique = {(item['command_port'], item['data_port'], item['width'],
               item['height'], item['pixel_format']) for item in profiles}
    return profiles[0] if len(unique) == 1 else None
