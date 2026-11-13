"""High-linked small-page NAND bootstrap code and supplied load descriptors."""
from __future__ import annotations

import struct
from capstone import arm as a
from msm5xxx_emulator.detection.facts import CodeAddress, facts_for
from msm5xxx_emulator.detection.values import SymbolicValue
from msm5xxx_emulator.detection.capabilities import (
    Capability, Decision, Evidence, ResourceClaim, resolve_proposals,
)
REQUIRES = {
    '_reset_called': ('external_bus.observations', 'reset_called'),
    '_reset_helper_source_spans': ('external_bus.observations', 'reset_helper_source_spans'),
    'find_indexed28': ('display.indexed28_writer', 'find_indexed28'),
    'find_boot_nand_word': ('storage.boot_nand_word', 'find_boot_nand_word'),
    'word_machine_plan': ('storage.boot_nand_word_plan', 'machine_plan'),
}

_HIGH = 0xffff0000
_PREFIX = 0x4000


def _returns(facts, function):
    return tuple(pc for pc in function.instructions
                 if (ins := facts.decode(pc)) is not None
                 and (ins.id == a.ARM_INS_BX and ins.operands[0].reg == a.ARM_REG_LR
                      or ins.id == a.ARM_INS_POP and any(
                          op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_PC
                          for op in ins.operands)))


def _constant_result(facts, entry):
    function = facts.function(entry, budget=32)
    returns = _returns(facts, function)
    if (not function.complete or function.unresolved or function.truncated
            or function.calls or function.accesses or not returns):
        return None
    values = {facts.register_value(function, pc, a.ARM_REG_R0, follow_stack=True)
              for pc in returns}
    if len(values) != 1:
        return None
    value = next(iter(values))
    return (value.value, function) if isinstance(value, SymbolicValue) and value.kind == 'const' else None


def _span(facts, function, source_offset=0):
    addresses = [pc.address for pc in function.instructions]
    begin = min(addresses)
    end = max(pc.address + facts.decode(pc).size for pc in function.instructions)
    return {'span': [source_offset + begin - facts.base, end - begin],
            'extra_spans': [[source_offset + pool.pool - facts.base, 4]
                            for pool in function.literals]}


def _commands(function):
    return tuple(use.value for use in function.accesses
                 if use.operation == 'write' and use.address == 0x64000300
                 and use.width == 1 and use.predicate == a.ARM_CC_AL)


def _released_input(stage, facts):
    for target in _reset_called(stage) or ():
        if not target & 1:
            continue
        function = facts.function(CodeAddress(target & ~1), budget=2048)
        if not function.complete or function.unresolved or function.truncated:
            continue
        for read in function.accesses:
            if (read.operation, read.address, read.width) != ('read', 0x58000070, 1):
                continue
            at = read.instruction.address
            code = [facts.decode(CodeAddress(at + delta)) for delta in (0, 2, 4, 6, 8)]
            if any(ins is None or ins.size != 2 for ins in code):
                continue
            register = code[0].operands[0].reg
            if (any(ins.id != opcode or len(ins.operands) != 3
                    or ins.operands[0].reg != register or ins.operands[1].reg != register
                    or ins.operands[2].type != a.ARM_OP_IMM or ins.operands[2].imm != 27
                    for ins, opcode in zip(code[1:3], (a.ARM_INS_LSL, a.ARM_INS_LSR)))
                    or code[3].id != a.ARM_INS_CMP
                    or code[3].operands[0].reg != register
                    or code[3].operands[1].type != a.ARM_OP_IMM
                    or code[3].operands[1].imm != 31
                    or code[4].id != a.ARM_INS_B or code[4].cc != a.ARM_CC_EQ):
                continue
            absent = facts.function(CodeAddress(code[4].operands[0].imm), budget=32)
            returns = _returns(facts, absent)
            if (not absent.complete or absent.unresolved or absent.calls or absent.accesses
                    or not returns or any(facts.register_value(absent, pc, a.ARM_REG_R0,
                        follow_stack=True) != SymbolicValue.const(0) for pc in returns)):
                continue
            if not any(use.operation == 'write' and 0x58000000 <= use.address < 0x58000070
                       and function.dominates(use.instruction, read.instruction)
                       for use in function.accesses):
                continue
            return function, absent, _reset_helper_source_spans(stage, target)
    return None


def _two_bit_completion(facts, function):
    if not function.complete or function.unresolved or function.calls:
        return False
    for access in function.accesses:
        if (access.operation, access.address, access.width) != ('read', 0x80000c84, 4):
            continue
        code = [facts.decode(CodeAddress(access.instruction.address + delta))
                for delta in (0, 2, 4, 6, 8)]
        if any(ins is None for ins in code):
            continue
        register = code[0].operands[0].reg
        if (all(ins.id == opcode and len(ins.operands) == 3
                and ins.operands[0].reg == register and ins.operands[1].reg == register
                and ins.operands[2].type == a.ARM_OP_IMM and ins.operands[2].imm == shift
                for ins, opcode, shift in zip(code[1:3], (a.ARM_INS_LSL, a.ARM_INS_LSR), (17, 30)))
                and code[3].id == a.ARM_INS_CMP and code[3].operands[0].reg == register
                and code[3].operands[1].type == a.ARM_OP_IMM and code[3].operands[1].imm == 3
                and code[4].id == a.ARM_INS_B and code[4].cc == a.ARM_CC_EQ
                and any(pc.address == (code[4].operands[0].imm & 0xffffffff) for pc in _returns(facts, function))):
            return True
    return False


def _uart_tx_poll(facts, stage_size):
    """Require reset-linked byte polls for the two UART aliases, using bit 3."""
    references = facts.reset_references(CodeAddress(0, 'arm'), limit_address=stage_size)
    for entry in references.entries:
        if entry not in references.calls or entry.isa != 'thumb':
            continue
        function = facts.function(entry, budget=256)
        if (not function.complete or function.unresolved or function.truncated
                or function.calls):
            continue
        instructions = {pc.address: facts.decode(pc) for pc in function.instructions}
        literal_registers = set()
        for literal in function.literals:
            ins = instructions.get(literal.instruction.address)
            if (literal.value == 0x80000f10 and ins is not None
                    and ins.id == a.ARM_INS_LDR
                    and ins.operands[0].type == a.ARM_OP_REG
                    and ins.operands[0].reg == literal.register):
                literal_registers.add(literal.register)
        if not literal_registers:
            continue
        accesses = {use.instruction.address: use for use in function.accesses
                    if use.operation == 'read' and use.width == 1}
        direct = alternate = False
        for address, access in accesses.items():
            read = instructions.get(address)
            if (read is None or read.id != a.ARM_INS_LDRB or len(read.operands) != 2
                    or read.operands[1].type != a.ARM_OP_MEM
                    or read.operands[1].mem.disp != 4):
                continue
            base = read.operands[1].mem.base
            if access.address not in (0x80000f14, 0x80000e94) or base not in literal_registers:
                continue
            is_direct = access.address == 0x80000f14
            is_alternate = (access.address == 0x80000e94 and any(
                (previous := instructions.get(prior)) is not None
                and previous.id == a.ARM_INS_SUB and len(previous.operands) == 2
                and previous.operands[0].reg == base
                and previous.operands[1].type == a.ARM_OP_IMM
                and previous.operands[1].imm == 0x80
                for prior in range(max(entry.address, address - 32), address, 2)))
            if not (is_direct or is_alternate):
                continue
            shift = instructions.get(address + 2)
            branch = instructions.get(address + 4)
            if (shift is None or shift.id != a.ARM_INS_LSL or len(shift.operands) != 3
                    or shift.operands[1].reg != read.operands[0].reg
                    or shift.operands[2].type != a.ARM_OP_IMM
                    or shift.operands[2].imm != 28
                    or branch is None or branch.id != a.ARM_INS_B
                    or branch.cc != a.ARM_CC_PL or not branch.operands
                    or branch.operands[0].type != a.ARM_OP_IMM
                    or branch.operands[0].imm >= address):
                continue
            target = branch.operands[0].imm
            if not any(target <= pc.address < address
                       and (decoded := instructions.get(pc.address)) is not None
                       and decoded.id == a.ARM_INS_STRB
                       for pc in function.instructions):
                continue
            if not any(pc.address >= branch.address + branch.size
                       and instructions.get(pc.address) is not None
                       and instructions[pc.address].id == a.ARM_INS_POP
                       and any(op.type == a.ARM_OP_REG and op.reg == a.ARM_REG_PC
                               for op in instructions[pc.address].operands)
                       for pc in function.instructions):
                continue
            direct |= is_direct
            alternate |= is_alternate
        if direct and alternate:
            callers = []
            for caller_entry in references.entries:
                caller = facts.function(caller_entry, budget=256)
                if any(target == entry for _, target in caller.calls):
                    callers.append(caller)
            if callers:
                return (function, *callers)
    return None


def find_boot_nand(image: bytes):
    """Require linked controller operations, geometry, and an executable load record."""
    if not isinstance(image, bytes) or len(image) < 0x14000:
        return None
    prefix = image[:_PREFIX]
    if any(struct.pack('<I', value) not in prefix
           for value in (0x80001600, 0x64000300, 0x80000c80)):
        return None
    high = facts_for(prefix, base=_HIGH)
    reset = high.function(CodeAddress(_HIGH, 'arm'), budget=512)
    if not reset.complete or reset.unresolved or reset.truncated:
        return None
    writes = {(use.address, use.width, use.value) for use in reset.accesses
              if use.operation == 'write' and use.predicate == a.ARM_CC_AL}
    if not {(0x80001600, 4, 0), (0x600000c0, 4, 0x12200),
            (0x80001220, 1, 0x21), (0x80001220, 2, 0x20)} <= writes:
        return None
    boot_calls = [target for _, target in reset.calls
                  if target.isa == 'arm' and _HIGH < target.address < _HIGH + 0x2000]
    if len(boot_calls) != 1:
        return None
    boot = high.function(boot_calls[0], budget=128)
    linked_helpers = {target.address for _, target in boot.calls}
    if not any(target.isa == 'thumb' and target.address in linked_helpers
               for _, target in boot.calls):
        return None
    found = []
    for pointer in sorted({literal.value for literal in reset.literals
                           if _HIGH <= literal.value <= _HIGH + 0x2000 - 0x3c}):
        table = pointer - _HIGH
        entries = struct.unpack_from('<15I', prefix, table)
        indices = (3, 4, 5, 6, 9, 10, 11, 13)
        if any(not entries[index] & 1 or not _HIGH <= (entries[index] & ~1) < _HIGH + 0x2000
               for index in indices):
            continue
        getters = [_constant_result(high, CodeAddress(entries[index] & ~1)) for index in (3, 4, 5, 6)]
        if any(item is None for item in getters):
            continue
        blocks, pages, data, raw = (item[0] for item in getters)
        if not (0x100 <= blocks <= 0x4000 and (pages, data, raw) == (32, 512, 528)):
            continue
        operations = [high.function(CodeAddress(entries[index] & ~1), budget=512,
                        initial_memory=True, initial_registers={a.ARM_REG_R0: pointer})
                      for index in (9, 10, 11, 13)]
        if any(not operation.complete or operation.unresolved or operation.truncated
               for operation in operations):
            continue
        init, program, erase, read = operations
        if tuple(map(_commands, operations)) != ((0, 7, 5, 6), (3, 6), (4, 6), (1,)):
            continue
        if any(not {(0x80000c84, 4, 0x4000), (0x80000c84, 4, 0x2000)} <= {
                (use.address, use.width, use.value) for use in operation.accesses
                if use.operation == 'write'} for operation in operations):
            continue
        if any(not any(use.operation == 'read' and use.address == 0x64000308 and use.width == 4
                       for use in operation.accesses) for operation in (program, erase, read)):
            continue
        if any(not any(use.operation == 'write' and use.address == 0x64000304 and use.width == 4
                       for use in operation.accesses) for operation in (program, erase, read)):
            continue
        copies = None
        for operation, source in ((read, True), (program, False)):
            matches = {site.target for site in operation.call_sites
                       if dict(site.registers).get(a.ARM_REG_R2) == 512
                       and dict(site.registers).get(a.ARM_REG_R1 if source else a.ARM_REG_R0) == 0x64000000}
            copies = matches if copies is None else copies & matches
        if len(copies) != 1:
            continue
        copy_entry = next(iter(copies))
        if not _HIGH <= copy_entry.address < _HIGH + 0x2000:
            continue
        copy = high.function(copy_entry, budget=1024)
        if not copy.complete or copy.unresolved or copy.calls:
            continue
        field_waits = ({target for _, target in program.calls}
                       & {target for _, target in erase.calls}) - {target for _, target in read.calls}
        if len(field_waits) != 1:
            continue
        field_wait = high.function(next(iter(field_waits)), budget=128)
        if not _two_bit_completion(high, field_wait):
            continue
        waits = {target for _, target in init.calls} & {target for _, target in read.calls}
        if len(waits) != 1:
            continue
        wait = high.function(next(iter(waits)), budget=128)
        if (not wait.complete or wait.unresolved or wait.calls
                or not any(test.read.address == 0x80000c84 and test.mask == 0x2000
                           and test.when_set and any(pc.address == test.target for pc in _returns(high, wait))
                           for test in high.bit_tests(wait))):
            continue
        # The scan callback adds page 16 before invoking the table's page reader.
        scanners = [high.function(target, budget=2048) for _, target in boot.calls
                    if target.isa == 'thumb']
        scanner = None
        for candidate in scanners:
            for pc in candidate.instructions:
                ins = high.decode(pc)
                if (ins.id == a.ARM_INS_ADD and len(ins.operands) == 2
                        and ins.operands[0].reg == a.ARM_REG_R1
                        and ins.operands[1].type == a.ARM_OP_IMM and ins.operands[1].imm == 16):
                    following = high.decode(CodeAddress(pc.address + 2))
                    if (following is not None and following.id == a.ARM_INS_LDR
                            and following.operands[1].type == a.ARM_OP_MEM
                            and following.operands[1].mem.disp == 0x34):
                        scanner = candidate
        if scanner is None:
            continue
        source, destination, length = struct.unpack_from('<3I', image, 16 * 512)
        if (destination != 0 or source & 0x1ff or not 0x4000 <= length <= 0x10000
                or source < _PREFIX or source + length > len(image)):
            continue
        stage = image[source:source + length]
        stage_facts = facts_for(stage)
        vectors = stage_facts.vectors()
        if not vectors or vectors[0][0].address != 0 or not 0 <= vectors[0][1].address < length:
            continue
        presence = _released_input(stage, stage_facts)
        if presence is None:
            continue
        uart_poll = _uart_tx_poll(stage_facts, len(stage))
        if uart_poll is None:
            continue
        reachability = stage_facts.reset_references(
            CodeAddress(0, 'arm'), limit_address=len(stage))
        source_spans = []
        for pc, size, _ in reachability.source_sites:
            start, end = source + pc.address, source + pc.address + size
            if source_spans and start <= sum(source_spans[-1]):
                source_spans[-1][1] = max(sum(source_spans[-1]), end) - source_spans[-1][0]
            else:
                source_spans.append([start, size])
        evidence = [_span(high, reset), _span(high, boot),
                    {'span': [table, 60]}, {'span': [16 * 512, 512]},
                    *[_span(high, item[1]) for item in getters],
                    *[_span(high, operation) for operation in operations], _span(high, wait),
                    _span(high, field_wait), _span(high, copy),
                    _span(high, scanner),
                    *[{'span': span} for span in source_spans],
                    *[_span(stage_facts, body, source) for body in uart_poll],
                    *[_span(stage_facts, body, source) for body in presence[:2]],
                    *[{'span': [source + start, size]} for start, size in presence[2]]]
        found.append({'version': 1, 'blocks': blocks, 'page_size': data, 'spare_size': raw - data,
                      'pages_per_block': pages, 'stage_source': source, 'stage_size': length,
                      'high_code_size': 0x2000, 'input_address': 0x58000070,
                      'input_value': 31, 'evidence': evidence})
    return found[0] if len(found) == 1 else None


def find_bootstrap_nand(image: bytes):
    profile = find_boot_nand(image)
    if profile is not None:
        return profile
    return find_boot_nand_word(image)


def machine_plan(original: bytes, loaded: bytes, config):
    profile = find_bootstrap_nand(original)
    word = bool(profile and profile.get('word_interface'))
    if (profile is None or getattr(config, 'image_kind', None) != 'firmware'
            or (getattr(config, 'load_address', None), getattr(config, 'image_offset', None),
                getattr(config, 'entry', None), getattr(config, 'ram_base', None)) != (0, 0, 0, 0x01000000)
            or getattr(config, 'ram_size', None) not in (
                (0x00800000, 0x01000000) if word else (0x01000000,))
            or getattr(config, 'flash_size', None) != 0x01000000
            or any(getattr(config, name, None) for name in (
                'missing_overlays', 'ram_bootstrap_profile', 'native_nand_profile',
                'nand_image', 'secondary_flash_image', 'secondary_flash_address',
                'upper_flash_image', 'upper_flash_address'))):
        return resolve_proposals(()).plan
    if word:
        return word_machine_plan(original, loaded, config, profile)
    panel = find_indexed28(original, profile)
    size = getattr(config, 'file_size', 0)
    main_size = size // 528 * 512
    if (panel is None or size != len(original)
            or size <= 0 or size % 528 or main_size % 16384
            or not profile['blocks'] * 16384 <= main_size <= 0x08000000):
        return resolve_proposals(()).plan
    spans = [span for item in (*profile['evidence'], *panel['evidence'])
             for span in (item['span'], *item.get('extra_spans', ()))]
    if any(not 0 <= start < start + length <= min(len(original), len(loaded))
           or original[start:start + length] != loaded[start:start + length]
           for start, length in spans):
        return resolve_proposals(()).plan
    locations = tuple(sorted({start for start, _ in spans}))
    evidence = Evidence('high-linked-nand-bootstrap', (profile['blocks'], main_size,
        profile['stage_source'], profile['stage_size']), locations, 'linkage')
    ports = (0x28000000, 0x28000100)
    ranges = [(0, 0x02000000), (_HIGH, 0x100000000),
              (0x58000000, 0x58001000),
              (0x60000000, 0x60001000),
              (0x63800000, 0x63801000), (0x64000000, 0x64001000),
              (0x80000000, 0x80010000),
              (ports[0], ports[0] + 2),
              (ports[1], ports[1] + 2)]
    capability = Capability('high-linked-nand-bootstrap', (evidence.name,), (evidence,),
        properties=(('bootstrap-nand-main-size', main_size),),
        parameters=(('cpu', 'arm926,reset-hivecs=on'),
                    ('high_code_size', profile.get('high_code_size', 0x2000)),
                    ('raw_size', size), ('main_size', main_size)),
        claims=tuple(ResourceClaim('address', 'high-linked-nand-bootstrap', start, end,
                         shared_resource='indexed28-stream' if start in ports else None,
                         semantics='native-write-observer' if start in ports else None)
                     for start, end in ranges))
    return resolve_proposals((Decision('accepted', capability=capability),)).plan
