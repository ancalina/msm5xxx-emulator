"""Closed Thumb evidence for a GPIO bit-banged register readback device.

The profile describes only the serial register protocol. It does not identify
the physical part or infer any register reset values.
"""
from __future__ import annotations

import struct
import re

try:
    from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs
except ImportError:
    CS_ARCH_ARM = CS_MODE_ARM = CS_MODE_LITTLE_ENDIAN = CS_MODE_THUMB = Cs = None

from .arm import thumb_bl_target

_DECODER = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN) if Cs else None
_ARM_DECODER = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN) if Cs else None
_EPILOGUE = (('pop', '{r3}'), ('bx', 'r3'))
_PORTS = (0x030006E8, 0x03000720, 0x030006F4)
_SHADOW = 0x147FF000
_MAX_FUNCTION = 0x600
_BL_ENCODING = re.compile(rb'(?=(.[\xf0-\xf7].[\xf8-\xff]))', re.DOTALL)


def _instructions(image: bytes, start: int, limit: int = _MAX_FUNCTION):
    if _DECODER is None:
        return ()
    return tuple(_DECODER.disasm(image[start:min(len(image), start + limit)], start))


def _body_end(insns) -> int | None:
    for i, insn in enumerate(insns):
        if (insn.mnemonic == 'pop' and insn.op_str.endswith('pc}')):
            return insn.address + insn.size
        if i + 1 < len(insns) and (insn.mnemonic, insn.op_str) == _EPILOGUE[0] and \
                (insns[i + 1].mnemonic, insns[i + 1].op_str) == _EPILOGUE[1]:
            return insns[i + 1].address + insns[i + 1].size
    return None


def _literal(image: bytes, insn) -> tuple[int, int] | None:
    if insn.mnemonic != 'ldr' or '[pc,' not in insn.op_str:
        return None
    raw = struct.unpack_from('<H', image, insn.address)[0]
    pool = ((insn.address + 4) & ~3) + (raw & 0xff) * 4
    if pool + 4 > len(image):
        return None
    return pool, struct.unpack_from('<I', image, pool)[0]


def _memory_base(insn) -> tuple[str, int] | None:
    match = re.search(r'\[(r[0-7])(?:, #([^\]]+))?\]', insn.op_str)
    if not match:
        return None
    return match.group(1), int(match.group(2), 0) if match.group(2) else 0


def _irq_pair_closed(image: bytes, target: int) -> bool:
    if _ARM_DECODER is None or target < 0 or target + 0x1c > len(image):
        return False
    for entry, operation in ((target, 'orr'), (target + 0x18, 'bic')):
        if struct.unpack_from('<H', image, entry)[0] != 0x4778 or \
                struct.unpack_from('<H', image, entry + 2)[0] != 0:
            return False
        start = entry + 4
        insns = tuple(_ARM_DECODER.disasm(image[start:min(len(image), start + 0x30)], start))
        end = next((n for n, insn in enumerate(insns)
                    if insn.mnemonic == 'bx' and insn.op_str == 'lr'), None)
        if end is None:
            return False
        body = insns[:end + 1]
        if (not any(i.mnemonic == 'mrs' and ('cpsr' in i.op_str or 'apsr' in i.op_str) for i in body) or
                not any(i.mnemonic == 'msr' and 'cpsr_c' in i.op_str for i in body) or
                not any(i.mnemonic == operation for i in body)):
            return False
    return True


def _protocol_function(image: bytes, start: int, kind: str):
    if _DECODER is None:
        return None
    first = tuple(_DECODER.disasm(image[start:min(len(image), start + 12)], start, count=6))
    fast_ops = [(i.mnemonic, i.op_str) for i in first]
    prefix = ([('adds', 'r6, r1, #0'), ('lsls', 'r0, r0, #0x19'),
               ('lsrs', 'r4, r0, #0x18')] if kind == 'write' else
              [('lsls', 'r0, r0, #1'), ('movs', 'r1, #1'), ('orrs', 'r0, r1'),
               ('lsls', 'r4, r0, #0x18'), ('lsrs', 'r4, r4, #0x18')])
    if not fast_ops or fast_ops[0] != ('push', '{r3, r4, r5, r6, r7, lr}') or \
            fast_ops[1:1 + len(prefix)] != prefix:
        return None
    insns = _instructions(image, start)
    end = _body_end(insns)
    if end is None:
        return None
    body = tuple(i for i in insns if i.address < end)
    ops = [(i.mnemonic, i.op_str) for i in body]
    if not ops or ops[0] != ('push', '{r3, r4, r5, r6, r7, lr}'):
        return None
    if kind == 'write':
        prefix = [('adds', 'r6, r1, #0'), ('lsls', 'r0, r0, #0x19'),
                  ('lsrs', 'r4, r0, #0x18')]
    else:
        prefix = [('lsls', 'r0, r0, #1'), ('movs', 'r1, #1'), ('orrs', 'r0, r1'),
                  ('lsls', 'r4, r0, #0x18'), ('lsrs', 'r4, r4, #0x18')]
    if ops[1:1 + len(prefix)] != prefix:
        return None
    literals = [(i.address, *_literal(image, i)) for i in body if _literal(image, i)]
    values = {value for _, _, value in literals}
    tables = []
    table_registers = set()
    shadow_registers = set()
    for literal_use, _, value in literals:
        use = next(i for i in body if i.address == literal_use)
        if value + 12 <= len(image) and value % 4 == 0:
            ports = struct.unpack_from('<3I', image, value)
            if ports == _PORTS:
                tables.append(value)
                table_registers.add(use.op_str.split(',', 1)[0].strip())
        if value == _SHADOW:
            shadow_registers.add(use.op_str.split(',', 1)[0].strip())
    if _SHADOW not in values or not tables:
        return None
    table_offsets = set()
    table_entries = {}
    for insn in body:
        if insn.mnemonic != 'ldr':
            continue
        for register in table_registers:
            match = re.search(rf'\[{register}(?:, #([^\]]+))?\]', insn.op_str)
            if match:
                offset = int(match.group(1), 0) if match.group(1) else 0
                table_offsets.add(offset)
                table_entries.setdefault(offset, set()).add(insn.op_str.split(',', 1)[0].strip())
    if not table_offsets:
        return None
    shadow_reads = {base for insn in body if insn.mnemonic == 'ldr' and
                    (access := _memory_base(insn)) and access[0] in shadow_registers
                    for base in (insn.op_str.split(',', 1)[0].strip(),)}
    if not shadow_reads or not any(insn.mnemonic == 'str' and
                                   (access := _memory_base(insn)) and access[0] in shadow_registers
                                   for insn in body):
        return None
    calls = []
    for insn in body:
        if insn.mnemonic == 'bl':
            target = thumb_bl_target(image, insn.address)
            if target is not None:
                calls.append((insn.address, target))
    from collections import Counter
    counts = Counter(target for _, target in calls)
    irq = [(target, count) for target, count in counts.items()
           if counts.get(target + 0x18, 0) >= 6 and count >= 6]
    if len(irq) != 1:
        return None
    helper = irq[0][0]
    # Both ARM interworking veneers must be present and linked as a paired
    # save/restore route; the +0x18 relation is part of the observed ABI.
    if not _irq_pair_closed(image, helper):
        return None
    shifts = {int(i.op_str.rsplit('#', 1)[1], 0) for i in body
              if i.mnemonic in ('lsl', 'lsls') and '#' in i.op_str}
    if not {9, 10}.issubset(shifts):
        return None
    counters = {int(i.op_str.split('#')[-1], 0) for i in body
                if i.mnemonic == 'movs' and i.op_str.startswith(('r4, #', 'r5, #'))}
    if not {6, 7}.issubset(counters):
        return None
    back_edges = []
    for index, insn in enumerate(body):
        if (insn.mnemonic not in ('bpl', 'bne', 'bgt') or not insn.op_str.startswith('#0x') or
                int(insn.op_str[1:], 16) >= insn.address or index == 0):
            continue
        previous = body[index - 1]
        if previous.mnemonic == 'subs' and previous.op_str.endswith(', #1'):
            back_edges.append((int(insn.op_str[1:], 16), previous.op_str.split(',', 1)[0].strip()))
    loops = {}
    for index, insn in enumerate(body):
        match = re.fullmatch(r'movs (r[0-7]), #(6|7)', insn.mnemonic + ' ' + insn.op_str)
        if not match:
            continue
        register, count = match.group(1), int(match.group(2))
        following = body[min(index + 4, len(body) - 1)]
        limit = following.address + following.size
        target = next((address for address, branch_reg in back_edges
                       if branch_reg == register and insn.address < address <= limit), None)
        if target is not None:
            loops[count] = (register, target)
    if set(loops) != {6, 7}:
        return None
    if kind == 'read':
        # Table offset four supplies the input address, whose value is loaded
        # and shifted into the sampled serial bit.
        sample_path = False
        for index, insn in enumerate(body[:-2]):
            access = _memory_base(insn)
            if insn.mnemonic != 'ldr' or access is None or access[1] != 4:
                continue
            register = insn.op_str.split(',', 1)[0].strip()
            second = body[index + 1]
            third = body[index + 2]
            if (second.mnemonic == 'ldr' and second.op_str == f'{register}, [{register}]' and
                    third.mnemonic == 'lsls' and third.op_str == f'{register}, {register}, #0x16'):
                sample_path = True
                break
        if not sample_path:
            return None
        if 8 not in table_entries or not any(insn.mnemonic == 'str' and
                                              (access := _memory_base(insn)) and
                                              access[0] in table_entries[8] for insn in body):
            return None
    elif 0 not in table_entries or not any(insn.mnemonic == 'str' and
                                           (access := _memory_base(insn)) and
                                           access[0] in table_entries[0] for insn in body):
        return None
    return {'start': start, 'end': end, 'body': body, 'literals': literals,
            'table': tables[0], 'table_offsets': table_offsets, 'calls': calls, 'irq': helper,
            'loops': loops}


def _find_functions(image: bytes, kind: str):
    found = []
    pos = 0
    while True:
        pos = image.find(b'\xf8\xb5', pos)
        if pos < 0:
            break
        result = _protocol_function(image, pos, kind)
        if result is not None:
            found.append(result)
        pos += 2
    return found


def _candidate_callers(image: bytes, target: int):
    callers = {}
    for match in _BL_ENCODING.finditer(image):
        at = match.start()
        if at & 1:
            continue
        if thumb_bl_target(image, at) != target:
            continue
        start = at & ~1
        floor = max(0, start - 0x300)
        while start > floor:
            start -= 2
            if struct.unpack_from('<H', image, start)[0] & 0xFE00 == 0xB400:
                break
        else:
            continue
        insns = _instructions(image, start, at - start + 0x300)
        end = _body_end(insns)
        if end is None or at >= end:
            continue
        body = tuple(i for i in insns if i.address < end)
        calls = [(i.address, thumb_bl_target(image, i.address)) for i in body
                 if i.mnemonic == 'bl']
        callers[start] = (end, body, calls)
    return callers


def find_gpio_pmic_profile(image: bytes) -> tuple[dict | None, str]:
    """Return a register-readback profile and rejection reason, if closed."""
    if not isinstance(image, bytes) or len(image) < 0x100:
        return None, 'image-too-small'
    if _DECODER is None or _ARM_DECODER is None:
        return None, 'capstone-unavailable'
    writers = _find_functions(image, 'write')
    readers = _find_functions(image, 'read')
    for writer in writers:
        for reader in readers:
            if writer['irq'] != reader['irq'] or writer['table'] != reader['table']:
                continue
            if 0 not in writer['table_offsets'] or not {4, 8}.issubset(reader['table_offsets']):
                continue
            reader_callers = _candidate_callers(image, reader['start'])
            writer_callers = _candidate_callers(image, writer['start'])
            for poll_start, (poll_end, poll_body, poll_calls) in reader_callers.items():
                poll_targets = [target for _, target in poll_calls]
                if writer['start'] not in poll_targets or poll_targets.count(reader['start']) < 1:
                    continue
                reader_calls = [at for at, target in poll_calls if target == reader['start']]
                readback_closed = False
                for reader_at in reader_calls:
                    reader_index = next(i for i, insn in enumerate(poll_body) if insn.address == reader_at)
                    for i in range(reader_index + 1, len(poll_body) - 3):
                        sequence = [(insn.mnemonic, insn.op_str) for insn in poll_body[i:i + 3]]
                        if sequence != [('lsls', 'r1, r4, #0x1b'),
                                        ('lsrs', 'r1, r1, #0x1b'), ('cmp', 'r1, r0')]:
                            continue
                        if not any(at > reader_at and at < poll_body[i].address and
                                   target not in (reader['start'], writer['start'])
                                   for at, target in poll_calls):
                            continue
                        branch = poll_body[i + 3]
                        if (branch.mnemonic == 'bne' and branch.op_str.startswith('#0x') and
                                reader_at - 8 <= int(branch.op_str[1:], 16) <= reader_at):
                            readback_closed = True
                            break
                    if readback_closed:
                        break
                if not readback_closed:
                    continue
                init_matches = []
                for init_start, (init_end, init_body, init_calls) in writer_callers.items():
                    targets = [target for _, target in init_calls]
                    if targets.count(writer['start']) >= 7 and targets.count(poll_start) >= 3:
                        init_matches.append((init_start, init_end, init_body))
                if len(init_matches) != 1:
                    continue
                init_start, init_end, init_body = init_matches[0]
                evidence = []
                extra_spans = []
                for role, item in (('writer', writer), ('reader', reader)):
                    evidence.append({'role': role, 'span': [item['start'], item['end'] - item['start']]})
                    for insn_at, pool, value in item['literals']:
                        evidence.append({'role': role + '-literal-use', 'span': [insn_at, 2],
                                         'referent': [pool, 4], 'value': value})
                        extra_spans.append({'role': role + '-literal', 'span': [pool, 4]})
                evidence.extend([
                    {'role': 'irq-pair', 'span': [writer['irq'], 0x30]},
                    {'role': 'gpio-port-table', 'span': [writer['table'], 12],
                     'values': list(_PORTS)},
                    {'role': 'readback-poll', 'span': [poll_start, poll_end - poll_start]},
                    {'role': 'initializer', 'span': [init_start, init_end - init_start]},
                ])
                return {'kind': 'gpio-serial-register-readback-v1', 'register_count': 64,
                        'reset_value': 0, 'write_readback': True,
                        'evidence': evidence, 'extra_spans': extra_spans}, ''
    if not writers:
        return None, 'serial-writer-not-closed'
    if not readers:
        return None, 'serial-reader-not-closed'
    return None, 'serial-init-readback-linkage-not-closed'

