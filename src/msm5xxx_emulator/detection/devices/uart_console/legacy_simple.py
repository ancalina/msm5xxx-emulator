"""Closed temporary synchronous null-console identity from typed consumers."""
from __future__ import annotations

import struct
from capstone import arm as a

from ...arm import thumb_bl_target
from ...facts import CodeAddress, facts_for
from .legacy_tx import byte_code as _byte_code, called_code_candidates
from .hardware import _typed_tx_evidence

def _word(image: bytes, at: int) -> int | None: return struct.unpack_from('<H', image, at)[0] if 0 <= at <= len(image) - 2 else None


def _raw_mask_matches(image: bytes, at: int, mask: str, ignored_halfword: int | None = None) -> bool:
    if at < 0 or at + len(mask)//2 > len(image):
        return False
    for offset in range(len(mask)//2):
        if ignored_halfword is not None and ignored_halfword <= offset < ignored_halfword + 2:
            continue
        token = mask[offset*2:offset*2+2]
        if token != '??' and image[at+offset] != int(token,16):
            return False
    return True


def _control_evidence(image: bytes, entry: int) -> dict | None:
    facts = facts_for(image)
    owner = CodeAddress(entry, 'thumb')
    function = facts.function(owner, budget=128, symbolic_registers={})
    if (not function.complete or function.truncated or function.unresolved
            or function.calls or len(function.back_edges) != 2):
        return None
    events = tuple(access for access in function.accesses
                   if 0x03000000 <= access.address < 0x04000000)
    if any(access.address.kind != 'const' for access in function.symbolic_accesses):
        return None
    unknown = facts.unmodelled_memory(function)
    frame = facts.stack_frame(function)
    stack_sites = ({access.site for access in frame.accesses}
                   if frame is not None and frame.complete else set())
    if (unknown is None or set(unknown) - stack_sites
            or (unknown and (frame is None or not frame.balanced))):
        return None
    reads = tuple(access for access in events if access.operation == 'read')
    writes = tuple(access for access in events if access.operation == 'write')
    if (len(reads) != 1 or reads[0].width != 1 or len(writes) != 3
            or any(access.width != 1 for access in writes)
            or tuple(access.value for access in writes) != (1, 0, 0x20)
            or writes[0].address != writes[1].address
            or writes[2].address in (reads[0].address, writes[0].address)
            or tuple(access.instruction.address - entry
                     for access in (reads[0], *writes)) != (4, 24, 28, 34)):
        return None
    branch, repeat, tail, ret = (CodeAddress(entry + offset, 'thumb')
                                 for offset in (8, 18, 36, 38))
    first, again, last, returned = (facts.decode(site)
                                    for site in (branch, repeat, tail, ret))
    is_return = (returned is not None and (
        (returned.id == a.ARM_INS_BX and returned.operands
         and returned.operands[0].type == a.ARM_OP_REG
         and returned.operands[0].reg == a.ARM_REG_LR)
        or (returned.id == a.ARM_INS_MOV and len(returned.operands) == 2
            and returned.operands[0].type == a.ARM_OP_REG
            and returned.operands[0].reg == a.ARM_REG_PC
            and returned.operands[1].type == a.ARM_OP_REG
            and returned.operands[1].reg == a.ARM_REG_LR)))
    if (any(ins is None or ins.id != a.ARM_INS_B for ins in (first, again, last))
            or not is_return
            or tuple(function.back_edges) != ((entry + 18, entry + 2),
                                               (entry + 36, entry + 2))):
        return None
    predicate = facts.branch_predicate(function, branch)
    if (predicate is None or predicate.operation != 'lsr' or predicate.shift != 4
            or predicate.condition != a.ARM_CC_HS or len(predicate.read_sources) != 1
            or predicate.read_sources[0].site != reads[0].instruction
            or predicate.read_sources[0].address.kind != 'const'
            or predicate.read_sources[0].address.value != reads[0].address):
        return None
    if (first.operands[0].imm != ret.address or again.operands[0].imm != entry + 2
            or last.operands[0].imm != entry + 2
            or not function.dominates(writes[0].instruction, writes[1].instruction)
            or not function.dominates(writes[1].instruction, writes[2].instruction)):
        return None
    status, pulse, control = reads[0].address, writes[0].address, writes[2].address
    if (any(not 0x03000000 <= address < 0x04000000 or address & 3
            for address in (status, pulse, control))
            or len({status, pulse, control}) != 3):
        return None
    return {'entries': [entry], 'status_address': status, 'mask': 8,
            'pulse_address': pulse, 'control_address': control, 'control_value': 0x20}


def _uart_rx_read_offset(image: bytes, entry: int, status_address: int,
                         pulse_address: int) -> int | None:
    """Find the bounded byte RX-status read used by the initializer contract."""
    facts = facts_for(image)
    limit = min(len(image) - 36, entry + 0x1000)
    for start in range(max(0, entry), limit, 2):
        if not facts.view.covers(start, 36):
            continue
        words = struct.unpack_from('<18H', image, start)
        if (words[0] & 0xF800 != 0x4800 or words[0] >> 8 & 7
                or words[1:5] != (0x3830, 0x7900, 0x0840, 0xD200)
                or words[6] & 0xF800 != 0x4800 or words[6] >> 8 & 7
                or words[7:10] != (0x3830, 0x7A02, 0x2001)
                or words[10] & 0xF800 != 0x4800 or words[10] >> 8 & 7 != 1):
            continue
        status = facts.thumb_literal_value(start, 0)
        if (status != status_address + 0x2C
                or facts.thumb_literal_value(start + 12, 0) != status):
            continue
        add = words[11] & 0xFF00 == 0x3100
        noop = words[11] == 0x3000
        store = 12 if add or noop else 11
        if (words[store:store + 3] != (0x7008, 0x2000, 0x7008)
                or words[store + 3] & 0xF800 != 0xE000):
            continue
        exit_branch = facts.decode(CodeAddress(start + 10, 'thumb'))
        repeat = facts.decode(CodeAddress(start + (store + 3) * 2, 'thumb'))
        end = start + (store + 4) * 2
        returned = facts.decode(CodeAddress(end, 'thumb'))
        if (exit_branch is None or exit_branch.id != a.ARM_INS_B
                or exit_branch.cc not in (a.ARM_CC_AL, a.ARM_CC_INVALID)
                or exit_branch.operands[0].imm != end
                or repeat is None or repeat.operands[0].imm != start
                or returned is None):
            continue
        if returned.id == a.ARM_INS_POP:
            registers = {op.reg for op in returned.operands if op.type == a.ARM_OP_REG}
            tail = facts.decode(CodeAddress(end + returned.size, 'thumb'))
            if (a.ARM_REG_PC not in registers and
                    (tail is None or tail.id != a.ARM_INS_BX
                     or tail.operands[0].reg not in registers)):
                continue
        elif not (returned.id == a.ARM_INS_BX
                  and returned.operands[0].reg == a.ARM_REG_LR):
            continue
        pulse = facts.thumb_literal_value(start + 20, 1)
        if (pulse is None or status >= 0x04000000
                or pulse + (words[11] & 0xFF if add else 0) != pulse_address):
            continue
        return start + 4 - entry
    return None


def _initializer(image: bytes, start: int, end: int, primary: int) -> list[dict] | None:
    """Interpret only the closed straight-line constant/literal typed-write producer."""
    facts = facts_for(image)
    if (_word(image, start) != 0xB500 or not start < end <= start + 0x100
            or not facts.view.covers(start, end - start)):
        return None
    parsed = _byte_writes(image, start + 2, end, primary, allow_lsl=False)
    if parsed is None:
        return None
    writes, _, calls = parsed
    return writes if calls == [start + 14] else None


def _find_modern_uart_console_profile(image: bytes, ready_profile: dict | None) -> tuple[dict | None, str]:
    """Bind primary, initializer and TX via an independently closed console family."""
    def reject(reason: str) -> tuple[None, str]:
        return None, reason

    if not isinstance(ready_profile, dict):
        return reject('console-primary-profile-absent')
    entries = ready_profile.get('entries')
    if (not isinstance(entries, list) or len(entries) != 1 or type(entries[0]) is not int
            or ready_profile.get('signature') not in (
                'thumb-byte-ready-pulse-control-v1',
                'thumb-byte-ready-pulse-control-uart-empty-v1')):
        return reject('console-primary-ownership-unclosed')
    primary = entries[0]
    if primary < 0 or primary & 1 or primary + 40 > len(image):
        return reject('console-primary-entry-out-of-bounds')
    status, pulse = ready_profile.get('status_address'), ready_profile.get('pulse_address')
    if (type(status) is not int or type(pulse) is not int
            or ready_profile.get('mask') != 8 or pulse != 0x03000700):
        return reject('console-primary-contract')
    base = status - 8
    if (base & 3 or not 0x03000000 <= base <= 0x03FFFFC0
            or ready_profile.get('control_address') != base + 0x10
            or ready_profile.get('control_value') != 0x20):
        return reject('console-primary-contract')
    # The ready profile only seeds this local hardware proof. Re-derive the
    # status loop and its typed peripheral events from this image.
    control = _control_evidence(image, primary)
    if (control is None or control['entries'] != [primary]
            or any(control.get(k) != ready_profile.get(k) for k in (
                'status_address', 'mask', 'pulse_address', 'control_address', 'control_value'))):
        return reject('console-primary-code-unclosed')
    read_offset = _uart_rx_read_offset(image, primary, status, pulse)
    if read_offset is None:
        return reject('console-initializer-rx-unclosed')
    read = primary + read_offset - 4
    # The existing profile offset denotes its LDRB, four bytes after the literal.
    calls = list(facts_for(image).call_candidates('thumb'))
    init_candidates = [at for at in range(max(0, read - 0x140), read, 2)
                       if _word(image, at) == 0xB500
                       and _initializer(image, at, read, primary) is not None]
    if len(init_candidates) != 1:
        return reject('console-initializer-ambiguous')
    init = init_candidates[0]
    writes = _initializer(image, init, read, primary)
    clock_setup = tuple(w['value'] for w in writes[2:6])
    if clock_setup not in ((0xC0, 0xAF, 0x80, 0x19), (0xC0, 0xB2, 0x7D, 0x1C)):
        return reject('console-clock-setup-unclosed')
    expected = [(base + 0x38, 1, 0), (pulse - 0xDC, 2, 0x80),
                *[(base + offset, 1, value) for offset, value in
                  zip((0x28, 0x2C, 0x30, 0x34), clock_setup)],
                (base + 0x14, 1, 0), (base + 0x20, 2, 0),
                (base + 0x1C, 2, 30), (base, 2, 0),
                (base + 4, 1, 0x34), (base + 8, 1, 0x99),
                *[(base + 0x10, 1, value) for value in (0x30, 0x10, 0x10, 0x20, 0x20, 1, 4)]]
    if [(w['address'], w['size'], w['value']) for w in writes] != expected:
        return reject('console-typed-initialization-mismatch')
    init_callers = [at for at, target in calls if target == init]
    if len(init_callers) != 1:
        return reject('console-initializer-callers-ambiguous')
    tx_proofs = _typed_tx_evidence(image, calls, base)
    if len(tx_proofs) != 1:
        return reject('console-tx-consumer-unclosed')
    tx, tx_evidence = next(iter(tx_proofs.items()))
    tx_callers, tx_isr_pc, tx_fifo_pc = tx_evidence
    if not tx_callers:
        return reject('console-tx-ownership-ambiguous')
    end = facts_for(image).decode(CodeAddress(read + 10, 'thumb')).operands[0].imm + 4
    profile = dict(signature='thumb-uart-sync-console-v1', admission='temporary-evidence-gated',
                policy='provisional-synchronous-null-console', base=base,
                primary_entry=primary, init_entry=init, tx_entry=tx,
                status_address=base + 8, control_address=base + 0x10,
                isr_address=base + 0x14, fifo_address=base + 0xC, pulse_address=pulse,
                primary_status_pc=primary + 4, primary_control_pc=primary + 0x22,
                init_writes=writes, clock_setup=clock_setup, rx_drain_pc=read + 4,
                tx_isr_pc=tx_isr_pc, tx_fifo_pc=tx_fifo_pc, tx_callers=list(tx_callers),
                code_intervals=[(primary, primary + 40), (init, end), (tx, tx + 28)])
    return profile, 'accepted'

_BYTE_LAYOUTS = {
    "register-and": {
        "primary": (
            "90b4??4a0121??4f0020147d0823234002d139703870f8e790bcf746"
        ),
        "init_head": (
            "90b5d54501da????????"
        ),
        "drain": (
            "??48137ddb07db0f03d0137e01700770f7e790bd"
        ),
        "rx": (
            "b0b40006000e??4f00230122??4c002811d0??4900290bdd01e00139fae7387dc507ed0f01d0b0bcf74622702370f4e7"
            "0120c043f7e7387dc107c90f00d0f2e722702370f7e70000"
        ),
        "wrapper": (
            "80b5d54501da??????????4f3878002804d00120????????011c03e00020????????011c0120c043814203d13a78002a"
            "00d080bd40230b40??4a0020c043002b01d0117ef5e72023194001d0117ef0e7107e00213970ece7"
        ),
        "tx": (
            "80b40106090e??4a0123??481778ff07ff0f01d10370f9e700220270??48017680bcf746"
        ),
        "root": (
            "00b5d54501da????????0820??498887????????????????????????????????00bd"
        ),
        "dispatch": (
            "90b5d54501da??????????4c206801235b03c01a??4fb863b86b????????011cb86b02780f2a27d202a3"
        ),
        "parser_head": (
            "f1b5d54501da????????002600250024032c5fd00121??48017000210170????????071c0123"
        ),
        "ack1": (
            "80b5d54501da????????c71c7e20????????3878????????387801377e28f8d180bd"
        ),
        "ack2": (
            "80b5d54501da????????8000??490f587e20????????3878????????387801377e28f8d180bd"
        ),
        "flag": (
            "0120??490870f746"
        ),
        "primary_call": 42,
        "body": 10,
        "drain_off": 108,
        "root_init_call": 20,
        "root_primary_call": 16,
        "root_flag_call": 24,
        "root_dispatch_call": 28,
        "dispatch_parser_call": 26,
        "parser_receive_calls": (30, 132),
        "wrapper_rx_calls": (20, 30),
        "ack_calls": ((14, 20), (18, 24)),
    },
    "lsr-ready": {
        "primary": (
            "??480079000905d20120??49087000200870f5e7f746"
        ),
        "init_head": (
            "80b5????????????????"
        ),
        "drain": (
            "??480079400807d3??48077a0120??49087000200870f3e780bd"
        ),
        "rx": (
            "80b4021c002a16d0??4b002b02dc0ee0013bfae7??480179480802d3081c80bcf7460120??4f387000203870f0e70120"
            "c043f4e70be0??480179480801d3081cede70120??4f387000203870f3e70020e5e70000"
        ),
        "wrapper": (
            "90b5??480078002804d00120????????071c03e00020????????071c0223df4206d1??480078002802d00120c04390bd"
            "f80904d3??48047a0020c043f7e7b80904d3??48047a0020c043f0e7??48007a041c0020??490870201ce8e70020e6e7"
        ),
        "tx": (
            "??490978490805d20121??4a117000211170f5e7??490872f746"
        ),
        "root": (
            "00b50020??490880????????????????????????????????00bd"
        ),
        "dispatch": (
            "80b5??48006801235b03c01a??494860??484068????????071c??48406800780f28"
        ),
        "parser_head": (
            "f1b5002600240025032d60d00120??49087000200870????????"
        ),
        "ack1": (
            "90b5071cfc1c7e20????????2078????????207801347e28f8d190bd"
        ),
        "ack2": (
            "90b5071cb800??490c587e20????????2078????????207801347e28f8d190bd"
        ),
        "flag": (
            "??490020082802db09e00130fae70a5cff2a03d00022??4b1a70f746f5e70122??4b1a70f9e7"
        ),
        "primary_call": 6,
        "body": 10,
        "drain_off": 82,
        "root_init_call": 12,
        "root_primary_call": 8,
        "root_flag_call": 16,
        "root_dispatch_call": 20,
        "dispatch_parser_call": 20,
        "parser_receive_calls": (22, 126),
        "wrapper_rx_calls": (12, 22),
        "ack_calls": ((8, 14), (12, 18)),
    },
}


_BYTE_EXTENDED_ROOT = {
    "root": (
        "00b5d54501da????????0820??4988870021??480170017110220272017301740175"
        "????????????????????????????????00bd"
    ),
    "root_primary_call": 34,
    "root_init_call": 38,
    "root_flag_call": 42,
    "root_dispatch_call": 46,
    "root_setup_literal": (0x12, 0, -0x10c),
}


def _byte_writes(image: bytes, start: int, end: int, primary: int, *,
                 allow_lsl: bool = True) -> tuple[list, list, list] | None:
    facts = facts_for(image)
    if end <= start or not facts.view.covers(start, end - start):
        return None
    registers=[None]*8
    writes=[];calls=[];at=start
    while at < end:
        word=_word(image,at)
        if word is None:return None
        kind=word&0xf800;register=word>>8&7
        if kind == 0x2000:registers[register]=word&255
        elif kind == 0x4800:
            registers[register]=facts.thumb_literal_value(at,register)
            if registers[register] is None:return None
        elif kind in (0x3000,0x3800):
            if registers[register] is None:return None
            registers[register]+=(word&255)*(1 if kind==0x3000 else -1)
        elif kind == 0 and allow_lsl:
            source=registers[word>>3&7]
            if source is None:return None
            registers[word&7]=(source<<(word>>6&31))&0xffffffff
        elif kind in (0x7000,0x8000):
            value,base=registers[word&7],registers[word>>3&7]
            size=1 if kind==0x7000 else 2
            if value is None or base is None or not 0<=value<1<<(size*8):return None
            writes.append(dict(pc=at,address=base+(word>>6&31)*size,size=size,value=value))
        elif at + 4 <= end and facts.thumb_call_target(at)==primary:
            calls.append(at);registers[:4]=[None]*4;at+=2
        else:return None
        at+=2
    return writes,registers,calls


def _byte_profile_at(image: bytes, primary: int, name: str, spec: dict, calls: list) -> tuple[dict | None,str]:
    def fail(reason):return None,'console-byte-'+reason
    def code(role,at):return _byte_code(image,at,spec[role])
    def literal(at,reg):return facts_for(image).thumb_literal_value(at,reg)
    if not code('primary',primary):return fail('primary-code-unclosed')
    if name=='register-and':
        base=literal(primary+2,2)+12;pulse=literal(primary+6,7);status_pc=primary+10
    else:
        base=literal(primary,0)-4;pulse=literal(primary+10,1);status_pc=primary+2
    if base&3 or not 0x03000000<=base<=0x03ffffc0 or pulse!=0x03000600:
        return fail('primary-address-contract')
    candidates=[]
    for site,target in calls:
        init=site-spec['primary_call']
        if target!=primary or not primary<init<primary+0x100 or not code('init_head',init):continue
        drain=init+spec['drain_off']
        parsed=_byte_writes(image,init+spec['body'],drain,primary)
        if parsed is not None and code('drain',drain):candidates.append((init,drain,parsed))
    if len(candidates)!=1:return fail('initializer-ambiguous-or-unclosed')
    init,drain,(writes,registers,init_calls)=candidates[0]
    if init_calls != ([init+spec['primary_call']] if name=='register-and' else []):
        return fail('initializer-primary-link')
    clock=[(base+off,1,value)for off,value in zip((0x28,0x2c,0x30,0x34),(0xc0,0xaf,0x80,0x19))]
    expected=[*clock,(base+0x14,1,0),(base+0x20,1,0),(base+0x1c,1,30),
              (base,1,0),(base+4,1,0x34),(base+8,1,0xff),
              *[(base+0x10,1,value)for value in (0x30,0x10,0x10,0x20,0x20,1,4)]]
    if name=='register-and':
        expected=[(base-0x64,2,0x82),(base-0x64,2,0x80),(base-0x64,2,0),
                  (base-0x68,2,0),(base-0x6c,2,0x37f),(base-0x6c,2,0x37f),
                  (base-0x58,1,8),(base-0x6c,2,0x37d),(base-0x6c,2,0x37d),*expected]
        drain_literals=((0,0,pulse),)
        if (registers[2],registers[1],registers[7])!=(base-12,1,0):return fail('drain-register-producers')
    else:drain_literals=((0,0,base+4),(8,0,base+4),(14,1,pulse))
    actual=[(w['address'],w['size'],w['value'])for w in writes]
    halfword_expected=[(address,2 if address==base+0x1c else size,value)
                       for address,size,value in expected]
    tfwr16 = name == 'lsr-ready' and actual == halfword_expected
    if actual!=expected and not tfwr16:
        return fail('typed-initialization-mismatch')
    if any(literal(drain+off,reg)!=value for off,reg,value in drain_literals):return fail('drain-aliases')
    init_callers=[at for at,target in calls if target==init]
    if len(init_callers)!=1:return fail('initializer-callers-ambiguous')
    if not init_callers:return fail('initializer-unreferenced')
    tx_literals = (((6, 2, base + 0x14), (10, 0, pulse), (0x1C, 0, base - 12))
                   if name == 'register-and' else
                   ((0, 1, base + 0x14), (10, 2, pulse), (0x14, 1, base + 4)))
    tx_candidates = {entry: sites for entry, sites in
                     called_code_candidates(image, calls, spec['tx'], _byte_code).items()
                     if all(literal(entry + offset, register) == value
                            for offset, register, value in tx_literals)}
    if len(tx_candidates) != 1:
        return fail('tx-hardware-evidence-ambiguous')
    tx, tx_calls = next(iter(tx_candidates.items()))
    call_targets = dict(calls)
    def near_code_shape(root, mask):
        if _raw_mask_matches(image, root, mask):
            return True
        for off in range(0, len(mask)//2, 2):
            if _raw_mask_matches(image, root, mask, off):
                return True
        return False

    normal_roots = {site - spec['root_primary_call']
                    for site, target in calls if target == primary}
    init_roots = {site - spec['root_init_call']
                  for site, target in calls if target == init}
    normal_roots = {root for root in normal_roots & init_roots
                    if 0 <= root < len(image) and near_code_shape(root, spec['root'])}
    if len(normal_roots) > 1:
        return fail('root-owner-ambiguous')
    if normal_roots:
        root = next(iter(normal_roots))
        if not code('root', root):
            return fail('root-dispatch-links')

    roots = set()
    if name == 'register-and':
        possible = {site - _BYTE_EXTENDED_ROOT['root_primary_call']
                    for site, target in calls if target == primary}
        possible.update(site - _BYTE_EXTENDED_ROOT['root_init_call']
                        for site, target in calls if target == init)
        roots = {root for root in possible if 0 <= root < len(image)
                 and near_code_shape(root, _BYTE_EXTENDED_ROOT['root'])}
    if len(roots) > 1:
        return fail('extended-root-ambiguous')
    root = next(iter(roots), None)
    if root is not None:
        setup_off, setup_reg, setup_delta = _BYTE_EXTENDED_ROOT['root_setup_literal']
        root_calls = {site: target for site, target in calls
                      if root <= site < root + 0x34}
        if (not _byte_code(image, root, _BYTE_EXTENDED_ROOT['root'])
                or root_calls.get(root + _BYTE_EXTENDED_ROOT['root_primary_call']) != primary
                or root_calls.get(root + _BYTE_EXTENDED_ROOT['root_init_call']) != init
                or not code('flag', root_calls.get(root + _BYTE_EXTENDED_ROOT['root_flag_call'], -1))
                or not code('dispatch', root_calls.get(root + _BYTE_EXTENDED_ROOT['root_dispatch_call'], -1))
                or literal(root + 0x0C, 1) != base - 0x16C
                or literal(root + setup_off, setup_reg) != base + setup_delta):
            return fail('extended-root-hardware-setup')
    profile = dict(signature=('thumb-uart-byte-tfwr16-sync-console-v1' if tfwr16
                              else 'thumb-uart-byte-sync-console-v1'),
        admission='temporary-evidence-gated',
        policy='provisional-synchronous-null-console',layout=name,
        register_width=1,csr_value=0xff,base=base,status_address=base+8,
        control_address=base+0x10,isr_address=base+0x14,fifo_address=base+0xc,
        pulse_address=pulse,primary_entry=primary,primary_status_pc=status_pc,
        primary_control_pc=None,init_entry=init,tx_entry=tx,
        init_writes=writes,clock_setup=(0xc0,0xaf,0x80,0x19),
        rx_drain_pc=drain+2,tx_callers=tx_calls,
        tx_isr_pc=tx+(12 if name=='register-and' else 2),
        tx_fifo_pc=tx+(30 if name=='register-and' else 22),
        code_intervals=[(primary,primary+len(spec['primary'])//2),
                        (init,drain+len(spec['drain'])//2),
                        (tx,tx+len(spec['tx'])//2)])
    if root is not None:
        profile['console_root'] = root
        profile['code_intervals'].append((root, root + len(_BYTE_EXTENDED_ROOT['root'])//2))
    return profile, 'accepted'


def _find_existing_uart_console_profile(image: bytes, ready_profile: dict | None) -> tuple[dict | None,str]:
    """Keep independently closed typed UART dialects separate and unambiguous."""
    modern,reason=_find_modern_uart_console_profile(image,ready_profile)
    candidates=[]
    seen_anchor=False
    for marker,name,adjust in ((bytes.fromhex('0823234002d1'),'register-and',12),
                              (bytes.fromhex('0079000905d20120'),'lsr-ready',2)):
        cursor=0
        while (at:=image.find(marker,cursor))>=0:
            cursor=at+1;primary=at-adjust
            seen_anchor |= primary>=0 and not primary&1
            if _byte_code(image,primary,_BYTE_LAYOUTS[name]['primary']):candidates.append((primary,name))
    if not candidates:
        return (None,'console-byte-primary-code-unclosed') if modern is None and seen_anchor else (modern,reason)
    calls=list(facts_for(image).call_candidates('thumb'))
    complete=[];failures=[]
    for primary,name in candidates:
        profile,failed_reason=_byte_profile_at(image,primary,name,_BYTE_LAYOUTS[name],calls)
        if profile is not None:complete.append(profile)
        else:failures.append(failed_reason)
    if len(complete)>1:return None,'console-byte-profiles-ambiguous'
    if modern is not None:
        return (None,'console-protocol-ownership-ambiguous') if complete else (modern,reason)
    if complete:return complete[0],'accepted'
    return None,failures[0] if len(failures)==1 else 'console-byte-candidates-unclosed'


# Typed mixed-width console dialect; hardware timing remains provisional.
