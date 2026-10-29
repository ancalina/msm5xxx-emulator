"""Closed temporary synchronous null-console identity from typed consumers."""
from __future__ import annotations

import struct
import re

from .ready_poll import (
    _THUMB_BL, _find_control_ready_poll_profile,
    _find_control_uart_rx_empty_profile, thumb_bl_target, thumb_literal_value,
)


def _word(image: bytes, at: int) -> int | None:
    return struct.unpack_from('<H', image, at)[0] if 0 <= at <= len(image) - 2 else None


def _initializer(image: bytes, start: int, end: int, primary: int) -> list[dict] | None:
    """Interpret only the closed straight-line constant/literal typed-write producer."""
    if _word(image, start) != 0xB500 or not start < end <= start + 0x100:
        return None
    registers = [None] * 8
    writes = []
    calls = []
    at = start + 2
    while at < end:
        word = _word(image, at)
        kind = word & 0xF800
        register = word >> 8 & 7
        if kind == 0x2000:
            registers[register] = word & 255
        elif kind == 0x4800:
            registers[register] = thumb_literal_value(image, at, register)
            if registers[register] is None:
                return None
        elif kind in (0x3000, 0x3800):
            if registers[register] is None:
                return None
            registers[register] += (word & 255) * (1 if kind == 0x3000 else -1)
        elif kind in (0x7000, 0x8000):
            value, base = registers[word & 7], registers[word >> 3 & 7]
            size = 1 if kind == 0x7000 else 2
            if value is None or base is None or not 0 <= value < 1 << (size * 8):
                return None
            writes.append(dict(pc=at, address=base + (word >> 6 & 31) * size,
                               size=size, value=value))
        elif thumb_bl_target(image, at) == primary:
            calls.append(at)
            registers[:4] = [None] * 4
            at += 2
        else:
            return None
        at += 2
    return writes if calls == [start + 14] else None


def _tx_at(image: bytes, at: int, base: int, pulse: int) -> bool:
    if at < 0 or at & 1 or at + 28 > len(image):
        return False
    words = struct.unpack_from('<14H', image, at)
    fixed = {1: 0x7809, 2: 0x0849, 3: 0xD205, 4: 0x2101,
             6: 0x7011, 7: 0x2100, 8: 0x7011, 9: 0xE7F5,
             11: 0x3910, 12: 0x7208, 13: 0x4770}
    return (all(words[i] == value for i, value in fixed.items())
            and words[0] & 0xFF00 == words[10] & 0xFF00 == 0x4900
            and words[5] & 0xFF00 == 0x4A00
            and thumb_literal_value(image, at, 1) == base + 0x14
            and thumb_literal_value(image, at + 10, 2) == pulse
            and thumb_literal_value(image, at + 20, 1) == base + 0x14)


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
    # Existing predicates validate the actual local code, not just a caller-supplied marker.
    begin, limit = max(0, primary - 0x100) & ~3, min(len(image), primary + 0x400)
    local = image[begin:limit]
    control = _find_control_ready_poll_profile(local)
    if (control is None or control['entries'] != [primary - begin]
            or any(control.get(k) != ready_profile.get(k) for k in (
                'status_address', 'mask', 'pulse_address', 'control_address', 'control_value'))):
        return reject('console-primary-code-unclosed')
    coupled = _find_control_uart_rx_empty_profile(local, control)
    if coupled is None:
        return reject('console-initializer-rx-unclosed')
    read = primary + coupled['uart_rx_empty_read_pc_offset'] - 4
    # The existing profile offset denotes its LDRB, four bytes after the literal.
    calls = [(m.start(), thumb_bl_target(image, m.start()))
             for m in _THUMB_BL.finditer(image) if not m.start() & 1]
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
    root = init_callers[0] - 6
    if (not begin <= root < primary or _word(image, root) != 0xB500
            or thumb_bl_target(image, root + 2) != primary
            or image[root + 14:root + 30] != bytes.fromhex('011c0c2902d1012008bc18470020fbe7')):
        return reject('console-root-family-unclosed')
    receive = thumb_bl_target(image, root + 10)
    if receive is None or not init < receive < limit - 30:
        return reject('console-receive-wrapper-unclosed')
    wrapper = [_word(image, receive + offset) for offset in range(0, 30, 2)]
    if (wrapper[0] != 0xB590 or wrapper[1] & 0xFF00 != 0x4800
            or wrapper[2:6] != [0x7800, 0x2800, 0xD004, 0x2001]
            or wrapper[8:11] != [0x1C07, 0xE003, 0x2000]
            or wrapper[13:15] != [0x1C07, 0x1CBB]):
        return reject('console-receive-wrapper-unclosed')
    flag = thumb_literal_value(image, receive + 2, 0)
    if flag is None or not 0x01000000 <= flag < 0x02000000:
        return reject('console-receive-flag-unclosed')
    rx = thumb_bl_target(image, receive + 12)
    if (rx is None or thumb_bl_target(image, receive + 22) != rx
            or not init < rx < receive or receive - rx > 0x200
            or image[rx:rx + 6] != bytes.fromhex('b0b5051c0a20')
            or _word(image, rx + 10) != 0x2D00
            or [at for at, target in calls if target == rx] != [receive + 12, receive + 22]
            or [at for at, target in calls if target == receive] != [root + 10]):
        return reject('console-receive-call-family-unclosed')
    tx = thumb_bl_target(image, rx + 6)
    if tx is None or not receive < tx < limit or not _tx_at(image, tx, base, pulse):
        return reject('console-tx-consumer-unclosed')
    tx_callers = [at for at, target in calls if target == tx]
    if (any(target != tx for at, target in calls if rx <= at < receive)
            or [at for at, target in calls if receive <= at < tx] != [receive + 12, receive + 22]):
        return reject('console-call-family-extra-calls')
    if (len(tx_callers) not in (2, 3) or tx_callers[0] != rx + 6
            or any(not rx <= at < receive or _word(image, at - 2) != 0x200A
                   for at in tx_callers)):
        return reject('console-tx-call-family-unclosed')
    reads = []
    for at in range(rx, receive - 2, 2):
        load, access = _word(image, at), _word(image, at + 2)
        if load & 0xFF00 == 0x4800 and access & 0xF800 == 0x7800 and access >> 3 & 7 == 0:
            offset = access >> 6 & 31
            if offset in (4, 8):
                if thumb_literal_value(image, at, 0) != base + 4:
                    return reject('console-receive-base-mismatch')
                reads.append((at + 2, offset))
    if not {4, 8}.issubset({offset for _, offset in reads}):
        return reject('console-receive-consumers-unclosed')
    hits, cursor = [], 0
    while (marker := image.find(bytes.fromhex('0978490805d20121'), cursor)) >= 0:
        cursor = marker + 1
        if _tx_at(image, marker - 2, base, pulse):
            hits.append(marker - 2)
    if hits != [tx]:
        return reject('console-tx-ownership-ambiguous')
    return dict(signature='thumb-uart-sync-console-v1', admission='temporary-evidence-gated',
                policy='provisional-synchronous-null-console', base=base,
                primary_entry=primary, init_entry=init, tx_entry=tx,
                status_address=base + 8, control_address=base + 0x10,
                isr_address=base + 0x14, fifo_address=base + 0xC, pulse_address=pulse,
                primary_status_pc=primary + 4, primary_control_pc=primary + 0x22,
                init_writes=writes, clock_setup=clock_setup, rx_drain_pc=read + 4, tx_isr_pc=tx + 2,
                tx_fifo_pc=tx + 24, console_root=root, receive_entry=rx,
                receive_wrapper=receive, tx_callers=tx_callers,
                receive_reads=reads, code_intervals=[(root, root + 30), (primary, primary + 40),
                                (init, read + (36 if _word(image, read + 22) & 0xFF00 == 0x3100 else 34)),
                                (rx, rx + 12), (receive, receive + 30), (tx, tx + 28)]), 'accepted'

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


def _byte_code(image: bytes, at: int, mask: str) -> bool:
    if at < 0 or at & 1 or at + len(mask)//2 > len(image):
        return False
    if any(token != '??' and image[at+i//2] != int(token,16)
           for i in range(0,len(mask),2) for token in (mask[i:i+2],)):
        return False
    off=0
    while off<len(mask)//2-1:
        if mask[off*2:off*2+8]=='????????':
            target=thumb_bl_target(image,at+off)
            if target is None or not 0<=target<len(image)-1:return False
            off+=4
            continue
        word=_word(image,at+off)
        if word&0xf800==0x4800 and thumb_literal_value(image,at+off,word>>8&7) is None:
            return False
        off+=2
    return True


def _byte_writes(image: bytes, start: int, end: int, primary: int) -> tuple[list, list, list] | None:
    registers=[None]*8
    writes=[];calls=[];at=start
    while at < end:
        word=_word(image,at)
        if word is None:return None
        kind=word&0xf800;register=word>>8&7
        if kind == 0x2000:registers[register]=word&255
        elif kind == 0x4800:
            registers[register]=thumb_literal_value(image,at,register)
            if registers[register] is None:return None
        elif kind in (0x3000,0x3800):
            if registers[register] is None:return None
            registers[register]+=(word&255)*(1 if kind==0x3000 else -1)
        elif kind == 0:
            source=registers[word>>3&7]
            if source is None:return None
            registers[word&7]=(source<<(word>>6&31))&0xffffffff
        elif kind in (0x7000,0x8000):
            value,base=registers[word&7],registers[word>>3&7]
            size=1 if kind==0x7000 else 2
            if value is None or base is None or not 0<=value<1<<(size*8):return None
            writes.append(dict(pc=at,address=base+(word>>6&31)*size,size=size,value=value))
        elif thumb_bl_target(image,at)==primary:
            calls.append(at);registers[:4]=[None]*4;at+=2
        else:return None
        at+=2
    return writes,registers,calls


def _byte_profile_at(image: bytes, primary: int, name: str, spec: dict, calls: list) -> tuple[dict | None,str]:
    def fail(reason):return None,'console-byte-'+reason
    def code(role,at):return _byte_code(image,at,spec[role])
    def literal(at,reg):return thumb_literal_value(image,at,reg)
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
    roots=[]
    root_specs=(spec,{**spec,**_BYTE_EXTENDED_ROOT}) if name=='register-and' else (spec,)
    for root_spec in root_specs:
        root=init_callers[0]-root_spec['root_init_call']
        if (_byte_code(image,root,root_spec['root'])
                and thumb_bl_target(image,root+root_spec['root_primary_call'])==primary):
            roots.append((root,root_spec))
    if len(roots)!=1:return fail('root-primary-link')
    root,spec=roots[0]
    if literal(root+(0xc if name=='register-and' else 4),1)!=base-(0x16c if name=='register-and' else 0x12c):
        return fail('root-clock-producer')
    if 'root_setup_literal' in spec:
        offset,register,delta=spec['root_setup_literal']
        if literal(root+offset,register)!=base+delta:return fail('root-setup-producer')
    flag=thumb_bl_target(image,root+spec['root_flag_call'])
    dispatch=thumb_bl_target(image,root+spec['root_dispatch_call'])
    if flag is None or dispatch is None or not code('flag',flag) or not code('dispatch',dispatch):return fail('root-family-unclosed')
    flag_address=literal(flag+2,1) if name=='register-and' else literal(flag+0x16,3)
    if flag_address is None or not 0x01000000<=flag_address<0x02000000:return fail('root-flag-range')
    if name=='lsr-ready':
        source=literal(flag,1)
        if source is None or not 0<=source<=len(image)-8 or literal(flag+0x20,3)!=flag_address:
            return fail('root-flag-source')
    buffer=literal(dispatch+(0xa if name=='register-and' else 2),4 if name=='register-and' else 0)
    flag_terms=((0x14,7),) if name=='register-and' else ((0xc,1),(0x10,0),(0x1a,0))
    if (buffer is None or buffer&3 or not 0<=buffer<=len(image)-4
            or any(literal(dispatch+off,reg)!=flag_address for off,reg in flag_terms)):
        return fail('dispatcher-global-ownership')
    parser=thumb_bl_target(image,dispatch+spec['dispatch_parser_call'])
    if parser is None or not code('parser_head',parser):return fail('parser-link')
    if literal(parser+(0x16 if name=='register-and' else 0xe),0 if name=='register-and' else 1)!=pulse:
        return fail('parser-pulse-producer')
    receive_sites=[parser+off for off in spec['parser_receive_calls']]
    wrapper=thumb_bl_target(image,receive_sites[0])
    if (wrapper is None or not code('wrapper',wrapper)
            or any(thumb_bl_target(image,at)!=wrapper for at in receive_sites)
            or [at for at,target in calls if target==wrapper]!=receive_sites):return fail('receive-wrapper-link')
    rx_sites=[wrapper+off for off in spec['wrapper_rx_calls']]
    rx=thumb_bl_target(image,rx_sites[0])
    if (rx is None or not code('rx',rx) or any(thumb_bl_target(image,at)!=rx for at in rx_sites)
            or [at for at,target in calls if target==rx]!=rx_sites):return fail('receive-call-family')
    if name=='register-and':
        rx_literals=((6,7,base-12),(12,4,pulse),(18,1,0xf4240))
        wrapper_literals=((0xa,7,None),(0x38,2,base-12))
    else:
        rx_literals=((8,3,0xf4240),(0x14,0,base+4),(0x24,7,pulse),(0x36,0,base+4),(0x44,7,pulse))
        wrapper_literals=((2,0,None),(0x34,0,base+4),(0x42,0,base+4),(0x4c,0,base+4))
    if any(literal(rx+off,reg)!=value for off,reg,value in rx_literals):return fail('receive-aliases')
    if literal(wrapper+(0xa if name=='register-and' else 2),7 if name=='register-and' else 0)!=flag_address+(0x3c if name=='register-and' else 8):
        return fail('receive-global-ownership')
    for off,reg,value in wrapper_literals:
        resolved=literal(wrapper+off,reg)
        if (resolved!=value if value is not None else resolved is None or not 0x01000000<=resolved<0x02000000):
            return fail('receive-wrapper-aliases')
    tx_candidates=[]
    anchor=bytes.fromhex(spec['tx'].split('??',1)[0])
    if not anchor:anchor=bytes.fromhex('0978490805d20121')
    cursor=0
    while (at:=image.find(anchor,cursor))>=0:
        cursor=at+1
        if not bytes.fromhex(spec['tx'].split('??',1)[0]):at-=2
        if not code('tx',at):continue
        terms=((6,2,base+0x14),(10,0,pulse),(0x1c,0,base-12)) if name=='register-and' else ((0,1,base+0x14),(10,2,pulse),(0x14,1,base+4))
        if all(literal(at+off,reg)==value for off,reg,value in terms):tx_candidates.append(at)
    if len(tx_candidates)!=1:return fail('tx-ownership-ambiguous')
    tx=tx_candidates[0];tx_calls=[at for at,target in calls if target==tx]
    if len(tx_calls)!=4:return fail('tx-call-family')
    ack1=tx_calls[0]-spec['ack_calls'][0][0];ack2=tx_calls[2]-spec['ack_calls'][1][0]
    if (not code('ack1',ack1) or not code('ack2',ack2)
            or tx_calls != [ack+off for ack,offsets in ((ack1,spec['ack_calls'][0]),(ack2,spec['ack_calls'][1])) for off in offsets]
            or not any(target==ack2 and parser<=at<parser+0x140 for at,target in calls)):
        return fail('framed-tx-link')
    table=literal(ack2+(0xc if name=='register-and' else 6),1)
    if table is None or table&3 or not (0<=table<=len(image)-4 or 0x01000000<=table<0x02000000):
        return fail('framed-response-table')
    if name=='register-and':
        stack_calls=(root+6,init+6,dispatch+6,parser+6,wrapper+6,ack1+6,ack2+6)
        if len({thumb_bl_target(image,at)for at in stack_calls})!=1:return fail('stack-guard-family')
    return dict(signature=('thumb-uart-byte-tfwr16-sync-console-v1' if tfwr16
                           else 'thumb-uart-byte-sync-console-v1'),admission='temporary-evidence-gated',
        policy='provisional-synchronous-null-console',layout=name,register_width=1,csr_value=0xff,
        base=base,status_address=base+8,control_address=base+0x10,isr_address=base+0x14,
        fifo_address=base+0xc,pulse_address=pulse,primary_entry=primary,primary_status_pc=status_pc,
        primary_control_pc=None,init_entry=init,tx_entry=tx,init_writes=writes,
        clock_setup=(0xc0,0xaf,0x80,0x19),rx_drain_pc=drain+2,console_root=root,
        receive_entry=rx,receive_wrapper=wrapper,tx_callers=tx_calls,
        tx_isr_pc=tx+(12 if name=='register-and' else 2),tx_fifo_pc=tx+(30 if name=='register-and' else 22),
        code_intervals=[(init,drain+len(spec['drain'])//2),*[(at,at+len(spec[role])//2)for role,at in (
            ('primary',primary),('root',root),('dispatch',dispatch),
            ('parser_head',parser),('rx',rx),('wrapper',wrapper),('tx',tx),('ack1',ack1),('ack2',ack2),('flag',flag))]]),'accepted'


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
    calls=[(m.start(),thumb_bl_target(image,m.start()))for m in _THUMB_BL.finditer(image)if not m.start()&1]
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
_DD_MASKS = {
    'primary': (
        '90b400200122??4f??4901e00a7008703c792309fad390bc7047'
    ),
    'init': (
        '??4980b5002008710320??4980030882??490020203188800120??4980030880c80a8881??????????49c02010390871'
        'b22008727d200873??491c200870??4900202039087088811e200881??49002040398881??4a3420303a1070dd201071'
        '302010731020107310732020107310730120107304211173??492039002302e0177a08700b7017797f08f9d280bc08bc'
        '1847'
    ),
    'root': (
        '80b5??4800270780????????0920c005017b002904d1082101720121017301e007700773????????????????????????'
        '????????????????80bc08bc1847'
    ),
    'dispatch': (
        'b0b5??4d??4c286886e0381c????????3978112900d15be00edc0f2900d377e001a35b5c5b009f44732b737330353a3d'
        '7340??484d735000232900d15ae014dc16294fd009dc122947d0132900d05fe0011c381c????????5de0202947d02229'
        '00d055e0????????55e0302945d0312946d0322947d033294ad1????????4ae0011c381c????????45e0011c381c????'
        '????40e0011c381c????????3be0????????38e0????????35e0011c381c????????30e0????????2de0011c381c????'
        '????28e0????????25e0????????22e0011c381c????????1de0011c381c????????18e0011c381c????????13e0????'
        '????10e0????????0de0????????0ae0????????07e0011c381c????????02e00620????????2868071976e7'
    ),
    'parser': (
        'f1b5002600254fe0??480121017000210170????????071c431c45d0bb1c07d1??48002120300180c10a8181????????'
        '002c09d0012c0bd0022c35d17e2f0cd1032d19da04201be07e2fddd10124dbe77e2fd9d00025??4e02247d2f06d1????'
        '????431c20d020214840071c01235b039d4208db052003e0??4b9e4216d00120????????10e0681c0004000c291c051c'
        '0098??4a475430127e40311c0906c90d515a4840061cafe70024ade7281cf8bc08bc1847'
    ),
    'wrapper': (
        '80b5??4f3878002808d00120????????831c06d1981e80bc08bc18470020????????402303400021c943002b??4a01d1'
        '800902d3107a081cede7107a00217970e9e7'
    ),
    'rx': (
        'b0b4012700240028??4a??4b0cd0??491079450806d21f701c7001390029f7dc0120c043b0bc704710794108fad21f70'
        '1c70f9e7'
    ),
    'tx': (
        '90b400230121??4f??4a01e0117013703c786408fad3??491039087290bc7047'
    ),
    'ack1': (
        '80b50330071c7e20????????3878????????387801377e28f8d180bc08bc1847'
    ),
    'ack2': (
        '??4980b580000f587e20????????3878????????387801377e28f8d180bc08bc1847'
    ),
    'extra': (
        '00b57e20????????0220????????6a20????????d320????????7e20????????08bc1847'
    ),
    'flag': (
        '??49??4a00200b5cff2b01d0002003e001300828f7db012010707047'
    ),
    'clear': (
        '??48??4900684118002008607047'
    ),
    'policy': (
        '80b50027??????????490870'
    ),
    'boolean': (
        '9fb4??4902a80cc90cc001221204002103290cda04e04b1c1b041b0c191cf7e71388971c3a1c4f006c46e353f3e70120'
        '002103290eda04e04b1c1b041b0c191cf7e74b006f46fb5a4f0002ace75bbb42f2d0002004b090bc7047'
    ),
    'argument_root': (
        '80b5??48002707800120????????0920c005017b002904d1082101720121017301e007700773????????????????????'
        '????????????????????80bc08bc1847'
    ),
    'argument_prelude': (
        'f0b587b00021802280270025002401280292069104910391019103d0022804d0032805d00421059105e00a21059103e0'
        '0a21059101210691??4a9088009013211182????????????????0026012d1dd1002c0dd1????????029a049952100131'
        '0906090e0491072902920ddd01240be0????????03997f1001310906090e0391072901dd01210191002514e0????????'
        '002c04d10599029a114006d102e00699394002d1????????01e0????????01990125012904d001363606360e802ec5db'
        '????????????????002001300006000e0128fadb??4a009890801321118207b0f0bc08bc184700002007000302210843'
        '??4988807047000020070003??498880704700002007000301210843??49888070470000200700034008??4940008880'
        '704700002007000310210843??49888070470000200700031023??49984388807047000020070003'
    ),

}


def _dd_hits(image: bytes, role: str) -> list[int]:
    mask = _DD_MASKS[role]
    pattern = b''.join(b'.' if mask[i:i+2] == '??' else
                       re.escape(bytes([int(mask[i:i+2], 16)]))
                       for i in range(0, len(mask), 2))
    return [m.start() for m in re.finditer(pattern, image, re.DOTALL)
            if not m.start() & 1 and _byte_code(image, m.start(), mask)]


def _dd_at(image: bytes, root: int, calls: list, root_role: str = 'root') -> tuple[dict | None, str]:
    def fail(reason): return None, 'console-dd-' + reason
    def target(at): return thumb_bl_target(image, at)
    def literal(at, reg): return thumb_literal_value(image, at, reg)
    def code(role, at):
        return at is not None and _byte_code(image, at, _DD_MASKS[root_role if role == 'root' else role])
    delta = 2 if root_role == 'argument_root' else 0
    primary, init = target(root+0x24+delta), target(root+0x28+delta)
    flag, clear, dispatch = target(root+0x2c+delta), target(root+0x30+delta), target(root+0x34+delta)
    positions = dict(root=root, primary=primary, init=init, flag=flag, clear=clear,
                     dispatch=dispatch)
    if any(not code(role, at) for role, at in positions.items()):
        return fail('root-family')
    if target(init+0x24) != primary: return fail('init-primary-link')
    if delta:
        prelude = target(root+0xa)
        if not code('argument_prelude',prelude): return fail('argument-prelude')
        # This prelude owns a separate halfword domain; no GPIO meaning is imported.
        for off,reg in ((0x38,2),(0xd4,2),(0xf0,1),(0xfc,1),(0x10c,1),
                        (0x11a,1),(0x12c,1),(0x13a,1)):
            if literal(prelude+off,reg) != 0x03000720:
                return fail('argument-prelude-domain')
        for site,to in ((0x42,0x118),(0x46,0xec),(0x54,0x108),(0x70,0x108),
                        (0x8c,0x118),(0xa4,0x138),(0xaa,0x128),
                        (0xc0,0x118),(0xc4,0x138)):
            if target(prelude+site) != prelude+to:
                return fail('argument-prelude-call')
        positions['argument_prelude'] = prelude
    base, pulse = literal(primary+6, 7), literal(primary+8, 1)
    if base is None: return fail('base')
    base -= 4
    if base & 3 or not 0x03000000 <= base <= 0x03ffffc0 or pulse != 0x03000700:
        return fail('address-contract')
    parser = target(dispatch+0xc)
    if not code('parser', parser): return fail('parser')
    wrapper = target(parser+0x12)
    if not code('wrapper', wrapper) or target(parser+0x5e) != wrapper:
        return fail('rx-wrapper')
    rx = target(wrapper+0xc)
    if not code('rx', rx) or target(wrapper+0x1e) != rx: return fail('rx-status')
    ack2 = target(parser+0x80)
    if not code('ack2', ack2): return fail('response')
    tx = target(ack2+0xa)
    if not code('tx', tx) or target(ack2+0x10) != tx: return fail('tx')
    others = {}
    for role, offsets in (('ack1',(8,0xe)),('extra',(4,0xa,0x10,0x16,0x1c))):
        hits = [at for at in _dd_hits(image,role)
                if all(target(at+off) == tx for off in offsets)]
        if len(hits) != 1: return fail(role + '-ambiguous')
        others[role] = hits[0]
    ack1, extra = others['ack1'], others['extra']
    positions.update(parser=parser,wrapper=wrapper,rx=rx,ack1=ack1,ack2=ack2,
                     tx=tx,extra=extra)
    flag_address = literal(flag+2, 2)
    pointer = literal(dispatch+2, 5)
    if (flag_address is None or not 0x01000000 <= flag_address <= 0x01fffffa
            or flag_address & 3 or pointer is None or pointer & 3
            or not 0 <= pointer <= len(image)-4
            or struct.unpack_from('<I', image, pointer)[0] != flag_address):
        return fail('global-pointer')
    policies = []
    for at in _dd_hits(image,'policy'):
        boolean_at = target(at+4)
        if literal(at+8,1) != flag_address+4 or not code('boolean',boolean_at): continue
        seed_at = literal(boolean_at+2,1)
        if seed_at is not None and 0 <= seed_at <= len(image)-8:
            policies.append((at,boolean_at))
    if not policies: return fail('policy-producer')
    policy,boolean = policies[0]
    positions.update(policy=policy,boolean=boolean)
    terms = {
        'primary': ((6,7,base+4),(8,1,pulse)),
        'init': ((0,1,base+0x34),(0xa,1,pulse-0x100),(0x10,1,pulse-0x100),
                 (0x1a,1,pulse+0x20),(0x28,1,base+0x34),(0x38,1,base+0x34),
                 (0x3e,1,base+0x34),(0x4c,1,base+0x34),(0x54,2,base+0x34),
                 (0x78,1,pulse+0x20)),
        'root': ((2,0,pulse+0x40),),
        'dispatch': ((2,5,pointer),(4,4,0xffffe000)),
        'clear': ((0,0,pointer),(2,1,0xffffde00)),
        'parser': ((8,0,pulse),(0x20,0,pulse),(0x56,6,0xffff),
                   (0x78,3,0xf0b8)),
        'wrapper': ((2,7,flag_address+4),(0x2c,2,base+4)),
        'rx': ((8,2,base+4),(0xa,3,pulse),(0xe,1,0x5b8d80)),
        'tx': ((6,7,base+0x14),(8,2,pulse),(0x16,1,base+0x14)),
        'policy': ((8,1,flag_address+4),),
    }
    if any(literal(positions[role]+off, reg) != value
           for role, terms_ in terms.items() for off,reg,value in terms_):
        return fail('literal-ownership')
    # Software timeout policy and packet tables are only source identity, never MMIO defaults.
    seed = literal(boolean+2, 1)
    source = literal(flag, 1)
    crc = literal(parser+0x92, 2)
    table = literal(ack2, 1)
    if any(at is None or not 0 <= at <= len(image)-size
           for at,size in ((seed,8),(source,8),(crc,512),(table,52))):
        return fail('table-bounds')
    for index in range(13):
        at = struct.unpack_from('<I', image, table+index*4)[0]
        if not 0 <= at < len(image) or image.find(b'\x7e',at,min(at+16,len(image))) < 0:
            return fail('response-bounds')
    owned = {
        init: [root+0x28+delta], dispatch: [root+0x34+delta], parser: [dispatch+0xc],
        wrapper: [parser+0x12,parser+0x5e], rx: [wrapper+0xc,wrapper+0x1e],
        tx: [ack1+8,ack1+0xe,ack2+0xa,ack2+0x10,
             *[extra+off for off in (4,0xa,0x10,0x16,0x1c)]],
    }
    if any(sorted(at for at,to in calls if to == dest) != sorted(sites)
           for dest,sites in owned.items()): return fail('call-family')
    response_calls = [at for at,to in calls if to == ack2]
    if len(response_calls) != 24 or parser+0x80 not in response_calls:
        return fail('response-call-family')
    if any((_word(image,at-2) or 0) & 0xff00 != 0x2000
           or (_word(image,at-2) & 255) > 12 for at in response_calls):
        return fail('response-index')
    if target(dispatch+0x112) != ack2: return fail('dispatcher-response-link')
    if len(policies) != 1: return fail('complete-ownership-ambiguous')
    # Masks fix every typed store/value; resolved literals above fix their producers.
    writes = [dict(pc=init+off,address=address,size=size,value=value)
              for off,address,size,value in (
                  (6,base+0x38,1,0),(0xe,pulse-0xf0,2,0xc000),
                  (0x16,pulse-0xdc,2,0),(0x1e,pulse+0x20,2,0x4000),
                  (0x22,pulse+0x2c,2,(pulse+0x20)>>11),
                  (0x2e,base+0x28,1,0xc0),(0x32,base+0x2c,1,0xb2),
                  (0x36,base+0x30,1,0x7d),(0x3c,base+0x34,1,0x1c),
                  (0x44,base+0x14,1,0),(0x46,base+0x20,2,0),
                  (0x4a,base+0x1c,2,30),(0x52,base,2,0),(0x58,base+4,1,0x34),
                  (0x5e,base+8,1,0xdd),
                  *[(off,base+0x10,1,value) for off,value in
                    ((0x62,0x30),(0x66,0x10),(0x68,0x10),(0x6c,0x20),
                     (0x6e,0x20),(0x72,1),(0x76,4))])]
    return dict(signature='thumb-uart-sync-console-dd-v1',
        admission='temporary-evidence-gated',policy='provisional-synchronous-null-console',
        register_width=2,csr_value=0xdd,base=base,status_address=base+8,
        control_address=base+0x10,isr_address=base+0x14,fifo_address=base+0xc,
        pulse_address=pulse,primary_entry=primary,primary_status_pc=primary+0x10,
        primary_control_pc=None,init_entry=init,tx_entry=tx,console_root=root,
        rx_drain_pc=init+0x86,receive_entry=rx,receive_wrapper=wrapper,
        tx_callers=sorted(owned[tx]),tx_isr_pc=tx+0x10,tx_fifo_pc=tx+0x1a,
        init_writes=writes,clock_setup=(0xc0,0xb2,0x7d),
        code_intervals=[(at,at+len(_DD_MASKS[root_role if role == 'root' else role])//2)
                        for role,at in positions.items()]), 'accepted'


def _find_dd_uart_console_profile(image: bytes) -> tuple[dict | None,str]:
    roots = [(at,role) for role in ('root','argument_root') for at in _dd_hits(image,role)]
    if not roots: return None, 'console-dd-not-found'
    calls = [(m.start(),thumb_bl_target(image,m.start()))
             for m in _THUMB_BL.finditer(image) if not m.start() & 1]
    complete = []
    reasons = []
    for root,root_role in roots:
        profile,reason = _dd_at(image,root,calls,root_role)
        if profile is not None: complete.append(profile)
        else: reasons.append(reason)
    if len(complete) > 1: return None, 'console-dd-profiles-ambiguous'
    if 'console-dd-complete-ownership-ambiguous' in reasons:
        return None, 'console-dd-complete-ownership-ambiguous'
    if complete: return complete[0], 'accepted'
    return None, reasons[0] if len(reasons) == 1 else 'console-dd-candidates-unclosed'


def _find_prior_uart_console_profile(image: bytes, ready_profile: dict | None) -> tuple[dict | None,str]:
    existing,reason = _find_existing_uart_console_profile(image,ready_profile)
    dd,dd_reason = _find_dd_uart_console_profile(image)
    if dd is not None:
        if existing is not None or reason in ('console-byte-profiles-ambiguous',
                                              'console-protocol-ownership-ambiguous'):
            return None, 'console-protocol-ownership-ambiguous'
        return dd, 'accepted'
    if dd_reason in ('console-dd-profiles-ambiguous','console-dd-complete-ownership-ambiguous'):
        return None, dd_reason
    if existing is not None: return existing, reason
    if dd_reason != 'console-dd-not-found': return None, dd_reason
    return None, reason


# Separate mixed-width fixed-CSR compiler class. The prior profiles stay closed.
_FF_SPECS = {
    'tag': ('????0088????0988884201d100207047????fce7', (), ((0, 0), (4, 1), (16, 0))),
    'console': ('00b50020????0880????????????????????????????????????????????????08bc1847', (8, 12, 16, 20, 24, 28), ((4, 1),)),
    'primary': ('????0068002809d1????0079000905d20120????087000200870f5e77047', (), ((0, 0), (8, 0), (18, 1))),
    'init': ('00b50020????087100210920????????????????c020????10390871b22008727d2008731c20????08700020????2039087088811e2008810020????403988813420????30390870ff200871302008731020087308732020087308730120087304200873????0068002800d00ee0????30380079400800d208e0????3038027a0120????087000200870f0e708bc1847', (12, 16), ((4, 1), (22, 1), (38, 1), (44, 1), (58, 1), (66, 1), (100, 0), (110, 0), (122, 0), (130, 1))),
    'rx': ('80b4031c002b16d0????002a10dd02e0501e021cf9e7????0179480802d3081c80bc70470120????387000203870efe70120c043f4e7????0179480801d3081ceee70120????387000203870f3e7', (), ((8, 2), (22, 0), (38, 7), (54, 0), (68, 7))),
    'wrapper': ('90b5????0078002804d00120????????071c03e00020????????071cbb1c07d1????0078002803d0981e90bc08bc1847f80904d3????047a0020c043f5e7b80904d3????047a0020c043eee7????007a041c0020????0870201ce6e7', (12, 22), ((2, 0), (32, 0), (52, 0), (66, 0), (76, 0), (84, 1))),
    'tx': ('????0978490805d20121????117000211170f5e7????103908727047', (), ((0, 1), (10, 2), (20, 1))),
    'byteflag': ('????002008280ada02e0421c101cf9e70a5cff2af9d00022????1a7070470122????1a70fae7', (), ((0, 1), (24, 3), (32, 3))),
    'dispatch': ('90b5????0068002841d1????0068????4718381c????????041c38780f282ed201a31b5c5b009f442a072a2a0c1116192a2a1c1f242a2700211c381c????????20e0211c381c????????1be0211c381c????????16e0????????13e0????????10e0????????0de0211c381c????????08e0????????05e0????????02e00620????????????0068????4718c1e790bc08bc1847', (20, 60, 70, 80, 86, 92, 98, 108, 114, 120, 128), ((2, 0), (10, 0), (14, 1), (132, 0), (136, 1))),
    'parser': ('f1b5002600250024032c00d15ae00120????087000200870????????071c7b1c01d10024f0e7bb1c01d1????????002c04d0012c06d0022c42d108e07e2fe3d10124e1e77e2fdfd00025????02247e2f10d1032d04da0420????????0024d3e7????9e4204d00120????????0024cbe70324c9e77d2f09d1????????071c7b1c01d10024c0e720207840071c01235b039d4204db0520????????0024b4e7681c0004000c291c051c0098475430127e40311c0906c90d????515a4840061ca3e70024a1e7281cf8bc08bc1847', (24, 42, 88, 104, 120, 150), ((16, 1), (74, 6), (96, 3), (182, 2))),
    'ack1': ('90b5041ce71c7e20????????3878????????3878791c0f1c7e28f7d190bc08bc1847', (8, 14), ()),
    'ack2': ('90b5041ca000????0f587e20????????3878????????3878791c0f1c7e28f7d190bc08bc1847', (12, 18), ((6, 1),)),
    'wordflag': ('01200021096a????994200d00020????48607047', (), ((6, 3), (14, 1))),
    'aux': ('90b5????0068002811d1????????0420????888200200881081c007bc707ff0f05d10220????08828880????????90bc08bc1847', (10, 42), ((2, 0), (16, 1), (36, 1))),
    'delay': ('????6021017004210170ff2101700020????0860????09680a2905da????09680131????1160f5e77047', (), ((0, 0), (16, 1), (20, 1), (28, 1), (34, 2))),
    'hardware': ('0320????88800420????403908820020????20398881????0880????888000208882????088100200883????df308883????08827047', (), ((2, 1), (8, 1), (16, 1), (22, 0), (26, 0), (34, 0), (42, 0), (48, 0))),
    'prelude': ('0921c905087b0022002804d1082008720120087301e00a700a730a71????????0880????88807047', (), ((28, 0), (30, 1), (34, 0))),
    'config': ('fcb5041c0d1c????????300c4718072c13d0092c20d1????????798a????1940c0222a4011437982798ab180002801d1????????fcbc08bc1847????????798a????bd331940aa07920f11437982798ab1800028ecd0ede7????00270088032805dc3b1c0022211c????????????????????f83a019200223b1c0091211c08a0????????d6e7', (22, 48, 58, 106, 128), ((6, 6), (8, 1), (28, 3), (64, 3), (88, 0), (104, 0), (110, 2), (112, 1))),
    'copy': ('0120????087000200870????0068????09684018061c????0068051c????0068041cb44208d204e0281d051c201d041cf7e728682060f7e70120????087000200870????0068????09684018061c????0068041cb44206d202e0201d041cf9e700202060f9e70120????087000200870????0068????09684018061c????0068051c????0068041cb44208d204e0281d051c201d041cf7e728682060f7e70120????087000200870????0068????09684018061c????0068041cb4420dd202e0201d041cf9e700202060a003f8d10120????087000200870f2e70120????087000200870????0068????09684018061c????0068051c????0068041cb44208d204e0281d051c201d041cf7e728682060f7e70120????0870002008707047', (), ((2, 1), (10, 0), (14, 1), (22, 0), (28, 0), (58, 1), (66, 0), (70, 1), (78, 0), (104, 1), (112, 0), (116, 1), (124, 0), (130, 0), (160, 1), (168, 0), (172, 1), (180, 0), (208, 1), (220, 1), (228, 0), (232, 1), (240, 0), (246, 0), (276, 1))),
}
_FF_RESET = bytes.fromhex('38429fe5010014e334e29f1534e29f0514ff2fe1784700002c429fe5010014e328e29f1528e29f0514ff2fe17847000020429fe5010014e31ce29f151ce29f0514ff2fe17847000014429fe5010014e310e29f1510e29f0514ff2fe178470000000050e32000001ad7f021e3a8d19fe5dbf021e3f4d19fe5d3f021e3f0d19fe5f0419fe5010014e3ece19f15ece19f0514ff2fe178470000e4419fe5010014e3e0e19f15e0e19f0514ff2fe178470000000050e30c00001ad0419fe5010014e3cce19f15cce19f0514ff2fe178470000c4419fe5010014e3c0e19f15c0e19f0514ff2fe17847000077d60aead3f021e37cd19fe534119fe5010011e3a4e19f15a4e19f0511ff2fe17847000078470000d3f021e358d19fe590419fe5010014e38ce19f158ce19f0514ff2fe1784700001eff2fe178470000d3f021e378419fe514ff2fe1')
_FF_THUNK = bytes.fromhex('7847c04600c09fe51cff2fe1')
_FF_IRQ_SAVE = bytes.fromhex('7847000000000fe1c01080e301f021e1c00000e21eff2fe1')
_FF_IRQ_RESTORE = bytes.fromhex('7847000000000fe1c010c0e301f021e1c00000e21eff2fe1')

from .arm import arm_b_target
from .mono_page import _shape as _source_thumb_shape
from .memory_layout import _HIGH_RAM_TEST_SHA256
import hashlib


class _HalfFFUnclosed(ValueError):
    pass


def _ff_need(condition, reason):
    if not condition:
        raise _HalfFFUnclosed('console-half-ff-' + reason)


def _ff_u32(image, at):
    _ff_need(type(at) is int and 0 <= at <= len(image)-4, 'source-bounds')
    return struct.unpack_from('<I', image, at)[0]


def _ff_shape(image, at, role):
    mask,calls,literals = _FF_SPECS[role]
    result = _source_thumb_shape(image,at,bytes.fromhex(mask.replace('??','00')),calls,literals)
    _ff_need(result is not None,role+'-body')
    return result


def _ff_hits(image, role):
    mask,_,_ = _FF_SPECS[role]
    runs=[(match.start()//2,bytes.fromhex(match.group()))
          for match in re.finditer(r'(?:[0-9a-f]{2})+',mask)]
    offset,anchor=max(runs,key=lambda pair:len(pair[1]));start=0
    while (hit:=image.find(anchor,start))>=0:
        start=hit+1;at=hit-offset
        try:result=_ff_shape(image,at,role)
        except _HalfFFUnclosed:continue
        yield at,result


def _ff_overlap(a,b):
    return a[0]<b[1] and b[0]<a[1]


def _ff_ram(address,size):
    return 0x01000000<=address and size>0 and address+size<=0x01800000


def _ff_thunk(image,at):
    _ff_need(type(at)is int and not at&3 and 0<=at<=len(image)-16 and
             image[at:at+12]==_FF_THUNK,'interwork-thunk')
    target=_ff_u32(image,at+12)
    _ff_need(target&1,'interwork-target-isa')
    return target-1


def _ff_reset_copy(image):
    reset=arm_b_target(image,0)
    _ff_need(reset is not None and reset>=4 and not reset&3 and reset+len(_FF_RESET)<=len(image),'reset-owner')
    pools=[]
    for off in range(0,len(_FF_RESET),4):
        want=struct.unpack_from('<I',_FF_RESET,off)[0];actual=_ff_u32(image,reset+off)
        mask=0xfffff000 if want&0x0f7f0000==0x051f0000 else 0xffffffff
        if off==0xe8:mask=0xff000000
        _ff_need(actual&mask==want&mask,'reset-body')
        if mask==0xfffff000:
            pool=reset+off+8+(actual&4095);_ff_u32(image,pool);pools.append((pool,pool+4))
    def literal(pc):
        op=_ff_u32(image,pc)
        return _ff_u32(image,pc+8+(op&4095))
    for off in (0,0x18,0x30,0x48,0x80,0x98,0xb8,0xd0,0xf4,0x118):
        pc=reset+off;target=literal(pc)
        _ff_need(target<len(image) and (target&1 or not target&3) and
                 literal(pc+8)==pc+21 and literal(pc+12)==pc+(25 if off==0xf4 else 24),'reset-return')
    stacks=[literal(reset+off) for off in (0x6c,0x74,0x7c,0xf0,0x114)]
    _ff_need(all(not sp&3 and _ff_ram(sp-56,56) for sp in stacks),'stack-range')
    test=literal(reset+0x48);test_table=test-28
    _ff_need(not test&3 and test_table>=0 and test+0x150<=len(image) and
             hashlib.sha256(image[test:test+0x150]).hexdigest()==_HIGH_RAM_TEST_SHA256,'ram-test-body')
    fields=struct.unpack_from('<7I',image,test_table)
    base,extent,stride,word,half,byte,watchdog=fields
    _ff_need(not base&3 and extent>=15 and extent&15==15 and
             _ff_ram(base,extent+1) and (stride,word,half,byte,watchdog)==
             (16,0x55aa0f,0xaa0f,0x55,0x03000700),'ram-test-span')
    test_pools=[]
    for off,field in ((0,0),(0x10,8),(0x40,24),(0x6c,4),(0x80,4),
                      (0xf4,12),(0x108,16),(0x11c,20)):
        op=_ff_u32(image,test+off);pool=test+off+8+(op&4095)
        _ff_need(_ff_u32(image,pool)==test_table+field,'ram-test-field')
        test_pools.append((pool,pool+4))
    failure_pool=test+0x148+8+(_ff_u32(image,test+0x148)&4095)
    _ff_need(_ff_u32(image,failure_pool)!=0,'ram-test-failure-return')
    test_pools.append((failure_pool,failure_pool+4))
    tag=literal(reset+0x98)-1;_,tag_values=_ff_shape(image,tag,'tag')
    _ff_need(tag_values[0]==0x24 and tag_values[4]==0x2c and tag_values[16]!=0 and
             _word(image,0x24)==_word(image,0x2c),'header-pair-normal-path')
    copy=literal(reset+0x80)-1;_,values=_ff_shape(image,copy,'copy')
    _ff_need(all(values[o]==0x03000700 for o in (2,0x3a,0x68,0xa0,0xd0,0xdc,0x114)),'copy-pulse')
    copies=[];zeros=[];tables=[]
    for source_off,target_off,size_off,reload_off,zrefs in (
            (0x16,0xa,0xe,0x1c,(0x42,0x46,0x4e)),
            (0x7c,0x70,0x74,0x82,(0xa8,0xac,0xb4)),(0xf0,0xe4,0xe8,0xf6,None)):
        table=values[source_off]
        _ff_need(not table&3 and values[target_off]==table+4 and values[size_off]==table+8 and
                 values[reload_off]==table+4,'copy-fields')
        source,target,size=(_ff_u32(image,table+n) for n in (0,4,8))
        _ff_need(size>0 and not(source|target|size)&3 and source+size<=len(image),'copy-bounds')
        _ff_need(_ff_ram(target,size) if zrefs else 0x03800000<=target<target+size<=0x03a00000,'copy-owner')
        copies.append({'table_offset':table,'source':source,'target':target,'size':size})
        if zrefs:
            a,b,c=zrefs
            _ff_need(values[a]==table+12 and values[b]==table+16 and values[c]==table+12,'zero-fields')
            begin,length=_ff_u32(image,table+12),_ff_u32(image,table+16)
            _ff_need(target+size==begin and not(begin|length)&3 and _ff_ram(begin,length),'zero-bounds')
            zeros.append((begin,begin+length));tables.append((table,table+20))
        else:tables.append((table,table+12))
    spans=[(c['target'],c['target']+c['size']) for c in copies]+zeros
    _ff_need(not any(_ff_overlap(a,b)for i,a in enumerate(spans)for b in spans[i+1:]),'copy-zero-overlap')
    app=arm_b_target(image,reset+0xe8)
    _ff_need(app is not None and not app&3 and 0<=app<=len(image)-4,'application-target')
    return dict(reset=reset,literal=literal,copy=copy,copies=copies,zeros=zeros,tables=tables,
                pools=pools,stacks=stacks,application=app,test=test,test_table=test_table,
                test_pools=test_pools,test_ram=(base,base+extent+1),tag=tag)


def _ff_profile_at(image,console,console_shape,context,all_calls):
    root=context['reset'];literal=context['literal'];copies=context['copies']
    _ff_need(literal(root+0x118)==console|1,'console-reset-link')
    calls,values=console_shape
    entries={'console':console,'copy':context['copy'],'tag':context['tag']};shapes={'console':console_shape}
    shapes['tag']=_ff_shape(image,context['tag'],'tag')
    for off,role in ((12,'hardware'),(16,'primary'),(20,'init'),(24,'byteflag'),(28,'dispatch')):
        entries[role]=calls[off];shapes[role]=_ff_shape(image,entries[role],role)
    primary=entries['primary'];pv=shapes['primary'][1];word_flag=pv[0];pulse=pv[18];base=pv[8]-4
    window=(base,base+0x24)
    _ff_need(base==0x03000f0c and pulse==0x03000700 and
             not any(_ff_overlap(window,span)for span in ((0x03000624,0x03000626),(0x03000720,0x03000736),(0x03000740,0x03000742),(pulse,pulse+1),
               (copies[2]['target'],copies[2]['target']+copies[2]['size']))),'hardware-owner')
    _ff_need(_ff_ram(word_flag,4) and not word_flag&3,'word-flag-range')
    word_entry=literal(root+0xb8)-1;entries['wordflag']=word_entry
    shapes['wordflag']=_ff_shape(image,word_entry,'wordflag');wv=shapes['wordflag'][1]
    _ff_need(wv[14]+4==word_flag and _ff_u32(image,0x20)!=wv[6],'header-normal-path')
    aux=literal(root+0xd0)-1;entries['aux']=aux;shapes['aux']=_ff_shape(image,aux,'aux')
    ac,av=shapes['aux'];_ff_need(av[2]==word_flag and av[16]==av[36]==0x03000720 and ac[42]==root+0x10c,'aux-root-link')
    entries['delay']=ac[10];shapes['delay']=_ff_shape(image,ac[10],'delay')
    dv=shapes['delay'][1];delay_counter=dv[16]
    _ff_need(dv[20]==dv[28]==dv[34]==delay_counter and _ff_ram(delay_counter,4) and
             dv[0] < len(image) and not _ff_overlap((dv[0],dv[0]+1),window),'delay-owner')
    init=entries['init'];ic,iv=shapes['init']
    _ff_need(ic[16]==primary and iv[100]==word_flag,'init-primary-flag')
    parsed=_byte_writes(image,init+0x14,init+0x64,primary)
    _ff_need(parsed is not None,'init-writes')
    writes,_,write_calls=parsed
    expected=[(base+0x28,1,0xc0),(base+0x2c,1,0xb2),(base+0x30,1,0x7d),(base+0x34,1,0x1c),
              (base+0x14,1,0),(base+0x20,2,0),(base+0x1c,2,30),(base,2,0),(base+4,1,0x34),
              (base+8,1,0xff),*[(base+0x10,1,v)for v in (0x30,0x10,0x10,0x20,0x20,1,4)]]
    _ff_need(not write_calls and [(w['address'],w['size'],w['value'])for w in writes]==expected and
             iv[4]==base+0x34 and iv[110]-0x30==iv[122]-0x30==base+4 and iv[130]==pulse,'typed-init')
    prelude_thunk=calls[8];config_thunk=ic[12]
    entries['prelude']=_ff_thunk(image,prelude_thunk);shapes['prelude']=_ff_shape(image,entries['prelude'],'prelude')
    entries['config']=_ff_thunk(image,config_thunk);shapes['config']=_ff_shape(image,entries['config'],'config')
    _ff_need(shapes['prelude'][1][30]==0x04800080,'prelude-domain')
    hw=_byte_writes(image,entries['hardware'],entries['hardware']+len(_FF_SPECS['hardware'][0])//2-2,primary)
    _ff_need(hw is not None and all(0x04800000<=w['address']<0x04800100 for w in hw[0]),'hardware-domain')
    cfg_calls,cfg_values=shapes['config'];gpio=cfg_values[6]
    _ff_need(gpio==0x03000620 and cfg_values[28]==0xff3f,'config-nine-domain')
    shadow=cfg_values[8]+(gpio>>16)+0x12
    _ff_need(not shadow&1 and _ff_ram(shadow,2),'config-shadow')
    irq_sources=[];irq_entries=[];thunks=[]
    iram=copies[2]
    for off,pattern in ((22,_FF_IRQ_SAVE),(48,_FF_IRQ_RESTORE)):
        thunk=cfg_calls[off];ram_entry=_ff_thunk(image,thunk)
        _ff_need(not ram_entry&3 and iram['target']<=ram_entry and ram_entry+24<=iram['target']+iram['size'],'irq-copy-range')
        source=iram['source']+ram_entry-iram['target']
        _ff_need(image[source:source+24]==pattern,'copied-irq-body')
        irq_sources.append((source,source+24));irq_entries.append((ram_entry,ram_entry+24));thunks.append((thunk,thunk+16))
    dispatch=entries['dispatch'];dc,dv_dispatch=shapes['dispatch']
    _ff_need(dv_dispatch[2]==word_flag and dv_dispatch[10]==dv_dispatch[132]==copies[0]['table_offset']+4 and
             dv_dispatch[14]==dv_dispatch[136]==0xffffe000,'dispatch-global-ownership')
    packet_buffer=(copies[0]['target']+dv_dispatch[14])&0xffffffff
    _ff_need(any(a<=packet_buffer and packet_buffer+0x2000<=b for a,b in context['zeros']),'packet-buffer-provenance')
    entries['parser']=dc[20];shapes['parser']=_ff_shape(image,entries['parser'],'parser')
    pcalls,pl=shapes['parser'];wrapper=pcalls[24]
    _ff_need(pl[16]==pulse,'parser-pulse')
    _ff_need(pcalls[120]==wrapper and pcalls[42]==root+0x134,'parser-receive-links')
    entries['wrapper']=wrapper;shapes['wrapper']=_ff_shape(image,wrapper,'wrapper')
    wc,wl=shapes['wrapper'];rx=wc[12]
    _ff_need(wc[22]==rx,'receive-call-links');entries['rx']=rx;shapes['rx']=_ff_shape(image,rx,'rx')
    timeout=wl[2]
    _ff_need(wl[32]==wl[84]==timeout and wl[52]==wl[66]==wl[76]==base+4,'receive-global-links')
    rv=shapes['rx'][1]
    _ff_need(rv[22]==rv[54]==base+4 and rv[38]==rv[68]==pulse and rv[8]>0,'receive-domain')
    main=copies[1];private=copies[0]
    _ff_need(private['target']<=timeout<private['target']+private['size'],'timeout-copy')
    timeout_source=private['source']+timeout-private['target']
    _ff_need(image[timeout_source]==1,'timeout-initial-one')
    bf=shapes['byteflag'][1]
    _ff_need(bf[0]==0x44 and bf[24]==bf[32]==timeout-4,'byte-flag-domain')
    _ff_need(main['target']<=word_flag and word_flag+4<=main['target']+main['size'],'word-flag-copy')
    ram_fields=[(word_flag,word_flag+4),(timeout,timeout+1),(timeout-4,timeout-3),
                (delay_counter,delay_counter+4),(shadow,shadow+2)]
    _ff_need(not any(_ff_overlap(a,b)for i,a in enumerate(ram_fields)for b in ram_fields[i+1:]),'metadata-alias')
    ack2=pcalls[88];_ff_need(pcalls[104]==ack2 and dc[128]==ack2,'ack2-links')
    entries['ack2']=ack2;shapes['ack2']=_ff_shape(image,ack2,'ack2')
    response_table=shapes['ack2'][1][6]
    _ff_need(not response_table&3 and 0<=response_table<=len(image)-4,'response-table')
    tx=shapes['ack2'][0][12];_ff_need(shapes['ack2'][0][18]==tx,'ack2-transmit-links')
    entries['tx']=tx;shapes['tx']=_ff_shape(image,tx,'tx')
    tv=shapes['tx'][1];_ff_need(tv[0]==base+0x14 and tv[10]==pulse and tv[20]-0x10==base+4,'transmit-domain')
    ack1s=[(at,shape)for at,shape in _ff_hits(image,'ack1')if shape[0][8]==shape[0][14]==tx]
    _ff_need(len(ack1s)==1,'ack1-owner');entries['ack1'],shapes['ack1']=ack1s[0]
    # Shared RX/TX ownership is a complete local call family, not a lone poll.
    owned={rx:{wrapper+12,wrapper+22},wrapper:{entries['parser']+24,entries['parser']+120},
           tx:{entries['ack1']+8,entries['ack1']+14,ack2+12,ack2+18},init:{console+20}}
    _ff_need(all({site for site,target in all_calls if target==at}==sites for at,sites in owned.items()),'consumer-call-ownership')
    code=[(at,at+len(_FF_SPECS[role][0])//2)for role,at in entries.items()]
    code+=irq_sources+[(prelude_thunk,prelude_thunk+16),(config_thunk,config_thunk+16)]+thunks
    code.append((context['test'],context['test']+0x150))
    _ff_need(not any(_ff_overlap(a,b)for i,a in enumerate(code)for b in code[i+1:]),'code-owner-overlap')
    app=context['application']
    _ff_need(not any(a<=app<b for a,b in code+[(root,root+len(_FF_RESET))]),'application-code-owner')
    pools=list(context['pools'])+context['test_pools']
    for role,at in entries.items():
        for off,_reg in _FF_SPECS[role][2]:
            op=_word(image,at+off);pool=((at+off+4)&~3)+(op&255)*4;pools.append((pool,pool+4))
    pools += [(at+12,at+16)for at,_end in [(prelude_thunk,prelude_thunk+16),(config_thunk,config_thunk+16)]+thunks]
    # Thunk literal words belong to their own 16-byte body; ordinary Thumb
    # pools must not alias known instruction bodies.
    ordinary=pools[:len(pools)-4]
    _ff_need(all(0<=a<b<=len(image) and not any(_ff_overlap((a,b),c)for c in code)for a,b in ordinary),'literal-owner')
    data=context['tables']+[(context['test_table'],context['test_table']+28),(0x24,0x26),(0x2c,0x2e)]+[(c['source'],c['source']+c['size'])for c in copies]+[(0x20,0x24),(0x44,0x4c),(response_table,response_table+4)]
    _ff_need(all(0<=a<b<=len(image)for a,b in data) and
             not any(a<=app<b for a,b in pools+data),'application-data-owner')
    guards=sorted(set(code+pools+data+[(root,root+len(_FF_RESET))]))
    ram_intervals=[context['test_ram']]+[(c['target'],c['target']+c['size'])for c in copies[:2]]+context['zeros']+ram_fields+[(sp-56,sp)for sp in context['stacks']]
    return dict(signature='thumb-byte-uart-word-flag-fixed-ff-mixed-v1',admission='temporary-evidence-gated',
        policy='provisional-synchronous-null-console',register_width=2,csr_value=0xff,
        base=base,status_address=base+8,control_address=base+0x10,isr_address=base+0x14,fifo_address=base+0xc,
        pulse_address=pulse,primary_entry=primary,primary_status_pc=primary+10,primary_control_pc=None,
        init_entry=init,tx_entry=tx,console_root=console,rx_drain_pc=init+0x72,receive_entry=rx,receive_wrapper=wrapper,
        tx_callers=sorted(owned[tx]),tx_isr_pc=tx+2,tx_fifo_pc=tx+24,init_writes=writes,clock_setup=(0xc0,0xb2,0x7d,0x1c),
        code_intervals=[list(x)for x in sorted(set(code))],literal_intervals=[list(x)for x in sorted(set(pools))],
        data_intervals=[list(x)for x in sorted(set(data))],boot_guard_intervals=[list(x)for x in sorted(((root,root+len(_FF_RESET)),(0x20,0x24),(0x24,0x26),(0x2c,0x2e)))],
        guard_intervals=[list(x)for x in guards],ram_intervals=[list(x)for x in sorted(set(ram_intervals))],
        iram_intervals=[list(x)for x in sorted(set(irq_entries+[(iram['target'],iram['target']+iram['size'])]))],
        word_flag=word_flag,word_flag_producer=word_entry,header_marker=wv[6],header_value=_ff_u32(image,0x20),
        receive_timeout_flag=timeout,receive_timeout_source=timeout_source,copy_layouts=copies,
        reset_entry=root,copy_entry=context['copy'],stack_predecrement_bytes=56,packet_buffer=packet_buffer,
        runtime_source_policy='defer-until-postpatch-primary-reparse-and-immutable-byte-match')


def _find_half_ff_uart_console_profile(image):
    roots=list(_ff_hits(image,'console'))
    if not roots:return None,'console-half-ff-not-found'
    try:context=_ff_reset_copy(image)
    except _HalfFFUnclosed as error:return None,str(error)
    calls=[(m.start(),thumb_bl_target(image,m.start()))for m in _THUMB_BL.finditer(image)if not m.start()&1]
    profiles=[];reasons=[]
    for at,shape in roots:
        try:profiles.append(_ff_profile_at(image,at,shape,context,calls))
        except _HalfFFUnclosed as error:reasons.append(str(error))
    if len(profiles)>1:return None,'console-half-ff-profiles-ambiguous'
    if profiles:return profiles[0],'accepted'
    return None,reasons[0]if len(reasons)==1 else'console-half-ff-candidates-unclosed'


def find_uart_console_profile(image: bytes, ready_profile: dict | None) -> tuple[dict | None,str]:
    prior,reason=_find_prior_uart_console_profile(image,ready_profile)
    new,new_reason=_find_half_ff_uart_console_profile(image)
    if new is not None:
        if prior is not None or 'ambiguous' in reason:
            return None,'console-protocol-ownership-ambiguous'
        return new,'accepted'
    if 'ambiguous' in new_reason:return None,new_reason
    if prior is not None or 'ambiguous' in reason:return prior,reason
    return (None,reason)if new_reason=='console-half-ff-not-found'else(None,new_reason)


# A distinct finite boot probe; old source contracts above remain unchanged.
_PROBE_SPECS = {
    'root': ('80b5????????ff20????????0a20????????????????071c3806000e0c2808d1????????????????????012080bc08bc1847dd20????????0020f7e7', (2, 8, 14, 18, 32, 38, 52), ((36, 0),)),
    'init': ('80b5071c????????0020????087100210920????????????????c020????10390871b22008727d2008731c20????08700020????2039087088811e2008810020????403988813420????30390870081c0771302008731020087308732020087308730120087304200873????30380079400800d208e0????3038027a0120????087000200870f0e780bc08bc1847', (4, 18, 22), ((10, 1), (28, 1), (44, 1), (50, 1), (64, 1), (72, 1), (106, 0), (118, 0), (126, 1))),
    'primary': ('2020????08730873????0079000905d20120????087000200870f5e77047', (), ((2, 1), (8, 0), (18, 1))),
    'setup': ('f0b58bb02c226846????????????????????05042d0c????????????0722d2018f183988????????1940398039881170002801d1????????????????????032212028c18a188????????023b194080221143a180a1883181002801d1????????????????a188????????023b1940a180a1883181002801d1????????????????3988????????7c3319400222114339803988????1170002801d1????????????????3988????????7c331940398039881170002801d1????????????????????0f20????????0420????????6846????????0120????????????????2188????4904490c218021881180002801d1????????????????1921490171184a8a????7c331a404a82498a????a03a1171002801d1????????????0222f0380272????????????8024b98b2143b983b98b3a691180002801d1????????????????f98b2143f983f98bba691180002801d1????????002d00d001e0????????0bb0f0bc08bc1847', (10, 14, 22, 52, 56, 92, 96, 120, 124, 154, 158, 182, 188, 194, 200, 206, 212, 216, 238, 242, 274, 286, 310, 314, 334, 344), ((8, 1), (26, 1), (36, 3), (38, 2), (60, 1), (70, 3), (72, 6), (102, 3), (104, 6), (130, 3), (132, 6), (146, 2), (164, 3), (166, 2), (186, 0), (222, 2), (254, 3), (264, 2), (278, 0), (290, 7))),
    'config': ('b0b5????0c1c????290c8f18072813d0092820d1????????798a????1940c022224011437982798aa980002801d1????????b0bc08bc1847????????798a????bd331940a207920f11437982798aa9800028ecd0ede7????????????????e8e7', (20, 46, 56, 90), ((2, 5), (6, 2), (26, 3), (62, 3), (86, 1), (88, 0))),
    'copy': ('0120????087000200870????0068????09684018061c????0068051c????0068041cb44208d204e0281d051c201d041cf7e728682060f7e70120????087000200870????0068????09684018061c????0068041cb44206d202e0201d041cf9e700202060f9e70120????087000200870????0068????09684018061c????0068051c????0068041cb44208d204e0281d051c201d041cf7e728682060f7e70120????087000200870????0068????09684018061c????0068041cb4420dd202e0201d041cf9e700202060a003f8d10120????087000200870f2e70120????0870002008707047', (), ((2, 1), (10, 0), (14, 1), (22, 0), (28, 0), (58, 1), (66, 0), (70, 1), (78, 0), (104, 1), (112, 0), (116, 1), (124, 0), (130, 0), (160, 1), (168, 0), (172, 1), (180, 0), (208, 1), (220, 1))),
    'delay': ('f0b4????978c116a79437a013f239a1a0026322809dc4843222179438018401a801100d4061c????22e032234b439d1822237b43341ceb1a9b1100d41c1c????3c8032234b4332389b189b1101d41c1c00e0341c2404240c01e03c8032383228fbdc002805dd48438018801100d4061c3e80f0bc7047', (), ((2, 2), (38, 7), (62, 7))),
    'pinset': ('80b5071c????????????032212028918ca89ba433a43ca81c989????1173002801d1????????80bc08bc1847', (4, 34), ((8, 1), (26, 2))),
    'clockset': ('f0b5????????290c8f180a28????1bd1????????0404240c????00200870????????????????????????3988326d91431143398039882980002801d1????????002c00d026e023e0c400305900280cd0????????3a8831598a431143398039882980002801d1????????a4196068002800d10fe0????????398a6268914311433982398a????20321180002800d001e0????????f0bc08bc1847', (16, 30, 34, 38, 60, 80, 102, 116, 144), ((2, 5), (4, 2), (12, 6), (24, 1), (132, 2))),
    'apply': ('f0b5071c????????0404240c2c22391c????????????????0321090247183d883e8a0420????????????????????????????????????798a3f2352889b0219409205920d11437982798a????9180002801d1????????????????39890907090f03229203114339813989????203a1182002801d1????????3d803e82????????3988????39803988203a1180002801d1????????????????398a????3982398a1180002801d1????????????????002c00d001e0????????f0bc08bc1847', (4, 18, 36, 40, 44, 48, 82, 86, 116, 124, 144, 148, 166, 170, 180), ((16, 0), (22, 0), (52, 2), (74, 2), (106, 2), (130, 2), (154, 2))),
    'clockclear': ('f0b5c4000026????0321????090228598f1800280dd0????????39882a599143314339803988????1180002801d1????????6419606800280ed0????????398a6268914331433982398a????20321180002801d1????????f0bc08bc1847', (22, 46, 58, 84), ((6, 5), (10, 2), (38, 2), (74, 2))),
}
_PROBE_RESET = bytes.fromhex('58429fe5010014e354e29f1554e29f0514ff2fe1784700004c429fe5010014e348e29f1548e29f0514ff2fe17847000040429fe5010014e33ce29f153ce29f0514ff2fe17847000034429fe5010014e330e29f1530e29f0514ff2fe178470000000050e31600001ad7f021e3c8d19fe5dbf021e314d29fe5d3f021e310d29fe510429fe5010014e30ce29f150ce29f0514ff2fe17847000004429fe5010014e300e29f1500e29f0514ff2fe178470000000050e30100000a9c019fe510ff2fe1045c07ead3f021e3c4d19fe57c119fe5010011e3d4e19f15d4e19f0511ff2fe1784700005419a0e30000a0e10000a0e10000a0e1c0319fe50140a0e3004083e50040a0e3004083e5011041e2000051e3f4ffff1aa4119fe5010011e394e19f159ce19f0511ff2fe17847000078470000d3f021e358d19fe58c419fe5010014e380e19f1584e19f0514ff2fe1784700001eff2fe178470000')
_PROBE_APP = bytes.fromhex('d2f021e328d09fe5dff021e324d09fe5d1f021e30dd02de01cd09fe5d3f021e318209fe512ff2fe1')
_PROBE_TEMPLATE = bytes.fromhex('6755a8000004faef020a550150f10208290003008000a3026000000002000000007d00001000020001000000')
# Only the aligned 44-byte path: 32 + 8 + 4 bytes, saved R4/LR restored.
_PROBE_MEMCPY_44 = bytes.fromhex('7847000010402de9202052e20500003a1850b1281850a0281850b1281850a02820205222f9ffff2a02ceb0e11850b1281850a0281800b1481800a04802cfb0e104309124043080241040bde81eff2f01')



_CLOCK_SPECS = {'clock_commit': ('ffb5??486f460fc80fc7082601240925??4aed05??49383a01984968d71d1937884222d330329079012804d100ab1878????????03e000ab1878????????00ab58892871387b002804d09889304328722c7304e000ab1889287000202873387b002800d000243c7318e0387b002805d000ab9889304328722c7304e000ab1889287000202873387b002800d000243c7300ab588928711878????????00ab5889042802da5e89013604e000ab5889042800d0102637043f0c7d20c0000199????????391c????????6846??4f0fc80fc7ffbc08bc1847',
                  (48, 58, 152, 190, 196),
                  ((2, 0), (16, 2), (20, 1), (202, 7))),
 'clock_regs': ('80b5??????????4f??4a032339881b02d2185181??4a9182002801d1????????b888??494031088338898883f888??496031088078890881f8898881b889088280bc08bc1847',
                (2, 28),
                ((6, 7), (8, 2), (20, 2), (34, 1), (46, 1))),
 'clock_version': ('90b5??4f??4c788a2072????????d5231b02984201db802000e00020398a0843a081072020719620????????90bc08bc1847',
                   (10, 40),
                   ((2, 7), (4, 4))),
 'clock_select_a': ('80b5071c062f24d201a3db5d5b009f4412020a121812??48??490880??48888080bc08bc1847??481130??490880??4811308880f4e7??48??490880??488880eee7??482238??490880??4822388880e6e7??49??48????????e1e7',
                    (86,),
                    ((22, 0),
                     (24, 1),
                     (28, 0),
                     (38, 0),
                     (42, 1),
                     (46, 0),
                     (54, 0),
                     (56, 1),
                     (60, 0),
                     (66, 0),
                     (70, 1),
                     (74, 0),
                     (82, 1),
                     (84, 0))),
 'clock_select_b': ('80b5071c062f24d201a3db5d5b009f4412020a121812??48??490880??48888080bc08bc1847??480130??490880??4811308880f4e7??48??490880??488880eee7??482238??490880??4822388880e6e7??49??48????????e1e7',
                    (86,),
                    ((22, 0),
                     (24, 1),
                     (28, 0),
                     (38, 0),
                     (42, 1),
                     (46, 0),
                     (54, 0),
                     (56, 1),
                     (60, 0),
                     (66, 0),
                     (70, 1),
                     (74, 0),
                     (82, 1),
                     (84, 0))),
 'clock_select_c': ('80b5071c062f24d201a3db5d5b009f4412020a121812??48??490880??48888080bc08bc1847??481130??490880??4811308880f4e7??48??490880??488880eee7??482238??490880??4822388880e6e7??49b1208000????????e0e7',
                    (88,),
                    ((22, 0),
                     (24, 1),
                     (28, 0),
                     (38, 0),
                     (42, 1),
                     (46, 0),
                     (54, 0),
                     (56, 1),
                     (60, 0),
                     (66, 0),
                     (70, 1),
                     (74, 0),
                     (82, 1))),
 'clock_update': ('90b5071c0c1c??????????4900280f628c8401d1????????90bc08bc1847', (6, 20), ((10, 1),)),
 'clock_version_get': ('??490879002807d101200871??48007b??49487000200870??482a38408d7047',
                       (),
                       ((0, 1), (12, 0), (16, 1), (24, 0))),
 'clock_select_b_old': ('80b5071c062f24d201a3db5d5b009f4412020a121812??48??490880??48888080bc08bc1847??480130??490880??4811308880f4e7??48??490880??488880eee7??482238??490880??4822388880e6e7??4929200001????????e0e7',
                        (88,),
                        ((22, 0),
                         (24, 1),
                         (28, 0),
                         (38, 0),
                         (42, 1),
                         (46, 0),
                         (54, 0),
                         (56, 1),
                         (60, 0),
                         (66, 0),
                         (70, 1),
                         (74, 0),
                         (82, 1))),
 'clock_select_c_old': ('80b5071c062f24d201a3db5d5b009f4412020a121812??48??490880??48888080bc08bc1847??481130??490880??4811308880f4e7??48??490880??488880eee7??482238??490880??4822388880e6e7??49??48????????e1e7',
                        (86,),
                        ((22, 0),
                         (24, 1),
                         (28, 0),
                         (38, 0),
                         (42, 1),
                         (46, 0),
                         (54, 0),
                         (56, 1),
                         (60, 0),
                         (66, 0),
                         (70, 1),
                         (74, 0),
                         (82, 1),
                         (84, 0)))}
_FFCC_ROOT = ('9cb5??48006801900027022f30da02e0781c071cf9e7????????002f03d1ff20????????02e0cc20????????0a20????????0024022c08da02e0601c041cf9e7????????69460855f7e700ab187919788842ddd1587959788842d9d1??????????48a038????????01209cbc08bc18479920????????0020f7e7', (22, 32, 40, 46, 64, 92, 100, 114), ((2, 0), (96, 0)))
_PROBE_DIVIDE = bytes.fromhex('784700000020a0e3a1c170e02000003a21c470e00f00003a0004a0e1ff2482e321c270e01700003a21c470e00900003a0004a0e1ff2882e321c470e00004a021ff2c822321c270e00e00003a00c070e29500002a2004a021a1c370e0801341200220a2e021c370e0001341200220a2e0a1c270e0801241200220a2e021c270e0001241200220a2e0a1c170e0801141200220a2e021c170e0001141200220a2e0a1c070e0801041200220a2e001c070e0001041200220b2e0e5ffff2a0200a0e11eff2fe1')

class _ProbeUnclosed(ValueError):
    pass


def _probe_need(condition, reason):
    if not condition:
        raise _ProbeUnclosed('console-probe-' + reason)


def _probe_u32(image, at):
    _probe_need(type(at) is int and 0 <= at <= len(image)-4, 'source-bounds')
    return struct.unpack_from('<I', image, at)[0]


def _probe_specs(role, ffcc=False):
    if role in _CLOCK_SPECS:
        key = role + '_old' if not ffcc and role in ('clock_select_b','clock_select_c') else role
        return _CLOCK_SPECS[key]
    if ffcc and role == 'root':
        return _FFCC_ROOT
    if ffcc and role == 'copy':
        return _FF_SPECS['copy']
    if ffcc and role == 'init':
        mask,calls,literals = _PROBE_SPECS[role]
        return mask[:28] + '8021' + mask[32:],calls,literals
    return (_PROBE_SPECS if role in _PROBE_SPECS else _FF_SPECS)[role]


def _probe_shape(image, at, role, ffcc=False):
    mask,calls,literals = _probe_specs(role,ffcc)
    pattern = bytearray.fromhex(mask.replace('??','00'))
    # Diagnostic line immediates differ; the fixed template selects argument2,
    # so this out-of-range diagnostic path is not an active clock operation.
    if (role == 'clock_select_b' and not ffcc) or (role == 'clock_select_c' and ffcc):
        line = _word(image,at+0x54)
        _probe_need(line is not None and line & 0xff00 == 0x2000,'clock-diagnostic-operand')
        shift = _word(image,at+0x56)
        _probe_need(shift is not None and shift & 0xf83f == 0,'clock-diagnostic-shift')
        struct.pack_into('<2H',pattern,0x54,line,shift)
    found = _source_thumb_shape(image, at, bytes(pattern), calls, literals)
    _probe_need(found is not None, role + '-body')
    return found


def _probe_roots(image, ffcc=False):
    mask,calls,literals = _probe_specs('root',ffcc)
    runs=[(m.start()//2,bytes.fromhex(m.group())) for m in re.finditer(r'(?:[0-9a-f]{2})+',mask)]
    offset,anchor=max(runs,key=lambda pair:len(pair[1]));start=0
    while (hit:=image.find(anchor,start)) >= 0:
        start=hit+1;at=hit-offset
        try:shape=_probe_shape(image,at,'root',ffcc)
        except _ProbeUnclosed:continue
        yield at,shape


def _probe_clock_closure(image, entries, shapes, copies, zeros, timeout, delay_state,
                         sv, irqsave, irqrestore, memcpy, code, pools, data, ram, iram, ffcc):
    def need(value, reason):
        _probe_need(value,'clock-'+reason)
    def zero(address, size):
        return _ff_ram(address,size) and any(a<=address and address+size<=b for a,b in zeros)
    def add(role, address):
        need(address not in entries.values(),'callee-alias')
        entries[role]=address;shapes[role]=_probe_shape(image,address,role,ffcc)
        return shapes[role]
    apply, av=shapes['apply'];cs,cl=shapes['clockset'];clear,clv=shapes['clockclear'];pin,pv=shapes['pinset']
    need(apply[4]==irqsave and apply[0x12]==memcpy and apply[0x24]==entries['clockset'],'apply-links')
    need(all(apply[o]==irqsave for o in (0x30,0x56,0x7c,0x94)) and
         all(apply[o]==irqrestore for o in (0x52,0x74,0x90,0xa6,0xb4)),'apply-irq')
    need(pin[4]==irqsave and pin[0x22]==irqrestore and pv[8]==sv[0x1a] and pv[0x1a]==0x03000610,'pin-links')
    need(all(cs[o]==irqsave for o in (0x10,0x26,0x50,0x74)) and
         all(cs[o]==irqrestore for o in (0x3c,0x66,0x90)) and
         clear[0x16]==clear[0x3a]==irqsave and clear[0x2e]==clear[0x54]==irqrestore,'selector-irq')
    need(cl[2]==cl[0x84]==clv[0x26]==clv[0x4a]==0x03000600 and
         cl[4]==clv[0xa]==sv[0x1a] and cl[0x18]==0x03000400,'selector-domain')
    table=cl[0xc]
    need(not table&3 and table==clv[6] and 0<=table<=len(image)-40,'selector-table')
    # Only source constants4 (set) and1 (clear) index this table. Argument10's
    # delay/diagnostic branch is native and not selected by the fixed template.
    need(struct.unpack_from('<2I',image,table+8)==(0x737f,8) and
         struct.unpack_from('<2I',image,table+32)==(0xff7f,15),'selector-rows')
    data.extend(((table+8,table+16),(table+32,table+40)))
    def owned(address,size):
        if zero(address,size):return True
        matches=[c for c in copies if c['target']<=address and address+size<=c['target']+c['size']]
        if len(matches)!=1:return False
        c=matches[0];raw=c['source']+address-c['target'];data.append((raw,raw+size));return True
    params=av[0x10]
    need(not params&3 and params==copies[0]['target'] and
         av[0x34]==params and av[0x16]==sv[0x1a] and owned(params,0x48),'parameter-state')
    regs,rl=add('clock_regs',apply[0x28]);version,vl=add('clock_version',apply[0x2c]);commit,ml=add('clock_commit',apply[0xaa])
    need(regs[2]==irqsave and regs[0x1c]==irqrestore and rl[6]==params and
         rl[8]==sv[0x1a] and all(rl[o]==0x03000600 for o in (0x14,0x22,0x2e)),'register-apply')
    need(vl[2]==params and vl[4]==0x03000640 and version[0x28]==entries['delay'],'version-domain')
    need(ml[2]==params+0x1c and ml[0x10]==ml[0x14]==ml[0xca]==params+0x38,'commit-state')
    word1=0x1033 if ffcc else 0x833
    diagnostic=shapes['config'][0][0x5a]
    for role,offset in (('clock_select_a',0x98),('clock_select_b',0x30),('clock_select_c',0x3a)):
        calls,values=add(role,commit[offset])
        need(len(calls)==1 and next(iter(calls.values()))==diagnostic,'selector-diagnostic-link')
        need(all(values[o]==0x2033 for o in (0x16,0x26,0x36,0x42)) and
             all(values[o]==0x04800080 for o in (0x18,0x2a,0x38,0x46)) and
             all(values[o]==word1 for o in (0x1c,0x2e,0x3c,0x4a)),'selector-literals')
    update,uv=add('clock_update',commit[0xc4]);get,gl=add('clock_version_get',version[0xa])
    need(update[6]==irqsave and update[0x14]==irqrestore and uv[0xa]==params+0x88 and
         owned(uv[0xa],0x26),'update-state')
    need(gl[0]==params+0xb8 and gl[0xc]==0x030007a0 and gl[0x10]==gl[0x18] and
         not gl[0x10]&1 and owned(gl[0],5) and zero(gl[0x10],2),'version-state')
    roles=[(params,params+0x48),(uv[0xa],uv[0xa]+0x26),(gl[0],gl[0]+5),
           (gl[0x10],gl[0x10]+2),(delay_state,delay_state+0x26),
           (timeout,timeout+1),(sv[0x1a],sv[0x1a]+0x382)]
    # Both typed users share this copied state; other semantic roles stay disjoint.
    need(roles[1]==roles[4] and not any(_ff_overlap(a,b) for i,a in enumerate(roles) for j,b in enumerate(roles[i+1:],i+1) if not (i==1 and j==4)), 'state-alias')
    ram.extend(roles[:4])
    target=commit[0xbe];veneer=None
    if image[target:target+12]==_FF_THUNK:
        veneer=target;target=_ff_thunk(image,target)
        code.append((veneer,veneer+12));pools.append((veneer+12,veneer+16))
    owners=[]
    if 0<=target<=len(image)-len(_PROBE_DIVIDE):owners.append((target,'rom'))
    for copy in copies:
        if copy['target']<=target and target+len(_PROBE_DIVIDE)<=copy['target']+copy['size']:
            owners.append((copy['source']+target-copy['target'],'copied'))
    need(len(owners)==1,'divide-owner');raw,owner=owners[0]
    actual=bytearray(image[raw:raw+len(_PROBE_DIVIDE)]);expected=bytearray(_PROBE_DIVIDE)
    branch=struct.unpack_from('<I',actual,0x50)[0]
    need(branch>>24==0x2a,'divide-zero-branch')
    delta=branch&0xffffff
    if delta&0x800000:delta-=0x1000000
    zero_target=target+0x50+8+delta*4
    need(not zero_target&3 and 0<=zero_target<=len(image)-4,'divide-zero-owner')
    struct.pack_into('<I',actual,0x50,branch&0xff000000)
    struct.pack_into('<I',expected,0x50,struct.unpack_from('<I',expected,0x50)[0]&0xff000000)
    need(actual==expected,'divide-nonzero-abi')
    code.append((raw,raw+len(_PROBE_DIVIDE)))
    if owner=='copied':iram.append((target,target+len(_PROBE_DIVIDE)))
    return dict(parameter_state=params,update_state=uv[0xa],version_cache=gl[0],version_output=gl[0x10],
                selector_table=table,selector_indices=[1,4],division_entry=target,
                division_source=raw,division_veneer=veneer)


def _probe_profile(image, console, console_shape, ffcc=False):
    reset=arm_b_target(image,0)
    _probe_need(reset is not None and reset>=4 and not reset&3 and reset+len(_PROBE_RESET)<=len(image),'reset-owner')
    code=[(reset,reset+len(_PROBE_RESET))];pools=[];data=[];ram=[];iram=[]
    def u32(at):return _probe_u32(image,at)
    def arm_literal(pc):
        op=u32(pc);_probe_need(op&0x0f7f0000==0x051f0000,'arm-literal')
        pool=pc+8+(op&4095);pools.append((pool,pool+4));return u32(pool)
    for off in range(0,len(_PROBE_RESET),4):
        expected=struct.unpack_from('<I',_PROBE_RESET,off)[0];actual=u32(reset+off)
        mask=0xfffff000 if expected&0x0f7f0000==0x051f0000 else 0xffffffff
        if off==0xc0:mask=0xff000000
        _probe_need(actual&mask==expected&mask,'reset-body')
        if mask==0xfffff000:arm_literal(reset+off)
    for off in (0,0x18,0x30,0x48,0x80,0x98,0x138):
        pc=reset+off;target=arm_literal(pc)
        _probe_need(0<=target<len(image) and (target&1 or not target&3) and
                    arm_literal(pc+8)==pc+21 and arm_literal(pc+12)==pc+24,'reset-return')
    _probe_need(arm_literal(reset+0x98)==console|1,'root-reset-link')
    stacks=[arm_literal(reset+off) for off in (0x6c,0x74,0x7c,0xc8,0x134)]
    _probe_need(all(not sp&3 and _ff_ram(sp-56,56) for sp in stacks),'stack-range')
    ram.extend((sp-56,sp) for sp in stacks)
    test=arm_literal(reset+0x48);table=test-28
    _probe_need(not test&3 and table>=0 and test+0x150<=len(image) and
                hashlib.sha256(image[test:test+0x150]).hexdigest()==_HIGH_RAM_TEST_SHA256,'ram-test-body')
    base,extent,stride,word,half,byte,pulse=struct.unpack_from('<7I',image,table)
    _probe_need((base,extent,stride,word,half,byte,pulse)==
                (0x01000000,0x3fffff if ffcc else 0x1fffff,16,0x55aa0f,0xaa0f,0x55,0x03000700),'ram-test-span')
    for off,field in ((0,0),(0x10,8),(0x40,24),(0x6c,4),(0x80,4),(0xf4,12),(0x108,16),(0x11c,20)):
        _probe_need(arm_literal(test+off)==table+field,'ram-test-field')
    _probe_need(arm_literal(test+0x148)!=0,'ram-test-failure-return')
    code.append((test,test+0x150));data.append((table,table+28));ram.append((base,base+extent+1))
    copy=arm_literal(reset+0x80)-1;cc,cv=_probe_shape(image,copy,'copy',ffcc)
    _probe_need(not cc and all(cv[o]==pulse for o in (2,0x3a,0x68,0xa0,0xd0,0xdc)),'copy-domain')
    copies=[];zeros=[]
    for so,to,no,ro,zs,zn,zr in ((0x16,0xa,0xe,0x1c,0x42,0x46,0x4e),(0x7c,0x70,0x74,0x82,0xa8,0xac,0xb4)):
        at=cv[so]
        _probe_need(not at&3 and cv[to]==cv[ro]==at+4 and cv[no]==at+8 and
                    cv[zs]==cv[zr]==at+12 and cv[zn]==at+16,'copy-fields')
        src,dst,size,za,zn=struct.unpack_from('<5I',image,at) if 0<=at<=len(image)-20 else (0,0,0,0,0)
        _probe_need(size>0 and zn>0 and not(src|dst|size|za|zn)&3 and
                    0<=src<=len(image)-size and _ff_ram(dst,size) and za==dst+size and _ff_ram(za,zn),'copy-span')
        copies.append(dict(table_offset=at,source=src,target=dst,size=size));zeros.append((za,za+zn))
        data.extend(((at,at+20),(src,src+size)));ram.extend(((dst,dst+size),(za,za+zn)))
    if ffcc:
        table=cv[0xf0]
        _probe_need(not table&3 and cv[0xe4]==cv[0xf6]==table+4 and cv[0xe8]==table+8,'iram-copy-fields')
        src,dst,size=struct.unpack_from('<3I',image,table) if 0<=table<=len(image)-12 else (0,0,0)
        _probe_need(size>0 and not(src|dst|size)&3 and 0<=src<=len(image)-size and
                    0x03800000<=dst<dst+size<=0x03a00000,'iram-copy-span')
        copies.append(dict(table_offset=table,source=src,target=dst,size=size))
        data.extend(((table,table+12),(src,src+size)));iram.append((dst,dst+size))
    _probe_need(not _ff_overlap((copies[0]['target'],copies[0]['target']+copies[0]['size']),
                                (copies[1]['target'],copies[1]['target']+copies[1]['size'])),'copy-ambiguity')
    _probe_need(not any(_ff_overlap(z,(c['target'],c['target']+c['size'])) for z in zeros for c in copies),'zero-copy-overlap')
    def source(address,size):
        owners=[c for c in copies if c['target']<=address and address+size<=c['target']+c['size']]
        _probe_need(len(owners)==1 and not any(_ff_overlap((address,address+size),z) for z in zeros),'copied-field')
        return owners[0]['source']+address-owners[0]['target']
    entries={'root':console,'copy':copy};shapes={'root':console_shape,'copy':(cc,cv)}
    rc,rv=console_shape
    marker=None; peer_branch=None
    if ffcc:
        _probe_need(rc[0x20]==rc[0x28]==rc[0x72],'ffcc-init-links')
        # No-peer RX never reaches these calls. Preserve source targets without
        # claiming or replacing the external-download peripheral graph.
        _probe_need(all(0<=rc[o]<=len(image)-2 for o in (0x5c,0x64)), 'ffcc-peer-target-bounds')
        peer_branch=dict(call_pcs=[console+0x5c,console+0x64],
            targets=[rc[0x5c],rc[0x64]],argument_literal=rv[0x60],
            policy='unreachable-while-owned-null-rx-empty',semantics='unsupported-external-peer-path')
        marker=rv[2]
        _probe_need(u32(marker)==0x6c64,'ffcc-response-marker')
        data.append((marker,marker+4))
        rc={2:rc[0x16],8:rc[0x20],14:rc[0x2e],18:rc[0x40],0x34:rc[0x72]}
    primary,init,tx,wrapper=rc[2],rc[8],rc[14],rc[18]
    _probe_need(rc[0x34]==init and len({primary,init,tx,wrapper,console,copy})==6,'root-call-links')
    for role,at in (('primary',primary),('init',init),('tx',tx),('wrapper',wrapper)):
        entries[role]=at;shapes[role]=_probe_shape(image,at,role,ffcc)
    ic,iv=shapes['init'];setup,config=ic[4],ic[0x12]
    _probe_need(ic[0x16]==primary,'init-drain-link')
    for role,at in (('setup',setup),('config',config)):
        entries[role]=at;shapes[role]=_probe_shape(image,at,role)
    _probe_need(set(iv.values())=={0x03000f40,pulse},'init-domain')
    base=0x03000f0c
    pl=shapes['primary'][1];tl=shapes['tx'][1]
    _probe_need(set(pl.values())=={base+4,pulse} and tl[0]==base+0x14 and
                tl[10]==pulse and tl[20]==base+0x14,'poll-transmit-domain')
    wc,wl=shapes['wrapper'];rx=wc[12]
    _probe_need(wc[22]==rx and wl[2]==wl[32]==wl[84] and
                wl[52]==wl[66]==wl[76]==base+4,'receive-call-links')
    entries['rx']=rx;shapes['rx']=_probe_shape(image,rx,'rx');rl=shapes['rx'][1]
    _probe_need(rl[8]==200000 and rl[22]==rl[54]==base+4 and rl[38]==rl[68]==pulse,'receive-domain')
    timeout=wl[2];timeout_source=source(timeout,1)
    _probe_need(image[timeout_source]==1,'receive-timeout-source')
    ram.append((timeout,timeout+1));data.append((timeout_source,timeout_source+1))
    sc,sv=shapes['setup'];fc,fl=shapes['config']
    irqsave,irqrestore=fc[0x14],fc[0x2e]
    _probe_need(fc[0x38]==irqsave and image[irqsave:irqsave+24]==_FF_IRQ_SAVE and
                image[irqrestore:irqrestore+24]==_FF_IRQ_RESTORE,'irq-source')
    code.extend(((irqsave,irqsave+24),(irqrestore,irqrestore+24)))
    _probe_need(all(sc[o]==irqsave for o in (0xe,0x16,0x38,0x60,0x7c,0x9e,0xd8,0xf2,0x11e,0x13a)) and
                all(sc[o]==irqrestore for o in (0x34,0x5c,0x78,0x9a,0xb6,0xee,0x112,0x136,0x14e,0x158)),'setup-irq-links')
    _probe_need(fl[2]==0x03000620 and fl[0x1a]==fl[0x3e]==0xff3f and fl[6]==sv[0x1a],'config-nine-domain')
    _probe_need(sv[0x1a]==sv[0x3c]==sv[0x84] and _ff_ram(sv[0x1a],0x382) and
                all(sv[o]==0xff81 for o in (0x24,0x46,0x66,0x82,0xa4,0xfe)) and
                all(sv[o]==pulse for o in (0x26,0x92,0xa6,0x108,0x116)) and
                all(sv[o]==0x03000600 for o in (0x48,0x68,0xde)) and sv[0xba]==20000,'setup-domain')
    template=sv[8]
    _probe_need(not template&3 and image[template:template+44]==_PROBE_TEMPLATE,'setup-template')
    data.append((template,template+44));ram.append((sv[0x1a],sv[0x1a]+0x382))
    memcpy=sc[0xa];memcpy_source=memcpy
    if ffcc:
        target=_ff_thunk(image,memcpy)
        memcpy_source=source(target,len(_PROBE_MEMCPY_44))
        _probe_need(copies[2]['target']<=target<target+len(_PROBE_MEMCPY_44)<=copies[2]['target']+copies[2]['size'],'setup-copy-iram-owner')
        code.append((memcpy,memcpy+12));pools.append((memcpy+12,memcpy+16))
        iram.append((target,target+len(_PROBE_MEMCPY_44)))
    _probe_need(image[memcpy_source:memcpy_source+len(_PROBE_MEMCPY_44)]==_PROBE_MEMCPY_44,'setup-template-copy-abi')
    code.append((memcpy_source,memcpy_source+len(_PROBE_MEMCPY_44)))
    for off,role in ((0xbc,'delay'),(0xc2,'pinset'),(0xc8,'clockset'),(0xce,'apply'),(0xd4,'clockclear')):
        entries[role]=sc[off];shapes[role]=_probe_shape(image,sc[off],role)
    delay_values=shapes['delay'][1]
    delay_state=delay_values[2]
    _probe_need(delay_values[0x26]==delay_values[0x3e]==0x04800020,'delay-strobe-domain')
    _probe_need(not delay_state&3 and delay_state==copies[0]['target']+0x88 and
                _ff_ram(delay_state,0x26),'delay-state-role')
    delay_source=source(delay_state,0x26)
    _probe_need(not _ff_overlap((delay_state,delay_state+0x26),(timeout,timeout+1)) and
                u32(delay_source+0x20)>0 and
                struct.unpack_from('<H',image,delay_source+0x24)[0]>0,'delay-state-fields')
    data.append((delay_source,delay_source+0x26));ram.append((delay_state,delay_state+0x26))
    descriptor=sv[0x122];desc_source=source(descriptor,44)
    fields=struct.unpack_from('<11I',image,desc_source)
    _probe_need(tuple(fields[i]for i in (0,1,2,4,5,6,8,9,10))==
                (0x03000720,0x03000720,0x0300072c,0x03000724,0x03000724,0x03000730,0x03000728,0x03000728,0x03000734),'setup-descriptor')
    ram.append((descriptor,descriptor+44));data.append((desc_source,desc_source+44))
    clock_metadata=_probe_clock_closure(image,entries,shapes,copies,zeros,timeout,delay_state,sv,irqsave,irqrestore,memcpy,code,pools,data,ram,iram,ffcc)
    normal=arm_b_target(image,reset+0xc0)
    _probe_need(normal is not None and normal>=0 and normal+len(_PROBE_APP)<=len(image),'application-owner')
    for off in range(0,len(_PROBE_APP),4):
        expect=struct.unpack_from('<I',_PROBE_APP,off)[0];mask=0xfffff000 if expect&0x0f7f0000==0x051f0000 else 0xffffffff
        _probe_need(u32(normal+off)&mask==expect&mask,'application-body')
    for off in (4,12,24):
        sp=arm_literal(normal+off);_probe_need(not sp&3 and _ff_ram(sp-56,56),'application-stack');ram.append((sp-56,sp))
    app=arm_literal(normal+32)
    app_size=6 if ffcc else 4
    _probe_need(app&1 and 0<=app-1<=len(image)-app_size,'application-thumb-entry')
    if ffcc:
        _probe_need(_word(image,app-1)==0xb50f and (_word(image,app+1)or 0)&0xff00==0xa100 and
                    _word(image,app+3)==0x201f,'application-thumb-entry')
    else:
        _probe_need(image[app-1:app+3]==bytes.fromhex('0fb50022'),'application-thumb-entry')
    code.extend(((normal,normal+len(_PROBE_APP)),(app-1,app-1+app_size)))
    for role,at in entries.items():
        spec=_probe_specs(role,ffcc)
        code.append((at,at+len(spec[0])//2))
        for off,_ in spec[2]:
            op=_word(image,at+off);pool=((at+off+4)&~3)+(op&255)*4;pools.append((pool,pool+4))
    _probe_need(len(set(entries.values()))==len(entries) and not any(_ff_overlap(a,b)for i,a in enumerate(code)for b in code[i+1:]),'code-overlap')
    _probe_need(all(0<=a<b<=len(image) and not any(_ff_overlap((a,b),c)for c in code)for a,b in pools),'literal-owner')
    _probe_need(all(0<=a<b<=len(image) for a,b in data) and not any(_ff_overlap((app-1,app+3),v)for v in pools+data),'data-owner')
    if marker is not None:
        _probe_need(not any(_ff_overlap((marker,marker+4),v)for v in code+pools),'ffcc-marker-owner')
    guards=sorted(set(code+pools+data+[(0,4)]))
    writes=[dict(pc=init+off,address=address,size=width,value=value) for off,address,width,value in
            ((0x36,base+0x14,1,0),(0x38,base+0x20,2,0),(0x3c,base+0x1c,2,0x1e),
             (0x44,base,2,0),(0x4c,base+4,1,0x34),(0x50,base+8,1,0xff),
             *((off,base+0x10,1,value) for off,value in ((0x54,0x30),(0x58,0x10),(0x5a,0x10),(0x5e,0x20),(0x60,0x20),(0x64,1),(0x68,4))))]
    profile=dict(signature='thumb-byte-uart-finite-ff-cc-99-console-v1' if ffcc else 'thumb-byte-uart-finite-ff-dd-console-v1',admission='temporary-evidence-gated',
        policy='provisional-synchronous-null-console',register_width=2,csr_value=0xff,csr_sequence=[0xff,0xcc,0x99] if ffcc else [0xff,0xdd],
        base=base,status_address=base+8,control_address=base+0x10,isr_address=base+0x14,fifo_address=base+0xc,
        pulse_address=pulse,primary_entry=primary,primary_status_pc=primary+0xa,primary_control_pc=primary+4,
        init_entry=init,tx_entry=tx,console_root=console,receive_entry=rx,receive_wrapper=wrapper,
        init_writes=writes,rx_drain_pc=init+0x7a,
        tx_isr_pc=tx+2,tx_fifo_pc=tx+24,tx_callers=[console+(0x2e if ffcc else 14)],clock_setup=(0xc0,0xb2,0x7d,0x1c),
        code_intervals=[list(v)for v in sorted(set(code))],literal_intervals=[list(v)for v in sorted(set(pools))],
        data_intervals=[list(v)for v in sorted(set(data))],boot_guard_intervals=[[0,4],[reset,reset+len(_PROBE_RESET)],[normal,normal+len(_PROBE_APP)]],
        guard_intervals=[list(v)for v in guards],ram_intervals=[list(v)for v in sorted(set(ram))],iram_intervals=[list(v)for v in sorted(set(iram))],
        receive_timeout_flag=timeout,receive_timeout_source=timeout_source,copy_layouts=copies,zero_ranges=[list(z)for z in zeros],
        reset_entry=reset,copy_entry=copy,application_entry=app-1,setup_entry=setup,setup_template=template,
        setup_memcpy_entry=memcpy,delay_entry=entries['delay'],delay_state=delay_state,delay_state_source=delay_source,
        runtime_source_policy='defer-until-postpatch-primary-reparse-and-immutable-byte-match')
    profile.update(clock_guard=clock_metadata)
    if ffcc:
        profile.update(outside_config_drains=[4,4,2],lf_stages=[True,True,False],
            response_bytes=2,response_marker_address=marker,response_marker_word=0x6c64,
            config9_argument=0x80,setup_memcpy_source=memcpy_source,
            external_peer_branch=peer_branch)
    else:
        profile['reset_reentry']=dict(write_pcs=[primary+4,primary+6],status_read_pc=primary+0xa,
            root_lr=(console+2+4)|1,config_lr=(init+0x16+4)|1,address=base+0x10,
            width=1,value=0x20,status_address=base+8,status_mask=8)
    return profile


_find_fixed_uart_console_profile = find_uart_console_profile


def _find_previous_uart_console_profile(image: bytes, ready_profile: dict | None) -> tuple[dict | None,str]:
    prior,reason=_find_fixed_uart_console_profile(image,ready_profile)
    if prior is not None or 'ambiguous' in reason:
        return prior,reason
    roots=list(_probe_roots(image))
    if not roots:return prior,reason
    if len(roots)!=1:return None,'console-probe-roots-ambiguous'
    try:return _probe_profile(image,*roots[0]),'accepted'
    except (_ProbeUnclosed,struct.error,TypeError,ValueError) as error:
        return None,str(error) if isinstance(error,_ProbeUnclosed) else 'console-probe-malformed-source'


def find_uart_console_profile(image: bytes, ready_profile: dict | None) -> tuple[dict | None,str]:
    prior,reason=_find_previous_uart_console_profile(image,ready_profile)
    complete=[];failures=[]
    for at,shape in _probe_roots(image,True):
        try:complete.append(_probe_profile(image,at,shape,True))
        except (_ProbeUnclosed,_HalfFFUnclosed,struct.error,TypeError,ValueError) as error:
            failures.append(str(error))
    if len(complete)>1:return None,'console-ffcc-profiles-ambiguous'
    if complete:
        if prior is not None or 'ambiguous' in reason:return None,'console-protocol-ownership-ambiguous'
        return complete[0],'accepted'
    if prior is not None or 'ambiguous' in reason:return prior,reason
    return None,failures[0] if len(failures)==1 else 'console-ffcc-candidates-unclosed' if failures else reason
