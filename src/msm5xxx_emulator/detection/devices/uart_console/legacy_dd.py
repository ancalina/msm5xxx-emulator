"""Legacy fixed double-width console signatures pending fact-rule migration."""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import re
import struct
from ...facts import facts_for
from .legacy_simple import (_find_existing_uart_console_profile, _word,)
from .legacy_tx import byte_code as _byte_code

_DD_MASKS = {'primary': '90b400200122??4f??4901e00a7008703c792309fad390bc7047', 'init':
    '??4980b5002008710320??4980030882??490020203188800120??4980030880c80a8881??????????49c02010390871b22008727d200873??491c200870??4900202039087088811e200881??49002040398881??4a3420303a1070dd201071302010731020107310732020107310730120107304211173??492039002302e0177a08700b7017797f08f9d280bc08bc1847',
    'root': '80b5??4800270780????????0920c005017b002904d1082101720121017301e007700773????????????????????????????????????????80bc08bc1847', 'dispatch':
    'b0b5??4d??4c286886e0381c????????3978112900d15be00edc0f2900d377e001a35b5c5b009f44732b737330353a3d7340??484d735000232900d15ae014dc16294fd009dc122947d0132900d05fe0011c381c????????5de0202947d0222900d055e0????????55e0302945d0312946d0322947d033294ad1????????4ae0011c381c????????45e0011c381c????????40e0011c381c????????3be0????????38e0????????35e0011c381c????????30e0????????2de0011c381c????????28e0????????25e0????????22e0011c381c????????1de0011c381c????????18e0011c381c????????13e0????????10e0????????0de0????????0ae0????????07e0011c381c????????02e00620????????2868071976e7',
    'parser':
    'f1b5002600254fe0??480121017000210170????????071c431c45d0bb1c07d1??48002120300180c10a8181????????002c09d0012c0bd0022c35d17e2f0cd1032d19da04201be07e2fddd10124dbe77e2fd9d00025??4e02247d2f06d1????????431c20d020214840071c01235b039d4208db052003e0??4b9e4216d00120????????10e0681c0004000c291c051c0098??4a475430127e40311c0906c90d515a4840061cafe70024ade7281cf8bc08bc1847',
    'wrapper': '80b5??4f3878002808d00120????????831c06d1981e80bc08bc18470020????????402303400021c943002b??4a01d1800902d3107a081cede7107a00217970e9e7', 'rx':
    'b0b4012700240028??4a??4b0cd0??491079450806d21f701c7001390029f7dc0120c043b0bc704710794108fad21f701c70f9e7', 'tx':
    '90b400230121??4f??4a01e0117013703c786408fad3??491039087290bc7047', 'ack1': '80b50330071c7e20????????3878????????387801377e28f8d180bc08bc1847', 'ack2':
    '??4980b580000f587e20????????3878????????387801377e28f8d180bc08bc1847', 'extra': '00b57e20????????0220????????6a20????????d320????????7e20????????08bc1847',
    'flag': '??49??4a00200b5cff2b01d0002003e001300828f7db012010707047', 'clear': '??48??4900684118002008607047', 'policy': '80b50027??????????490870', 'boolean':
    '9fb4??4902a80cc90cc001221204002103290cda04e04b1c1b041b0c191cf7e71388971c3a1c4f006c46e353f3e70120002103290eda04e04b1c1b041b0c191cf7e74b006f46fb5a4f0002ace75bbb42f2d0002004b090bc7047',
    'argument_root': '80b5??48002707800120????????0920c005017b002904d1082101720121017301e007700773????????????????????????????????????????80bc08bc1847',
    'argument_prelude':
    'f0b587b00021802280270025002401280292069104910391019103d0022804d0032805d00421059105e00a21059103e00a21059101210691??4a9088009013211182????????????????0026012d1dd1002c0dd1????????029a0499521001310906090e0491072902920ddd01240be0????????03997f1001310906090e0391072901dd01210191002514e0????????002c04d10599029a114006d102e00699394002d1????????01e0????????01990125012904d001363606360e802ec5db????????????????002001300006000e0128fadb??4a009890801321118207b0f0bc08bc184700002007000302210843??4988807047000020070003??498880704700002007000301210843??49888070470000200700034008??4940008880704700002007000310210843??49888070470000200700031023??49984388807047000020070003'}

def _dd_hits(image: bytes, role: str) -> list[int]:
    mask = _DD_MASKS[role]
    pattern = b''.join(b'.' if mask[i:i+2] == '??' else re.escape(bytes([int(mask[i:i+2], 16)])) for i in range(0, len(mask), 2))
    return [m.start() for m in re.finditer(pattern, image, re.DOTALL) if not m.start() & 1 and _byte_code(image, m.start(), mask)]

def _dd_at(image: bytes, root: int, calls: list, root_role: str = 'root') -> tuple[dict | None, str]:
    def fail(reason): return None, 'console-dd-' + reason
    def target(at): return facts_for(image).thumb_call_target(at)
    def literal(at, reg): return facts_for(image).thumb_literal_value(at, reg)
    def code(role, at):
        return at is not None and _byte_code(image, at, _DD_MASKS[root_role if role == 'root' else role])
    delta = 2 if root_role == 'argument_root' else 0
    primary, init = target(root+0x24+delta), target(root+0x28+delta)
    flag, clear, dispatch = target(root+0x2c+delta), target(root+0x30+delta), target(root+0x34+delta)
    positions = dict(root=root, primary=primary, init=init, flag=flag, clear=clear, dispatch=dispatch)
    if any(not code(role, at) for role, at in positions.items()):
        return fail('root-family')
    if target(init+0x24) != primary: return fail('init-primary-link')
    if delta:
        prelude = target(root+0xa)
        if not code('argument_prelude',prelude): return fail('argument-prelude')
        # This prelude owns a separate halfword domain; no GPIO meaning is imported.
        for off,reg in ((0x38,2),(0xd4,2),(0xf0,1),(0xfc,1),(0x10c,1), (0x11a,1),(0x12c,1),(0x13a,1)):
            if literal(prelude+off,reg) != 0x03000720:
                return fail('argument-prelude-domain')
        for site,to in ((0x42,0x118),(0x46,0xec),(0x54,0x108),(0x70,0x108), (0x8c,0x118),(0xa4,0x138),(0xaa, 0x128), (0xc0,0x118),(0xc4,0x138)):
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
        hits = [at for at in _dd_hits(image,role) if all(target(at+off) == tx for off in offsets)]
        if len(hits) != 1: return fail(role + '-ambiguous')
        others[role] = hits[0]
    ack1, extra = others['ack1'], others['extra']
    positions.update(parser=parser,wrapper=wrapper,rx=rx,ack1=ack1,ack2=ack2, tx=tx,extra=extra)
    flag_address = literal(flag+2, 2)
    pointer = literal(dispatch+2, 5)
    if (flag_address is None or not 0x01000000 <= flag_address <= 0x01fffffa or flag_address & 3 or pointer is None or pointer & 3 or not 0 <= pointer <= len(image)-4
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
    terms = { 'primary': ((6,7,base+4),(8,1,pulse)), 'init': ((0,1,base+0x34),(0xa,1,pulse-0x100),(0x10,1,pulse- 0x100), (0x1a,1,pulse+0x20),(0x28,1,base+0x34),(0x38,1,base+0x34),
        (0x3e,1,base+0x34),(0x4c,1,base+0x34),(0x54,2,base+0x34), (0x78,1,pulse+0x20)), 'root': ((2,0,pulse+0x40),), 'dispatch': ((2,5,pointer),(4,4, 0xffffe000)),
        'clear': ((0,0,pointer),(2,1,0xffffde00)), 'parser': ((8,0,pulse),(0x20,0,pulse),(0x56,6, 0xffff), (0x78,3,0xf0b8)), 'wrapper': ((2,7,flag_address+4),(0x2c,2,base+4)),
        'rx': ((8,2,base+4),(0xa,3,pulse),(0xe,1,0x5b8d80)), 'tx': ((6,7,base+0x14),(8,2,pulse),(0x16,1,base+0x14)), 'policy': ((8,1, flag_address+4),), }
    if any(literal(positions[role]+off, reg) != value for role, terms_ in terms.items() for off,reg,value in terms_):
        return fail('literal-ownership')
    # Software timeout policy and packet tables are only source identity, never MMIO defaults.
    seed = literal(boolean+2, 1)
    source = literal(flag, 1)
    crc = literal(parser+0x92, 2)
    table = literal(ack2, 1)
    if any(at is None or not 0 <= at <= len(image)-size for at,size in ((seed,8),(source,8),(crc,512),(table,52))):
        return fail('table-bounds')
    for index in range(13):
        at = struct.unpack_from('<I', image, table+index*4)[0]
        if not 0 <= at < len(image) or image.find(b'\x7e',at,min(at+16,len(image))) < 0:
            return fail('response-bounds')
    owned = { init:[root+0x28+delta], dispatch:[root+0x34+delta], parser:[dispatch+0xc], wrapper:[parser+ 0x12,parser+0x5e], rx:[wrapper+0xc,wrapper+0x1e], tx:[ack1+8,ack1+0xe,ack2+0xa,ack2+0x10,
        *[extra+off for off in (4,0xa,0x10,0x16,0x1c)]], }
    if any(sorted(at for at,to in calls if to == dest) != sorted(sites) for dest,sites in owned.items()): return fail('call-family')
    response_calls = [at for at,to in calls if to == ack2]
    if len(response_calls) != 24 or parser+0x80 not in response_calls:
        return fail('response-call-family')
    if any((_word(image,at-2) or 0) & 0xff00 != 0x2000 or (_word(image,at-2) & 255) > 12 for at in response_calls):
        return fail('response-index')
    if target(dispatch+0x112) != ack2: return fail('dispatcher-response-link')
    if len(policies) != 1: return fail('complete-ownership-ambiguous')
    # Masks fix every typed store/value; resolved literals above fix their producers.
    writes = [dict(pc=init+off,address=address,size=size,value=value) for off,address,size,value in ((6,base+ 0x38,1,0),(0xe,pulse-0xf0,2,0xc000), (0x16,pulse-0xdc,2,0),(0x1e,pulse+0x20,2,0x4000),
        (0x22,pulse+0x2c, 2,(pulse+0x20)>>11), (0x2e,base+0x28,1,0xc0),(0x32,base+0x2c,1,0xb2), (0x36,base+0x30,1,0x7d),(0x3c,base +0x34,1,0x1c), (0x44,base+0x14,1,0),(0x46,base+0x20,2,0),
        (0x4a,base+0x1c,2,30),(0x52,base,2,0),(0x58, base+4,1,0x34), (0x5e,base+8,1,0xdd), *[(off,base+0x10,1,value) for off,value in ((0x62,0x30),(0x66,0x10),(0x68,0x10),(0x6c,0x20),
        (0x6e,0x20),(0x72,1),(0x76,4))])]
    return dict(signature='thumb-uart-sync-console-dd-v1', admission='temporary-evidence-gated',policy= 'provisional-synchronous-null-console', register_width=2,csr_value=0xdd,base=base,status_address=base+8,
        control_address=base+0x10,isr_address=base+0x14,fifo_address=base+0xc, pulse_address=pulse,primary_entry =primary,primary_status_pc=primary+0x10,
        primary_control_pc=None,init_entry=init,tx_entry=tx, console_root=root, rx_drain_pc=init+0x86,receive_entry=rx,receive_wrapper=wrapper, tx_callers=sorted(owned[tx]),tx_isr_pc=tx+0x10,tx_fifo_pc=tx+0x1a,
        init_writes=writes,clock_setup=(0xc0,0xb2,0x7d), code_intervals= [(at,at+len(_DD_MASKS[root_role if role == 'root' else role])//2) for role,at in
        positions.items()]), 'accepted'

def _find_dd_uart_console_profile(image: bytes) -> tuple[dict | None,str]:
    roots = [(at,role) for role in ('root','argument_root') for at in _dd_hits(image,role)]
    if not roots: return None, 'console-dd-not-found'
    calls = list(facts_for(image).call_candidates('thumb'))
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
        if existing is not None or reason in ('console-byte-profiles-ambiguous', 'console-protocol-ownership-ambiguous'):
            return None, 'console-protocol-ownership-ambiguous'
        return dd, 'accepted'
    if dd_reason in ('console-dd-profiles-ambiguous','console-dd-complete-ownership-ambiguous'):
        return None, dd_reason
    if existing is not None: return existing, reason
    if dd_reason != 'console-dd-not-found': return None, dd_reason
    return None, reason

# Separate mixed-width fixed-CSR compiler class. The prior profiles stay closed.
