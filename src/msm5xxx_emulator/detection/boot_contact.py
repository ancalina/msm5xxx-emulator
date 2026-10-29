"""Evidence-only source-owned first boot-contact sample candidate.

Provisional virtual no-contact means the source's low-five-bit inactive predicate,
not a physical key/accessory claim. Runtime setup/reset/ownership enforcement is
required separately; this finder does not modify memory or input state.
"""
from __future__ import annotations
import struct

_ROOT = bytes.fromhex('24429fe5010014e320e29f1520e29f0514ff2fe17847000018429fe5010014e314e29f1514e29f0514ff2fe1784700000c429fe5010014e308e29f1508e29f0514ff2fe178470000d7f021e3a4d19fe5dbf021e3f4d19fe5d3f021e3f0d19fe5f0419fe5010014e3ece19f15ece19f0514ff2fe178470000e4419fe5010014e3e0e19f15e0e19f0514ff2fe178470000d8419fe5010014e3d4e19f15d4e19f0514ff2fe178470000000050e30300001ac63f00ead3f021e394d19fe578470000d3f021e388d19fe5ac419fe5010014e3a8e19f15a8e19f0514ff2fe1784700001eff2fe1')
_ROOT_EXTRA = bytes.fromhex('f4419fe5010014e3f0e19f15f0e19f0514ff2fe178470000e8419fe5010014e3e4e19f15e4e19f0514ff2fe178470000dc419fe5010014e3d8e19f15d8e19f0514ff2fe178470000d7f021e390d19fe5dbf021e3c4d19fe5d3f021e3c0d19fe5c0419fe5010014e3bce19f15bce19f0514ff2fe178470000b4419fe5010014e3b0e19f15b0e19f0514ff2fe178470000a8419fe5010014e3a4e19f15a4e19f0514ff2fe1784700009c419fe5010014e398e19f1598e19f0514ff2fe178470000000050e30300001ad73f00ead3f021e34cd19fe578470000d3f021e340d19fe570419fe5010014e36ce19f156ce19f0514ff2fe1784700001eff2fe1')
_NORMAL = bytes.fromhex('d2f021e388d09fe5dff021e384d09fe5d1f021e30dd02de07cd09fe5d3f021e378009fe5010010e374e09f1574e09f0510ff2fe1784700006c209fe512ff2fe1')
_SETUP = bytes.fromhex('0020c1002f4a515800290bd0c10089188988c2002b4b9a581180411c0904090c081ceee704210922d205117000211171082111728321c901234a91810021234a11811180224a11731f4ad03a11721e4aa03a11731c4a11801b4a203211801b4ac03a11800121490391810021194a918211831949118091800021164a20329180118191811449134a11819181118203210d4a50321171fd21117001210b4aa03a11720a4ae03a11700021117000200b4b984200db04e0411c0904090c081cf6e77047')
_MARKER = bytes.fromhex('9fb4164902a80cc90cc001221204002103290cda04e04b1c1b041b0c191cf7e71388971c3a1c4f006c46e353f3e70120002103290eda04e04b1c1b041b0c191cf7e74b006f46fb5a4f0002ace75bbb42f2d0002004b090bc7047')
_PREDICATE = bytes.fromhex('80b50027fff7ccff3c4908703b480078002803d1012080bc08bc18470020384b18810022052a00db66e004e0501c0004000c021cf6e71f20314b98820620314b18802f488089c106c90e1f2901d10020e1e700202a4b1881012098820620294b18802748808904210140dfd1002f07d0012f12d0022f1dd0032f00d034e026e004201f4b988206201e4b18801c4880890821014028d1012726e00420184b98820620184b188016488089102101401bd1022719e00220124b98820620114b18800f488089082101400ed103270ce002200b4b988206200b4b1880094880891021014001d1012096e700220120044b203b18700020187099e700208ce7')

_PRED_LITERALS = {8:(1,None),12:(0,None),30:(3,0x03000720),56:(3,0x03000720),62:(3,0x04800020),66:(0,0x03000720),84:(3,0x03000720),94:(3,0x04800020),98:(0,0x03000720),130:(3,0x03000720),136:(3,0x04800020),140:(0,0x03000720),156:(3,0x03000720),162:(3,0x04800020),166:(0,0x03000720),182:(3,0x03000720),188:(3,0x04800020),192:(0,0x03000720),208:(3,0x03000720),214:(3,0x04800020),218:(0,0x03000720),236:(3,0x03000720)}
_SETUP_LITERALS = {4:(2,None),20:(3,None),56:(2,0x03000600),62:(2,0x030007e0),68:(2,0x030004f0),72:(2,0x03000600),78:(2,0x03000600),84:(2,0x03000600),88:(2,0x03000600),94:(2,0x030007e0),108:(2,0x03000c80),114:(1,0xffff),122:(2,0x03000c80),132:(1,0xffff),134:(2,0x03000c80),144:(2,0x03000600),156:(2,0x030007e0),162:(2,0x030007e0),174:(3,3500)}
_INIT_TABLE = bytes.fromhex('a00080040600000038070003fe0700003c070003002000000000000000000000')


def _bytes(image, at, length):
    return image[at:at+length] if type(at) is int and 0 <= at <= len(image)-length else None


def _u32(image, at):
    data = _bytes(image, at, 4)
    return None if data is None else struct.unpack('<I', data)[0]


def _branch(image, pc):
    op = _u32(image, pc)
    if op is None or op >> 24 != 0xea:
        return None
    displacement = op & 0xffffff
    return pc + 8 + ((displacement - 0x1000000 if displacement & 0x800000 else displacement) * 4)


def _arm_literal(image, pc):
    op = _u32(image, pc)
    if op is None or op & 0x0f7f0000 != 0x051f0000:
        return None
    return _u32(image, pc+8+(op & 0xfff)*(1 if op & 0x800000 else -1))


def _literal(image, pc, reg):
    data = _bytes(image, pc, 2)
    if data is None:
        return None
    op = struct.unpack('<H', data)[0]
    return (_u32(image, ((pc+4)&~3)+(op&255)*4)
            if op & 0xff00 == 0x4800 | (reg << 8) else None)


def _bl(image, pc):
    data = _bytes(image, pc, 4)
    if data is None:
        return None
    hi, lo = struct.unpack('<HH', data)
    if hi & 0xf800 != 0xf000 or lo & 0xf800 != 0xf800:
        return None
    delta = ((hi & 0x7ff) << 12) | ((lo & 0x7ff) << 1)
    return pc+4+delta-(0x800000 if hi & 0x400 else 0)


def _thumb_shape(image, at, pattern, literals, calls=()):
    data = _bytes(image, at, len(pattern))
    if data is None or at & 1:
        return False
    holes = {offset+n for offset in literals for n in (0,1)}
    holes.update(offset+n for offset in calls for n in range(4))
    if any(byte != pattern[i] for i,byte in enumerate(data) if i not in holes):
        return False
    return all(_literal(image, at+offset, reg) is not None and
               (value is None or _literal(image, at+offset, reg) == value)
               for offset,(reg,value) in literals.items())


def _arm_shape(image, at, pattern, branch_at=None):
    if at & 3 or _bytes(image, at, len(pattern)) is None:
        return False
    for offset in range(0,len(pattern),4):
        want = struct.unpack_from('<I',pattern,offset)[0]
        got = _u32(image,at+offset)
        mask = 0xfffff000 if want & 0x0f7f0000 == 0x051f0000 else 0xffffffff
        if offset == branch_at:
            mask = 0xff000000
        if got & mask != want & mask:
            return False
    return True


def find_boot_contact_profile(image: bytes) -> tuple[dict | None, str]:
    """Close a unique reset-linked first sample; no runtime policy is applied."""
    if not isinstance(image, bytes):
        return None, 'image-type-invalid'
    root = _branch(image,0)
    variants = ((_ROOT, (0,0x18,0x30,0x60,0x78,0x90,0xc8),
                 0x90,0xb0,0xc8,'three-poststack-gates'),
                (_ROOT_EXTRA, (0,0x18,0x30,0x60,0x78,0x90,0xa8,0xe0),
                 0xa8,0xc8,0xe0,'four-poststack-gates'))
    matched = [variant for variant in variants if root is not None and root >= 4
               and _arm_shape(image,root,variant[0],variant[3])]
    if len(matched) != 1:
        return None, 'reset-route-unclosed'
    root_code, gates, predicate_gate, normal_branch, service_gate, layout = matched[0]
    # Interworking LR values must return into their own ARM gate, including
    # the final predicate and service route; literal placement may relocate.
    for offset in gates:
        gate = root+offset
        if (_arm_literal(image,gate+8) != gate+0x15 or
                _arm_literal(image,gate+12) != gate+0x18):
            return None, 'root-return-unclosed'
        target = _arm_literal(image,gate)
        if target is None or not target & 1 or _bytes(image,target-1,2) is None:
            return None, 'root-callee-unclosed'
    setup = _arm_literal(image,root+0x30)-1
    normal = _branch(image,root+normal_branch)
    if (not _thumb_shape(image,setup,_SETUP,_SETUP_LITERALS) or
            normal is None or not _arm_shape(image,normal,_NORMAL)):
        return None, 'setup-or-normal-route-unclosed'
    init_table = _literal(image,setup+4,2)
    if (_literal(image,setup+0x14,3) != init_table or
            _bytes(image,init_table,len(_INIT_TABLE)) not in (_INIT_TABLE, _INIT_TABLE[:12]+bytes.fromhex('fa07')+_INIT_TABLE[14:])):
        return None, 'setup-table-unclosed'
    if (_arm_literal(image,normal+0x28) != normal+0x35 or
            _arm_literal(image,normal+0x2c) != normal+0x38):
        return None, 'normal-return-unclosed'
    scatter = _arm_literal(image,normal+0x20)
    if scatter is None or not scatter & 1 or _bytes(image,scatter-1,2) is None:
        return None, 'normal-callee-unclosed'
    candidates = []
    start = 0
    while True:
        at = image.find(_PREDICATE[:4],start)
        if at < 0:
            break
        start = at+1
        if not _thumb_shape(image,at,_PREDICATE,_PRED_LITERALS,(4,)):
            continue
        helper = _bl(image,at+4)
        if helper is None or not _thumb_shape(image,helper,_MARKER,{2:(1,None)}):
            continue
        expected = _literal(image,helper+2,1)
        marker = _bytes(image,expected,8)
        cache = _literal(image,at+8,1)
        if (marker is None or marker[:6] != bytes.fromhex('6d6f64656c20') or _bytes(image,0x10000,6) != marker[:6] or
                cache != _literal(image,at+12,0) or cache & 3 or
                not 0x01000000 <= cache < 0x02000000):
            continue
        candidates.append((at,helper,expected,marker,cache))
    if len(candidates) != 1:
        return None, 'predicate-ambiguous' if len(candidates)>1 else 'marker-predicate-unclosed'
    entry,helper,expected,marker,cache = candidates[0]
    if _arm_literal(image,root+predicate_gate) != entry|1:
        return None, 'predicate-root-link-unclosed'
    service = _arm_literal(image,root+service_gate)-1
    spans = [(root,len(root_code)),(normal,len(_NORMAL)),(setup,len(_SETUP)),
             (entry,len(_PREDICATE)),(helper,len(_MARKER))]
    if any(a < c+d and c < a+b for i,(a,b) in enumerate(spans) for c,d in spans[i+1:]):
        return None, 'code-owner-overlap'
    for offset in gates:
        if offset in (0x30,predicate_gate):
            continue
        target = _arm_literal(image,root+offset)-1
        if any(a <= target < a+length for a,length in spans):
            return None, 'foreign-callee-in-owned-code'
    guards = [(a,length) for a,length in spans]+[(init_table,len(_INIT_TABLE)),(expected,8),(0x10000,6)]
    # Include every dereferenced code literal, not only the fixed MMIO values.
    for at,pattern,step in ((root,root_code,4),(normal,_NORMAL,4),(setup,_SETUP,2),
                            (entry,_PREDICATE,2),(helper,_MARKER,2)):
        for offset in range(0,len(pattern),step):
            op = int.from_bytes(image[at+offset:at+offset+step],'little')
            pool = None
            if step==4 and op & 0x0f7f0000 == 0x051f0000:
                pool = at+offset+8+(op&0xfff)*(1 if op&0x800000 else -1)
            elif step==2 and op & 0xf800 == 0x4800:
                pool = ((at+offset+4)&~3)+(op&255)*4
            if pool is not None:
                if _bytes(image,pool,4) is None or any(a <= pool < a+n or a < pool+4 <= a+n for a,n in spans):
                    return None,'literal-owner-unclosed'
                guards.append((pool,4))
    if any(scatter-1 < a+n and a < scatter+1 for a,n in guards):
        return None,'normal-callee-owner-overlap'
    return {'signature':'arm-thumb-first-boot-contact-v1',
            'admission':'temporary-evidence-gated','candidate':True,
            'address':0x0300072c,'width':2,'mask':0x1f,'inactive':0x1f,
            'read_pc':entry+0x44,'predicate_entry':entry,'root':root,
            'layout':layout,'root_call_pc':root+predicate_gate,'return_pc':root+predicate_gate+0x18,
            'initialization_entry':setup,'initialization_call_pc':root+0x30,
            'normal_entry':normal,'service_entry':service,
            'normal_result':0,'service_result':1,
            'marker':{'helper':helper,'source':0x10000,'expected':expected,
                      'compared_bytes':6,'expected_hex':marker[:6].hex(),'cache':cache},
            'precontrol':{'pc':setup+0x68,'address':0x0300072c,'width':2,'value':0x2000},
            'setup':[{'pc':entry+0x20,'address':0x03000728,'width':2,'value':0},
                     {'pc':entry+0x3a,'address':0x03000734,'width':2,'value':0x1f},
                     {'pc':entry+0x40,'address':0x04800020,'width':2,'value':6}],
            'expected_code':[{'address':a,'hex':image[a:a+n].hex()} for a,n in sorted(set(guards))],
            'runtime_contract':{'once_after_setup_per_reset':True,'preserve_upper_bits':True,
                                'preserve_all_writes_and_foreign_reads':True,
                                'require_native_halfword_owner':True,
                                'reject_full_input_or_board_status_owner':True,
                                'keep_694_byte_class_separate':True},
            'semantics':'provisional virtual source-inactive no-contact; physical input identity unproved'},'accepted-source-bound-candidate'
