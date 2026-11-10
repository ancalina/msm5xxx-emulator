from __future__ import annotations

def find_loop_row_scanners(image: bytes):
    """Exact loop/dual-selector class; released bit4 is opt-in approximation."""
    from . import _loop_descriptor_copy, _mapped_irq, _normalized_thumb_sha256, facts_for, find_all, struct
    found = []
    for entry in find_all(image, bytes.fromhex('f8b5')):
        # A full signature, not a filename or fixed entry, identifies the class.
        if entry & 1 or entry + 0x170 > len(image):
            continue
        if image[entry+0x18:entry+0x24].hex() != '686b0088400901d251276ce0':
            continue
        if _normalized_thumb_sha256(image, entry, 0x170) != ('6512e3835bad7cd92142bd67556fbd43a87f9c841a570ef44769a4523cb18e40', (0x10,0x24,0x4e,0x76,0x7a,0x94,
            0xac,0xb0,0xc8,0xe8,0xfa,0x11e,0x140,0x156,0x15c,0x16c)):
            continue
        def call(pc):
            target = facts_for(image).thumb_call_target(pc)
            return target if target is not None and 0 <= target <= len(image)-2 else None
        calls = {off: call(entry+off) for off in (0x10,0x24,0x4e,0x76,0x7a,0x94,0xac,0xb0,0xc8,0xe8,0xfa,0x11e, 0x140,0x156,0x15c,0x16c)}
        if any(p is None for p in calls.values()) or calls[0x24] != calls[0xfa] or calls[0x11e] != calls[0x140]:
            continue
        task_calls = [calls[d] for d in (0x10,0x156)]
        if any(p & 3 or image[p:p+8] != bytes.fromhex('7847c04604f01fe5') or p+12 > len(image) or not 0x3000000 <= struct.unpack_from('<I',image,p+8)[0] <
            0x4000000 or struct.unpack_from('<I',image,p+8)[0] & 3 for p in task_calls):
            continue
        helper, producer = calls[0x24], calls[0x140]
        if (_normalized_thumb_sha256(image, helper, 0x8a) != ('4a7cd5a973272db39301a387f52fbb437e0004e3b7e77851062a5c7e41f738f7', (2,0xe,0x2a,0x2e,0x4a,0x62,0x66,
            0x80)) or _normalized_thumb_sha256(image, producer, 0x54) != ('f8a4491f57840e16430d52d7bac84ac1a0f58959dce3b06a3448b508d8c6c4d1', (0x1a,0x24,0x4e))):
            continue
        lock, unlock, mode = calls[0x4e], calls[0x76], calls[0xe8]
        edges = [call(helper+d) for d in (2,0xe,0x2a,0x2e,0x4a,0x62,0x66,0x80)]
        if (edges !=[mode,lock,unlock,lock,lock,unlock,lock,unlock] or any(calls[d] != lock for d in (0x7a,0x94,0xb0)) or any(calls[d] != unlock for d in (0xac,0xc8))
            or call(producer+0x24) != lock or call(producer+0x4e) != unlock or not _mapped_irq(image, lock, False) or not _mapped_irq(image, unlock, True) or (lock
            | unlock) & 3):
            continue
        callback = call(producer+0x1a)
        if callback is None or image[callback:callback+2] != bytes.fromhex('0847'):
            continue
        if image[mode:mode+6] != bytes.fromhex('014800787047'):
            continue
        mode_byte = facts_for(image).thumb_literal_value(mode, 0)
        live = facts_for(image).thumb_literal_value(entry+0x14, 5)
        copied = facts_for(image).thumb_literal_value(entry+0x46, 6)
        state = facts_for(image).thumb_literal_value(entry+2, 4)
        state_loads = [facts_for(image).thumb_literal_value(entry+d, 4) for d in (0x36,0xfe)]
        helper_desc = [facts_for(image).thumb_literal_value(helper+d, r) for d,r in ((6,4),(8,7))]
        enabled = facts_for(image).thumb_literal_value(producer+4, 0)
        producer_state = facts_for(image).thumb_literal_value(producer+0xc, 0)
        ring = facts_for(image).thumb_literal_value(producer+0x28, 3)
        task = facts_for(image).thumb_literal_value(entry+0xe, 0)
        ram = ((live,0x38),(copied,0x38),(state,5),(mode_byte,1), (enabled,1),(producer_state,0x2c),(ring,34),(task,0x10))
        if (any(type(p) is not int or not 0x1000000 <= p <= 0x2000000-n for p,n in ram) or live & 3 or copied & 3 or state & 1 or task & 3 or abs(live-copied) <
            0x38 or state_loads !=[state,state] or helper_desc !=[copied,live] or producer_state != state or enabled != state+0x21 or facts_for(image).thumb_literal_value(entry+0x154,
            0) != task):
            continue
        extents = [(live,0x38),(copied,0x38),(state,0x2c),(mode_byte,1),(ring,34),(task,0x10)]
        if any(a < b+m and b < a+n for i,(a,n) in enumerate(extents) for b,m in extents[i+1:]):
            continue
        copy = _loop_descriptor_copy(image, copied)
        columns = facts_for(image).thumb_literal_value(entry+0xd8, 1)
        if (copy is None or columns is None or not 24 <= columns <= len(image)-16 or image[columns:columns+16] != bytes([0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,4])):
            continue
        events = list(image[columns-24:columns])
        if any(events.count(v) != 1 for v in b'123456789*0#'):
            continue
        found.append({'grammar':'indirect-halfword-loop-six-row-v1', 'descriptor':live,'copied_descriptor': copied,'descriptor_copy':copy, 'contact_site':entry+0x1a,'presence_site':entry+0x2a,'sense_site':
            entry+0xce, 'rows':6,'columns':4,'no_key':31, 'single_key_column_sense':[30,29,27,23], 'event_table':columns-24,'event_codes':events, 'token_cells':[{'token':chr(v),'event':v,'row':events.index(v)%6,
            'column':events.index(v)//6} for v in b'123456789*0#'], 'row_selection':{'ports':[0x3000728, 0x3000720], 'masks':[31,32], 'row_values':[(31^(1<<r),32)
            for r in range(5)]+[(31,0)], 'presence_values':[(30,32),(0,0)],'mode_byte':mode_byte}, 'scanner_state':state,'task_record':task, 'producer_enabled':enabled,'queue_sink':hex(producer),
            'producer':{'family': 'optional-callback-byte-ring32-v1','ring':ring,'slots':32, 'write_index_offset':1,'event_offset':2, 'callback_offset':0x28},
            'event_transfer':{'move':hex(entry+0x13e),'call':hex(entry+0x140), 'release_call':hex(entry+0x11e),'release_event':255}, 'runtime_admitted':False,'promotion':
            'temporary-evidence-gated', 'limits':
            'Opt-in released bit4 approximation; physical role/key51/OK/Menu unknown. Live descriptor/shadow and natural input consumption require validation.'
            })
    return found

_LOOP_CONFIRM_RULE = 'same-image-loop-functional-confirm-v1'
_LOOP_CONFIRM_SHAPES = { 'selection': ('2e49b0b509682e4f498b0329', 0, 0xba, '845a7a47bb67db2707b20bcdb5a52a48c46d232d220deb11315b11cdaa435845', (56,62,98,106,138,144,154,174,178)),
    'selection_wrapper': ('021c081c124b111c9a4200b5', 0, 0x50, 'c380d62ff3ba7f2d0908a1cae36d9858efb8f0de1aaad346369f4c7e439b4cf9', (34,64,74)), 'save_wrapper':
    ('031c081c111c1a1c1b4b00b5', 0, 0x78, '0ef3196a58cf06eb5e6df7c623c58d0767601f152aeb117830acb241922df219', (46,74,80,86,92,98,104,110)), 'save': ('b0b57e2800d178e016dcf127',
    0, 0x130, '130ec359f4cc55049f349ebdd1c883c052795e03199bcaa84fba1c0eb6ba64d1', (36,46,50,78,94,100,112,118,132,140,146, 152,160,174,180,186,202,206,214,218,226,236,244,250,258,262,272,286)),
    'commit': ('90b5074c0027b800c0192118', 0, 0x20, '6c02f1d11e4dd51af0bbe0f03c81b6e50eb1090e5cc2dbd34b38c0083cb75751', (16,)), 'record': ('f0b50f1c041c042803d91e49',
    0, 0x82, '4fce10fe09915d4966045ae70bea87fadebe0aa4f2996ef59e6b042eff200930', (14,48,60,72,84,96,104,120)), 'registrar': ('f0b5051c1d480e1c', 0, 0x7a,
    '8ed34ad3d68e668a439df0252ce9da09731bac5e79b1c553e566c3afd53a79de', (10,18,22,30,68,84,88,94,102)), 'lookup': ('0a4b00b500218a009a581288', 0, 0x28,
    'dc2b048eefe04335fa5d7937250698043557a321bb4d1cfea0d704516495f4a1', (34,)), 'allocator': ('90b50d4c00277800c0190001', 0, 0x38,
    '125b0998f531dd0bbcdb69641dd019ce1907ee89f1b1f71e40eb6a564cd2f824', (38,)), 'publisher': ('044a11688162034910600860', 0, 0x10,
    '898d0e0f2e151cce017129e29d24dcc40c195efa176b8d3a606b9af6481089d4', ()), 'action_send': ('b0b4174d2b68dc1c04d56442', 0, 0x5e,
    'a6350958d50d800d70822738f11ca89e9bd8af7867e6bc68076403d2f3e7b0a9', ()), 'action_drain': ('2e4e2e4f2f4c2f48', 0, 0xae,
    'd161a54ef3a416918b1e1a5016e83373eeb042bf61b7a3c6c24b6f3b369d191a', (8,58,74,94,108,114,154)), 'typed': ('f7b5071c0120800781b08c4e', 0, 0x23c,
    '5b630d8c71edf18093f33ee9207634782aff47efdc1f88e709bccc2ff35fcdb5', (52,62,102,112,156,164,182,192,208,216, 230,234,244,248,260,264,274,314,322,340,350,384,436,460,476,502,516,524,544,556,562,566)),
    'dispatch': ('071c00d1c9e0664d674e062f', 6, 0x1a4, '7eb82f89f75175a53df858b4d3b22c62bd10843bdfbdc77ed8076dde57516de6', (2,48,58,68,74,86,96,104,116,160,170,180,186,198,208,214,236,244,264,274,282,290,300,306,324,336,348,368,386,
    392,402,406)), }

def _loop_functional_confirm(image: bytes, matrix: dict):
    from . import _LOOP_CONFIRM_RULE, _LOOP_CONFIRM_SHAPES, _normalized_thumb_sha256, facts_for, find_all, re, struct
    def reject(reason):
        return {}, {'ok_mapping_status': 'rejected', 'ok_mapping_reject_reasons':[reason]}
    events = matrix.get('event_codes',[])
    if len(events) != 24 or events.count(0x53) != 1:
        return reject('confirm-namespace-not-unique')
    # Direct helper avoids resolver recursion; reuse the already closed scanner,
    # callback registration, byte ring and event-preserving dispatcher proof.
    from msm5xxx_emulator.detection.devices.input.halfword_status import _loop_status
    status, reason, _ = _loop_status(image, matrix)
    if status is None:
        return reject('confirm-' + reason)
    def ram(p, size):
        return type(p) is int and 0x1000000 <= p <= 0x2000000-size
    def word(p):
        return struct.unpack_from('<I', image, p)[0] if type(p) is int and 0 <= p <= len(image)-4 else None
    def call(p):
        target = facts_for(image).thumb_call_target(p)
        return target if target is not None and not target & 1 and 0 <= target <= len(image)-2 else None
    matched = {}
    for name, (anchor, back, size, digest, offsets) in _LOOP_CONFIRM_SHAPES.items():
        hits = [p-back for p in find_all(image, bytes.fromhex(anchor)) if p >= back and not (p-back) & 1 and (name != 'action_send' or p-back == call(status['consumer']['dispatch']+0xd0))
            and _normalized_thumb_sha256(image, p-back, size) == (digest, offsets) and all(call(p-back+d) is not None for d in offsets)]
        if len(hits) != 1:
            return reject('confirm-shape-' + ('missing-' if not hits else 'ambiguous-') + name)
        matched[name] = hits[0]
    sel, sw, save, vw, commit, record = (matched[n] for n in ('selection','selection_wrapper','save', 'save_wrapper','commit','record'))
    reg, lookup, alloc, pub, send, drain, typed, dispatch = (matched[n] for n in ('registrar','lookup', 'allocator','publisher','action_send','action_drain','typed','dispatch'))
    current = facts_for(image).thumb_literal_value(pub+6, 1)
    action_ring = facts_for(image).thumb_literal_value(send+2, 5)
    if (dispatch != status['consumer']['dispatch'] or call(dispatch+2) != status['consumer']['dequeue'] or call(dispatch+0xd0) != send or call(drain+0x3a) !=
        typed or call(drain+0x9a) != typed or not ram(action_ring, 8+32*12) or action_ring & 3 or facts_for(image).thumb_literal_value(drain+4, 4) !=
        action_ring or not ram(current,4) or current & 3 or any(facts_for(image).thumb_literal_value(typed+d, 6) != current for d in (0xa,0x162,0x1c0)) or image[call(typed+0x1cc):call(typed+0x1cc)+2]
        != bytes.fromhex('1847') or facts_for(image).thumb_literal_value(sel, 1) != current or facts_for(image).thumb_literal_value(sw+4, 3) != 0x40000001 or
        facts_for(image).thumb_literal_value(vw+0x12, 3) != 0x40000001 or facts_for(image).thumb_literal_value(typed+0x5c, 0) != 0x40000004 or call(sw+0x4a) !=
        sel or call(vw+0x56) != save or call(sel+0xae) != reg or call(reg+0x16) != alloc or call(reg+0x1e) != lookup or call(reg+0x5e) != pub or facts_for(image).thumb_literal_value(reg+4,
        0) != facts_for(image).thumb_literal_value(pub, 2) or not ram(facts_for(image).thumb_literal_value(alloc+2, 4),20*48) or not ram(facts_for(image).thumb_literal_value(pub,
        2),4) or not ram(facts_for(image).thumb_literal_value(sel+0x16, 5),0x3c) or not ram(facts_for(image).thumb_literal_value(sel+0x70, 2),2)):
        return reject('confirm-typed-registration-link-mismatch')
    # Copy-source provenance for every searched 48-byte descriptor; lookup
    # compares header IDs, never table indices. No absolute ROM/RAM offset gate.
    table = facts_for(image).thumb_literal_value(lookup, 3)
    if type(table) is not int or table & 3 or not 0 <= table <= len(image)-0x97*4:
        return reject('confirm-registry-table-bounds')
    pointers = [word(table+4*i) for i in range(0x97)]
    if any(not ram(p,48) or p & 3 for p in pointers):
        return reject('confirm-registry-pointer-ambiguity')
    pattern = re.compile(b'.\x48\x00\x68.\x49\x09\x68\x40\x18\x06\x1c' b'.\x48\x00\x68\x05\x1c.\x48' + re.escape (bytes.fromhex('0068041cb44208d204e0281d051c201d041cf7e728682060f7e7')),
        re.S)
    copies = []
    for match in pattern.finditer(image[:0x20000]):
        pc = match.start()
        slots = [facts_for(image).thumb_literal_value(pc+d, r) for d,r in ((0,0),(4,1),(12,0),(18,0))]
        if pc & 1 or any(type(p) is not int or p & 3 or not 0 <= p <= len(image)-4 for p in slots):
            continue
        dest,size,source,reload = [word(p) for p in slots]
        if ((slots[1],slots[2],slots[3]) != (slots[0]+4,slots[0]-4,slots[0]) or reload != dest or (source | dest | size) & 3 or not ram(dest,size) or size < 48
            or not 0 <= source <= len(image)-size or any(not dest <= p <= dest+size-48 for p in pointers)):
            continue
        copies.append((pc,source,dest,size))
    if len(copies) != 1:
        return reject('confirm-registry-copy-missing-or-ambiguous')
    copy_pc,source,dest,size = copies[0]
    descriptors = [source+p-dest for p in pointers]
    ids = [struct.unpack_from('<H',image,p)[0] for p in descriptors]
    registered = []
    for wrapper in (sw,vw):
        matches = [p for p in descriptors if word(p+0xc) == wrapper+1]
        if (len(matches) != 1 or ids.count(struct.unpack_from('<H',image,matches[0])[0]) != 1 or word(matches[0] +0x20) != 0 or word(matches[0]+0x24) != 0):
            return reject('confirm-registered-callback-missing-or-ambiguous')
        registered.append(matches[0])
    # Independent setting commit and its named result, tied to the raw53 arm.
    strings = call(save+0xe2)
    if (call(save+0xda) != commit or call(commit+0x10) != record or call(save+0xec) != strings or strings is None or image[strings:strings+8] != bytes.fromhex('0149800008587047')
        or facts_for(image).thumb_literal_value(record+0x12, 0) != 0x36a or not ram(facts_for(image).thumb_literal_value(commit+2, 4),25) or not ram(facts_for(image).thumb_literal_value(record+0x14,
        6),5) or not ram(facts_for(image).thumb_literal_value(record+0x6e, 0),25)):
        return reject('confirm-save-link-mismatch')
    text_table = facts_for(image).thumb_literal_value(strings, 1)
    if type(text_table) is not int or text_table & 3 or not 0 <= text_table <= len(image)-4*0x1a1:
        return reject('confirm-save-string-table-bounds')
    for index,text in ((0x11d,'저장했습니다'),(0x1a0,'알림')):
        pointer = word(text_table+4*index)
        raw = text.encode('cp949')+b'\0'
        if type(pointer) is not int or not 0 <= pointer <= len(image)-len(raw) or image[pointer:pointer+len(raw)] != raw:
            return reject('confirm-save-result-string-mismatch')
    mapping = {5: {'event':0x53,'semantic_status':'temporary-evidence-gated-provisional', 'rule': _LOOP_CONFIRM_RULE,'semantic_grammar_fingerprint':_LOOP_CONFIRM_SHAPES['selection'][3],
        'evidence': 'same-image-scanner+typed-dispatch+copied-registry+selection+named-save', 'functional_only':True, 'physical_keycap_proven':False,
        'selection':sel,'save':save,'typed_dispatch':typed,'registry_lookup': lookup, 'registry_copy':{'loop':copy_pc,'source':source,'target':dest,'size':size},
        'registered_callbacks':[{'rom':p,'ram':dest+p-source,'callback':word(p+0xc)} for p in registered], 'limits':'Functional confirm is state-dependent; physical keycap and Home/Menu mapping unproven.'}}
    return mapping, {'ok_mapping_status':'accepted-provisional','ok_mapping_reject_reasons':[]}

def _mapped_physical_menu(image: bytes, matrix: dict):
    """Temporary exact queue-to-menu class; unrelated scanners keep numeric input."""
    from . import _normalized_thumb_sha256, _thumb_reachable_preserving_register, facts_for, find_all, re
    # shortcut: one closed local class, promote only after independent peer consumer proof.
    contracts = {'dequeue':[(0, 28, '1fc8ee03fae7bdaa2c9678aa2e34f72968a6fe31206eead28e9bb853b5ba6710', ())], 'forward':[(0, 86,
        '18a4311723b801a06073250b289e940a51fe03e839f6f53ae0a7651688c39ed6', (38,))], 'task':[(0, 28,
        '9e4e15d23145abe199cecc25fed61d9207ebcfa5d017f759e96764967f71a29f', (2,)), (162, 54, '6b5518d18dda44626d1fb27690a10fa7fe9421f65e6f74a87eedb9e4aa973409',
        (34, 50))], 'poll':[(-52, 64, '2649e76223b422e9c695405624c0bdffdcd5ba4f4b79c50f9657442547227645', (2, 48, 52, 60)), (-130, 78,
        'eb1e6ea9f4384935055fe9465666a3ae1c30287198ee47d615ddc92bdb891c08', (50,))], 'application':[(0, 10,
        'ad02919762ca66006a81b99b5bc30eb788fee6101fdf66ead4f2009c17f32de3', ()), (208, 56, 'b0603e36a177454d0f4859a06ba23b18a59e079b60343588187ec6cd480f5762', (26,
        42)), (8186, 50, 'f5ff17f36450e7e0582bacd32c200d32e67ab43fd9e8a3e47ac20752244393e7', ()), (8236, 18,
        '089a61b84b4b0a7655e41d3977fa7756b4a1fe2864f992ab94928dff40de77b1', (0, 6, 12)), (8480, 20,
        'd4aca9220345a3a21d353bfff3761a459f375c3552f6d4c0feeca3f0b2ac044d', (10,)), (8542, 20,
        'ed4b87b2be488bedb210974acedf1e51dcd2941b30584c724f8780e8856b8479', (4, 10)), (8302, 6,
        'dc42eb6c417da95a243a7fa8bd1b0ee0b6b3aa8b3c397cb91c30c6b81fcda848', (0,)), (72, 6, '65035037b6b707d30cb2ecfb4f6cc838bb1e1a5b59349ddf5f4cc11424d8bf3c', ())],
        'menu':[(0, 20, '6b0b644c8cdac5b8ec86082acd79c7aaa202374455884f50c0b0e8c7f8da4f2f', (8,)), (4534, 32,
        '59e55998c9f1bcb88ff0ea65c042b0e55ad01cfd77f9ed14e701519a0aca1a0d', (12, 24)), (4650, 40,
        'deb61d8111134e3a4a32c8309b4619e3c3d355ec964483a245755e144ba36769', (4, 14, 36)), (7694, 124,
        '26ba3d4b4900870468da2c60368eea8b313efb55450421fd749fe948685fdb92', (18, 76)), (7818, 38,
        '21f64e23f9f31c1466cbb5ac2459027349999ac0c56d214437387068f7250583', (22,)), (8142, 28,
        '73e0c2dc99b775d0d80b8af3b2c14328cb17b44998c1e793b34b2df2dda3ff67', (14,)), (8224, 16,
        '3155a3bf21cb8b1dbf61929b1294fe95291ecd80fda3270bdb9e10e2ccda446c', ()), (11088, 14, '462c01ffc3f440968f56aca7d4203be47386dc8f89346387203e4defd59866cc',
        ()), (11284, 10, '6d0f6ca64581de890f881a3bd8651e99a37a1c9dbbf7d9457f42e072d6350a21', ()), (438, 4,
        'df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119', (0,))], 'install':[(0, 68,
        'ac6323a2e9a9d9130088c68104f0a2718f37ba6c15b1945ee30ab25413bb73ef', (20,))]}
    def shape(name, base):
        return type(base) is int and not base & 1 and all(_normalized_thumb_sha256(image, base+off, size) == (digest, calls) and all(call(base+off+delta) is not
            None for delta in calls) for off,size,digest, calls in contracts[name])
    def literal(pc, reg):
        return facts_for(image).thumb_literal_value(pc, reg)
    def call(pc):
        target = facts_for(image).thumb_call_target(pc)
        return target if target is not None and not target & 1 and 0 <= target <= len(image)-2 else None
    def reject(reason):
        return None, {'menu_mapping_status':'rejected', 'menu_mapping_reject_reasons':[reason]}
    producer = matrix.get('producer', {})
    if producer.get('family') != 'filtered-byte-ring4-v1':
        return reject('menu-ring-family')
    dequeue = int(matrix['queue_sink'], 16)-0x20
    if not shape('dequeue', dequeue) or literal(dequeue, 2) != producer['ring']:
        return reject('menu-dequeue-ring')
    callers = [m.start() for m in re.finditer(rb'(?=.[\xf0-\xf7].[\xf8-\xff])', image, flags=re.S) if not m.start() & 1 and facts_for(image).thumb_call_target(m.start())
        == dequeue]
    if len(callers) != 1:
        return reject('menu-dequeue-callers')
    poll = callers[0]
    if not shape('poll', poll):
        return reject('menu-poll-shape')
    block = call(poll+8)
    forward = call(poll-0x32)
    if (block is None or not shape('forward', forward) or call(poll-4) != forward or call(block+0x338) != poll- 0x82 or block+0x338 not in
        _thumb_reachable_preserving_register(image,block,poll+12,7) or poll-0x34 not in _thumb_reachable_preserving_register(image,poll-0x82,poll,7)):
        return reject('menu-raw-forward-flow')
    secondary = literal(forward+2,4)
    tasks = [pc for pc in find_all(image,bytes.fromhex('f8b5')) if shape('task',pc) and literal(pc+0x18,4) == secondary]
    if len(tasks) != 1:
        return reject('menu-secondary-consumers')
    task = tasks[0]
    if task+0xcc not in _thumb_reachable_preserving_register(image,task+0x1a,task+0xe6,4):
        return reject('menu-secondary-register-flow')
    app = call(task+0xd4)
    if not shape('application', app):
        return reject('menu-application-shape')
    menu = call(app+0x2038)
    if (not shape('menu', menu) or call(menu+0x1b6) != menu+0x2b44):
        return reject('menu-consumer-shape')
    outer = literal(app+0x4a,7)
    reachable = _thumb_reachable_preserving_register(image,app+0x4c,app+0x2172,7)
    if app+0x1ffa not in reachable or app+0x216c not in reachable:
        return reject('menu-outer-state-register-flow')
    global_key = literal(app+0x104,1)
    if global_key != literal(menu+0x11b6,1):
        return reject('menu-global-key-mismatch')
    install = call(menu+0x1ea0)
    if (not shape('install',install) or call(menu+0x11ce) != menu+0x1e0e or call(menu+0x124e) != menu+0x1e8a):
        return reject('menu-key-arms-or-descriptor')
    inner = literal(menu+0x2026,0)
    if (inner is None or inner-0xc3 != literal(menu+0x2b50,7) or literal(menu+0x1fe2,0) != inner):
        return reject('menu-state-bridge')
    descriptor = literal(install+4,0)
    descriptor_state = literal(install+2,7)
    spans = [(producer['ring'],6),(secondary,72),(global_key,4), (inner-0xc3,4),(descriptor,8),(descriptor_state,0x20),(outer,0x10)]
    if any(type(a) is not int or not 0x1000000 <= a <= 0x2000000-n for a,n in spans):
        return reject('menu-ram-bounds')
    if any(a < other+n and other < a+size for i,(a,size) in enumerate(spans) for other,n in spans[i+1:]):
        return reject('menu-ram-alias')
    # Byte table and owning call/return shapes close state5 -> returned state0B.
    table = app+0x200c
    if (app+0x200e+2*image[table+3] != app+0x2038 or app+0x200e+2*image[table+9] != app+0x206e):
        return reject('menu-state-table')
    event = image[menu+0x124a]
    events = matrix['event_codes']
    if event != 0x5b or len(events) != 28 or events.count(event) != 1:
        return reject('menu-event-cell')
    cell = events.index(event)
    mapping = {'event':event,'rule':'same-image-mapped-physical-menu-v1', 'semantic_status': 'temporary-evidence-gated-provisional','physical_only':True,
        'queue_consumer':dequeue,'secondary_ring': secondary,'application':app, 'global_key':global_key,'consumer':menu,'descriptor':descriptor, 'inner_state':inner-0xc3+3,'outer_state':outer+0xf,
        'row':cell%7,'column':cell//7}
    return {0:mapping}, {'menu_mapping_status':'accepted-provisional', 'menu_mapping_reject_reasons':[]}

_MAPPED_CONFIRM_RULE = 'same-image-mapped-functional-confirm-v1'
_MAPPED_CONFIRM_SHAPES = { 'consumer': (0x10, '8ba71a6d6a2b462491ce56afb1d67025e0dae6d1db321c3f87304dc0f8b404b1', ()), 'dispatch': (0xe2,
    '01b2bc53421e62ad1cd13fcf29270e21747f41b84fca10060642b8001f48e455', ()), 'activation': (0xba,
    'cdf26c1647c3c22f9d1172eae077fbbb5611839d85a3a0dbce64dbb0a9163a98', ((10, 158760), (36, 6682), (60, 29122))), 'helper': (0x48,
    '620aa71f725acf732fb9442f16bec1187eb65ce41086af33d2aa3f3850781186', ((38, -1119888),)), 'builder': (0x32,
    '71c55216bdec13303c0503e31180c3f1cc5e5c9de202bab08f9dfe029a4b78a8', ((8, -6136), (26, -6080), (44, 2381174))), 'allocator': (0x2a,
    'e3f82c8c89c03dca27d29d0b086fc11521c7f947b4d029dc5ced284857f26b0a', ((4, 2385252), (16, 537100), (26, 2388456))), 'publisher': (0x20,
    '26efc06d2a8be26244d77e91929ccbbcef81f0995a107f45fdd86c2bcd166d23', ((6, 203854), (14, 2385220), (22, 2385208))), 'global104': (0x4,
    'd5229a21f29eb79f5ac6165fb1ecc8fdce6348ff9c8f2ceb0f527c6e6a728c50', ()), 'join': (0x4, 'df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119', ((0,
    23672),)), 'mode_bridge': (0xe, '71acde7918c0a02a005880a23e1528c9eacc4131ed1202fe8e0e73c9b6544b1c', ((0, 1682),)), 'mode_commit': (0x6,
    '00f25fa65b1e5e5c5b973cf6c7ab1579cd404775dc8e0c08b007bf712a88e747', ()), 'install': (0x44,
    'ac6323a2e9a9d9130088c68104f0a2718f37ba6c15b1945ee30ab25413bb73ef', ((20, 165900),)), }
