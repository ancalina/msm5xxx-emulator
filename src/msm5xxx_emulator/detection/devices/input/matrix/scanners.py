from __future__ import annotations

def _distributed_ram(pointer: int | None, size: int) -> bool:
    return isinstance(pointer, int) and 0x01000000 <= pointer <= 0x03000000 - size

def _distributed_irq(image: bytes, pc: int | None, enable: bool) -> bool:
    """Direct Thumb-to-ARM wrapper; previous IRQ mask returned in r0."""
    body = bytes.fromhex('7847000001e08ee300000fe1c010' + ('c0' if enable else '80') + 'e301f021e1c00000e21eff2fe1')
    return pc is not None and 0 <= pc <= len(image) - len(body) and image[pc:pc + len(body)] == body

def _distributed_branch(image: bytes, pc: int, end: int, condition: int | None = None):
    from . import _distributed_word, _thumb_successors
    word = _distributed_word(image, pc)
    if condition is None:
        if word & 0xf800 != 0xe000:
            return None
    elif word & 0xff00 != 0xd000 | condition << 8:
        return None
    edges = _thumb_successors(image, pc, end)
    target = edges[-1] if edges else None
    return target if target is not None and 0 <= target < end else None

def _distributed_hop(image: bytes, pc: int | None, goal: int, lower: int, end: int):
    """At most two unconditional trampolines, never arbitrary instructions."""
    from . import _distributed_branch
    for _ in range(3):
        if pc == goal:
            return True
        if pc is None or not lower <= pc < end:
            return False
        pc = _distributed_branch(image, pc, end)
    return False

def _distributed_gpio_arm(image: bytes, start: int, sense: int, unlock_site: int, lock: int, unlock: int):
    """Three protected byte shadow updates and their GPIO store consumers."""
    from . import _distributed_branch, _distributed_hop, _distributed_ram, _distributed_word, facts_for
    pc = start
    if _distributed_word(image, pc) & 0xf800 == 0xe000:
        pc = _distributed_branch(image, pc, sense)
    blocks = []
    for offset in (12, 8, 4):
        if pc is None or not start <= pc < sense - 24 or facts_for(image).thumb_call_target(pc) != lock:
            return None
        shadow = facts_for(image).thumb_literal_value(pc + 4, 1)
        mask_word = _distributed_word(image, pc + 6)
        if (not _distributed_ram(shadow, 1) or mask_word & 0xff00 != 0x2300 or not mask_word & 255 or image[pc + 8:pc + 10] != bytes.fromhex('0a78')):
            return None
        mask, value, cursor = mask_word & 255, 0, pc + 10
        if _distributed_word(image, cursor) == 0x439a:
            cursor += 2
            if _distributed_word(image, cursor) & 0xff00 == 0x2300:
                value = _distributed_word(image, cursor) & 255
                cursor += 2
                if _distributed_word(image, cursor) != 0x431a:
                    return None
                cursor += 2
        elif _distributed_word(image, cursor) == 0x431a:
            value, cursor = mask, cursor + 2
        else:
            return None
        if value & ~mask or image[cursor:cursor + 4] != bytes.fromhex('0a700978'):
            return None
        base = facts_for(image).thumb_literal_value(cursor + 4, 2)
        if base is None:
            return None
        cursor += 6
        if _distributed_word(image, cursor) & 0xf800 == 0xe000:
            cursor = _distributed_branch(image, cursor, sense)
        if (cursor is None or not start <= cursor <= sense - 6 or _distributed_word(image, cursor) != 0x7011 | offset << 6):
            return None
        compare = cursor + 2
        if _distributed_word(image, compare) & 0xf800 == 0xe000:
            compare = _distributed_branch(image, compare, sense)
        if compare is None or not start <= compare <= sense - 6 or _distributed_word(image, compare) != 0x2800:
            return None
        next_pc = compare + 8
        taken = _distributed_branch(image, compare + 2, sense + 2, 1)
        if offset != 4:
            if taken != next_pc or facts_for(image).thumb_call_target(compare + 4) != unlock:
                return None
        else:
            if (not _distributed_hop(image, taken, sense, sense - 0x300, sense + 2) or not _distributed_hop(image, compare + 4, unlock_site, start, sense + 2)):
                return None
        blocks.append({'shadow': shadow, 'address': base + offset, 'mask': mask, 'value': value, 'store': cursor })
        pc = next_pc
    return blocks

def _distributed_clear(image: bytes, helper: int, lock: int, unlock: int, ports):
    from . import _distributed_branch, _distributed_word, facts_for
    if not 0 <= helper <= len(image) - 84 or image[helper:helper + 2] != bytes.fromhex('80b5'):
        return False
    base = facts_for(image).thumb_literal_value(helper + 12, 7)
    for block, call, offset, port in zip((6, 34, 60), (2, 30, 56), (12, 8, 4), ports):
        pc = helper + block
        shift = 2 if block == 6 else 0  # First block loads the shared GPIO pointer.
        if (facts_for(image).thumb_call_target(helper + call) != lock or facts_for(image).thumb_literal_value(pc, 1) != port['shadow'] or _distributed_word(image,
            pc + 2) != 0x2300 | port['mask'] or _distributed_word(image, pc + 4) != 0x780a or image[pc + 6 + shift:pc + 12 + shift] != bytes.fromhex ('9a430a700978')
            or _distributed_word(image, pc + 12 + shift) != 0x7039 | offset << 6 or _distributed_word(image, pc + 14 + shift) != 0x2800 or _distributed_branch(image,
            pc + 16 + shift, helper + 84, 1) != pc + 22 + shift or facts_for(image).thumb_call_target(pc + 18 + shift) != unlock or base is None or port['address']
            != base + offset):
            return False
    return image[helper + 82:helper + 84] == bytes.fromhex('80bd')

def _distributed_ring32(image: bytes, sink: int, lock: int, unlock: int):
    from . import SAMSUNG_RAW_DEQUEUE, _distributed_ram, _thumb_path_preserves_register, facts_for, find_all
    if not 0 <= sink <= len(image) - 126 or image[sink:sink + 2] != bytes.fromhex('b0b5') or image[sink + 4:sink + 6] != bytes.fromhex('071c'):
        return None
    state = facts_for(image).thumb_literal_value(sink + 2, 4)
    queue = facts_for(image).thumb_literal_value(sink + 62, 0)
    tail = bytes.fromhex('2d0c417803784a1cd206d20e9a4207d009188f7041780131c906c90e417003e0')
    if (not _distributed_ram(state, 0x34) or not _distributed_ram(queue, 34) or facts_for(image).thumb_call_target(sink + 56) != lock or image[sink + 60:sink +
        62] != bytes.fromhex('0504') or image[sink + 64:sink + 96] != tail or facts_for(image).thumb_call_target(sink + 108) != unlock or image[sink + 124:sink
        + 126] != bytes.fromhex('b0bd') or not _thumb_path_preserves_register(image, sink + 6, sink + 82, sink + 126, 7)):
        return None
    dequeues = [pc for pc in find_all(image, SAMSUNG_RAW_DEQUEUE) if not pc & 1 and facts_for(image).thumb_literal_value(pc, 2) == queue]
    if len(dequeues) != 1:
        return None
    return {'family': 'distributed-filtered-byte-ring32-v1', 'ring': queue, 'state': state, 'state_size': 0x34, 'slots': 32, 'event_offset': 2, 'wrap_mask': 31,
        'enqueue': sink, 'dequeue': dequeues[0], 'event_store': sink + 82, 'write_index_store': sink + 92, 'read_index_store': dequeues[0] + 24}

def _distributed_control_profile(image: bytes, parent: dict):
    """Optional compiled queue/dispatch class; functional labels remain provisional."""
    from . import _distributed_branch, _distributed_ram, _thumb_path_preserves_register, facts_for, find_all
    def require(condition, reason):
        if not condition:
            raise ValueError(reason)
    def code(pc, body):
        return pc >= 0 and image[pc:pc + len(bytes.fromhex(body))] == bytes.fromhex(body)
    try:
        events = parent['event_codes']
        require(len(events) == 24 and all(type(v) is int for v in events) and all(events.count(v) == 1 for v in (0x5B, 0x53)), 'control-events-not-unique')
        producer = parent['producer']
        dequeue, raw_ring = producer['dequeue'], producer['ring']
        require(facts_for(image).thumb_literal_value(dequeue, 2) == raw_ring and _distributed_ram(raw_ring, 34), 'control-parent-ring-mismatch')
        callers = [pc for pc in find_all(image, bytes.fromhex('071c')) if pc >= 4 and not pc & 1 and facts_for(image).thumb_call_target(pc - 4) == dequeue and
            _distributed_branch(image, pc + 2, len(image), 0) == pc + 6 and _distributed_branch(image, pc + 4, len(image)) is not None]
        require(len(callers) == 1, 'control-raw-caller-not-unique')
        returned = callers[0]
        task = _distributed_branch(image, returned + 4, len(image))
        require(0 <= task < returned and returned + 6 - task <= 0x800, 'control-task-bounds')
        forwards = [returned - 0x60, returned - 0x3E]
        sinks = [facts_for(image).thumb_call_target(pc + 2) for pc in forwards]
        require(all(task <= pc < returned and code(pc, '381c') and _thumb_path_preserves_register(image, task, pc, returned + 6, 7) for pc in forwards) and
            sinks[0] is not None and sinks[0] == sinks[1], 'control-forward-link-unclosed')
        sink = sinks[0]
        require(0 <= sink <= len(image) - 80 and code(sink, '90b5') and code(sink + 4, '071c') and code(sink + 6,
            '2068033004d54042c006c00e404201e0c006c00e6168884203d1') and code(sink + 0x28,
            '20680130011c002804da4042c006c00e404201e0c006c00e6268904203d0206040000019078190bd'), 'control-secondary-producer-unclosed')
        ring = facts_for(image).thumb_literal_value(sink + 2, 4)
        require(_distributed_ram(ring, 72), 'control-secondary-ring-outside-ram')
        consumers = []
        for pc in find_all(image, bytes.fromhex('5060400080180089')):
            if (pc < 0x12 or pc & 1 or pc + 0x1C > len(image) or not code(pc - 0x12, '013004d54042c006c00e404201e0c006c00e') or facts_for(image).thumb_literal_value(pc
                + 0x12, 2) != ring or not code(pc + 0x14, '506811688842') or _distributed_branch(image, pc + 0x1A, len(image), 1) != pc - 0x12):
                continue
            app = facts_for(image).thumb_call_target(pc + 8)
            if app is not None and code(app, 'f0b598b000210191') and code(app + 10, '071c'):
                consumers.append((pc, app))
        require(len(consumers) == 1, 'control-secondary-consumer-not-unique')
        consumer, app = consumers[0]
        require(app + 0x1638 <= len(image), 'control-application-bounds')
        mode = facts_for(image).thumb_literal_value(app + 0x6A, 1)
        global_word = facts_for(image).thumb_literal_value(app + 0x92, 0)
        owner = facts_for(image).thumb_literal_value(app + 0xF4, 7)
        require(code(app + 0x6C, '0879303116910028') and _distributed_branch(image, app + 0x74, len(image), 0) == app + 0x92 and code(app + 0x76, '1699087a0028')
            and _distributed_branch(image, app + 0x7C, len(image), 1) == app + 0x92 and code(app + 0x7E, '381c') and code(app + 0x8C, '0860') and code(app +
            0x94, '0760') and code(app + 0x9A, '0168') and facts_for(image).thumb_literal_value(app + 0x84, 1) == global_word and facts_for(image).thumb_literal_value(app
            + 0x96, 0) == global_word, 'control-direct-global-link-unclosed')
        dispatch = app + 0x14FC
        require(code(dispatch, '7878b87002381d28') and _distributed_branch(image, dispatch + 8, len(image), 2) == dispatch + 0x86 and code(dispatch + 10,
            '02a31b5c5b009f44001c') and _thumb_path_preserves_register(image, app + 0xF6, dispatch, dispatch + 0x140, 7), 'control-state-dispatch-unclosed')
        table = dispatch + 0x14
        menu_call, ok_call = [table + 2 * image[table + state - 2] for state in (5, 12)]
        menu, confirm = [facts_for(image).thumb_call_target(pc) for pc in (menu_call, ok_call)]
        join = dispatch + 0x10C
        require(menu_call != ok_call and menu is not None and confirm is not None and _distributed_branch(image, menu_call + 4, len(image)) == join and
            _distributed_branch(image, ok_call + 4, len(image)) == join and code(join, '041c0128') and _distributed_branch(image, join + 4, len(image), 1) ==
            join + 0x1C and code(join + 10, '7870041c') and code(join + 0x20, '7878') and code(join + 0x26, '7c70002c') and _distributed_branch(image, join +
            0x2C, len(image)) == dispatch, 'control-return-state-loop-unclosed')
        require(0 <= menu <= len(image) - 0xDA and code(menu, 'f0b5beb0') and code(menu + 0x1A, 'a178e170') and code(menu + 0xD0, '0026e078') and code(menu +
            0xD6, 'a070e670'), 'control-menu-status-return-unclosed')
        menu_status = facts_for(image).thumb_literal_value(menu + 0xE, 4)
        require(facts_for(image).thumb_literal_value(menu + 0xCE, 4) == menu_status, 'control-menu-status-owner-mismatch')
        require(0 <= confirm <= len(image) - 0x292 and code(confirm, 'f0b5b2b0') and code(confirm + 6, '0026e71d1937be73387b') and code(confirm + 0x22E,
            '08685428') and code(confirm + 0x280, '5328') and _distributed_branch(image, confirm + 0x282, len(image), 1) == confirm + 0x31C and code(confirm +
            0x288, '486bc21d29323260496d') and code(confirm + 0x19A, '0020c8650121f973') and code(confirm + 0x1A4, '5521316002217973269a'),
            'control-confirm-or-internal-request-unclosed')
        status = facts_for(image).thumb_literal_value(confirm + 4, 4)
        require(all(facts_for(image).thumb_literal_value(pc, register) == global_word for pc, register in ((confirm + 0x10, 5), (confirm + 0x22C, 1), (confirm +
            0x286, 6), (confirm + 0x1A2, 6))) and all(facts_for(image).thumb_literal_value(pc, 1) == status for pc in (confirm + 0x15E, confirm + 0x284)),
            'control-handler-global-or-status-owner-mismatch')
        objects = [(raw_ring,34),(ring,72),(global_word,4),(owner,3), (menu_status,0x60),(status,0x60),(mode, 0x3C)]
        require(all(_distributed_ram(pointer, size) for pointer,size in objects), 'control-owner-outside-ram')
        require(all(not pointer & 3 for pointer in (ring, global_word, status)), 'control-word-owner-unaligned')
        require(all(a + na <= b or b + nb <= a for i,(a,na) in enumerate(objects) for b,nb in objects[i+1:]), 'control-owner-alias')
        roots = [(parent['scanner_state'], parent['scanner_state_size']), (parent['batch_state'], parent['batch_state_size']), (producer['state'], producer['state_size'])]
        roots.extend((port['shadow'], 1) for port in parent['gpio_ports'])
        require(all(a + na <= b or b + nb <= a for a,na in objects[1:] for b,nb in roots), 'control-parent-state-alias')
        mappings = {bit: dict(event=event, rule=rule, semantic_status='temporary-evidence-gated-provisional', functional_only=True) for bit,event,rule in ((0,0x5B,'same-image-distributed-functional-menu-v1'),
            (5,0x53,'same-image-distributed-functional-confirm-v1'))}
        return mappings, dict(menu_mapping_status='accepted-provisional', ok_mapping_status= 'accepted-provisional', control_consumer=dict(grammar='distributed-queued-direct-word-controls-v1',
            raw_dequeue=dequeue, raw_return=returned, raw_task=task, forwards=forwards, secondary_producer=sink, secondary_consumer=consumer, secondary_ring=ring,
            application=app, global_word=global_word, state_owner=owner, dispatcher=dispatch, menu_handler=menu, confirm_handler=confirm, menu_status=
            menu_status, confirm_status=status), control_mapping_limits=
            'Temporary compiled queue class with functional MENU/confirm evidence; physical legends and other boot contexts unverified.')
    except (ValueError, KeyError, IndexError, TypeError) as error:
        return {}, dict(menu_mapping_status='rejected', ok_mapping_status='rejected', control_mapping_reject_reasons= [str(error)])

_DISTRIBUTED_NAVIGATION_SPANS = ((0x22C,
    '00490868542836d036dc362835d013dc322832d009dc23282fd02a282dd030282bd0312864d11ae191e0332825d0342823d035285cd112e150281ed006dc37281bd0382819d0392852d108e1512850d052284fd053284bd10049004e486bc21d29323260496d004a914244d1002843d1ff2005301fe369e000e03be3ff230233984236d039dc642838d038dc552837d05b2836d060282cd0632829d1004a004e516d004ee160506bb142106344d1c11e51631991106d0068002813d01999004800290fda806bc11c061c03200000000043001999181840180049b042486301dd00484663ff20004e013030600048bfe1b7e02ee003e1e1e0d6e01ee0dce201e004e03fe3652821d0662820d1ff2000490130004a0860566de660506b411c10635163106d0068002812d0906b013000000000004a516393e192e2ff231933984207d007dcff230533984245e0dae19be07ee14ae05ee0'),
    (0x67C, '00480139806b00000000481c00494863'), (0x730, '004aff21506b004e10630131316001385063116d0968002902d0002804da01e0002801d1906b5063'), (0x88C,
    '004b994225d12799497a002921d10049033848631890086d0069002813d01899004801290fda806bc11c061c03200000000043001899181840180049b042486301dd00484663ff20004e013030600048e3e6'),
    (0x8E4,
    '0049004a486d904228d1486bc61c08634e63086d0068002817d0886b1790864213dd1798c11c03200000000043001818b04204dd00491798486306e04be00320311c0000000000484163ff200049013008600049486b000000001ee1004a904232d1279b587a00282fd10049486bc61c08634e63086d0069002817d0886b1690864213dd1698c11c032000000000430018180130b04203dd00491698486305e00320311c0000000000484163ff20004901300860'),)
_DISTRIBUTED_NAVIGATION_DIVISION = bytes.fromhex('cb175940c91ac2175040801a0cb44b08021c02d10000000052009a42fcd90023914205d2db18824206d052089142f9d35b41891a8242f8d1181c0cbc5a405040801a5940c91a7047')

def _distributed_navigation_profile(image: bytes, parent: dict):
    """Optional menu-grid consumer; rejection never removes existing controls."""
    from . import _DISTRIBUTED_NAVIGATION_DIVISION, _DISTRIBUTED_NAVIGATION_SPANS, _distributed_branch, _distributed_ram, facts_for
    def require(condition, reason):
        if not condition:
            raise ValueError(reason)
    try:
        require(parent.get('menu_mapping_status') == parent.get('ok_mapping_status') == 'accepted-provisional', 'navigation-parent-controls-rejected')
        control = parent['control_consumer']
        require(control['grammar'] == 'distributed-queued-direct-word-controls-v1', 'navigation-parent-grammar')
        handler, status, global_word = [control[key] for key in ('confirm_handler', 'confirm_status', 'global_word')]
        events = parent['event_codes']
        require(len(events) == 24 and all(type(v) is int and 0 <= v <= 255 for v in events) and all(events.count (v) == 1 for v in (0x63, 0x64, 0x65, 0x66)),
            'navigation-events-not-unique')
        require(type(handler) is int and not handler & 1, 'navigation-handler-invalid')
        # Descriptor comparisons in both +/-3 mode arms must share the same
        # respective owner. Neither pointer is a guessed global layout default.
        grid = facts_for(image).thumb_literal_value(handler + 0x2CE, 6)
        alternate = facts_for(image).thumb_literal_value(handler + 0x88C, 3)
        owners = {**{offset: status for offset in (0x284,0x2C8,0x2EA,0x304,0x30C,0x318,0x33E,0x35E,0x67C,0x688, 0x730,0x89A,0x8AC,0x8C6,0x8CE,0x8DA,0x8E4,0x918,0x92A,0x936,0x94E,0x97C,0x98C)},
            **{offset: global_word for offset in (0x22C,0x286,0x2CA,0x312,0x33A,0x736,0x8D4,0x930,0x992)}, **{offset: grid for offset in (0x292,0x2CE,0x8E6)},
            **{offset: alternate for offset in (0x88C,0x940)}}
        require(all(type(v) is int and not v & 3 and _distributed_ram(v, 4) for v in (grid, alternate)) and grid != alternate, 'navigation-grid-owner-invalid')
        owned = [(control['secondary_ring'],72),(global_word,4),(control['state_owner'],3), (control['menu_status'],0x60),(status,0x60),(parent['producer']['ring'],34),
            (parent['scanner_state'],parent['scanner_state_size']), (parent['batch_state'],parent['batch_state_size']), (parent['producer']['state'],parent['producer']['state_size'])]
        owned +=[(port['shadow'],1) for port in parent['gpio_ports']]
        owned.append((facts_for(image).thumb_literal_value(control['application'] + 0x6A, 1),0x3C))
        require(all(a + 4 <= b or b + size <= a for a in (grid, alternate) for b,size in owned) and (grid + 4 <= alternate or alternate + 4 <= grid),
            'navigation-grid-owner-alias')
        division_sites = (0x2F8,0x35A,0x682,0x8BA,0x90C,0x926,0x96E,0x988)
        division = facts_for(image).thumb_call_target(handler + division_sites[0])
        require(division is not None and 0 <= division <= len(image) - len(_DISTRIBUTED_NAVIGATION_DIVISION), 'navigation-division-outside-image')
        for offset, body in _DISTRIBUTED_NAVIGATION_SPANS:
            template = bytes.fromhex(body)
            start = handler + offset
            require(0 <= start <= len(image) - len(template), 'navigation-span-outside-image')
            actual = bytearray(image[start:start + len(template)])
            cursor = 0
            while cursor < len(template):
                expected = int.from_bytes(template[cursor:cursor + 2], 'little')
                pc, relative = start + cursor, offset + cursor
                if expected & 0xF800 == 0x4800:
                    value = facts_for(image).thumb_literal_value(pc, (expected >> 8) & 7)
                    require(relative in owners and value == owners[relative], 'navigation-literal-owner-mismatch')
                    actual[cursor] = 0
                elif template[cursor:cursor + 4] == b'\0\0\0\0':
                    target = facts_for(image).thumb_call_target(pc)
                    require(target is not None and 0 <= target <= len(image) - 2, 'navigation-call-outside-image')
                    require(target == (division if relative in division_sites else handler - 0x2870), 'navigation-call-link-mismatch')
                    actual[cursor:cursor + 4] = b'\0\0\0\0'
                    cursor += 2
                elif expected & 0xF800 == 0xE000 or expected & 0xF000 == 0xD000:
                    condition = (expected >> 8) & 15 if expected & 0xF000 == 0xD000 else None
                    require(_distributed_branch(image, pc, len(image), condition) is not None, 'navigation-branch-outside-image')
                cursor += 2
            require(bytes(actual) == template, 'navigation-opcode-mismatch')
        arithmetic = bytearray(image[division:division + len(_DISTRIBUTED_NAVIGATION_DIVISION)])
        zero_error = facts_for(image).thumb_call_target(division + 0x14)
        require(zero_error is not None and 0 <= zero_error <= len(image) - 2, 'navigation-zero-error-outside-image')
        arithmetic[0x14:0x18] = b'\0\0\0\0'
        require(bytes(arithmetic) == _DISTRIBUTED_NAVIGATION_DIVISION, 'navigation-division-opcode-mismatch')
        mappings = {bit: dict(event=event, rule='same-image-distributed-functional-navigation-v1', semantic_status='temporary-evidence-gated-provisional',
            functional_only=True) for bit,event in ((1, 0x63),(9,0x64),(4,0x65),(6,0x66))}
        return mappings, dict(navigation_mapping_status='accepted-provisional', navigation_consumer=dict(grammar ='distributed-menu-grid-navigation-v1',handler=handler,status=status,
            global_word=global_word, grid_stride=3,grid_descriptor=grid,alternate_grid_descriptor=alternate, division=division,previous= handler+0x730,next=handler+0x338,
            up=handler+0x2C8,down=handler+0x8E4), navigation_mapping_limits=
            'Temporary functional menu-grid class; physical legends and other contexts unverified.')
    except (ValueError, KeyError, IndexError, TypeError) as error:
        return {}, dict(navigation_mapping_status='rejected',navigation_mapping_reject_reasons= [str(error)])

_DISTRIBUTED_BACK_SPAN = bytes.fromhex('004a0049506d884201d101209070906d002803d1ff200130004930e300490868002802dd0138086005e0ff20004e0130306032207873506d004b984206d1279b587a002802d0279b00205872906d004950654369161c13650968002905dc0022b265ff22e272a27208e0004bca00d2181268b265e27aa2720022e272004ac90089184968321c01397163007e02210138b0630120f8737973004e55213160')

def _distributed_back_profile(image: bytes, parent: dict):
    """Back rejection is independent of numeric/MENU/confirm/navigation admission."""
    from . import _DISTRIBUTED_BACK_SPAN, _distributed_branch, _distributed_ram, facts_for
    def require(condition, reason):
        if not condition:
            raise ValueError(reason)
    try:
        require(parent.get('navigation_mapping_status') == 'accepted-provisional' and parent.get('menu_mapping_status') == parent.get('ok_mapping_status') ==
            'accepted-provisional', 'back-parent-rejected')
        control, nav = parent['control_consumer'], parent['navigation_consumer']
        require(control['grammar'] == 'distributed-queued-direct-word-controls-v1' and nav['grammar'] == 'distributed-menu-grid-navigation-v1',
            'back-parent-grammar')
        handler, status, global_word = [control[k] for k in ('confirm_handler', 'confirm_status', 'global_word')]
        require(all(type(v) is int for v in (handler,status,global_word)) and (nav['handler'],nav['status'],nav['global_word']) == (handler,status,global_word),
            'back-parent-owner-mismatch')
        events = parent['event_codes']
        require(len(events) == 24 and all(type(v) is int and 0 <= v <= 255 for v in events) and events.count(0x52) == 1, 'back-event-not-unique')
        history = facts_for(image).thumb_literal_value(handler + 0x546, 1)
        comparison = facts_for(image).thumb_literal_value(handler + 0x52C, 1)
        require(all(type(v) is int and not v & 3 and _distributed_ram(v,8 if v == history else 4) for v in (history,comparison)),
            'back-history-or-comparison-invalid')
        producer = parent['producer']
        owned = [(control['secondary_ring'],72),(global_word,4),(control['state_owner'],3), (control['menu_status'],0x60),(status,0x60),(producer['ring'],34), (parent['scanner_state'],parent['scanner_state_size']),
            (parent['batch_state'],parent['batch_state_size']), (producer['state'], producer['state_size']), (nav['grid_descriptor'],4),(nav['alternate_grid_descriptor'],4),
            (facts_for (image).thumb_literal_value(control['application'] + 0x6A, 1),0x3C)]
        owned.extend((port['shadow'],1) for port in parent['gpio_ports'])
        require(history + 8 <= comparison or comparison + 4 <= history, 'back-history-comparison-alias')
        require(all(a + size <= b or b + extent <= a for a,size in ((history,8),(comparison,4)) for b,extent in owned), 'back-owned-span-alias')
        # The existing event tree must select this local restoration block.
        require(_distributed_branch(image, handler + 0x27E, len(image),0) == handler + 0x320 and _distributed_branch(image,handler + 0x320,len(image)) ==
            handler + 0x52A, 'back-event-branch-link')
        start = handler + 0x52A
        require(not handler & 1 and 0 <= start <= len(image)-len(_DISTRIBUTED_BACK_SPAN), 'back-span-outside-image')
        owners = {0x52A:status,0x52C:comparison,0x542:global_word, 0x546:history,0x556:global_word,0x562:nav['alternate_grid_descriptor'],0x578:history, 0x594:history,0x5A6:history,0x5C2:global_word}
        actual = bytearray(image[start:start+len(_DISTRIBUTED_BACK_SPAN)])
        for relative,value in owners.items():
            offset=relative-0x52A;word=int.from_bytes(_DISTRIBUTED_BACK_SPAN[offset:offset+2],'little')
            require(facts_for(image).thumb_literal_value(handler+relative, (word>>8)&7) == value, 'back-literal-owner-mismatch')
            actual[offset]=0
        require(bytes(actual) == _DISTRIBUTED_BACK_SPAN, 'back-restoration-opcode-mismatch')
        for offset in range(0,len(_DISTRIBUTED_BACK_SPAN),2):
            word=int.from_bytes(_DISTRIBUTED_BACK_SPAN[offset:offset+2],'little')
            if word & 0xF800 == 0xE000 or word & 0xF000 == 0xD000:
                condition=(word>>8)&15 if word & 0xF000 == 0xD000 else None
                require(_distributed_branch(image,start+offset,len(image),condition) is not None,'back-branch-outside-image')
        return {2:dict(event=0x52,rule='same-image-distributed-functional-back-v1', semantic_status= 'temporary-evidence-gated-provisional',functional_only=True)}, dict(back_mapping_status=
            'accepted-provisional',back_consumer=dict(grammar='distributed-saved-menu-back-v1', handler=handler, status=status,global_word=global_word,history=history,comparison_descriptor=nav['alternate_grid_descriptor'],saved_menu_comparison=comparison),
            back_mapping_limits=
            'Temporary saved-menu restoration class, observed one-level history1-to0 path only; physical legends and other contexts unverified; no indexed history capacity/runtime default.')
    except (ValueError,KeyError,IndexError,TypeError) as error:
        return {},dict(back_mapping_status='rejected',back_mapping_reject_reasons= [str(error)])

_DISTRIBUTED_CALL_SPANS = ((-72904, '08b5011c004806d100000000004800490000000008bd', ((4, 0, 'cleanup_node'), (12, 0, 'cleanup_flags'), (14, 1, 'mask_constant')),
    ((8, -723096), (16, -74426))), (-62432, '00b500480423c056002805d000000000002801d1012000e000200006000e00bd', ((2, 0, 'gate_state'),), ((12, -62464),)), (0,
    'f0b5b2b0004c0026e71d1937be73387b004d', ((4, 4, 'status'), (16, 5, 'global_word')), ()), (224, '387300207873387b332801d243009f44', (), ()), (342, '39e3', (),
    ()), (556, '00490868542836d036dc362835d013dc322832d009dc23282fd02a282dd030282bd0312864d11ae191e0332825d0342823d035285cd112e150281ed0', ((0, 1, 'global_word'),),
    ()), (678, '3be3', (), ()), (1084, '322039e3', (), ()), (1996, '77e3', (), ()), (2336, '4be0', (), ()), (2490, '00000000002804d100490868502800d137e5', ((8,
    1, 'global_word'),), ((0, -62432),)), (2740, '4be3', (), ()), (3774, '43e3', (), ()), (4430, '21e3', (), ()), (5448, '46e3', (), ()), (6036, '1ce2', (), ()),
    (7120, '7ee3', (), ()), (7128, '7ee3', (), ()), (8912, '40e3', (), ()), (8920, '40e3', (), ()), (10580, '60e2', (), ()), (10588, '46e3', (), ()), (11800,
    '47e3', (), ()), (12268, '6ee3', (), ()), (13482, '05e1', (), ()), (14008, '7873', (), ()), (14010, '76e0', (), ()), (14028, '4ae3', (), ()), (14250, '18e2',
    (), ()), (15326, 'ebe2', (), ()), (15716, '45e3', (), ()), (16824, '3ce3', (), ()), (17394, '03e3', (), ()), (18484, '1be2', (), ()), (18940, '67e3', (), ()),
    (19566, '15e1', (), ()), (20124, 'c8e2', (), ()), (20686, '6ee3', (), ()), (21552, 'd5e1', (), ()), (22446, '2ce0', (), ()), (22494, '2ee0', (), ()), (22538,
    '0026ff22e660e272a272002000000000269800490671279b01205e723873b873', ((18, 1, 'exit_status'),), ((12, -72904),)), (22570,
    '259846738e70ce701d99887b002801d01d998e73787b002801d000000000b87b32b0f0bd', (), ((26, 224),)), (22590, '787b', (), ()))
