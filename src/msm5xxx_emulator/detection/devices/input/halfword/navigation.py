from __future__ import annotations
from msm5xxx_emulator.detection.contracts import fields_match

def _mapped_functional_confirm(image: bytes, matrix: dict):
    """Optional selected activation on the already accepted mapped MENU class."""
    from . import _MAPPED_CONFIRM_RULE, _MAPPED_CONFIRM_SHAPES, _normalized_thumb_sha256, _thumb_successors, facts_for, struct
    def reject(reason):
        return {}, {'ok_mapping_status': 'rejected', 'ok_mapping_reject_reasons':['mapped-confirm-' + reason]}
    mappings = matrix.get('provisional_mappings', {})
    parent = mappings.get(0) if isinstance(mappings, dict) else None
    if (matrix.get('grammar') != 'indirect-halfword-mapped-row-v1' or type(matrix.get('rows')) is not int or type(matrix.get('columns')) is not int or ((matrix.get('rows'),
        matrix.get('columns')) != (7, 4)) or (matrix.get('menu_mapping_status') != 'accepted-provisional') or (not isinstance(parent, dict)) or (not
        fields_match(parent, (('rule', 'same-image-mapped-physical-menu-v1'), ('semantic_status', 'temporary-evidence-gated-provisional'), ('event', 91)))) or (parent.get('physical_only')
        is not True)):
        return reject('parent-menu-unclosed')
    events, tokens = matrix.get('event_codes', ()), matrix.get('token_cells', ())
    if (not isinstance(events, (list, tuple)) or len(events) != 28 or events.count(0x53) != 1 or not isinstance(tokens, list) or any(not isinstance(cell, dict)
        for cell in tokens) or any(cell.get('token') == 'O' or cell.get('event') == 0x53 for cell in tokens) or 5 in mappings):
        return reject('namespace-conflict')
    fields = [parent.get(key) for key in ('application', 'consumer', 'global_key', 'descriptor', 'secondary_ring', 'inner_state', 'outer_state')]
    producer = matrix.get('producer')
    if not isinstance(producer, dict) or producer.get('family') != 'filtered-byte-ring4-v1':
        return reject('parent-producer-unclosed')
    producer_ring = producer.get('ring')
    if any(type(value) is not int for value in fields +[producer_ring]):
        return reject('parent-fields-unclosed')
    app, menu, global_key, active, secondary, inner, outer = fields
    def call(pc):
        if type(pc) is not int:
            return None
        target = facts_for(image).thumb_call_target(pc)
        return target if target is not None and not target & 1 and 0 <= target <= len(image)-2 else None
    def branch(pc):
        if type(pc) is not int or not 0 <= pc <= len(image)-2:
            return None
        if struct.unpack_from('<H', image, pc)[0] & 0xF800 != 0xE000:
            return None
        targets = _thumb_successors(image, pc, len(image))
        target = targets[0] if len(targets) == 1 else None
        return target if target is not None and not target & 1 and 0 <= target <= len(image)-2 else None
    def shape(name, pc):
        size, digest, edges = _MAPPED_CONFIRM_SHAPES[name]
        if type(pc) is not int or pc & 1 or not 0 <= pc <= len(image)-size:
            return False
        normalized = _normalized_thumb_sha256(image, pc, size)
        if name == 'dispatch':
            # Only this decoded, parent-global-linked data slot is relocatable.
            if facts_for(image).thumb_literal_value(pc, 1) != global_key:
                return False
            word = struct.unpack_from('<H', image, pc)[0]
            pool = ((pc+4) & ~3) + 4*(word & 0xFF)
            if pool != pc+0x48:
                return False
            code = bytearray(image[pc:pc+size])
            code[pool-pc:pool-pc+4] = b'\0'*4
            normalized = _normalized_thumb_sha256(bytes(code), 0, size)
        return (normalized == (digest, tuple(d for d, _ in edges)) and all(call(pc+d) == pc+relative for d, relative in edges))
    def literal(pc, register):
        return facts_for(image).thumb_literal_value(pc, register)
    consumer, install = call(app+0x206E), call(menu+0x1EA0)
    if not shape('consumer', consumer) or not shape('install', install):
        return reject('consumer-or-install-shape')
    if (not shape('dispatch', consumer+0x394) or literal(consumer+0x394, 1) != global_key):
        return reject('consumer-global-dispatch')
    activation = branch(consumer+0x474)
    if activation != consumer+0x6BC or not shape('activation', activation):
        return reject('selected-arm-shape')
    event = image[consumer+0x470]
    selected = literal(activation, 0)
    if (event != 0x53 or literal(activation+2, 6) != global_key or literal(activation+0xE, 0) != selected or literal(activation+0x10, 3) != active or literal(install+2,
        7) != selected or literal(install+4, 0) != active):
        return reject('selected-install-global-identity')
    helper = call(activation+0xA)
    if not shape('helper', helper) or literal(helper+2, 4) != global_key:
        return reject('selected-helper-global')
    builder = call(helper+0x26)
    if not shape('builder', builder):
        return reject('type8-builder-shape')
    allocator, publisher = call(builder+8), call(builder+0x1A)
    if not shape('allocator', allocator) or not shape('publisher', publisher):
        return reject('type8-helper-edges')
    allocation_owner = literal(allocator+2, 0)
    publication_owner, signal_owner = literal(publisher+0xC, 0), literal(publisher+0x14, 0)
    # Keep failure-path arguments and primitive call relations exact, without ABI claims.
    error_text = literal(allocator+0xC, 1)
    if (type(error_text) is not int or error_text != allocator+0x2EEF72 or not 0 <= error_text <= len(image)-2 or literal(allocator+0xE, 0) != 0x405 or type(publication_owner)
        is not int or allocation_owner != publication_owner+0xC or literal(helper+0x30, 1) != 0x6390):
        return reject('type8-literal-contract')
    global104 = call(activation+0x24)
    if not shape('global104', global104):
        return reject('selected-global104-shape')
    join = branch(global104+2)
    if not shape('join', join):
        return reject('selected-join-shape')
    mode_entry = call(join)
    mode_bridge = branch(mode_entry+2) if mode_entry is not None else None
    if (not shape('mode_bridge', mode_bridge) or mode_entry != mode_bridge+0xA or call(activation+0x3C) != mode_entry or literal(mode_bridge+4, 1) != global_key):
        return reject('selected-mode-bridge')
    commit = call(mode_bridge)
    if (not shape('mode_commit', commit) or literal(commit, 1) != selected or branch(commit+4) != mode_bridge+ 0x66):
        return reject('selected-mode-commit')
    spans = [(producer_ring, 6), (secondary, 72), (global_key, 4), (inner-3, 4), (active, 8), (selected, 0x30), (outer-0xF, 0x10), (allocation_owner, 4), (publication_owner,
        4), (signal_owner, 4), (literal(helper+ 0x2A, 1), 8), (literal(helper+0x10, 0), 1), (literal(helper+0x18, 0), 1), (global_key+0x160, 4), (global_key+0x6390,
        4)]
    if (any(type(address) is not int or not 0x1000000 <= address <= 0x2000000-size for address, size in spans) or any(address & 3 for address, _ in spans[:11])):
        return reject('ram-bounds-or-alignment')
    if any(address < other+length and other < address+size for index, (address, size) in enumerate(spans) for other, length in spans[index+1:]):
        return reject('ram-alias')
    cell = events.index(event)
    return {5: {'event': event, 'rule': _MAPPED_CONFIRM_RULE, 'semantic_status': 'temporary-evidence-gated-provisional', 'functional_only': True,
        'physical_keycap_proven': False, 'context': 'MENU-selected-activation', 'evidence':
        'parent-menu+same-global+selected-install+exact-helper-edges+original-mode-commit', 'consumer': consumer, 'selection': selected, 'descriptor': active,
        'global_key': global_key, 'row': cell%7, 'column': cell// 7}}, { 'ok_mapping_status': 'accepted-provisional', 'ok_mapping_reject_reasons':[]}

def resolve_indirect_matrix_input(image: bytes, load_address: int=0):
    """Return only a unique linked scanner with unambiguous semantic cells."""
    from . import _loop_functional_confirm, _mapped_functional_confirm, _mapped_physical_menu, find_indirect_matrix_scanners, find_loop_row_scanners, find_mapped_row_scanners
    if load_address != 0:
        return (None, 'unsupported-load-address',[])
    from msm5xxx_emulator.detection.devices.input.seven_row import find_seven_row_scanners
    candidates = (find_indirect_matrix_scanners(image) + find_mapped_row_scanners(image) + find_loop_row_scanners(image) + find_seven_row_scanners(image))
    if not candidates:
        return (None, 'not-found',[])
    if len(candidates) != 1:
        return (None, 'ambiguous-scanners', candidates)
    candidate = candidates[0]
    if not candidate['token_cells']:
        return (None, 'no-exact-semantic-cells', candidates)
    if candidate['grammar'] == 'indirect-halfword-mapped-row-v1':
        mappings, metadata = _mapped_physical_menu(image, candidate)
        candidate.update(metadata)
        if mappings:
            candidate['provisional_mappings'] = mappings
            mapping = mappings[0]
            candidate['token_cells'].append({'token':'M','event':mapping['event'], 'row':mapping['row'],'column':mapping['column']})
            confirm, metadata = _mapped_functional_confirm(image, candidate)
            candidate.update(metadata)
            if confirm:
                candidate['provisional_mappings'].update(confirm)
                mapping = confirm[5]
                candidate['token_cells'].append({'token':'O','event':mapping['event'], 'row':mapping['row'], 'column':mapping['column']})
    if candidate['grammar'] == 'indirect-halfword-loop-six-row-v1':
        mappings, metadata = _loop_functional_confirm(image, candidate)
        candidate.update(metadata)
        if mappings:
            candidate['provisional_mappings'] = mappings
            events = candidate['event_codes']
            cell = events.index(mappings[5]['event'])
            candidate['token_cells'].append({'token':'O','event':events[cell], 'row':cell%6,'column':cell//6})
    return (candidate, 'static-candidate',[])
