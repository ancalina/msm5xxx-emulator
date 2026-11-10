from __future__ import annotations

_TRAFFIC_CALLBACK_SHAPE = (bytes.fromhex("f0b586b0004800888406a40e032c004d1bd12878002818d00048004940780000000000000000004a0028908104d1022701200000000003e000200000000000270021381c00000000d3e200490878002822dd01380870087800281dd1004f381c000000001022381c391c0000000000480021027802a800000000381c391c02aa000000000422381c391c000000000121381c0000000003e00048012100000000004800000000071c04d1004900480000000096e2"),
    (30, 34, 50, 58, 68, 96, 106, 118, 128, 138, 146, 156, 162, 174), (4, 14, 24, 26, 38, 74, 92, 110, 152, 160, 170, 172))
_TRAFFIC_DATA_CALL_SHAPE = (bytes.fromhex("f888002806d0004800224178f81d013000000000"), (16,), (6,))
_TRAFFIC_EMIT_SHAPE = (bytes.fromhex("0420b8800598004900000000391c0048000000000048082100000000"), (8, 16, 24), (6, 14, 20))
_TRAFFIC_QUALITY_SHAPE = (bytes.fromhex("00b500484178062917d202a35b5c5b009f44001c13030c0f0f0f4088032802d10000000000bd0000000000bd"), (32, 38), (2,))
_TRAFFIC_ORDINARY_SHAPE = (bytes.fromhex("b0b500480078c1070048c90f427807794079d407e40f002909d0002c03d00f3087421fdc01e04d2f37dc0420b0bd004a02239178d57819401d40d3799279002c12d03c2810dc002901d1002d0ad0002d04d0d91d033188421ddc03e0d11d0331884212dc0320b0bd00290ad0002d08d0934201da402b0edd9a420eda3c2a0cdc03e0002903d03c2a01dc0220b0bd002d03d0402b01dc0120b0bd0020b0bd"),
    (), (2, 8, 46))
_TRAFFIC_VARIANT_SHAPE = (bytes.fromhex("f0b5004d0223a8789843a870c820a8712878c6070048f60f417807794279cc07c178e40fc0791940002e14d0002c09d0d31d08339f420cdd00291ad00c30904228db16e04d2f27dc002902d01730b84220db0420f0bd002c0dd03c2a0bdcaf78bb0801d2002904d0002902d00a30824210dc0320f0bdaa7802231a4006d0002904d0c82808da402806dc03e0002903d0402801dc0120f0bd0020f0bd"),
    (), (2, 20))
_TRAFFIC_COEFFICIENTS_SHAPE = (bytes.fromhex("0022052801dd101cf74600490a83004a80018218d01f393803888b8343888b8383888b83c3888b8303898b8343898b8383898b83c3898b83038a8b83438a8b83838a8b83c38a8b83038b8b83438b8b83838b8b83c08b8883d01f193802888a8342888a8382888a83c2888a8302898a8342898a8382898a83c2898a83028a8a83428a8a83828a8a83c28a8a83028b8a83428b8a83828b8a83c08b88830120f746"),
    (), (10, 14))
_TRAFFIC_SELECTORS_SHAPE = (bytes.fromhex("80b5004a0023138041277f029780004fc000c0191038077a7f089780004f9780477a7f089780004f9780877a7f089780002901d0004900e000499180c07a400890809380938020201080938093804020108093809380602010809380938080bd"),
    (), (2, 14, 28, 38, 52, 56))

def find_traffic_decoder_profile(image: bytes, tick_position: int) -> dict[str, object]:
    """Bind mode1 erasure output only; no timing, qualification or RF is inferred."""
    from . import _TRAFFIC_CALLBACK_SHAPE, _TRAFFIC_COEFFICIENTS_SHAPE, _TRAFFIC_DATA_CALL_SHAPE, _TRAFFIC_EMIT_SHAPE, _TRAFFIC_INIT_SHAPE, _TRAFFIC_METRICS_SHAPE, _TRAFFIC_ORDINARY_SHAPE, _TRAFFIC_QUALITY_SHAPE, _TRAFFIC_READER_SHAPE, _TRAFFIC_REGISTRATION_SHAPE, _TRAFFIC_SELECTORS_SHAPE, _TRAFFIC_VARIANT_SHAPE, _literal, _tx_init_code_matches, _u16, facts_for, find_decoder_init_profile, re
    from msm5xxx_emulator.detection.layout_queries import find_linker_layout
    result = {"signature": "thumb-traffic-mode1-erasure-row5-v1", "accepted": False, "active": False, "semantic_limit":
        "static mode1 erasure-only output and matched callback intervals; auxiliary status ports, other modes, cadence, qualified frames, RF and calls unproven"
        }
    def reject(reason):
        return {**result, "reject_reason": reason}
    def matches(at, shape):
        return at is not None and _tx_init_code_matches(image, at, shape)
    readers = []
    for match in re.finditer(re.escape(bytes.fromhex("f0b5041c171c")), image):
        at = match.start()
        if matches(at, _TRAFFIC_READER_SHAPE):
            readers.append(at)
    if len(readers) != 1:
        return reject(f"traffic-reader-cardinality:{len(readers)}")
    reader = readers[0]
    decoder = find_decoder_init_profile(image, tick_position)
    if not decoder["accepted"]:
        return reject("traffic-shared-decoder-unclosed")
    helper = decoder["copy_helper"]
    if (any(facts_for(image).thumb_call_target(reader + off) != helper for off in (0x2c, 0x4c, 0x6c, 0x8c)) or _literal(image, reader + 0x12, 6, 0) !=
        0x03000a40 or any(_literal(image, reader + off, 0, 0) != 0x03000a70 for off in (0x2a, 0x4a, 0x6a, 0x8a))):
        return reject("traffic-reader-port-copy-unclosed")
    layout_pointer = _literal(image, reader + 6, 0, 0)
    if layout_pointer is None or layout_pointer & 3 or not 0x01000008 <= layout_pointer <= 0x01ffffd8:
        return reject("traffic-layout-address-invalid")
    layout_address = layout_pointer - 8
    registrar = facts_for(image).thumb_call_target(decoder["registration"])
    registrations = []
    for match in re.finditer(rb"[\x00-\xff][\xf0-\xf7][\x00-\xff][\xf8-\xff]", image):
        pc = match.start()
        if (not pc & 1 and facts_for(image).thumb_call_target(pc) == registrar and matches(pc - 20, _TRAFFIC_REGISTRATION_SHAPE)):
            registrations.append(pc)
    if len(registrations) != 1:
        return reject(f"traffic-registration-cardinality:{len(registrations)}")
    registration = registrations[0]
    mode_base = _literal(image, registration - 20, 0, 0)
    callback = _literal(image, registration - 4, 1, 0)
    initializer = facts_for(image).thumb_call_target(registration - 16)
    if (callback is None or not callback & 1 or mode_base is None or mode_base & 3 or not 0x01000000 <= mode_base <= 0x01ffffec):
        return reject("traffic-mode-callback-address-invalid")
    isr = callback - 1
    data_call, emission = isr + 0x17c, isr + 0x5c6
    if (not matches(isr, _TRAFFIC_CALLBACK_SHAPE) or not matches(data_call, _TRAFFIC_DATA_CALL_SHAPE) or not matches(emission, _TRAFFIC_EMIT_SHAPE) or facts_for(image).thumb_call_target(data_call
        + 16) != reader or _literal(image, data_call + 6, 0, 0) != mode_base or _literal(image, isr + 4, 0, 0) != 0x03000a60 or _literal(image, isr + 0x18, 0, 0)
        != mode_base or _literal(image, isr + 0xe, 5, 0) != mode_base + 0x10):
        return reject("traffic-callback-reader-shape-unclosed")
    metrics = facts_for(image).thumb_call_target(isr + 0x1e)
    quality = facts_for(image).thumb_call_target(isr + 0x22)
    if (not matches(metrics, _TRAFFIC_METRICS_SHAPE) or _literal(image, metrics + 2, 2, 0) != layout_pointer or _literal(image, metrics + 0xe, 3, 0) !=
        0x03000a40 or _literal(image, metrics + 0x16, 0, 0) != 0x03000a60 or not matches(quality, _TRAFFIC_QUALITY_SHAPE) or _literal(image, quality + 2, 0, 0)
        != mode_base):
        return reject("traffic-metrics-quality-dispatch-unclosed")
    variant = facts_for(image).thumb_call_target(quality + 0x20)
    ordinary = facts_for(image).thumb_call_target(quality + 0x26)
    metric_record = _literal(image, isr + 0x1a, 1, 0)
    if (not matches(ordinary, _TRAFFIC_ORDINARY_SHAPE) or not matches(variant, _TRAFFIC_VARIANT_SHAPE) or metric_record is None or any(_literal(image, ordinary
        + off, reg, 0) != metric_record for off, reg in ((2, 0), (8, 0), (0x2e, 2))) or any(_literal(image, variant + off, reg, 0) != metric_record for off, reg
        in ((2, 5), (0x14, 0)))):
        return reject("traffic-mode1-quality-leaves-unclosed")
    if not matches(initializer, _TRAFFIC_INIT_SHAPE):
        return reject("traffic-initializer-shape-unclosed")
    clock = facts_for(image).thumb_call_target(initializer + 4)
    clock_shape = (bytes.fromhex("00490320087000490020087000490870f746"), (), (0, 6, 12))
    lock = facts_for(image).thumb_call_target(initializer + 8)
    unlock = facts_for(image).thumb_call_target(initializer + 0x24)
    coefficients = facts_for(image).thumb_call_target(initializer + 0x86)
    selectors = facts_for(image).thumb_call_target(initializer + 0x8e)
    shadow = _literal(image, initializer + 0xc, 4, 0)
    if (not matches(clock, clock_shape) or any(_literal(image, clock + off, 1, 0) != value for off, value in ((0, 0x03000300), (6, 0x030002e0), (12, 0x03000900)))
        or lock == unlock or any(facts_for(image).thumb_call_target(initializer + off) != lock for off in (0x28, 0x48, 0x62)) or any(facts_for(image).thumb_call_target(initializer
        + off) != unlock for off in (0x3c, 0x76)) or shadow is None or _literal(image, initializer + 0x42, 4, 0) != shadow + 0x20 or any(_literal(image,
        initializer + off, reg, 0) != value for off, reg, value in ((0xe, 3, 0xffdf), (0x12, 5, 0x03000a00), (0x2e, 3, 0xfff8), (0x40, 5, 0x03000a60), (0x4e, 3,
        0xfffd), (0x68, 3, 0xfffd))) or not matches(coefficients, _TRAFFIC_COEFFICIENTS_SHAPE) or _literal(image, coefficients + 0xa, 1, 0) != 0x03000a20 or
        _literal(image, coefficients + 0xe, 2, 0) != layout_address + 0x60 or not matches(selectors, _TRAFFIC_SELECTORS_SHAPE) or any(_literal(image, selectors
        + off, reg, 0) != value for off, reg, value in ((2, 2, 0x03000a40), (0xe, 7, layout_pointer), (0x1c, 7, 0x8210), (0x26, 7, 0x8220), (0x34, 1, 0x9230), (0x38,
        1, 0x8230)))):
        return reject("traffic-initializer-ports-aliases-unclosed")
    decoder_isr = decoder["isr"]
    queue_get = facts_for(image).thumb_call_target(initializer + 0x7c)
    queue_put = facts_for(image).thumb_call_target(initializer + 0xa0)
    free_queue = _literal(image, isr + 0xa0, 0, 0)
    if (free_queue is None or queue_get != facts_for(image).thumb_call_target(decoder_isr + 0xc) or queue_put != facts_for(image).thumb_call_target(decoder_isr
        + 0x62) or image[decoder_isr + 0x66:decoder_isr + 0x6a] != bytes.fromhex("0821281c") or facts_for(image).thumb_call_target(emission + 24) != facts_for(image).thumb_call_target(decoder_isr
        + 0x6a) or _literal(image, emission + 20, 0, 0) != _literal(image, decoder_isr + 0x10, 5, 0) or free_queue != _literal(image, decoder_isr + 0x3e, 0, 0)
        or facts_for(image).thumb_call_target(isr + 0xa2) != queue_get or facts_for(image).thumb_call_target(emission + 16) != queue_put or _literal(image,
        emission + 6, 1, 0) != _literal(image, isr + 0x5c, 7, 0) or _literal(image, emission + 0xe, 0, 0) != free_queue - 12):
        return reject("traffic-frame-queue-aliases-unclosed")
    layout = find_linker_layout(image, required_span=(layout_address, 48))
    if layout is None:
        return reject("traffic-layout-linker-unclosed")
    layout_source = layout.data_source + layout_address - layout.data_target
    rows = image[layout_source:layout_source + 48]
    if len(rows) != 48 or rows[:8] != bytes(8):
        return reject("traffic-layout-rows-invalid")
    maxima = [0, 0, 0, 0]
    for row in range(1, 6):
        descriptor = rows[row * 8:(row + 1) * 8]
        end = 0
        for rate, capacity in enumerate((36, 18, 10, 6)):
            start, count = descriptor[rate], descriptor[rate + 4]
            if start != end or start & 1 or count & 1 or not 0 < count <= capacity:
                return reject("traffic-layout-descriptor-invalid")
            end = start + count + 4
            maxima[rate] = max(maxima[rate], count)
        if end > 86:
            return reject("traffic-layout-descriptor-overflow")
    if maxima !=[36, 18, 10, 6]:
        return reject("traffic-layout-capacity-class-unclosed")
    shapes = ((reader, _TRAFFIC_READER_SHAPE), (metrics, _TRAFFIC_METRICS_SHAPE), (initializer, _TRAFFIC_INIT_SHAPE), (clock, clock_shape), (registration - 20,
        _TRAFFIC_REGISTRATION_SHAPE), (isr, _TRAFFIC_CALLBACK_SHAPE), (data_call, _TRAFFIC_DATA_CALL_SHAPE), (emission, _TRAFFIC_EMIT_SHAPE), (quality,
        _TRAFFIC_QUALITY_SHAPE), (ordinary, _TRAFFIC_ORDINARY_SHAPE), (variant, _TRAFFIC_VARIANT_SHAPE), (coefficients, _TRAFFIC_COEFFICIENTS_SHAPE), (selectors,
        _TRAFFIC_SELECTORS_SHAPE))
    code_dependencies = [(layout.table_offset, 20), (layout_source, 48), (decoder["descriptor_template"], 28), (decoder_isr, 0x74), (helper, 22)]
    ram_dependencies = [(mode_base, 0x14), (layout_address, 48), (metric_record, 16), (shadow, 0x32), (decoder["irq_callback_slot"], 4), (free_queue - 12, 24),
        (_literal(image, isr + 0x26, 2, 0), 0x12)]
    for at, shape in shapes:
        code_dependencies.append((at, len(shape[0])))
        code_dependencies.extend((facts_for(image).thumb_call_target(at + off), 2) for off in shape[1])
        for off in shape[2]:
            pc = at + off
            pool = ((pc + 4) & ~3) + (_u16(image, pc) & 255) * 4
            code_dependencies.append((pool, 4))
            value = _literal(image, pc, _u16(image, pc) >> 8 & 7, 0)
            if value is not None and 0x01000000 <= value < 0x02000000:
                ram_dependencies.append((value, 4))
    if any(at is None or at < 0 or size <= 0 or at + size > len(image) for at, size in code_dependencies):
        return reject("traffic-code-dependency-outside-image")
    if any(at is None or at < 0x01000000 or at + size > 0x02000000 for at, size in ram_dependencies):
        return reject("traffic-RAM-dependency-outside-class")
    return {**result, "accepted": True, "reject_reason": None, "isr": isr, "reader": reader, "status_reader": metrics, "initializer": initializer, "mode_base":
        mode_base, "layout_address": layout_address, "layout_source": layout_source, "linker_table_offset": layout.table_offset, "copy_helper": helper,
        "registration": registration, "quality_dispatcher": quality, "quality_ordinary": ordinary, "quality_variant3": variant, **{key: decoder[key] for key in
        ("descriptor_template", "irq_callback_slot", "irq_status", "irq_enable", "irq_mask")}, "code_dependencies": sorted(set(code_dependencies)),
        "ram_dependencies": sorted(set(ram_dependencies))}

def find_legacy_cdma_profile(image: bytes) -> dict[str, object]:
    """Bind a C80, six-word searcher and dec5000 decoded FIFO to one image."""
    from . import _literal, _load_store, _mov_imm, _u16, facts_for, struct
    def occurrences(value: bytes):
        at = 0
        while (at := image.find(value, at)) >= 0:
            if not at & 1:
                yield at
            at += 1
    def literal_users(value: int, register: int):
        found = set()
        for pool in occurrences(struct.pack('<I', value)):
            for pc in range(max(0, pool - 1024) & ~1, pool, 2):
                if _literal(image, pc, register, 0) == value:
                    found.add(pc)
        return found
    def one(values, reason):
        values = set(values)
        if len(values) != 1:
            raise ValueError(f'{reason}-cardinality:{len(values)}')
        return next(iter(values))
    try:
        users = literal_users(0x030002a0, 1)
        writers = []
        consumers = []
        for pc in users:
            if _u16(image, pc + 2) != 0x3920:  # SUBS r1, #32
                continue
            stores = [at for at in range(pc + 4, min(pc + 48, len(image) - 1), 2) if (op := _load_store(_u16(image, at))) is not None and op[0] == 'strh' and op[2:]
                == (1, 20)]
            if len(stores) == 6:
                tables = (_literal(image, pc - 18, 1, 0), _literal(image, pc - 12, 1, 0))
                if all(t is not None and 0 <= t <= len(image) - 1024 for t in tables):
                    values = [struct.unpack_from('<512H', image, t) for t in tables]
                    if (all(0 < v < 0x8000 for table in values for v in table) and len(set(zip(*values))) == 512):
                        writers.append((pc, *tables))
            at = pc + 4
            if (_load_store(_u16(image, at)) == ('ldrh', 5, 1, 28)
                    and _load_store(_u16(image, at + 2)) == ('ldrh', 3, 1, 28)
                    and _load_store(_u16(image, at + 14)) == ('strh', 5, 1, 56)
                    and _load_store(_u16(image, at + 16)) == ('strh', 3, 1, 48)
                    and _u16(image, at + 18) == 0x2a04):  # CMP r2, #4
                consumers.append(pc)
        writer, masks_i, masks_q = one(writers, 'legacy-search-writer')
        consumer = one(consumers, 'legacy-search-consumer')
        descriptors = []
        for at in occurrences(struct.pack('<III', 0x03000c80, 0x03000c94, 0x80)):
            if at >= 6 * 28 and at + 24 * 28 <= len(image):
                def row(index):
                    return struct.unpack_from('<III', image, at + (index - 7) * 28)
                if (row(1) == (0x03000c80, 0x03000c94, 0x100) and row(6) == (0x03000c80, 0x03000c94, 0x10) and row(30) == (0x03000c80, 0x03000c94, 0x200)):
                    descriptors.append(at)
        descriptor = one(descriptors, 'legacy-c80-descriptor')
        readers = []
        for pc in literal_users(0x03000d40, 2):
            if (_mov_imm(_u16(image, pc + 4)) != (1, 0) or _load_store(_u16(image, pc + 6)) != ('strh', 1, 2, 24) or _mov_imm(_u16(image, pc + 12)) != (2, 6) or
                _u16(image, pc + 14) != 0x3830):
                continue
            target = facts_for(image).thumb_call_target(pc + 16)
            if (target is not None and _load_store(_u16(image, target + 6)) == ('ldrh', 4, 0, 0) and _u16(image, target + 14) == (0x5200 | 7 << 6 | 1 << 3 | 4)):
                readers.append((pc, target))
        decoder, fifo_copy = one(readers, 'legacy-decoder-reader')
        modes = {}
        for pc, base in ((pc, base) for base in (4, 5) for pc in literal_users(0x03000d00, base)):
            mode = _mov_imm(_u16(image, pc + 4))
            if (mode is not None and mode[0] == 2 and mode[1] in (0x20, 0x40) and _load_store(_u16(image, pc + 12)) == ('strh', 1, base, 8)):
                modes.setdefault(mode[1],[]).append(pc)
        sync_mode = one(modes.get(0x40,[]), 'legacy-sync-mode')
        paging_mode = one((pc for pc in modes.get(0x20,[]) if sync_mode < pc < sync_mode + 0xd0), 'legacy-paging-mode')
        if not all(struct.pack('<I', value) in image for value in (0x6030b9c7, 0x0b105aa5)):
            raise ValueError('legacy-decoder-crc-missing')
        fixed24 = list(occurrences(struct.pack('<HHH', 0x2701, 0x05ff, 0x0b3e)))
        serial22 = set()
        for pc in occurrences(struct.pack('<H', 0x2116)):
            target = facts_for(image).thumb_call_target(pc + 2)
            if target is not None and any(_u16(image, q) == 0x2116 and facts_for(image).thumb_call_target(q + 2) == target for q in range(pc + 4, min(pc + 64,
                len(image) - 4), 2)):
                serial22.add(target)
        if len(fixed24) == 1 and not serial22:
            pll_bits, pll = 24, fixed24[0]
        elif not fixed24 and len(serial22) == 1:
            pll_bits, pll = 22, next(iter(serial22))
            if (_u16(image, pll), _u16(image, pll + 2), _u16(image, pll + 4)) != (0xb5ff, 0x1c07, 0x2001):
                raise ValueError('legacy-pll-serializer-mismatch')
        else:
            raise ValueError('legacy-pll-signature-ambiguous')
        return {'signature': 'legacy-c80-search2-dec5000-v1', 'accepted': True, 'writer': writer, 'consumer': consumer, 'mask_i': masks_i, 'mask_q': masks_q,
            'descriptor': descriptor, 'decoder': decoder, 'fifo_copy': fifo_copy, 'sync_mode': sync_mode, 'paging_mode': paging_mode, 'pll_bits': pll_bits,
            'pll': pll}
    except ValueError as exc:
        return {'signature': 'legacy-c80-search2-dec5000-v1', 'accepted': False, 'reject_reason': str(exc)}
