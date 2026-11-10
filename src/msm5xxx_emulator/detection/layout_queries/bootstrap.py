from __future__ import annotations

def _referenced_flash_extent(image: bytes, load_address: int, facts) -> int:
    from . import PAGE, find_all, struct, thumb_literal_value
    extent = 0
    for offset, source_address, target, size in facts.rows(3, 0x20000):
        if not (0x03800000 <= target < 0x03A00000 and target % PAGE == 0 and 0x100 <= size <= 0x200000):
            continue
        source = source_address - load_address
        if (0x1000 <= source < 0x02000000 and source > offset + 0x20 and source + size <= 0x02000000):
            extent = max(extent, source + size)
    sentinel_extents: set[int] = set()
    for middle in find_all(image, bytes.fromhex("00689842")):
        position = middle - 4
        if position < 0 or position & 1 or position + 10 > len(image):
            continue
        first, second, _load, _compare, branch = struct.unpack_from("<5H", image, position)
        if (first & 0xFF00 != 0x4800 or second & 0xFF00 != 0x4B00 or branch & 0xFF00 != 0xD000):
            continue
        displacement = (branch & 0xFF) << 1
        if displacement & 0x100:
            displacement -= 0x200
        success = position + 12 + displacement
        if not 0 <= success <= len(image) - 2:
            continue
        address = thumb_literal_value(image, position, 0)
        expected = thumb_literal_value(image, position + 2, 3)
        if address is None or expected in (None, 0, 0xFFFFFFFF, address):
            continue
        source = address - load_address
        if (0x00800000 <= source < 0x01000000 and source % PAGE == 0 and source >= len(image)):
            sentinel_extents.add(source + 4)
    if len(sentinel_extents) == 1:
        extent = max(extent, next(iter(sentinel_extents)))
    return extent

def find_overlays(image: bytes, load_address: int = 0) -> list[CopyLayout]:
    """Find boot tables that relocate MSM internal-RAM executable overlays."""
    from . import CopyLayout, PAGE, _image_offset, layout_facts_for
    facts = layout_facts_for(image)
    seen: set[tuple[int, int]] = set()
    def accept(row: tuple[int, ...]) -> bool:
        offset, source_address, target, size = row
        source = _image_offset(source_address, len(image), load_address)
        internal_ram = 0x03800000 <= target < 0x03A00000 and target % PAGE == 0
        runtime_rom = (0x01400000 <= target < 0x01800000 and target % PAGE == 0 and source is not None and 0 < source - offset <= 0x40)
        key = (target, size)
        if (source is not None and 0x100 <= size <= 0x200000 and source + size <= len(image) and (internal_ram or runtime_rom) and key not in seen):
            seen.add(key)
            return True
        return False
    rows = facts.select_rows("overlays", 3, 0x20000, (load_address,), accept)
    return [CopyLayout(row[0], _image_offset(row[1], len(image), load_address), row[2], row[3]) for row in rows]

def find_missing_overlays(image: bytes, flash_size: int, load_address: int = 0) -> list[CopyLayout]:
    """Find boot copy entries whose executable ROM source was not dumped."""
    from . import CopyLayout, PAGE, layout_facts_for
    facts = layout_facts_for(image)
    seen: set[tuple[int, int, int, int]] = set()
    def accept(row: tuple[int, ...]) -> bool:
        offset, source_address, target, size = row
        source = source_address - load_address
        candidate = (offset, source, target, size)
        if (0x1000 <= source < flash_size and source > offset + 0x20 and 0x03800000 <= target < 0x03A00000 and target % PAGE == 0 and 0x100 <= size <= 0x200000
            and source + size <= flash_size and source + size > len(image) and candidate not in seen):
            seen.add(candidate)
            return True
        return False
    rows = facts.select_rows("missing-overlays", 3, 0x20000, (flash_size, load_address), accept)
    return [CopyLayout(offset, source_address - load_address, target, size) for offset, source_address, target, size in rows]

def find_runtime_overlays(image: bytes, ram_base: int, ram_size: int) -> list[CopyLayout]:
    """Find structural SDRAM-to-internal-RAM overlay copy candidates.

    A tuple alone does not prove a NAND/partition loader: bootstrap code can
    also initialize its SDRAM source from supplied NOR or scratch memory.
    """
    from . import CopyLayout, layout_facts_for
    facts = layout_facts_for(image)
    seen: set[tuple[int, int, int, int]] = set()
    ram_end = ram_base + ram_size
    def accept(row: tuple[int, ...]) -> bool:
        offset, source, target, size = row
        candidate = (offset, source, target, size)
        if (ram_base <= source < source + size <= ram_end and 0x03800000 <= target < target + size <= 0x03A00000 and source & 1 == 0 and target & 1 == 0 and
            0x100 <= size <= 0x200000 and candidate not in seen):
            seen.add(candidate)
            return True
        return False
    rows = facts.select_rows("runtime-overlays", 3, 0x40000, (ram_base, ram_size), accept)
    return [CopyLayout(*row) for row in rows]

def find_arm_memory_copy_addresses(image: bytes, overlays: list[CopyLayout], linker: LinkerLayout | None = None, load_address: int = 0) -> list[int]:
    """Locate the validated ARM copier in ROM and every proven runtime copy.

    The instruction hook performs its own full prefix/tail, CPU-state, source,
    destination, and overlap validation.  Discovery can therefore include all
    aligned exact bodies in primary NOR instead of assuming the copier always
    lives in an internal-RAM overlay; several MSM5000/5100 BSPs call it from
    ROM or from the linker-relocated data bank.
    """
    from . import ARM_MEMORY_COPY_SIGNATURE, ARM_MEMORY_COPY_TAIL, ARM_MEMORY_COPY_TAIL_OFFSET, find_all
    found: set[int] = set()
    for position in find_all(image, ARM_MEMORY_COPY_SIGNATURE):
        if (position & 3 or image[position + ARM_MEMORY_COPY_TAIL_OFFSET: position + ARM_MEMORY_COPY_TAIL_OFFSET + len(ARM_MEMORY_COPY_TAIL)] !=
            ARM_MEMORY_COPY_TAIL):
            continue
        found.add(load_address + position)
        if (linker is not None and linker.data_source <= position < linker.data_source + linker.data_size):
            found.add(linker.data_target + position - linker.data_source)
        for overlay in overlays:
            if overlay.source <= position < overlay.source + overlay.size:
                found.add(overlay.target + position - overlay.source)
    return sorted(found)

_DUAL_STAGE_RESET = bytes.fromhex("24429fe5010014e320e29f1520e29f0514ff2fe17847000018429fe5010014e314e29f1514e29f0514ff2fe1784700000c429fe5010014e308e29f1508e29f0514ff2fe178470000d7f021e3a4d19fe5dbf021e3f4d19fe5d3f021e3f0d19fe5f0419fe5010014e3ece19f15ece19f0514ff2fe178470000e4419fe5010014e3e0e19f15e0e19f0514ff2fe178470000d8419fe5010014e3d4e19f15d4e19f0514ff2fe178470000000050e30300001ac63f00ea")
_DUAL_STAGE_PRIVATE = bytes.fromhex("80b400201f4a0121002711701770013000041d4b000c9842f7db1c4bd88bd88bd88bd88b1a48d8831a48d8831a48d88300201170177001300004134b000c9842f7db117017701548154c036824681e19144b1d68046801e001cd01c4b442fbd3117017701048114c036824681e191c1c00e080c4b442fcd3117017701170177080bc7047")
_DUAL_STAGE_NORMAL = bytes.fromhex("d2f021e388d09fe5dff021e384d09fe5d1f021e30dd02de07cd09fe5d3f021e378009fe5010010e374e09f1574e09f0510ff2fe1784700006c209fe512ff2fe1")
_DUAL_STAGE_SCATTER = bytes.fromhex("884900b50120087000200870874a864b1568874a1f6814687f09012211e008cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c40a700870013febd2784b1f68bb085f077f0f03e008cd08c40a700870013ff9d20a700870744b1f68744b7f091c6809e001c401c401c401c401c401c401c401c40a700870013ff3d26b4b1f68bb085f077f0f02e001c40a700870013ffad20a700870664b1f68664b7f091d68664b1c6811e008cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c40a700870013febd2584b1f68bb085f077f0f03e008cd08c40a700870013ff9d20a700870544b1f68544b7f091c6809e001c401c401c401c401c401c401c401c40a700870013ff3d24b4b1f68bb085f077f0f03e0002001c40a700870013ff9d24848474b056848481f6804687f09002011e008cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c40a700870013febd2394b1f68bb085f077f0f03e008cd08c40a700870013ff9d20a700870354b1f68354b7f091c6809e001c401c401c401c401c401c401c401c40a700870013ff3d22c4b1f68bb085f077f0f03e0002001c40a700870013ff9d228488280294b27481d68284b07681c687f090fe008cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c408cd08c4013fedd20768b80847077f0f01e001cd01c4013ffbd20a70002008700a700870")
_DUAL_STAGE_ROUTE = bytes.fromhex("80b50027fff7ccff3c4908703b480078002803d1012080bc08bc18470020384b18810022052a00db66e004e0501c0004000c021cf6e71f20314b98820620314b18802f488089c106c90e1f2901d10020e1e7")

def dual_stage_ram_profile(image: bytes, linker: LinkerLayout | None, load_address: int = 0) -> tuple[dict | None, str | None]:
    """Derive a logical RAM allocation from linked private and normal writes.

    The allocation is not a physical capacity or device identification.
    """
    from . import PAGE, _DUAL_STAGE_NORMAL, _DUAL_STAGE_PRIVATE, _DUAL_STAGE_RESET, _DUAL_STAGE_ROUTE, _DUAL_STAGE_SCATTER, struct, thumb_literal_value
    if (type(load_address) is not int or load_address < 0 or load_address & 3 or load_address + len(image) > 0x100000000):
        return None, "dual-stage-load-invalid"
    def word(offset):
        if offset < 0 or offset + 4 > len(image):
            return None
        return struct.unpack_from("<I", image, offset)[0]
    def arm_literal(pc):
        value = word(pc)
        return None if value is None else word(pc + 8 + (value & 0xfff))
    def literal(pc):
        if pc < 0 or pc + 2 > len(image):
            return None
        return thumb_literal_value(image, pc, image[pc + 1] & 7)
    def offset(address):
        return -1 if address is None else address - load_address
    def branch(pc):
        value = word(pc)
        if value is None or value >> 24 != 0xea:
            return -1
        displacement = value & 0xffffff
        if displacement & 0x800000:
            displacement -= 0x1000000
        return pc + 8 + 4 * displacement
    def table(at):
        if at < 0 or at & 3 or at + 20 > len(image):
            return None
        source, target, size, zero, zero_size = struct.unpack_from("<5I", image, at)
        if (not size or not zero_size or (source | target | size | zero | zero_size) & 3 or source < load_address or source + size > load_address + len(image)
            or target + size != zero or zero + zero_size > 0x100000000):
            return None
        return source, target, size, zero, zero_size
    root = branch(0)
    if root < 0 or root & 3 or image[root:root + len(_DUAL_STAGE_RESET)] != _DUAL_STAGE_RESET:
        return None, None
    # Every interworking return rejoins the matched ARM sequence.
    for gate in (root, root + 0x18, root + 0x30, root + 0x60, root + 0x78, root + 0x90):
        if (arm_literal(gate + 8) != load_address + gate + 0x15 or arm_literal(gate + 12) != load_address + gate + 0x18):
            return None, "dual-stage-reset-return-unclosed"
    private = offset(arm_literal(root + 0x78)) - 1
    route = offset(arm_literal(root + 0x90)) - 1
    normal = branch(root + 0xb0)
    if (private & 3 or route & 1 or normal & 3 or min(private, route, normal) < 0 or image[private:private + len (_DUAL_STAGE_PRIVATE)] != _DUAL_STAGE_PRIVATE
        or image[route:route + len(_DUAL_STAGE_ROUTE)] != _DUAL_STAGE_ROUTE or image[normal:normal + len(_DUAL_STAGE_NORMAL)] != _DUAL_STAGE_NORMAL):
        return None, "dual-stage-entry-unclosed"
    scatter = offset(arm_literal(normal + 0x20)) - 1
    if (scatter < 0 or scatter & 3 or image[scatter:scatter + len(_DUAL_STAGE_SCATTER)] != _DUAL_STAGE_SCATTER or arm_literal(normal + 0x28) != load_address +
        normal + 0x35 or arm_literal(normal + 0x2c) != load_address + normal + 0x38):
        return None, "dual-stage-scatter-unclosed"
    # Unlinked duplicates do not establish an additional memory owner.
    private_table = offset(literal(private + 0x50))
    if[literal(private + pc) for pc in (0x46, 0x48, 0x50, 0x64, 0x66)] !=[load_address + private_table + field for field in (4, 8, 0, 12, 16)]:
        return None, "dual-stage-private-pointers-unclosed"
    private_fields = table(private_table)
    if private_fields is None or private_fields[2] != 8:
        return None, "dual-stage-private-table-unclosed"
    normal_table = offset(literal(scatter + 0xc))
    # Dereferenced pointers in all three copy/zero segments, including remainder.
    links = ((0xc, 0), (0xe, 8), (0x12, 4), (0x46, 8), (0x62, 16), (0x66, 12), (0x86, 16), (0xa0, 28), (0xa4, 20), (0xaa, 24), (0xd8, 28), (0xf4, 36), (0xf8, 32),
        (0x118, 36), (0x130, 40), (0x132, 48), (0x136, 44), (0x16a, 48), (0x186, 56), (0x18a, 52), (0x1aa, 56))
    if any(literal(scatter + pc) != load_address + normal_table + field for pc, field in links):
        return None, "dual-stage-normal-pointers-unclosed"
    fields = [table(normal_table + i * 20) for i in range(3)]
    if any(item is None for item in fields):
        return None, "dual-stage-normal-table-unclosed"
    if fields[0][3] + fields[0][4] != fields[1][1]:
        return None, "dual-stage-normal-span-disconnected"
    required = [(item[1], item[3] + item[4]) for item in fields]
    required.append((private_fields[1], private_fields[3] + private_fields[4]))
    if any(a < d and c < b for i, (a, b) in enumerate(required) for c, d in required[i + 1:]):
        return None, "dual-stage-write-overlap"
    bus_base = literal(private + 0x1a)
    commands = [literal(private + pc) for pc in (0x24, 0x28, 0x2c)]
    if (bus_base is None or bus_base + 0x20 > 0x100000000 or not fields[0][3] <= bus_base + 0x1e < fields[0][3] + fields[0][4] or any(value is None for value in
        commands) or[value & 0xffff for value in commands] !=[0xb2b2, 0xd0d0, 0xffff] or literal(private + 4) != 0x03000700 or literal(private + 0x12) != 0xfff):
        return None, "dual-stage-private-init-unclosed"
    stacks = [arm_literal(normal + pc) for pc in (4, 12, 24)]
    reset_stacks = [arm_literal(root + pc) for pc in (0x4c, 0x54, 0x5c)]
    if any(value is None or value & 3 or not private_fields[1] <= value <= required[-1][1] for value in stacks + reset_stacks):
        return None, "dual-stage-stack-unclosed"
    allowed = [(private_table, private_fields), *[(normal_table + i * 20, item) for i, item in enumerate(fields)]]
    if linker is None or not any((linker.table_offset, linker.data_source, linker.data_target, linker.data_size, linker.bss_target, linker.bss_size) == (at,
        item[0] - load_address, item[1], item[2], item[3], item[4]) for at, item in allowed):
        return None, "dual-stage-linker-conflict"
    base = min(a for a, _ in required)
    end = max(b for _, b in required)
    if base & (PAGE - 1):
        return None, "dual-stage-base-unaligned"
    # Raw input may contain appended RAM snapshots. Only source-owned ROM
    # intervals, not the whole file length, must be disjoint from RAM.
    code = ((root, _DUAL_STAGE_RESET), (private, _DUAL_STAGE_PRIVATE), (route, _DUAL_STAGE_ROUTE), (normal, _DUAL_STAGE_NORMAL), (scatter, _DUAL_STAGE_SCATTER))
    rom_intervals = [(at, at + len(signature)) for at, signature in code]
    for at, signature in code:
        step = 4 if at in (root, normal) else 2
        for pc in range(at, at + len(signature), step):
            instruction = int.from_bytes(image[pc:pc + step], "little")
            if step == 4 and instruction & 0x0f7f0000 == 0x051f0000:
                pool = pc + 8 + (instruction & 0xfff)
                rom_intervals.append((pool, pool + 4))
            elif step == 2 and instruction & 0xf800 == 0x4800:
                pool = ((pc + 4) & ~3) + (instruction & 0xff) * 4
                rom_intervals.append((pool, pool + 4))
    for at, item in allowed:
        rom_intervals.extend(((at, at + 20), (item[0] - load_address, item[0] - load_address + item[2])))
    # The last scatter copy has a separate, unclassified destination. Its ROM
    # source is still bounded; it does not contribute a RAM span.
    if[literal(scatter + pc) for pc in (0x1c6, 0x1c8, 0x1cc)] !=[load_address + normal_table + field for field in (60, 68, 64)]:
        return None, "dual-stage-tail-pointers-unclosed"
    if normal_table + 72 > len(image):
        return None, "dual-stage-tail-source-unclosed"
    tail_source, _, tail_size = struct.unpack_from("<3I", image, normal_table + 60)
    if not tail_size or (tail_source | tail_size) & 3:
        return None, "dual-stage-tail-source-unclosed"
    rom_intervals.extend(((normal_table + 60, normal_table + 72), (tail_source - load_address, tail_source - load_address + tail_size)))
    if any(not 0 <= begin < finish <= len(image) or load_address + finish > base for begin, finish in rom_intervals):
        return None, "dual-stage-rom-ram-overlap"
    size = 1 << (end - base - 1).bit_length()
    # Match the existing core 128 MiB allocation ceiling without importing
    # its legacy CPU-register dependency into static detection.
    if size > 0x08000000 or base + size > 0x100000000:
        return None, "dual-stage-allocation-overflow"
    return {"signature": "arm-thumb-dual-stage-scatter-ram-v1", "admission": "temporary-evidence-gated", "ram_base": base, "ram_size": size, "required_end": end,
        "rom_intervals":[[load_address + a, load_address + b] for a, b in rom_intervals], "required_spans":[list(span) for span in required], "stacks": stacks,
        "reset_stacks": reset_stacks, "reset_entry": load_address + root, "normal_entry": load_address + normal, "scatter_entry": load_address + scatter,
        "private_entry": load_address + private, "private_table": load_address + private_table, "normal_table": load_address + normal_table, "code_intervals":[[load_address
        + p, load_address + p + len(signature)] for p, signature in ((root, _DUAL_STAGE_RESET), (private, _DUAL_STAGE_PRIVATE), (route, _DUAL_STAGE_ROUTE), (normal,
        _DUAL_STAGE_NORMAL), (scatter, _DUAL_STAGE_SCATTER))]}, None
