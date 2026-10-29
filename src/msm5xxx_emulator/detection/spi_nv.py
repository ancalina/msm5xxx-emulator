"""Candidate identity for closed four-wire serial nonvolatile-memory producers."""
from __future__ import annotations

import re
import struct

from .arm import thumb_bl_target, thumb_literal_value

# Fixed instructions preserve transfer widths, edges, masks, loops and guards.
# Only typed BL displacements and PC-literal offsets vary between placements.
_COMMON = {
    'init': (
        '80b5d54501da??????????????????490a7840231a430a700978??4f3976002801d1??????????????????490a780323'
        '1a430a7009783977002801d1????????????????011c??48027810231a4302700078??4a1071002901d1????????????'
        '??????490a7840231a430a7009783971002801d1??????????????????490a78920892000a7009783972002801d1????'
        '????????????011c??4802781023db431a40027000783874002901d1????????80bd',
        ((6, 'guard'), (10, 'save_irq'), (34, 'restore_irq'), (38, 'save_irq'), (60, 'restore_irq'), (64, 'save_irq'), (90, 'restore_irq'), (94, 'save_irq'), (116, 'restore_irq'), (120, 'save_irq'), (142, 'restore_irq'), (146, 'save_irq'), (172, 'restore_irq')),
        ((14, 1, 'shadow', -1), (26, 7, 'constant', 50333280), (42, 1, 'shadow', 1), (70, 0, 'shadow', 5), (82, 2, 'constant', 50333312), (98, 1, 'shadow', -2), (124, 1, 'shadow', 0), (152, 0, 'shadow', 4))),
    'wren': (
        'b0b5d54501da??????????????????4d29780223db43194029702978??4f3972002801d1??????????????????4c2178'
        '4023db431940217021783971002801d1????????0620????????????????29780223db431940297029783972002801d1'
        '????????????????217840231943217021783971002801d1????????b0bd',
        ((6, 'guard'), (10, 'save_irq'), (36, 'restore_irq'), (40, 'save_irq'), (64, 'restore_irq'), (70, 'tx_byte'), (74, 'save_irq'), (96, 'restore_irq'), (100, 'save_irq'), (120, 'restore_irq')),
        ((14, 5, 'shadow', 0), (28, 7, 'constant', 50333280), (44, 4, 'shadow', -2))),
    'wrdi': (
        'b0b5d54501da??????????????????4d29780223db43194029702978??4f3972002801d1??????????????????4c2178'
        '4023db431940217021783971002801d1????????0420????????????????29780223db431940297029783972002801d1'
        '????????????????217840231943217021783971002801d1????????b0bd',
        ((6, 'guard'), (10, 'save_irq'), (36, 'restore_irq'), (40, 'save_irq'), (64, 'restore_irq'), (70, 'tx_byte'), (74, 'save_irq'), (96, 'restore_irq'), (100, 'save_irq'), (120, 'restore_irq')),
        ((14, 5, 'shadow', 0), (28, 7, 'constant', 50333280), (44, 4, 'shadow', -2))),
    'wrsr0': (
        'b0b5d54501da??????????????????4d29780223db43194029702978??4f3972002801d1??????????????????4c2178'
        '4023db431940217021783971002801d1????????0120????????0020????????????????29780223db43194029702978'
        '3972002801d1????????????????217840231943217021783971002801d1????????????????b0bd',
        ((6, 'guard'), (10, 'save_irq'), (36, 'restore_irq'), (40, 'save_irq'), (64, 'restore_irq'), (70, 'tx_byte'), (76, 'tx_byte'), (80, 'save_irq'), (102, 'restore_irq'), (106, 'save_irq'), (126, 'restore_irq'), (130, 'ready_poll')),
        ((14, 5, 'shadow', 0), (28, 7, 'constant', 50333280), (44, 4, 'shadow', -2))),
    'status': (
        'f0b5d54501da??????????????????4e31780223db43194031703178??4f3972002801d1??????????????????4c2178'
        '4023db431940217021783971002801d1????????0520????????????????051c????????31780223db43194031703178'
        '3972002801d1????????????????217840231943217021783971002801d1????????281cf0bd',
        ((6, 'guard'), (10, 'save_irq'), (36, 'restore_irq'), (40, 'save_irq'), (64, 'restore_irq'), (70, 'tx_byte'), (74, 'rx_byte'), (80, 'save_irq'), (102, 'restore_irq'), (106, 'save_irq'), (126, 'restore_irq')),
        ((14, 6, 'shadow', 0), (28, 7, 'constant', 50333280), (44, 4, 'shadow', -2))),
    'write_data': (
        'f0b5d54501da????????071c0c04240c1604360c??????????4d29780223db43194029702978??4a1172002801d1????'
        '??????????????490a784023db431a400a700978??4a1171002801d1????????0220????????200a????????2006000e'
        '????????0024b44208da03e0601c0404240cf8e7385d????????f7e7????????29780223db43194029702978??4f3972'
        '002801d1??????????????????490a7840231a430a7009783971002801d1????????????????f0bd',
        ((6, 'guard'), (20, 'save_irq'), (46, 'restore_irq'), (50, 'save_irq'), (76, 'restore_irq'), (82, 'tx_byte'), (88, 'tx_byte'), (96, 'tx_byte'), (118, 'tx_byte'), (124, 'save_irq'), (148, 'restore_irq'), (152, 'save_irq'), (174, 'restore_irq'), (178, 'ready_poll')),
        ((24, 5, 'shadow', 0), (38, 2, 'constant', 50333280), (54, 1, 'shadow', -2), (68, 2, 'constant', 50333280), (140, 7, 'constant', 50333280), (156, 1, 'shadow', -2))),
    'read_data': (
        'f0b5d54501da????????071c0c04240c1604360c??????????4d29780223db43194029702978??4a1172002801d1????'
        '??????????????490a784023db431a400a700978??4a1171002801d1????????0320????????200a????????2006000e'
        '????????0024b44208da03e0601c0404240cf8e7????????3855f7e7????????29780223db43194029702978??4f3972'
        '002801d1??????????????????490a7840231a430a7009783971002801d1????????f0bd',
        ((6, 'guard'), (20, 'save_irq'), (46, 'restore_irq'), (50, 'save_irq'), (76, 'restore_irq'), (82, 'tx_byte'), (88, 'tx_byte'), (96, 'tx_byte'), (116, 'rx_byte'), (124, 'save_irq'), (148, 'restore_irq'), (152, 'save_irq'), (174, 'restore_irq')),
        ((24, 5, 'shadow', 0), (38, 2, 'constant', 50333280), (54, 1, 'shadow', -2), (68, 2, 'constant', 50333280), (140, 7, 'constant', 50333280), (156, 1, 'shadow', -2))),
    'ready_poll': (
        '90b5d54501da????????99240027a7420cda03e0781c07063f0ef8e7????????c007c00f01d1012090bd',
        ((6, 'guard'), (28, 'status')),
        ()),
    'tx_byte': (
        'f0b5d54501da????????05062d0e????????061c0024??4f082c41da03e0601c0406240ef8e7????????39780223db43'
        '194039703978??4a1172002801d1????????802028400dd0????????39780123194339703978??4a1172002801d1????'
        '????0ce0????????39784908490039703978??4a1172002801d1????????????????39780223194339703978??4a1172'
        '002801d1????????680005062d0ebee7????????39784908490039703978??4a1172002801d1????????002e01d1????'
        '????f0bd',
        ((6, 'guard'), (14, 'save_irq'), (38, 'save_irq'), (62, 'restore_irq'), (72, 'save_irq'), (94, 'restore_irq'), (100, 'save_irq'), (122, 'restore_irq'), (126, 'save_irq'), (148, 'restore_irq'), (160, 'save_irq'), (182, 'restore_irq'), (190, 'restore_irq')),
        ((22, 7, 'shadow', 0), (54, 2, 'constant', 50333280), (86, 2, 'constant', 50333280), (114, 2, 'constant', 50333280), (140, 2, 'constant', 50333280), (174, 2, 'constant', 50333280))),
    'rx_byte': (
        'f0b5d54501da????????00270024??4d??4e082c2bda03e0601c0406240ef8e7????????29780223db43194029702978'
        '3172002801d1????????30798023184003d03806000e01270743????????297802231943297029783172002801d1????'
        '????072c02d0780007063f0ed4e7381cf0bd',
        ((6, 'guard'), (32, 'save_irq'), (54, 'restore_irq'), (74, 'save_irq'), (94, 'restore_irq')),
        ((14, 5, 'shadow', 0), (16, 6, 'constant', 50333280))),
}
_STACK_LAYOUT = {
    'write_root': (
        'f0b5d54501da????????071c86b081b00d042d0c1004000c00908bb001204003??491191854201da01950be011990979'
        '012901d1019505e001235b03e91a0904090c019111994a880626??4910910024??49824203d0119a1279022a1ed1019a'
        '3b239b021a4006d1019a0b9bd2183b239b021a4011d00888032807dc032805dc0b9a291c??48231c????????1099??48'
        '????????301c12b0f0bd1ee0019a03239b031a4006d1019a0b9bd21803239b031a4012d00888032807dc032805dc0b9a'
        '291c??48231c????????1099db208000????????301c12b0dee7854202da0120009001e000200090??480f90??480e90'
        '??480d90??4a0c920b98002873d0??????????4a11781023194311701178??4a1174002801d1????????04200921c905'
        '08840b98202801da0b9800e020200604360cec06e40ea0190004000c202814dd2020001b0404240c????????221c291c'
        '381c????????????????????????321b29193819????????06e0????????321c291c381c????????00200a90??480078'
        '002817d10024082c13da03e0601c0404240cf8e78020????????6420????????????????c007c00f02d101200a9000e0'
        'ece726e08020????????0f98??49????????f01d002800da0730c0100204120c012e02d0501c0204120c900080180204'
        '120c501d00e09ae00204120c0e990220????????????????c007c00f01d101200a900a98002812d1??????????480088'
        '042807dc042805dc291c0d9800230022????????10991f204001????????04200921c9050884??????????490a781023'
        'db431a400a700978??4a1174002801d1????????009800280dd00024b4420ada03e0601c0404240cf8e7385d01990919'
        '0c9a5054f5e7002011990870321c291c02a8????????002815d0??480088032807dc032805dc??48002300220021????'
        '????1099??48????????012011990870042012b0f0e60120119908700024b4421eda03e0601c0404240cf8e7395d02a8'
        '005d814213d0??480088032807dc032805dc0199??4800230022????????109949200001????????042012b0cce6e1e7'
        '019988190104090c0191a81905042d0cbf190b98801b0004000c0b90ece6????????002012b0b7e6',
        ((6, 'guard'), (136, 'external_0'), (144, 'external_1'), (198, 'external_0'), (208, 'external_1'), (254, 'save_irq'), (278, 'restore_irq'), (328, 'wren'), (338, 'write_data'), (342, 'ready_poll'), (346, 'wren'), (356, 'write_data'), (362, 'wren'), (372, 'write_data'), (406, 'external_2'), (412, 'external_3'), (416, 'status'), (438, 'external_2'), (446, 'external_4'), (496, 'external_5'), (500, 'status'), (520, 'external_6'), (544, 'external_0'), (554, 'external_7'), (566, 'save_irq'), (592, 'restore_irq'), (642, 'read_root'), (670, 'external_0'), (678, 'external_1'), (746, 'external_0'), (756, 'external_1'), (798, 'wrdi')),
        ((32, 1, 'descriptor', 0), (74, 1, 'rom_0', 0), (80, 1, 'ram_0', 0), (132, 0, 'rom_1', 0), (142, 0, 'constant', 870), (194, 0, 'rom_2', 0), (232, 0, 'ram_1', 0), (236, 0, 'ram_2', 0), (240, 0, 'rom_3', 0), (244, 2, 'cache', 0), (258, 2, 'shadow', 4), (270, 2, 'constant', 50333280), (380, 0, 'ram_3', 0), (444, 1, 'constant', 565), (524, 0, 'ram_0', 0), (570, 1, 'shadow', 4), (584, 2, 'constant', 50333280), (650, 0, 'ram_0', 0), (662, 0, 'rom_4', 0), (676, 0, 'constant', 1155), (726, 0, 'ram_0', 0), (740, 0, 'rom_5', 0))),
    'read_root': (
        'f0b5d54501da????????0904090c1204120c01277f03??4db94201da0c1c09e02b79012b01d10c1c04e001235b03cb1a'
        '1c04240c6e88??4f01235b039e4202d02b79022b19d13b239b02234004d1a6183b239b0233400fd0??480088032805dc'
        '032803dc??480023????????391c??48????????0620f0bd18e003239b03234004d1a61803239b0333400fd0??480088'
        '032805dc032803dc??480023????????391c??48????????0620e4e701235b03994201da012300e00023002a01d10020'
        'd9e7002b12d02b78002b0fd0??49002a0bd006e0631c1c04240c013a1204120cf5e70b5d03700130f4e701e0????????'
        '0020c0e7',
        ((6, 'guard'), (104, 'external_0'), (112, 'external_1'), (156, 'external_0'), (164, 'external_1'), (236, 'read_data')),
        ((22, 5, 'descriptor', 0), (54, 7, 'rom_0', 0), (88, 0, 'ram_0', 0), (100, 0, 'rom_6', 0), (110, 0, 'constant', 1292), (140, 0, 'ram_0', 0), (152, 0, 'rom_7', 0), (162, 0, 'constant', 1298), (204, 1, 'cache', 0))),
    'scalar_write': (
        '00b5d54501da????????0006000e0904090c81b000ab187068460122????????01b000bd',
        ((6, 'guard'), (28, 'write_root')),
        ()),
    'scalar_read': (
        '00b5d54501da????????0904090c0122????????00bd',
        ((6, 'guard'), (16, 'read_root')),
        ()),
    'geometry_init': (
        '01218903??4841800121017100214171f746',
        (),
        ((4, 0, 'descriptor', 0),)),
    'outer_init': (
        'f0b5d54501da????????????????0025??4e3570??????????48041c??4a0021????????071c01203070002f11d0????'
        '??????480088042807dc042805dc391c??482b1c0022??????????49??48????????aa209f235b01e118c877f0bd',
        ((6, 'guard'), (10, 'init'), (20, 'geometry_init'), (32, 'read_root'), (46, 'external_6'), (70, 'external_0'), (78, 'external_7')),
        ((16, 6, 'descriptor', 0), (24, 0, 'cache', 0), (28, 2, 'constant', 5119), (50, 0, 'ram_0', 0), (64, 0, 'rom_8', 0), (74, 1, 'rom_0', 0), (76, 0, 'constant', 1692))),
}
_REGISTER_LAYOUT = {
    'write_root': (
        'f0b5d54501da????????071c84b081b00e04360c1004000c00908bb001204003??490f91864201da01960be00f990979'
        '012901d1019605e001235b03f11a0904090c01910f9949880624814203d00f990979022913d101990f231b03194006d1'
        '01990b9a89180f231b03194006d08fa1??48????????201c10b0f0bd13e0019903239b03194006d101990b9a89180323'
        '9b03194007d085a1db208000????????201c10b0e9e7864202da0120009001e000200090??480e90??490d91??4a0c92'
        '0b98002873d0??????????4a11781023194311701178??4a1174002801d1????????04200921c90508840b98202801da'
        '0b9800e0202005042d0cf406e40e60190004000c202814dd2020001b0404240c????????221c311c381c????????????'
        '????????????2a1b31193819????????06e0????????2a1c311c381c????????00200a90??480078002817d10024082c'
        '13da03e0601c0404240cf8e78020????????6420????????????????c007c00f02d101200a9000e0ece726e08020????'
        '????0e98??49????????e81d002800da0730c0100204120c012d02d0501c0204120c900080180204120c501d00e076e0'
        '0204120c0d990220????????????????c007c00f01d101200a900a98002806d1????????36a11f204001????????0420'
        '0921c9050884??????????490a781023db431a400a700978??4a1174002801d1????????009800280dd00024ac420ada'
        '03e0601c0404240cf8e7395d019800190c9a1154f5e700200f9908702a1c311c02a8????????002809d01ca1??48????'
        '????01200f990870042010b015e701200f9908700024ac4212da03e0601c0404240cf8e7395d02a8005d814207d00fa1'
        '49200001????????042010b0fde6ede7019840190004000c019070190604360c7f190b98401b0004000c0b9010e7????'
        '????002010b0e8e6',
        ((6, 'guard'), (114, 'external_0'), (156, 'external_0'), (198, 'save_irq'), (222, 'restore_irq'), (272, 'wren'), (282, 'write_data'), (286, 'ready_poll'), (290, 'wren'), (300, 'write_data'), (306, 'wren'), (316, 'write_data'), (350, 'external_1'), (356, 'external_2'), (360, 'status'), (382, 'external_1'), (390, 'external_3'), (440, 'external_4'), (444, 'status'), (464, 'external_5'), (474, 'external_6'), (486, 'save_irq'), (512, 'restore_irq'), (562, 'read_root'), (574, 'external_0'), (628, 'external_0'), (670, 'wrdi')),
        ((32, 1, 'descriptor', 0), (112, 0, 'constant', 870), (180, 0, 'ram_0', 0), (184, 1, 'ram_1', 0), (188, 2, 'cache', 0), (202, 2, 'shadow', 4), (214, 2, 'constant', 50333280), (324, 0, 'ram_2', 0), (388, 1, 'constant', 565), (490, 1, 'shadow', 4), (504, 2, 'constant', 50333280), (572, 0, 'constant', 1155))),
    'read_root': (
        'f0b5d54501da????????0c04240c1204120c01277f03??4dbc4201da211c09e02979012901d1211c04e001235b03e11a'
        '0904090c6e88be4202d02b79022b10d10f231b030b4004d18e180f231b03334006d079468639??48????????0620f0bd'
        '0fe003239b030b4004d18e1803239b03334006d07946a839??48????????0620ede7bc4201da012300e000230027002a'
        '01d1381ce3e7002b12d02b78002b0fd0??4b002a0bd006e001310904090c013a1204120cf5e75c5c04700130f4e702e0'
        '211c????????381cc9e7',
        ((6, 'guard'), (88, 'external_0'), (122, 'external_0'), (194, 'read_data')),
        ((22, 5, 'descriptor', 0), (86, 0, 'constant', 1292), (120, 0, 'constant', 1298), (160, 3, 'cache', 0))),
    'scalar_write': (
        '00b5d54501da????????0006000e0904090c81b000ab187068460122????????01b000bd',
        ((6, 'guard'), (28, 'write_root')),
        ()),
    'scalar_read': (
        '00b5d54501da????????0904090c0122????????00bd',
        ((6, 'guard'), (16, 'read_root')),
        ()),
    'geometry_init': (
        '01218903??4841800121017100214171f746',
        (),
        ((4, 0, 'descriptor', 0),)),
    'outer_init': (
        '90b5d54501da????????????????0020??4f3870??????????48041c??4a0021????????01213970002805d0????????'
        '??49??48????????aa207f235b01e118c87790bd',
        ((6, 'guard'), (10, 'init'), (20, 'geometry_init'), (32, 'read_root'), (44, 'external_5'), (52, 'external_6')),
        ((16, 7, 'descriptor', 0), (24, 0, 'cache', 0), (28, 2, 'constant', 4095), (48, 1, 'rom_0', 0), (50, 0, 'constant', 1692))),
}

def _pattern(spec: tuple) -> re.Pattern:
    return re.compile(b''.join(b'.' if token == '??' else re.escape(bytes.fromhex(token))
                              for token in re.findall('..', spec[0])), re.S)


def _locations(image: bytes, spec: tuple):
    pattern = _pattern(spec)
    cursor = 0
    while (match := pattern.search(image, cursor)) is not None:
        cursor = match.start() + 1
        if not match.start() & 1:
            yield match.start()


class _Unclosed(Exception):
    pass


def _profile_at(image: bytes, root: int, layout: dict, layout_name: str) -> dict:
    specs = {**_COMMON, **layout}
    nodes = {'write_root': root}
    symbols = {}
    checked = set()
    intervals = []
    pools = []

    def reject(reason):
        raise _Unclosed('spi-nv-' + reason)

    def bind(table, key, value):
        if key in table and table[key] != value:
            reject('crosslinked-' + key)
        table[key] = value

    def visit(role):
        if role in checked:
            return
        at = nodes[role]
        spec = specs[role]
        size = len(spec[0]) // 2
        if (at < 0 or at & 1 or at + size > len(image)
                or _pattern(spec).fullmatch(image, at, at + size) is None):
            reject('typed-' + role + '-unclosed')
        checked.add(role)
        intervals.append((at, at + size))
        for offset, callee in spec[1]:
            target = thumb_bl_target(image, at + offset)
            if target is None or target & 1 or not 0 <= target < len(image) - 1:
                reject('call-' + role + '-out-of-bounds')
            bind(nodes if callee in specs else symbols, callee, target)
        for offset, register, symbol, delta in spec[2]:
            pc = at + offset
            value = thumb_literal_value(image, pc, register)
            if value is None:
                reject('literal-' + role + '-out-of-bounds')
            word = struct.unpack_from('<H', image, pc)[0]
            pools.append(((pc + 4) & ~3) + (word & 255) * 4)
            if symbol == 'constant':
                if value != delta:
                    reject('literal-' + role + '-value')
                continue
            value -= delta
            if symbol.startswith('rom_'):
                if not 0 <= value < len(image):
                    reject('rom-pointer-out-of-bounds')
            elif not 0x01000000 <= value < 0x02000000:
                reject('ram-pointer-out-of-bounds')
            bind(symbols, symbol, value)
        for _, callee in spec[1]:
            if callee in specs:
                visit(callee)

    visit('write_root')

    # The scalar callers and outer initializer close the unused command helpers,
    # geometry producer and initial uncached read into this same device group.
    for role in ('scalar_write', 'scalar_read', 'outer_init', 'wrsr0'):
        matches = []
        for at in _locations(image, specs[role]):
            calls = specs[role][1]
            if all(thumb_bl_target(image, at + offset) == nodes[callee]
                   for offset, callee in calls if callee in nodes):
                matches.append(at)
        if len(matches) != 1:
            reject(role + '-ownership-nonunique')
        bind(nodes, role, matches[0])
        visit(role)
    if checked != specs.keys():
        reject('helper-group-incomplete')
    descriptor = symbols['descriptor']
    shadow = symbols['shadow']
    cache = symbols['cache']
    if (descriptor & 3 or shadow & 3
            or not 0x01000000 <= descriptor <= 0x02000000 - 6
            or not 0x01000002 <= shadow <= 0x02000000 - 6
            or not 0x01000000 <= cache <= 0x02000000 - 0x2000):
        reject('descriptor-shadow-cache-range')
    data_spans = sorted(((descriptor, descriptor + 6),
                         (shadow - 2, shadow + 6), (cache, cache + 0x2000)))
    if any(left[1] > right[0] for left, right in zip(data_spans, data_spans[1:])):
        reject('descriptor-shadow-cache-overlap')
    geometry_spec = specs['geometry_init']
    geometries = [at for at in _locations(image, geometry_spec)
                  if thumb_literal_value(image, at + geometry_spec[2][0][0],
                                         geometry_spec[2][0][1]) == descriptor]
    if geometries != [nodes['geometry_init']]:
        reject('geometry-ownership-nonunique')
    if len(set(nodes.values())) != len(nodes):
        reject('helper-entry-alias')
    ordered = sorted(intervals)
    if any(left[1] > right[0] for left, right in zip(ordered, ordered[1:])):
        reject('helper-code-overlap')
    if any(begin <= pool < end or begin < pool + 4 <= end
           for pool in pools for begin, end in intervals):
        reject('literal-code-overlap')
    external = [value for key, value in symbols.items()
                if key in ('guard', 'save_irq', 'restore_irq') or key.startswith('external_')]
    if (len(set(external)) != len(external)
            or any(begin <= target < end for target in external
                   for begin, end in intervals)):
        reject('external-call-alias')
    return dict(class_name='thumb-four-wire-serial-nv-v1',
                admission='candidate-only', layout=layout_name,
                pins=dict(cs_address=0x03000664, cs_mask=0x40, cs_active_low=True,
                          clock_address=0x03000668, clock_mask=2,
                          mosi_address=0x03000668, mosi_mask=1,
                          miso_address=0x03000664, miso_mask=0x80,
                          cs_direction_address=0x03000678,
                          data_direction_address=0x0300067C),
                virtual_capacity=0x4000, page_size=32,
                geometry_mode=1, cache_size=0x2000,
                descriptor_address=descriptor, shadow_address=shadow,
                cache_address=cache, source_root=nodes['write_root'],
                source_init=nodes['outer_init'], source_gpio_init=nodes['init'],
                source_tx=nodes['tx_byte'], source_rx=nodes['rx_byte'],
                source_geometry_init=nodes['geometry_init'],
                source_read_root=nodes['read_root'], source_entries=dict(nodes),
                code_intervals=ordered,
                policy='virtual-serial-nv-capacity-not-part-identity')


def find_spi_nv_profile(image: bytes) -> tuple[dict | None, str]:
    """Return only one fully linked typed wire/geometry group; never admit hardware."""
    if not isinstance(image, bytes):
        return None, 'spi-nv-image-not-bytes'
    complete = []
    failures = []
    for name, layout in (('stack-checked', _STACK_LAYOUT),
                         ('register-checked', _REGISTER_LAYOUT)):
        for root in _locations(image, layout['write_root']):
            try:
                complete.append(_profile_at(image, root, layout, name))
            except _Unclosed as exc:
                failures.append(str(exc))
    if len(complete) > 1:
        return None, 'spi-nv-complete-groups-ambiguous'
    if complete:
        return complete[0], 'accepted'
    return None, failures[0] if failures else 'spi-nv-typed-root-unclosed'
