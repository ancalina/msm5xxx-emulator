"""Narrow source-closed legacy panel producer graphs, independent of filenames.

Whole bounded function hashes bind their instructions; resolved literal and call
edges are separately checked, including pools outside the function bodies.
These are runtime candidates only; actual guest coverage must establish scanout.
Color channels remain a temporary preview interpretation.
"""
from __future__ import annotations
from msm5xxx_emulator.detection.facts import facts_for
import hashlib
from msm5xxx_emulator.detection.fact_patterns import mov, lsl, halfword, match

# Additional halfword-window producer: boot fill/text and the later UI scanout
# use 75/15/5c with columns 140..267 and visible rows 0..159.  Only the source
# grammar is admitted here; the existing panel still requires live coverage.
_COLUMN16_BOOT = ((0xc1c, mov(2, 0x80)), (0xc26, mov(0, 0x7d)), (0xc28, lsl(0, 0, 3)), (0xc2e, mov(0, 0xbc)), (0xd22, mov(4, 0x75)), (0xd24, mov(6, 5)), (0xd26,
    lsl(6, 6, 0x17)), (0xd2a, halfword(False, 4, 6)), (0xd2c, halfword(False, 1, 6, 4)), (0xd2e, halfword(False, 3, 6, 4)), (0xd30, mov(4, 0x15)), (0xd32,
    halfword(False, 4, 6)), (0xd76, mov(1, 0)), (0xd78, mov(7, 0)), (0xe32, mov(2, 0)), (0xe34, mov(0, 0x75)), (0xe36, mov(4, 5)), (0xe38, lsl(4, 4, 0x17)), (0xe3a,
    halfword(False, 0, 4)), (0xe40, mov(5, 0xaf)), (0xe42, halfword(False, 5, 4, 4)), (0xe44, mov(0, 0x15)), (0x1b441c, mov(0, 0x75)), (0x1b441e, mov(3, 5)), (0x1b4420,
    lsl(3, 3, 0x17)), (0x1b4422, halfword(False, 0, 3)), (0x1b442a, mov(1, 0x9f)), (0x1b442e, mov(1, 0x15)), (0x1b4432, mov(1, 0x8c)),)
_SPECS = {'byte565_boot':[(619920, 124, 'baca6df280c63bba679ad60d3c828af8ac0e99ca63b2d64552a9699ce3cd08ef', ((10, 9888), (14, 614488), (18, 614912), (22, 618994),
    (26, 619052), (52, 619416), (56, 619584), (60, 619280), (64, 619052), (68, 619752)), ((6, 1, 4837514), (8, 2, 31920), (30, 0, 16790116), (38, 0, 2198092), (44,
    0, 2200008))), (614488, 424, 'e4d9576d6956e324b262e4425052480e156a7d86506149892fd2a9f86310692f', ((2, 1898104), (18, 36416), (26, 36416), (34, 1898132), (38,
    552392), (44, 36376), (48, 1898104), (60, 36416), (66, 36416), (74, 1898132), (78, 1898104), (90, 36416), (98, 36416), (106, 1898132), (110, 1898104), (122,
    36416), (130, 36416), (138, 1898132), (142, 1898104), (154, 36416), (162, 36416), (170, 1898132), (174, 1898104), (186, 36416), (192, 36416), (200, 1898132),
    (204, 1898104), (216, 36416), (224, 36416), (232, 1898132), (236, 1898104), (248, 36416), (256, 36416), (264, 1898132), (268, 1898104), (280, 36416), (286,
    36416), (294, 1898132), (298, 1898104), (310, 36416), (316, 36416), (324, 1898132), (328, 1898104), (340, 36416), (346, 36416), (354, 1898132), (358,
    1898104), (370, 36416), (376, 36416), (384, 1898132), (388, 1898104), (398, 36416), (406, 36416), (414, 1898132)), ((42, 0, 5000),)), (619752, 78,
    'e726010b0eac20ee93db7f9bbd7a7beb6154d66fd7cb8cbbf1e1729e8b934dfa', ((2, 1898104), (16, 36416), (24, 36416), (32, 1898132), (42, 1898104), (54, 36416), (62,
    36416), (70, 1898132)), ((36, 4, 75497504),))], 'column16':[(1919484, 106, '6879d83ca6bbcfe383e2f184b237f0156dd0f6dfc614c19d53aa67e03bbde0b1', ((50, 1912132),
    (56, 1912140), (62, 1912140), (68, 1912132), (76, 1912140), (82, 1912140), (90, 1912140), (96, 1912140)), ((4, 0, 18978468),)), (1912132, 8,
    'df0a4509958641ab0fed21c7b22ec652c007203df234a4dbb6262c439f9ee909', (), ()), (1912140, 8, 'e905734a288dbc716c87761d0cc30acb9d1d3d313d8d6d99c5f5cd86da179fe6',
    (), ()), (1419940, 42, '7b69a474fed6379d364129d7c22ad752514f92f6afb0d362cb7fafaec99342b7', ((10, 1919484),), ((22, 1, 20143038),)), (1419988, 48,
    'd496367e4a63ef66691a674affc864db27a3fc8bf702ad3ec9c0654be198be78', ((12, 1919484),), ((2, 7, 18956820), (24, 0, 20146622))), (1420044, 48,
    'e3edb59e14b33ba251e85bf5dabe324f3288d01b03ee44376d77bb8dc415a57d', ((12, 1919484),), ((2, 7, 18956820), (24, 0, 20159422))), (1420102, 60,
    'ff7a0fb7e4918eb876bcfc5c56f7b7fa218a813b480ff6c7eeb02578134a5517', ((12, 2160644), (28, 2160644), (50, 2160644)), ((0, 0, 20934836), (10, 0, 20143038), (16,
    7, 18956820), (18, 4, 20933864), (26, 0, 20146622), (44, 1, 4294963712), (48, 0, 20159422))), (1912716, 60,
    'dacf9284b4052d3c3a6589e05b35f46973ddeb42dee2426fa7f844c97a273955', ((20, 1919484), (26, 1912132), (38, 1912140)), ((0, 1, 20933820), (30, 4, 65535))), (1423944,
    120, '2ed62cbf7bdab643bf7cae85784f3b5b4fe4c78bea263d15540774e5d7f79f98', ((112, 1419896),), ((0, 2, 20117392), (36, 4, 20142992), (38, 7, 18956820), (52, 3,
    4294965504), (76, 0, 18978469))), (1919672, 66, '2751d820a1a7430fa8cffb9f516c695a7a02ffad4af47dcdb428b19788627024', (), ((12, 0, 18978468), (46, 3, 20933948)))],
    'byte31':[(3292, 4, '61854249f65fb63e992edb85ab4aa0597f8e6df14ac7a861629bee31e1020dc5', (), ()), (3296, 396,
    '1aceee8e546f3236cbd5b6fead2af88bf0f27db4618088c69a9d57ef55fad616', ((10, 3292), (20, 3292), (30, 3292), (40, 3292), (50, 3292), (60, 3292), (70, 3292), (80,
    3292), (122, 3292), (202, 3292), (214, 3292), (228, 3292), (238, 3292), (256, 3292), (274, 3292), (364, 3292), (374, 3292)), ((98, 1, 50333184), (120, 0,
    41943044), (156, 1, 50333184), (298, 1, 9240), (312, 2, 9240), (362, 0, 41943044), (372, 0, 41943044))), (3704, 332,
    '7c985810c1700e39be432ed8b800416b3130b86471e5f8355a2c59ece071cd95', ((4, 9020), (34, 9048), (38, 4056), (48, 3292), (58, 3292), (68, 3292), (78, 3292), (88,
    3292), (98, 3292), (108, 3292), (118, 3292), (160, 3292), (174, 3292), (184, 3292), (194, 3292), (204, 3292), (214, 3292), (224, 3292), (234, 3292), (244,
    3292), (292, 3292), (306, 3292), (316, 3292), (326, 3292)), ((10, 0, 20447393), (18, 1, 20447393), (22, 0, 20447393), (26, 1, 50333312), (136, 1, 50333184),
    (158, 0, 41943044), (262, 1, 50333184), (286, 1, 2914760), (290, 0, 41943044))), (4056, 332,
    'be610a773efb092dd53fc91a0dea2ec34ec4bdb9e0168a59a73ee15282477178', ((8, 3292), (24, 3292), (40, 3292), (56, 3292), (72, 3292), (88, 3292), (104, 3292), (120,
    3292), (136, 3292), (152, 3292), (168, 3292), (184, 3292), (200, 3292), (214, 1096), (224, 3292), (230, 1096), (240, 3292), (262, 3292), (278, 3292), (294,
    3292), (310, 3292), (326, 3292)), ((14, 1, 75497504), (30, 1, 75497504), (46, 1, 75497504), (62, 1, 75497504), (78, 1, 75497504), (94, 1, 75497504), (110, 1,
    75497504), (126, 1, 75497504), (142, 1, 75497504), (158, 1, 75497504), (174, 1, 75497504), (190, 1, 75497504), (204, 0, 20447400), (246, 1, 20447400), (252,
    1, 75497504), (268, 1, 75497504), (284, 1, 75497504), (300, 1, 75497504), (316, 1, 75497504))), (213964, 24,
    'd0ed02095aa44d4861c8c6e5a722809c614d4c2c1099e0a038781a66e4e2efd0', ((8, 1246208), (20, 1246208)), ((0, 3, 41943044), (6, 1, 20582556), (12, 3, 33554436), (18,
    1, 20597532))), (1246208, 44, '814bda3d3b59b0a6464484e1ae5ac4c1b103c89e1113f1b68b7e36b0c2d9c0bd', ((34, 8216),), ((8, 5, 20477184),)), (1236840, 88,
    'd768ac3eba79b42e3daef055373c4d3f11f451080cf52e745ba825bf78b2db99', (), ((2, 1, 20450186), (14, 7, 20477184)))], 'direct16':[(3870, 22,
    'ed53e086938e1aeb91d72b35277752e8eb1f6828af3b88846da5cd3489596375', (), ((0, 0, 1314), (2, 1, 75497600), (10, 1, 42074112))), (3900, 84,
    'cd397efe58fb9a4eaa289a0909dc7d9549d19758ded41a1e5c8cae982b7f0235', ((58, 8468),), ((4, 6, 4195544), (68, 1, 50333296), (76, 1, 50333296))), (1889392, 122,
    '6305844a0e8a1f30feb5354ef8157dc6ee1ad28a4b37e40e9aa83ab1748af119', ((6, 2151240), (112, 2151268)), ((10, 2, 21084236), (22, 2, 42074112), (92, 2, 21084236),
    (104, 2, 42074112))), (1377104, 24, 'e0d11861734d19b5b65d8168ccaa7585d50cd8d37a7a8d1af23f86c7841c9407', ((8, 101756),), ((2, 7, 42074112),)), (1377132, 32,
    '8044cf6005b2b5828f512f18ab59150175d49cd1f9d3dfe294def016173a8e66', ((12, 101756),), ((2, 7, 42074112),))], 'half43':[(1560, 214,
    'a875fda0e05e9a3e06ddab6ff86ebef57eba121bb0fd0752ae95243d9a68d0d6', (), ((34, 1, 65535), (50, 5, 50333184), (110, 3, 5476), (160, 3, 65535))), (1788, 66,
    '8beec5a7db390027033bb8475ec51a8584c7b66d1939228a28f71f300e1fcc1f', ((4, 1864),), ((2, 7, 16778670), (8, 0, 50333184))), (1864, 246,
    '3f466da0a9de2fa919a2953aca593270efbbbce95a94220212132af4c01ba471', ((26, 5140), (62, 5140), (74, 5140), (86, 5140)), ((2, 1, 50333296), (8, 1, 50333296), (24,
    0, 30000), (60, 0, 50000), (72, 0, 50000), (84, 0, 50000)))]}

def find_legacy_lcd_profile(image: bytes, ram_base: int, ram_size: int) -> str | None:
    if (not isinstance(image, bytes) or type(ram_base) is not int or type(ram_size) is not int or ram_size <= 0 or ram_base < 0 or ram_base + ram_size >
        0x100000000):
        return None
    # Exact immutable source identity: the byte-pair boot canvas is currently
    # closed for one supplied image only. Both raw and FF-padded loader images
    # must preserve every byte; the guest stream supplies all displayed pixels.
    raw_size = 0x7ffff0
    byte565_boot = (ram_base == 0x1000000 and ram_size == 0x800000 and len(image) in (raw_size, raw_size + 16) and (len(image) == raw_size or image[raw_size:]
        == b"\xff" * 16) and hashlib.sha256(image[0x97590: 0x9760c]).hexdigest() == "baca6df280c63bba679ad60d3c828af8ac0e99ca63b2d64552a9699ce3cd08ef" and
        hashlib.sha256(image[:raw_size]).hexdigest() == "ab2e08c6bd92324e662b97741222f4a2fb5f9aec6870243cecd529af49fe74d2")
    matches = []
    for protocol, rows in _SPECS.items():
        if protocol == "byte565_boot" and not byte565_boot:
            continue
        valid = True
        for at, size, digest, calls, literals in rows:
            if (not 0 <= at <= len(image) - size or hashlib.sha256(image[at:at+size]).hexdigest() != digest or any(facts_for(image).thumb_call_target(at+off) !=
                target for off,target in calls) or any(facts_for(image).thumb_literal_value(at+off, reg) != value for off,reg,value in literals)):
                valid = False
                break
        if not valid:
            continue
        spans = { "byte565_boot": ((0x1003264, 1),), "column16": ((0x12196a4, 2), (0x1214214, 10), (0x1335bbe, 0x5000), (0x13f70b4, 4), (0x13f6ce8, 4)),
            "byte31": ((0x13800a1, 8), (0x1387500, 0x20), (0x13a109c, 0x3a80), (0x13a4b1c, 0x3a80)), "direct16": ((0x141b84c, 4),), "half43": ((0x10005ae,
            0x9000),), }[protocol]
        if not all(ram_base <= at <= ram_base + ram_size - size for at,size in spans):
            continue
        if protocol == "direct16" and len(image) < 0x413358:
            continue
        if protocol == "byte31" and len(image) < 0x2cb9c8:
            continue
        matches.append(protocol)
    if (match(image, _COLUMN16_BOOT) and all(facts_for(image).thumb_call_target(at) == target for at, target in ((0xC22, 0x5788), (0xC2A, 0x2614), (0xC80,
        0x2614), (0xC8A, 0x2614), (0xCD4, 0x2614), (0xCF2, 0x2614), (0xCFE, 0x2614))) and all(facts_for(image).thumb_literal_value(at, reg) == value for at, reg,
        value in ((0xC20, 1, 0x6048), (0xC7E, 0, 0x14C08), (0xC88, 0, 0x13880), (0xCDE, 5, 0x10021C2), (0xCEE, 4, 3000), (0xDD2, 4, 0x5BD4), (0xDF4, 5, 0xFFFF),
        (0xE5A, 7, 0x42B852), (0x1B4424, 0, 0x102B818), (0x1B4448, 2, 0x119E2F4))) and all(ram_base <= at <= ram_base + ram_size - size for at, size in ((0x10021C2,
        1), (0x102B818, 0x20), (0x119E2F4, 0xA000))) and len(image) >= 0x42B852 + 0xA000):
        matches.append("column16")
    return matches[0] if len(matches) == 1 else None
