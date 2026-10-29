

"""Fail-closed finder for the admitted relocatable upper-NOR grammar."""
from __future__ import annotations

from .storage import (
    ADJACENT_AMD_X16_WRITER_PREFIX,
    _adjacent_amd_x16_writer_at,
    thumb_literal_value,
)


UPPER_FLASH_ADDRESS = 0x02800000
UPPER_FLASH_SIZE = 0x00800000
UPPER_FLASH_SECTOR_SIZE = 0x00010000
_CASE4 = bytes.fromhex("14a04860002088601320c004c8600120c00508610120c0024a618861")
_INIT_HEAD = bytes.fromhex("90b4184a9268174b5b689a4227d2154b9b68002b01d100270ae0")
_INIT_STORE = bytes.fromhex("0c4b9c681c2363430a4c24681a19516090604318013bd36017617b18013b5361c31b9361")
_TRANS_HEAD = bytes.fromhex("021c00210c488068814213d202e0481c011cf7e71c204843074b1b68c01840699042f4d9")
_TRANS_TAIL = bytes.fromhex("1c204843034b1b68c0188069801870470020fce7")
_MATERIAL_HEAD = bytes.fromhex("f8b5041c002c03d10020f8bc08bc1847")
_MATERIAL_MASK = "f8b5041c002c03d10020f8bc08bc18472f4920684968884201d30020f5e77423206858432a49096847183868431c01d00020eae7a068400f02d301208002a0612422211c381c????????fd1d1d35fe1d2d36e068????????00901e49b868084328600098686060692169????????a8606069e8601749b8680843306000987060a0692169????????b060a069f06000207864b864f91d39318881f91d3931c881f91d39310882f91d393148827865b865f86538667866b866f8660120f91d593108820449b8680843b86001209de70000????ba0100000080f7b581b00e1c151c274901984968884204d3002004b0f0bc08bc18477423019858432149096847183868431c01d10020f0e7b868000801d20020ebe7700804d2b868c00f01d30020e4e7b0080fd3bc6a3a8c201cf969????????002822d1????????1249ff200530????????1ae06b1c0dd10024f86aa04214d902e0601c041cf8e7f81d1d30211c????????f6e7f86aa84205d9f81d1d30291c????????01e00020b7e70120b5e7"
_WRITER_MASK = "feb5071c0c1c151c????????01906c4880890121890308436a49888169488089096808800198002801d1????????3e0b3603aa200101711848815520152189017118888220205521490171184881002d00d89ae0780813d378084000071c388800ab18812078611c0c1c5872a020388018893880681e051c01205249087024e0012d12d92078611c0c1c00ab18722078611c0c1c5872a020388018893880a81e051c0220484908700fe0388800ab18812078611c0c1c1872a020388018893880681e051c03203f4908703888019080230198184000ab198980231940884200d150e001988009f0d3388801900198184000ab198980231940884200d142e09020388000203880????????2e480078012804d0022809d0032810d10be0601e041c681c051c781c071c08e0a01e041ca81c051c03e0601e041c681c051c????????00901f4880890121890308431d4988811c488089096808800098002801d1????????3e0b3603aa20010171184881552015218901711888822020552149017118488164e7b81c071c61e79020308000203080????????01900a48808901239b0398430749888106488089096808800198002801d1????????0120febc08bc1847"
_INIT_SHAPES = tuple(bytes.fromhex(value) for value in (
    "0721c9041520c004", "0321490509204005", "0121c9050520c005",
))
_CALLER_WINDOW = bytes.fromhex("0d9005980e9006980f900798109000ab188c10ab988000ab588c10abd88009a800f037f8dbe712b090bc08bc184700b5")
_UPPER_X16_BUILDER_PREFIX = bytes.fromhex(
    "b0b40127bf02ba011f2464045503072800d384e001a31b5c"
)
_UPPER_X16_CAMERA_CASE = bytes.fromhex(
    "20a0486000208860ad200004c8600f20c004103185c11a481c395438c8615320"
    "0884012048840120b0bc7047"
)
_UPPER_X16_MAPPER_PREFIX = bytes.fromhex("80b50b4f02203968")
_UPPER_X16_ERASE_COMMAND = bytes.fromhex(
    "0024aa2318012018438155221521890161188a828026468143818a8230203880"
)


def _all(raw: bytes, needle: bytes) -> list[int]:
    result, at = [], 0
    while (at := raw.find(needle, at)) >= 0:
        result.append(at)
        at += 1
    return result


def _bl(raw: bytes, site: int) -> int | None:
    if not 0 <= site <= len(raw) - 4:
        return None
    first, second = int.from_bytes(raw[site:site + 2], "little"), int.from_bytes(raw[site + 2:site + 4], "little")
    if first & 0xF800 != 0xF000 or second & 0xF800 != 0xF800:
        return None
    offset = ((first & 0x7FF) << 12) | ((second & 0x7FF) << 1)
    return site + 4 + (offset - (1 << 23) if offset & (1 << 22) else offset)


def _mask(raw: bytes, start: int, encoded: str) -> bool:
    return (start >= 0 and start + len(encoded) // 2 <= len(raw)
            and all(token == "??" or raw[start + index] == int(token, 16)
                    for index, token in enumerate(
                        (encoded[index:index + 2] for index in range(0, len(encoded), 2)))))


def find_upper_nor(raw: bytes) -> tuple[bool, str]:
    """Return admission and the first fail-closed grammar gate."""
    enums = [case - 174 for case in _all(raw, _CASE4)
             if case >= 174 and raw[case - 146:case - 141] == bytes.fromhex("0316233649")]
    if len(enums) != 1:
        return False, "enumerator-case4"
    initializer = [at for at in _all(raw, _INIT_HEAD)
                   if raw[at + 48:at + 48 + len(_INIT_STORE)] == _INIT_STORE]
    if len(initializer) != 1:
        return False, "map-initializer"
    translator = [at for at in _all(raw, _TRANS_HEAD)
                  if raw[at + 36:at + 36 + len(_TRANS_TAIL)] == _TRANS_TAIL]
    if len(translator) != 1:
        return False, "translator"
    calls = [start + 8 for shape in _INIT_SHAPES for start in _all(raw, shape)
             if _bl(raw, start + 8) == initializer[0]]
    if len(calls) != 3 or calls != sorted(calls) or any(raw[site - 8:site] != shape for site, shape in zip(calls, _INIT_SHAPES)):
        return False, "three-map-calls"
    writer_anchor = bytes.fromhex(_WRITER_MASK[:16])
    writers = [at for at in _all(raw, writer_anchor) if _mask(raw, at, _WRITER_MASK)
               and all(_bl(raw, at + offset) is not None for offset in (8, 42, 262, 316, 350, 402, 436))]
    if len(writers) != 1:
        return False, "amd-writer"
    materials = [at for at in _all(raw, _MATERIAL_HEAD) if _mask(raw, at, _MATERIAL_MASK)
                 and (int.from_bytes(raw[at + 208:at + 212], "little")
                      & 0xFFFF0003) == 0x01BA0000
                 and all(_bl(raw, at + offset) is not None for offset in (70, 84, 106, 132, 302, 310, 320, 352, 370))
                 and _bl(raw, at + 84) == translator[0] and _bl(raw, at + 302) == writers[0]]
    if len(materials) != 1:
        return False, "materializer-links"
    window = calls[2] - 4
    enum_calls = [site for site in range(window, min(len(raw) - 3, window + 0x100), 2) if _bl(raw, site) == enums[0]]
    material_calls = [site for site in range(window, min(len(raw) - 3, window + 0x100), 2) if _bl(raw, site) == materials[0]]
    pairs = [(left, right) for left in enum_calls for right in material_calls
             if right - left == 56
             and raw[right - 32:right - 32 + len(_CALLER_WINDOW)] == _CALLER_WINDOW]
    if len(pairs) != 1 or pairs[0][0] < window:
        return False, "enumerator-materializer-loop"
    return True, "accepted"


# Ordered-map variant: all consumers must close before upper-bank ownership.
_MAPPED_UPPER_X16 = {
    "maps": (
        "0f21890429208004????????0321490509204005????????0121c9050520c005????????????????041c201c????????"
        "0027a74224da02e0781c071cf9e76946381c????????0028f6d0099701980a9002980b9003980c9004980d9005980e90"
        "06980f900798109000ab188c10ab988000ab588c10abd88009a8????????dbe7"
    , (8, 20, 32, 36, 44, 66, 122)),
    "init": (
        "90b4184a9268174b5b689a4227d2154b9b68002b01d100270ae0124b9c681c236343104c24681b19403b9b6b01331f1c"
        "0c4b9c681c2363430a4c24681a19516090604318013bd36017617b18013b5361c31b9361034b9b680133024ca36090bc"
        "70470000????????"
    , ()),
    "translate": (
        "021c00210c488068814213d202e0481c011cf7e71c204843074b1b68c01840699042f4d91c204843034b1b68c0188069"
        "801870470020fce7????????"
    , ()),
    "enum": (
        "b0b453240925ad040127bf02ba01052800d362e001a31b5c5b009f440215223548002fa048600120400788600f208004"
        "c86003200005103185c12a481c39c86160200884012044e027a048600120400788600020c8600d6122484a618f616130"
        "34e023a04860002088601b208004c86003200005103185c11a481c39b530c8616b200884042024e01ba0486001200007"
        "88600320c004cd60086112484a610338c86100228a61022008844a8412e014a048600020886027208004c8600120c005"
        "08610120c0024a6188610f48c8610c84022048840120b0bc70470020fbe7000043000000????????494d414745000000"
        "4d454449410000005245434f5244000043414d4552410000????????"
    , ()),
    "material": (
        "f8b5041c002c03d10020f8bc08bc18472f4920684968884201d30020f5e77423206858432a49096847183868431c01d0"
        "0020eae7a068400f02d301208002a0612422211c381c????????fd1d1d35fe1d2d36e068????????00901e49b8680843"
        "28600098686060692169????????a8606069e8601749b8680843306000987060a0692169????????b060a069f0600020"
        "7864b864f91d39318881f91d3931c881f91d39310882f91d393148827865b865f86538667866b866f8660120f91d5931"
        "08820449b8680843b86001209de70000????????00000080"
    , (70, 84, 106, 132)),
    "program": (
        "feb5071c0c1c151c????????01906c4880890121890308436a49888169488089096808800198002801d1????????3e0b"
        "3603aa200101711848815520152189017118888220205521490171184881002d00d89ae0780813d378084000071c3888"
        "00ab18812078611c0c1c5872a020388018893880681e051c01205249087024e0012d12d92078611c0c1c00ab18722078"
        "611c0c1c5872a020388018893880a81e051c0220484908700fe0388800ab18812078611c0c1c1872a020388018893880"
        "681e051c03203f4908703888019080230198184000ab198980231940884200d150e001988009f0d33888019001981840"
        "00ab198980231940884200d142e09020388000203880????????2e480078012804d0022809d0032810d10be0601e041c"
        "681c051c781c071c08e0a01e041ca81c051c03e0601e041c681c051c????????00901f4880890121890308431d498881"
        "1c488089096808800098002801d1????????3e0b3603aa20010171184881552015218901711888822020552149017118"
        "488164e7b81c071c61e79020308000203080????????01900a48808901239b0398430749888106488089096808800198"
        "002801d1????????0120febc08bc1847"
    , (8, 42, 262, 316, 350, 402, 436)),
    "write": (
        "ffb581b0041c151c0a9fe668b54204d3002005b0f0bc08bc1847e819b04200d9771b0020002c04d06068e168029a5143"
        "4018401900903a1c00980499????????002805d1????????02496c20????????381cdee7"
    , (60, 68, 76)),
    "boot": (
        "12040321c9041920c004????????012212040321090515200005????????01221204d1010520c005????????"
    , (10, 26, 40)),
    "erase": (
        "f8b5071c0d1c141c01231b049a4206d0db089c4203d00120f8bc08bc1847????????3f4a0126d189b6033143d181d189"
        "92681180002801d1????????????????374a01269189b60331439181918912681180002801d1????????ee190a3e3ee0"
        "????????aa2211017d186a8155231521890179188b8280226a81aa226a818b8230216981002801d1????????16e0????"
        "????00ab1888800910d3388818801888000a11d2????????f02155225201ba185181002801d1????????2fe0388800ab"
        "18801888000ae2d3f020688115a003c8????????15491648????????3f19be42bed8????????0e4f0126f989b6033143"
        "f981f989ba681180002801d1????????????????b98901239b039943b981b9893a681180002801d1????????00207be7"
    , (30, 56, 60, 86, 96, 136, 142, 164, 182, 208, 216, 226, 252, 256, 280)),
    "header": (
        "f0b594b000259f484468343400209d49496888659b494968c865002699484068c06bb04200d828e102e0701c061cf5e7"
        "0020002c03d06068e168714340180088c0430004000c139013988f4b984207d18c484068c06d01308a494968c865e4e7"
    , ()),
    "scan": (
        "90b500201c49c8608862????????041c0027a7422ad202e0781c071cf9e716480760381c????????1349486012484068"
        "0028f1d0????????0028edd10e4840688068400fe8d2????????0b48806a00280fd009480068????????002006498862"
        "????????0448806a0028d5d090bc08bc1847????????cfe7"
    , (10, 36, 52, 70, 86, 96, 114)),
    "lookup": (
        "011c0b484068814201d30020704774204843074a126880188068000801d20020f4e774204843024a12688018eee70000"
        "????????"
    , ()),
}


def _mapped_upper_amd_x16_at(raw: bytes) -> bool:
    positions = {}
    for name, (mask, calls) in _MAPPED_UPPER_X16.items():
        anchor = bytes.fromhex(mask.split("??", 1)[0])
        matches = [at for at in _all(raw, anchor)
                   if not at & 1 and _mask(raw, at, mask)
                   and all((target := _bl(raw, at + off)) is not None
                           and 0 <= target < len(raw) - 1
                           for off in calls)]
        if len(matches) != 1:
            return False
        positions[name] = matches[0]
    links = (("maps", 8, "init"), ("maps", 0x14, "init"),
             ("maps", 0x20, "init"), ("maps", 0x42, "enum"),
             ("maps", 0x7a, "material"), ("material", 0x54, "translate"),
             ("write", 0x3c, "program"), ("boot", 0xa, "erase"),
             ("boot", 0x1a, "erase"), ("boot", 0x28, "erase"),
             ("scan", 0x24, "lookup"), ("scan", 0x46, "header"),
             ("scan", 0x60, "header"))
    if any(_bl(raw, positions[left] + off) != positions[right]
           for left, off, right in links):
        return False
    def literal(name: str, offset: int, register: int) -> int | None:
        return thumb_literal_value(raw, positions[name] + offset, register)
    control = literal("init", 2, 2)
    devices = literal("material", 0x10, 1)
    header = literal("header", 6, 0)
    bus = literal("program", 0xe, 0)
    if (any(value is None or value & 3 or not 0x01000000 <= value < 0x02000000
            for value in (control, devices, header, bus))
            or literal("translate", 4, 0) != control
            or literal("lookup", 2, 0) != devices
            or literal("scan", 4, 1) != header
            or literal("erase", 0x22, 2) != bus):
        return False
    # The bus ownership and interrupt helpers must be shared by both primitives.
    if (_bl(raw, positions["program"] + 8) != _bl(raw, positions["erase"] + 0x1e)
            or _bl(raw, positions["program"] + 0x2a)
               != _bl(raw, positions["erase"] + 0x38)):
        return False
    return True


def _legacy_upper_amd_x16_nor(raw: bytes) -> tuple[int, int, int] | None:
    """Return the previously admitted exact compiler grammar."""
    builders = [
        at for at in _all(raw, _UPPER_X16_BUILDER_PREFIX)
        if (raw[at + 0xCC:at + 0xCC + len(_UPPER_X16_CAMERA_CASE)]
            == _UPPER_X16_CAMERA_CASE
            and raw[at + 0x150:at + 0x15C] == b"CAMERA\0\0LMS\0")
    ]
    mappers = [
        at for at in _all(raw, _UPPER_X16_MAPPER_PREFIX)
        if (raw[at + 0x0C:at + 0x16]
            == bytes.fromhex("a52109047b2000047a68")
            and raw[at + 0x1A:at + 0x24]
            == bytes.fromhex("0121c9050520c0057a68")
            and raw[at + 0x28:at + 0x30]
            == bytes.fromhex("80bc08bc01201847"))
    ]
    materials = [
        at for at in _all(raw, bytes.fromhex("b0b592b0"))
        if (raw[at + 8:at + 0x0C] == bytes.fromhex("051c281c")
            and raw[at + 0x10:at + 0x14] == bytes.fromhex("1c491d48")
            and raw[at + 0x22:at + 0x26] == bytes.fromhex("041c201c")
            and raw[at + 0x2A:at + 0x3C]
            == bytes.fromhex("0027a74224da02e0781c071cf9e76946381c"))
    ]
    writers = [
        at for at in _all(raw, ADJACENT_AMD_X16_WRITER_PREFIX)
        if _adjacent_amd_x16_writer_at(raw, at)
    ]
    if any(len(group) != 1 for group in (
            builders, mappers, materials, writers)):
        return None
    builder, mapper, material, writer = (
        builders[0], mappers[0], materials[0], writers[0]
    )
    bridge = _bl(raw, mapper + 0x50)
    erase = _bl(raw, mapper + 0x5A)
    wrapper_starts = (0x3A, 0x44, 0x4E, 0x58)
    if (_bl(raw, material + 0x1A) != mapper
            or _bl(raw, material + 0x3C) != builder
            or any(raw[mapper + offset:mapper + offset + 2] != b"\0\xb5"
                   or raw[mapper + offset + 6:mapper + offset + 10]
                   != bytes.fromhex("08bc1847")
                   for offset in wrapper_starts)
            or bridge is None
            or raw[bridge:bridge + 2] != b"\0\xb5"
            or raw[bridge + 6:bridge + 10] != bytes.fromhex("08bc1847")
            or _bl(raw, bridge + 2) != writer
            or erase is None
            or raw[erase:erase + 4] != bytes.fromhex("f0b5071c")
            or raw[erase + 0x94:erase + 0x94 + len(_UPPER_X16_ERASE_COMMAND)]
            != _UPPER_X16_ERASE_COMMAND):
        return None
    return UPPER_FLASH_ADDRESS, UPPER_FLASH_SIZE, UPPER_FLASH_SECTOR_SIZE


def find_upper_amd_x16_nor(raw: bytes) -> tuple[int, int, int] | None:
    """Admit one closed compiler grammar, rejecting conflicting ownership."""
    legacy = _legacy_upper_amd_x16_nor(raw)
    mapped = _mapped_upper_amd_x16_at(raw)
    if legacy is not None:
        return None if mapped else legacy
    return ((UPPER_FLASH_ADDRESS, UPPER_FLASH_SIZE, UPPER_FLASH_SECTOR_SIZE)
            if mapped else None)
