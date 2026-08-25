

"""Fail-closed finder for the admitted relocatable upper-NOR grammar."""
from __future__ import annotations

from .storage import (
    ADJACENT_AMD_X16_WRITER_PREFIX,
    _adjacent_amd_x16_writer_at,
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
                 and raw[at + 208:at + 210] in (bytes.fromhex("cc65"), bytes.fromhex("e865"))
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


def find_upper_amd_x16_nor(raw: bytes) -> tuple[int, int, int] | None:
    """Return one temporary exact mapped upper AMD x16 NOR profile."""
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
