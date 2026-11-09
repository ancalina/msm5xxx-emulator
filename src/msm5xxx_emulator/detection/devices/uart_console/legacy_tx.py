"""Temporary bounded code-signature checks for unmigrated TX families."""

from ...facts import facts_for


def byte_code(image: bytes, at: int, mask: str) -> bool:
    if at < 0 or at & 1 or at + len(mask)//2 > len(image):
        return False
    if any(token != '??' and image[at+i//2] != int(token,16)
           for i in range(0,len(mask),2) for token in (mask[i:i+2],)):
        return False
    facts = facts_for(image)
    if not facts.view.covers(at, len(mask) // 2):
        return False
    off = 0
    while off < len(mask)//2-1:
        if mask[off*2:off*2+8] == '????????':
            target = facts.thumb_call_target(at+off)
            if target is None or not 0 <= target < len(image)-1:
                return False
            off += 4
            continue
        word = int.from_bytes(image[at+off:at+off+2], 'little')
        if word & 0xf800 == 0x4800 and facts.thumb_literal_value(at+off, word>>8&7) is None:
            return False
        off += 2
    return True


def called_code_candidates(image, calls, mask, matcher):
    by_target = {}
    for site, target in calls:
        if (target not in by_target and target >= 0 and not target & 1
                and matcher(image, target, mask)):
            by_target[target] = []
        if target in by_target:
            by_target[target].append(site)
    return by_target
