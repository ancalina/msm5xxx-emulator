"""Firmware evidence for the high-stack IRQ boot hardware."""

import struct

_IRQ = bytes.fromhex('d2f021e304e0a0e1d3f021e330ff2fe10010e0e3010050e10400001a')
_IRQ_ZERO = _IRQ[:16] + bytes.fromhex('000050e3')
_STACKS_187 = bytes.fromhex('00d27f1890e77f1800c97f1890db7f1890e87f1800da7f18')
_STACKS_10FF = bytes.fromhex('0092ff1090a7ff100089ff10909bff1090a8ff10009aff10')
_BOOT_10FF = bytes.fromhex('f8b59e49002008608904c8600122d2024a609b4952040a60ca60914901220a70087090492020d03108828e4896495038816011214160')
_STACKS_300 = bytes.fromhex('00120330905f033000090330905303309060033000520330')
_BOOT_187 = bytes.fromhex('f8b5bf49002008608904c8600121c9020b22d2065160bb4a49041160d160b24a')
_BOOT_300 = tuple(bytes.fromhex(x) for x in (
    'b0b55148002404605149072008724a48012505614f492020088200f0adf9',
    'b0b55048002404605049072008724948012505614e492020088200f0abf9',
))


def requires_armv5(image: bytes) -> bool:
    """Find linked ARM interworking calls that require ARMv5."""
    for signature in (_IRQ, _IRQ_ZERO):
        constructor = image.find(signature)
        while constructor >= 0:
            if not constructor & 3:
                return True
            constructor = image.find(signature, constructor + 1)
    # shortcut: only early boot wrappers are scanned; upgrade when later code is linked to reset.
    limit = min(len(image), 0x10000)
    prefix = b'\x00\x40\x2d\xe9'
    calls = {}
    position = image.find(prefix, 0, limit)
    while position >= 0:
        if not position & 3 and position + 20 <= limit:
            _, call, result, load, branch = struct.unpack_from('<5I', image, position)
            if (call & 0xfe000000 == 0xfa000000 and
                    result & 0xfffff000 == 0xe3a00000 and load == 0xe89d0002 and
                    branch & 0xff000000 == 0xea000000):
                displacement = ((call & 0xffffff) << 2) | ((call >> 23) & 2)
                if displacement & 0x02000000:
                    displacement -= 0x04000000
                target = position + 12 + displacement
                delta = (branch & 0xffffff) << 2
                if delta & 0x02000000:
                    delta -= 0x04000000
                continuation = position + 24 + delta
                if (0 <= target <= len(image) - 4 and
                        image[target:target + 4] not in (b'\0' * 4, b'\xff' * 4) and
                        0 <= continuation < len(image)):
                    key = target, continuation
                    previous = calls.get(key)
                    if previous is not None and position - previous <= 0x80:
                        return True
                    calls[key] = position
        position = image.find(prefix, position + 1, limit)
    return False


def constructor_stack_page(image: bytes) -> int | None:
    """Find a constructor stack page linked to a Thumb push target."""
    pages = set()
    for signature in (_IRQ, _IRQ_ZERO):
        position = image.find(signature)
        while position >= 0:
            if position >= 20 and not position & 3:
                start = position - 20
                words = struct.unpack_from('<5I', image, start)
                if (words[0] & 0xfffff000 == 0xe59fd000 and
                        words[1] & 0xfffff000 == 0xe59f4000 and
                        words[2:4] == (0xe4940004, 0xe3500000) and
                        words[4] & 0xff000000 == 0x0a000000):
                    stack_literal = start + 8 + (words[0] & 0xfff)
                    table_literal = start + 12 + (words[1] & 0xfff)
                    if stack_literal <= len(image) - 4 and table_literal <= len(image) - 4:
                        stack = struct.unpack_from('<I', image, stack_literal)[0]
                        table = struct.unpack_from('<I', image, table_literal)[0]
                        # shortcut: only observed stack tops are supported; upgrade when more SRAM maps are proven.
                        if (stack in (0xffff2000, 0x78002000, 0x01ff0000) and
                                not table & 3 and table <= len(image) - 4):
                            for index in range(4):
                                at = table + index * 4
                                if at > len(image) - 4:
                                    break
                                target = struct.unpack_from('<I', image, at)[0]
                                if not target:
                                    break
                                address = target & ~1
                                if (target & 1 and address <= len(image) - 2 and
                                        struct.unpack_from('<H', image, address)[0] & 0xff00 == 0xb500):
                                    pages.add(stack - 0x1000)
                                    break
            position = image.find(signature, position + 1)
    return next(iter(pages)) if len(pages) == 1 else None


def high_stack_irq_boot_ram(image: bytes) -> tuple[int, int] | None:
    irq = image.find(_IRQ)
    if irq < 0 or irq % 4 or image.find(_IRQ, irq + 1) >= 0:
        return None
    boot10 = image.find(_BOOT_10FF)
    if (image[irq + 0x130:irq + 0x134] == bytes.fromhex('0020ffff')
            and image[irq + 0x178:irq + 0x190] == _STACKS_10FF
            and boot10 >= 0 and boot10 % 2 == 0 and image.find(_BOOT_10FF, boot10 + 1) < 0):
        return (0x10ff0000, 0x10000)
    boot = image.find(_BOOT_187)
    if (image[irq + 0xf0:irq + 0xf4] == bytes.fromhex('0020ffff')
            and image[irq + 0x120:irq + 0x138] == _STACKS_187
            and boot >= 0 and boot % 2 == 0 and image.find(_BOOT_187, boot + 1) < 0
            and image[boot + 0x302:boot + 0x306] == bytes.fromhex('00160080')):
        return (0x187f0000, 0x10000)
    for initial, stacks in ((0x2d8, 0x314), (0x2f8, 0x340)):
        if (image[irq + initial:irq + initial + 4] != bytes.fromhex('0020ffff')
                or image[irq + stacks:irq + stacks + 24] != _STACKS_300):
            continue
        for code in _BOOT_300:
            boot = image.find(code)
            if boot < 0 or boot % 2 or image.find(code, boot + 1) >= 0:
                continue
            literal = ((boot + 6) & ~3) + image[boot + 2] * 4
            if image[literal:literal + 4] == bytes.fromhex('00160080'):
                return (0x30000000, 0x40000)
    return None
