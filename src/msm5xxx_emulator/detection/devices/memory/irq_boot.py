"""Firmware evidence for the high-stack IRQ boot hardware."""

_IRQ = bytes.fromhex('d2f021e304e0a0e1d3f021e330ff2fe10010e0e3010050e10400001a')
_STACKS_187 = bytes.fromhex('00d27f1890e77f1800c97f1890db7f1890e87f1800da7f18')
_STACKS_300 = bytes.fromhex('00120330905f033000090330905303309060033000520330')
_BOOT_187 = bytes.fromhex('f8b5bf49002008608904c8600121c9020b22d2065160bb4a49041160d160b24a')
_BOOT_300 = tuple(bytes.fromhex(x) for x in (
    'b0b55148002404605149072008724a48012505614f492020088200f0adf9',
    'b0b55048002404605049072008724948012505614e492020088200f0abf9',
))


def high_stack_irq_boot_ram(image: bytes) -> tuple[int, int] | None:
    irq = image.find(_IRQ)
    if irq < 0 or irq % 4 or image.find(_IRQ, irq + 1) >= 0:
        return None
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
