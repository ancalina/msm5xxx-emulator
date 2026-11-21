"""Source-linked boot NOR and SDRAM command sequence."""

REQUIRES = {
    'high_stack_irq_boot_ram': ('memory.irq_boot', 'high_stack_irq_boot_ram'),
    'find_indexed44_boot': ('display.indexed44_writer', 'find_indexed44_boot'),
}

_DRAM = bytes.fromhex(
    '70b51f4cc30623431e1c1e4b0124a4039c605c611c4d358000259d605c611b4b'
    'c000c3181963194930314018027170bd')
_NOR = bytes.fromhex(
    '30b5c30660241c801c02240e1c80ac241c80dc432402240e1c807b241c80e924'
    '1c800e4d03241d432c800d4cc000041921630b493031401802717020188019880906'
    'fbd550201880ff20188030bd')
_TABLE = bytes.fromhex(
    '0202020201010505000000006e6e5050131328286e6e50501313141401010101'
    '00000000141414140101010100000000')


def has_boot_dual_nor(image: bytes) -> bool:
    if high_stack_irq_boot_ram(image) != (0x187f0000, 0x10000):
        return False
    panel = find_indexed44_boot(image)
    if panel is None:
        return False
    window = panel['evidence'][0]['span'][0]
    dram, nor, table = window - 0x1f26, window + 0x65ac, window + 0x4036
    if min(dram, nor, table) < 0:
        return False
    return (image[dram:dram + len(_DRAM)] == _DRAM
            and image[nor:nor + len(_NOR)] == _NOR
            and image[table:table + len(_TABLE)] == _TABLE
            and image[dram + 0x80:dram + 0x84] == bytes.fromhex('a6221200'))
