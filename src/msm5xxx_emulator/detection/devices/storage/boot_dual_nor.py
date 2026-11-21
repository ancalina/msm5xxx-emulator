"""Source-linked boot NOR and SDRAM command sequence."""

REQUIRES = {
    'high_stack_irq_boot_ram': ('memory.irq_boot', 'high_stack_irq_boot_ram'),
    'find_indexed28_boot': ('display.indexed28_boot', 'find_indexed28_boot'),
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


_NOR_WIDE = bytes.fromhex('30b5c30660241c80dc01240e1c80ac241c80dc43e401240e1c807b241c80e9241c80244d03241d432c80234cc0000419216321493031401802717020188019880906fbd550201880ff20188030bd')
_TABLE_WIDE = bytes.fromhex('0202020206010505000000006e6e5050131328286e6e50501313141401010101000000001414141401010101')


def has_boot_dual_nor(image: bytes) -> bool:
    if high_stack_irq_boot_ram(image) != (0x187f0000, 0x10000):
        return False
    panel = find_indexed44_boot(image)
    wide = panel is None
    if wide:
        panel = find_indexed28_boot(image)
    if panel is None:
        return False
    window = panel['evidence'][0]['span'][0]
    dram, nor, table = ((window - 0x13ac, window + 0x7ffe, window + 0x50e0) if wide
                        else (window - 0x1f26, window + 0x65ac, window + 0x4036))
    nor_code, table_code = (_NOR_WIDE, _TABLE_WIDE) if wide else (_NOR, _TABLE)
    if min(dram, nor, table) < 0:
        return False
    return (image[dram:dram + len(_DRAM)] == _DRAM
            and image[nor:nor + len(nor_code)] == nor_code
            and image[table:table + len(table_code)] == table_code
            and image[dram + 0x80:dram + 0x84] == bytes.fromhex('a6221200'))
