"""Shared upload table bounds and page projection helpers."""

_PAGE = 0x1000
_BANK_SECTION = 0x10000
_DESTINATION_FAMILIES = ((0x08000000, 0x09000000),
                         (0x50000000, 0x59000000))


def _merged_pages(intervals):
    rounded = sorted((low & ~(_PAGE - 1), (high + _PAGE - 1) & ~(_PAGE - 1))
                     for low, high in intervals)
    sections = {}
    for low, high in rounded:
        while low < high:
            section = low & ~(_BANK_SECTION - 1)
            end = min(high, section + _BANK_SECTION)
            if section in sections:
                sections[section] = (min(sections[section][0], low),
                                     max(sections[section][1], end))
            else:
                sections[section] = (low, end)
            low = end
    return [sections[key] for key in sorted(sections)]
