"""Identify the byte-wide DCS boot-clear writer and its data port."""


def find_byte_dcs_writer(image):
    # The called boot clear sets two 128-pixel windows, then streams byte pairs.
    header = bytes.fromhex(
        '2a204107087011480d4f427803923a717f323a712b220a700078029038717f3038712c200870')
    pixels = bytes.fromhex('05e0ff233b713b7101300004000c9042f7d3')
    found = []
    start = 0
    while (pos := image.find(header, start)) >= 0:
        if (image[pos + 62:pos + 66] == bytes.fromhex('00001e40')
                and image[pos + 90:pos + 108] == pixels):
            found.append((pos, 108))
        start = pos + 1
    # This driver has separate byte and halfword port accessors. Its boot
    # initialization configures the same 128 by 128 DCS panel.
    accessors = bytes.fromhex(
        '0121890708707047a349087170470120800700787047a04800797047'
        '01218907088070479c49888070470120800700887047994880887047'
        '01040a0e96490a7108717047')
    loads = (8, 22, 36, 50, 60)
    start = 0
    while (pos := image.find(accessors[:8], start)) >= 0:
        candidate = image[pos:pos + len(accessors)]
        if (pos % 2 == 0 and len(candidate) == len(accessors)
                and all(a == b or i in loads
                        for i, (a, b) in enumerate(zip(candidate, accessors)))):
            addresses = [((pos + i + 4) & ~3) + candidate[i] * 4 for i in loads]
            if (len(set(addresses)) == 1
                    and image[addresses[0]:addresses[0] + 4] == bytes.fromhex('00001e40')):
                found.append((pos, len(accessors)))
        start = pos + 1
    return tuple(found)
