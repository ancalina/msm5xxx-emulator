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
    return tuple(found)
