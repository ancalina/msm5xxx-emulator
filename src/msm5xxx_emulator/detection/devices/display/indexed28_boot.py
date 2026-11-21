"""Source proof for the NOR boot indexed LCD writer."""
from msm5xxx_emulator.detection.arm import thumb_bl_target

_WINDOW = bytes.fromhex('30b5141c603421252d0160330522d2061580f74d2880f74810802980013010802c80013010802b8030bd')
_CLEAR = bytes.fromhex('ff2340330022ef210020fff790fd0021002000f04ff8b8082080ff204130311c2f4a04e0f02400e00a80013cfcd20138f8d2')
_CURSOR = bytes.fromhex('01235b0260310522d2061380094b18800948108019807047')


def find_indexed28_boot(image):
    pos = image.find(_WINDOW, 0, min(len(image), 0x100000))
    if pos < 0 or pos % 2 or image.find(_WINDOW, pos + 1, min(len(image), 0x100000)) >= 0:
        return None
    clear, cursor, literal = pos + 0x4d2, pos + 0x586, pos + 0x3f0
    if (image[clear:clear + len(_CLEAR)] != _CLEAR
            or image[cursor:cursor + len(_CURSOR)] != _CURSOR
            or image[literal:literal + 4] != bytes.fromhex('00000828')
            or thumb_bl_target(image, clear + 10) != pos
            or thumb_bl_target(image, clear + 18) != cursor):
        return None
    return {'protocol': 'indexed28-rgb565', 'width': 240, 'height': 320,
            'x_origin': 0, 'y_origin': 96, 'command_port': 0x28000000,
            'data_port': 0x28080000,
            'evidence': [{'span': [pos, len(_WINDOW)], 'extra_spans': [[literal, 4]]},
                         {'span': [clear, len(_CLEAR)]}, {'span': [cursor, len(_CURSOR)]}]}
