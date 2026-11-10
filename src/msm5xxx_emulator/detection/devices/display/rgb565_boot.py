"""Complete copied ARM producers for the 120 by 133 boot raster."""
from __future__ import annotations
import hashlib
import struct

_TEMPLATES = ((((5882232, 8, '63bce64790470434b68f244981712112d0e0ed7e9abb401ebaa5ed8e8073efa6'), (5882232, 180,
    '60b5b6b0beefa8ed2c843ace00d4145feeb5bf26c6a05d4a2ed28f903b498c8c'), (5882436, 8, '4b34ae5de5f28c8742bbb23ffed6de962b4a80611851b3d75bbcbfe2368f2c72'), (5882436,
    164, '972a1a07fea1e96a956b383306050751c1ca4c49923311a0c5b20cdb9eaffedb'), (5882624, 8, 'a54d2049d6ca221a337bf6c1af11a922c8d8b094337425648e14d2bee116dc0d'),
    (5882624, 368, 'a9550aeb2730a8168723b55a07b948b49733f22039c2a6e8d3993735cec20c79'), (5883164, 204,
    'b53bfcbd80d9b65036f9023a89096a53540b6048a2f02195894dabad20a44a67'), (5896264, 8, 'e8c968b1c0e2eb8c47edf56001d7a29395359d831cfa8528bd272323b413e77c'), (5896276,
    8, 'e8c968b1c0e2eb8c47edf56001d7a29395359d831cfa8528bd272323b413e77c')), ((5880952, 17568692), (5880960, 58783064), (5881248, 50000), (5882412, 10000), (5882416,
    285), (5882420, 646), (5882424, 1030), (5882428, 1661), (5882432, 3139), (5882600, 4116), (5882604, 17565516), (5882608, 17567672), (5882612, 5126), (5882616,
    5637), (5882620, 6446), (5882992, 1803), (5882996, 7971), (5883148, 5402), (5883152, 6169), (5883368, 17568332), (5883372, 1149), (5883376, 1412)), (14044,
    5836348, 58720256, 61784), (16520, 5762208, 17539072, 74140), 17568332, 5791468), (((6964856, 8,
    '63bce64790470434b68f244981712112d0e0ed7e9abb401ebaa5ed8e8073efa6'), (6964856, 180, '9a77b7e4e72cbbb9b665a28a57795856a65d4a8df34e885d5bdea6d797d6ef21'), (6965060,
    8, '4b34ae5de5f28c8742bbb23ffed6de962b4a80611851b3d75bbcbfe2368f2c72'), (6965060, 164, 'f16ad1625e0382f0fb325fde068305dfd7758479224f3eb592f662c329575aa9'),
    (6965248, 8, 'a54d2049d6ca221a337bf6c1af11a922c8d8b094337425648e14d2bee116dc0d'), (6965248, 368,
    'a9550aeb2730a8168723b55a07b948b49733f22039c2a6e8d3993735cec20c79'), (6965788, 204, '143df375c559d1bb2be18c5a14f1c05a81e89b154fdb2eda98b67c4915333f3d'), (6970332,
    8, 'e8c968b1c0e2eb8c47edf56001d7a29395359d831cfa8528bd272323b413e77c'), (6970344, 8, 'e8c968b1c0e2eb8c47edf56001d7a29395359d831cfa8528bd272323b413e77c')), ((6963576,
    17578668), (6963584, 58777516), (6963872, 50000), (6965036, 10000), (6965040, 285), (6965044, 646), (6965048, 1030), (6965052, 1661), (6965056, 3139), (6965224,
    4116), (6965228, 17562873), (6965232, 17577648), (6965236, 5126), (6965240, 5637), (6965244, 6446), (6965616, 1803), (6965620, 7971), (6965772, 5402), (6965776,
    6169), (6965992, 17578308), (6965996, 1149), (6966000, 1412)), (14620, 6915984, 58720256, 56228), (16520, 6838380, 17539072, 77604), 17578308, 6877616))

def find_rgb565_boot_profile(image: bytes):
    if not isinstance(image, bytes):
        return None, 'rgb565-boot-primary-bytes-required'
    for spans, pools, tcm, maincopy, framebuffer, pixels in _TEMPLATES:
        if any(not 0 <= at <= len(image)-size or hashlib.sha256(image[at:at+size]).hexdigest() != digest for at, size,digest in spans):
            continue
        if any(not 0 <= at <= len(image)-4 or struct.unpack_from('<I',image,at)[0] != value for at,value in pools):
            continue
        if any(not 0 <= table <= len(image)-12 or struct.unpack_from('<III',image,table) != (source,target,size) or not 0 <= source <= len(image)-size for table,source,target,size
            in (tcm,maincopy)):
            continue
        if not maincopy[1] <= pixels <= maincopy[1]+maincopy[3]-120*133*2:
            continue
        return dict(signature='source-arm-packed-rgb565-boot120-v1', admission='temporary-evidence-gated',width= 120,height=133, pixel_port=0x02000000,command_port=0x02000002,access_width=2,
            code_intervals=tuple((at,at+size)for at,size,digest in spans), literal_intervals=tuple((at,at+4)for at,value in pools), data_intervals=((tcm[0],tcm[0]+12),(maincopy[0],maincopy[0]+12),
            (pixels,pixels+120*133*2)), ram_intervals=((maincopy[2],maincopy[2]+maincopy[3]),), iram_intervals=((tcm[2],tcm[2]+tcm[3]),), framebuffer=framebuffer,physical_viewport=None), 'source-rgb565-boot-candidate'
    return None, 'rgb565-boot-source-unclosed'
