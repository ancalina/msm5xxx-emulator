"""A310 primary page raster selected through a source-owned RAM port pair.

The alternate 02800000 branch is not owned by this observer. Primary ownership
requires the full observed clear and AF sequence on 02000000/02000002.
"""
from __future__ import annotations
import hashlib
import struct
from .arm import arm_b_target

_SPANS = ((1024, 8, '39633fe8ffb218b9ff65cc18abf7d6a16688ae5721bcc36b4edfe72a6efe4a2b'),
 (1412, 64, '4adad922c7f87bc4b69bfff63203b2caacb5a002cec884c3edb8d0bcaf386aa8'),
 (1508, 8, '12460344f558f6426c0807ad788e2238bca96e2ba4ddbe8da835767f5882f494'),
 (1508, 258, '00ecc4363fdeedef09dda00bbd81cf2313d716c24a738dd12d9bc56072ce5334'),
 (3156, 8, 'e0fbb01694e21b83788128dfccc51f16b1036ecb76e30c9e4f6a18f0887fbc4d'),
 (3288, 8, 'bfdef803e2edc28fc1e8da777f67137130edb0232db5e82cb5daab044c714059'),
 (3340, 82, '035ad9d6f5ef39a1964baa69a768bd9e74d2e3584dea3c2590fdcf56e3256854'),
 (3496, 8, '19548fc08a1ccdcd30598f7fc442dc6d5c6a11632e91599ac709bc51101fe34b'),
 (3620, 8, 'af95111fa2c496207039383cc4152c8226c07a92ede3517768045a079d4d9041'),
 (3964, 8, '1ca776e9659ed365ae3f55c759ac0d32dd082c716b10838d41b58c2e553404dc'),
 (3976, 8, '4c0eddc8721eb4ccd9d9a25470d0a8e59b201d2335fa211608c296f34286ba65'),
 (3988, 8, '480bafdad245a76ff13bb8646eec20d4d2eee6563a025f1a3229adb0753a3020'),
 (3988, 36, '8b2f4dc7efebff4cf115688b5154821945b4ef11bbf166aa043ff08db17e9f19'),
 (4032, 8, '1c212848fe046ad09e93dad44067de950964a3b674d4ef8121a6ef1b7c12da36'),
 (4032, 18, '135f8ef20b52427a12352b55ee2580d2183f306d13b61f5ec0353bdca2f2875f'),
 (4056, 8, '431c8b5f448271cbcfad415e1c69aae346ea1238d037ae68b09336db3fb94ef7'),
 (4056, 508, '266dc309ab0c5e10933ceb736459b4e8ec5e9d2b385e3c3f0ce3d1804c37f975'),
 (5624, 236, '4f733b17e39bd450f0f3ac8c89d862bfda64beefe00b32102494768bc51b76dd'),
 (6576, 8, '4c3c4e217274260fb70392736f985f444430eed5f5a260ec05edfc461e7361e6'))

_POOLS = ((1476, 50333472), (1480, 10242), (1484, 514), (1488, 65023), (1768, 17821692), (1772, 50333440), (1776, 30928), (3428, 50333504), (3492, 16786346), (3972, 17232244), (3984, 17232244), (4024, 17232244), (4028, 17821704), (4052, 17232244), (4564, 17821704), (4568, 17232244), (6092, 17822316), (6112, 1265), (6116, 5645), (6120, 5648), (6124, 1025), (6128, 5669), (6132, 5672), (6136, 1093), (6140, 5693), (6144, 5696), (6148, 6240), (6152, 5717), (6156, 5720), (6160, 17822572), (6164, 17821916), (6168, 2045), (6172, 5773), (6176, 5776), (6180, 1413), (6184, 5797), (6188, 5800), (6192, 3341), (6196, 5853), (6200, 5856))

_RAM = ((16786346, 16786347), (17232244, 17232245), (17232244, 17232252), (17821692, 17821693), (17821704, 17821705), (17821916, 17821917), (17822316, 17822317), (17822572, 17822573))


_POOL_VARIANTS = (_POOLS, tuple((at,0x0106f288 if value == 0x0106f174 else value)
                              for at,value in _POOLS))


def find_indirect_boot_page_profile(image: bytes):
    if not isinstance(image,bytes) or arm_b_target(image,0) != 0x15f8:
        return None,'indirect-boot-page-reset-unverified'
    if any(not 0 <= at <= len(image)-size or
           hashlib.sha256(image[at:at+size]).hexdigest() != digest
           for at,size,digest in _SPANS):
        return None,'indirect-boot-page-body-unverified'
    for pools,descriptor in zip(_POOL_VARIANTS,(0x0106f174,0x0106f288)):
        if any(not 0 <= at <= len(image)-4 or struct.unpack_from('<I',image,at)[0] != value
               for at,value in pools):
            continue
        ram=tuple((a,b)for a,b in _RAM if a != 0x0106f174)+((descriptor,descriptor+8),)
        return dict(signature='source-halfword-boot-page128-v1',admission='temporary-evidence-gated',
            width=128,height=128,clear_pages=16,planes=2,
            command_port=0x02000000,data_port=0x02000002,access_width=2,
            code_intervals=((0,4),)+tuple((at,at+size)for at,size,digest in _SPANS),
            literal_intervals=tuple((at,at+4)for at,value in pools),data_intervals=(),
            ram_intervals=ram,source_pcs={'selector':0xf94,'owner':0xd0c,'reset':0x15f8},
            port_descriptor=descriptor,alternate_port_owned=False,optical_properties=None), 'source-indirect-boot-page-candidate'
    return None,'indirect-boot-page-pool-unverified'
