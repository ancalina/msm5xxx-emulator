"""Observed mono byte boot diagnostic, including its row-zero fatal producer.

The early 16-page pre-init clear is not a viewport witness. The enabled row-zero
text path independently clears eight complete pages before drawing glyphs.
"""
from __future__ import annotations
import hashlib
import struct
from .arm import arm_b_target

_SPANS = ((1840, 8, '3eeea3571d8e97f88c1fa60842254a999fd58f2a3f1d28783eeb08d3b67e81fe'),
 (1968, 446, '03901a9e64769392c903db19621500cb05fd8ef045d521379982c50c013f983c'),
 (4392, 8, '7b0854c8753540e1472cda37b5486c7180a2030364e02756e97a215c4f65d8ca'),
 (4392, 98, '900218b8024917ad6edbb49fb64e4085feb99fd96059bc974b4f91d8a24979fd'),
 (4492, 8, '047e56206ca7b6234012035d66d191b11c67b5d9a4e8124998a2b7f47bf5e7d1'),
 (4492, 402, '34274572e417b44bed95024f4b2a880201bd3cb049e56c25df8395fd3f72c1ad'),
 (5072, 8, 'a007353a87e965ee8ac0b60fa65cbb36013765df148899f2c7395096fcc45db0'),
 (5128, 260, 'c43b4e0bc50ac148e78c9a45b1067b8cae133d09884a57153767c46ec9d48a36'),
 (5768, 8, '4c3c4e217274260fb70392736f985f444430eed5f5a260ec05edfc461e7361e6'),
 (65872, 8, '610fe185d6b26483b07d34d059e3ca446332ae22efab5ef9106de2b78fb04b17'),
 (472392, 222, 'b59ac1315bb6991e511a7d018a43cab2a838429b7fa77adbd15d3f4593b57e08'),
 (493828, 8, 'fe4ae561a645af377f1f9102e350da680cb4db1ed977b5a66655f78daf276970'),
 (494204, 8, '6789ee93e73a2e4de65dcf204d4929d43dfda46ff1176a787711292368a71b10'),
 (494204, 118, '4cce2d2352de22196dc911bb663d797de862f3d246f7ae1b085491e591f32a51'),
 (495196, 8, '60d14a244f288bf1f374009472f010eb7ef5f7c9f3ecc76374ae75aa8f101050'),
 (497892, 8, '7880af0c4999eadea49e36d5e3bb4b40e39b344da963055497d577349536df03'),
 (1362232, 8, 'fdcf65201c25fc95400ec5133ca2270a9b69177b7ffb51edffc48cc47856970e'),
 (1629032, 8, '56c933d8e166e8eee1f791d259d3dedf02747121b74a4654a454e072720287ae'),
 (1629056, 8, '56c933d8e166e8eee1f791d259d3dedf02747121b74a4654a454e072720287ae'),
 (1630760, 8, '8c2a69231216b59c4dda7e0aa783eb41b0bc3ecba966686e50b4c3881d28bea1'))

_POOLS = ((2416, 50333280), (2420, 25618), (2424, 9234), (2428, 18958804), (2444, 19922912), (4896, 18934324), (4900, 50333184), (4904, 19184), (4908, 14064), (5620, 19920744), (5656, 1809), (5660, 5149), (5664, 5152), (5668, 1533), (5672, 5173), (5676, 5176), (5680, 1597), (5684, 5197), (5688, 5200), (5692, 2497), (5696, 5221), (5700, 5224), (5704, 5808), (5708, 5245), (5712, 5248), (5716, 19921000), (5720, 19920344), (5724, 2625), (5728, 5301), (5732, 5304), (5736, 1969), (5740, 5325), (5744, 5328), (5748, 3809), (5752, 5381), (5756, 5384), (472616, 18882564), (472620, 50331728), (472624, 1742380), (472628, 50333536), (472632, 1742388), (494324, 50333376), (494328, 18882856), (494332, 19226760))

_RAM = ((18882564, 18882565), (18882856, 18882857), (18934324, 18934325), (18958804, 18958805), (19226760, 19226761), (19226760, 19226824), (19920344, 19920345), (19920744, 19920745), (19921000, 19921001), (19922912, 19922913))


def find_byte_boot_page_profile(image: bytes):
    if not isinstance(image,bytes) or arm_b_target(image,0) != 0x1408:
        return None,'byte-boot-page-reset-unclosed'
    if any(not 0 <= at <= len(image)-size or hashlib.sha256(image[at:at+size]).hexdigest() != digest
           for at,size,digest in _SPANS):
        return None,'byte-boot-page-source-body-unclosed'
    if any(not 0 <= at <= len(image)-4 or struct.unpack_from('<I',image,at)[0] != value
           for at,value in _POOLS):
        return None,'byte-boot-page-source-pool-unclosed'
    return dict(signature='source-byte-boot-page128-v1',admission='temporary-evidence-gated',
        width=128,height=64,clear_pages=8,planes=1,
        command_port=0x02000000,data_port=0x02000002,access_width=1,
        publish_after_clear_if_enabled=True,
        code_intervals=((0,4),)+tuple((at,at+size)for at,size,digest in _SPANS),
        literal_intervals=tuple((at,at+4)for at,value in _POOLS),
        data_intervals=((0x36f0,0x4cf0),),ram_intervals=_RAM,
        source_pcs={'text':0x118c,'fatal_owner':0x78a7c,'reset':0x1408},
        optical_properties=None), 'source-byte-boot-page-candidate'
