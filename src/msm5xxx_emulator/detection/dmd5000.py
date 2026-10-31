"""Legacy dual-descriptor DSP program/readback producer, not DSP execution.

Bind bounded driver bodies and every external call/literal edge. Payload data is
never supplied by this detector: the native buffer records actual guest writes.
"""
import hashlib
import struct
from .arm import thumb_bl_target, thumb_literal_value

_SPECS = [(440048,
  388,
  'e7027b545153eba0d9c14e86061b1a31578b86e93950e0d0b65d2a824efaaa62',
  ((14, 1898104),
   (28, 622744),
   (52, 552392),
   (56, 622744),
   (130, 552392),
   (144, 1898132),
   (160, 622744),
   (256, 622744),
   (366, 180),
   (382, 458640)),
  ((8, 1, 16784684),
   (22, 1, 50331728),
   (40, 3, 1969920),
   (44, 3, 1969912),
   (48, 1, 50331712),
   (68, 0, 50331712),
   (70, 3, 1969920),
   (100, 0, 50331712),
   (102, 3, 1969912),
   (134, 1, 50331728),
   (148, 7, 50333536),
   (172, 3, 1969920),
   (208, 3, 1969912),
   (246, 7, 50333536),
   (268, 3, 1969920),
   (284, 7, 50333536),
   (308, 3, 1969912),
   (324, 7, 50333536),
   (350, 7, 50333536),
   (358, 1, 16784684),
   (380, 1, 1969928)),
  1969912,
  (1953528, 0, 4096, 1961720, 0, 4096)),
 (450436,
  388,
  '5f40d8eb10b4527675ba491afab7178e1d2aee482caf67043360d931fb907330',
  ((14, 1823308),
   (28, 530476),
   (52, 470176),
   (56, 530476),
   (130, 470176),
   (144, 1823336),
   (160, 530476),
   (256, 530476),
   (366, 180),
   (382, 469236)),
  ((8, 1, 16783752),
   (22, 1, 50331728),
   (40, 3, 1893424),
   (44, 3, 1893416),
   (48, 1, 50331712),
   (68, 0, 50331712),
   (70, 3, 1893424),
   (100, 0, 50331712),
   (102, 3, 1893416),
   (134, 1, 50331728),
   (148, 7, 50333536),
   (172, 3, 1893424),
   (208, 3, 1893416),
   (246, 7, 50333536),
   (268, 3, 1893424),
   (284, 7, 50333536),
   (308, 3, 1893416),
   (324, 7, 50333536),
   (350, 7, 50333536),
   (358, 1, 16783752),
   (380, 1, 1893432)),
  1893416,
  (1877032, 0, 4096, 1885224, 0, 4096)),
 (528800,
  382,
  '1a7138f7e0096a5a8bf133afe667ea751a065e14e83d1bf624996b89361b3312',
  ((14, 9788),
   (28, 600288),
   (52, 544816),
   (56, 600288),
   (130, 544816),
   (144, 9816),
   (160, 600288),
   (256, 600288),
   (366, 180),
   (376, 543904)),
  ((8, 1, 18356832),
   (22, 1, 50331728),
   (40, 3, 1949040),
   (44, 3, 1949032),
   (48, 1, 50331712),
   (68, 0, 50331712),
   (70, 3, 1949040),
   (100, 0, 50331712),
   (102, 3, 1949032),
   (134, 1, 50331728),
   (148, 7, 50333536),
   (172, 3, 1949040),
   (208, 3, 1949032),
   (246, 7, 50333536),
   (268, 3, 1949040),
   (284, 7, 50333536),
   (308, 3, 1949032),
   (324, 7, 50333536),
   (350, 7, 50333536),
   (358, 1, 18356832),
   (374, 1, 1949048)),
  1949032,
  (1932648, 0, 4096, 1940840, 0, 4096))]


_CLOSURE = {440048: (((622744,
            20,
            '0568e312b8e92fc555f1e0cecbc1af686a158b86613dc3ffd4b8242c25f08975',
            (),
            ((2, 0, 50333520),)),
           (552392,
            68,
            '8ec52e3af32b574bb62cc162bcb057e01d1e2735a29a9c7aca61ff0c3df39e57',
            ((10, 1898104), (38, 1898132), (42, 1898104), (62, 1898132)),
            ((2, 0, 16789844), (14, 7, 17534332), (16, 3, 65534), (20, 4, 50333184), (48, 3, 65534))),
           (112200,
            14,
            '29d88a913067e4048d064afbbe671718c628ff22754d3798982f8bc474dfa8aa',
            ((0, 622836), (4, 111936), (8, 440048)),
            ())),
          ('beaba99087544db13e607867863b6233d42995e0c35a3a7085a6acbe9fb75cde',
           '675801b4c1a97bc1eda26834ae144d89b78fd452067f01c6e68a8e7c97451a96'),
          16784684),
 450436: (((530476,
            20,
            '0568e312b8e92fc555f1e0cecbc1af686a158b86613dc3ffd4b8242c25f08975',
            (),
            ((2, 0, 50333520),)),
           (470176,
            68,
            'd467457cc522dd77e6b3d6e6fc693f4d6b1bf2c10bbf1c57c3862a5fc36c0e2b',
            ((10, 1823308), (38, 1823336), (42, 1823308), (62, 1823336)),
            ((2, 0, 16783996), (14, 7, 17274040), (16, 3, 65534), (20, 4, 50333184), (48, 3, 65534))),
           (117416,
            14,
            '3621c6b54a40e1711c969901a0f42403bec977d19d5c2eaad556780fe2b2c7f8',
            ((0, 530568), (4, 117152), (8, 450436)),
            ())),
          ('beaba99087544db13e607867863b6233d42995e0c35a3a7085a6acbe9fb75cde',
           '675801b4c1a97bc1eda26834ae144d89b78fd452067f01c6e68a8e7c97451a96'),
          16783752),
 528800: (((600288,
            20,
            '0568e312b8e92fc555f1e0cecbc1af686a158b86613dc3ffd4b8242c25f08975',
            (),
            ((2, 0, 50333520),)),
           (544816,
            68,
            '192730429224d3470bb1382c647d07e99615d4b6d7f8818246e0f52d5fdc1cd1',
            ((10, 9788), (38, 9816), (42, 9788), (62, 9816)),
            ((2, 0, 18357052), (14, 7, 18875996), (16, 3, 65534), (20, 4, 50333184), (48, 3, 65534))),
           (154752,
            14,
            'de02dbb9a30c1da18dbb0234a878e6e09473691cf0588120cafab5b27f76f161',
            ((0, 600384), (4, 153864), (8, 528800)),
            ())),
          ('beaba99087544db13e607867863b6233d42995e0c35a3a7085a6acbe9fb75cde',
           '675801b4c1a97bc1eda26834ae144d89b78fd452067f01c6e68a8e7c97451a96'),
          18356832)}

def find_dmd5000_profile(image: bytes) -> dict | None:
    if not isinstance(image, bytes):
        return None
    for entry, size, digest, calls, literals, desc, words in _SPECS:
        if not 0 <= entry <= len(image) - size or desc + 16 > len(image):
            continue
        if (hashlib.sha256(image[entry:entry+size]).hexdigest() != digest
                or any(thumb_bl_target(image, entry+off) != target for off, target in calls)
                or any(thumb_literal_value(image, entry+off, reg) != value
                       for off, reg, value in literals)
                or struct.unpack_from('<IHHIHH', image, desc) != words):
            continue
        roles, payload_hashes, completion = _CLOSURE[entry]
        if any(not 0 <= at <= len(image)-length
               or hashlib.sha256(image[at:at+length]).hexdigest() != body_hash
               or any(thumb_bl_target(image, at+off) != target for off, target in edges)
               or any(thumb_literal_value(image, at+off, reg) != value
                      for off, reg, value in pools)
               for at, length, body_hash, edges, pools in roles):
            continue
        payload0, address0, count0, payload1, address1, count1 = words
        if (address0 or address1 or count0 != 0x1000 or count1 != count0
                or any(start & 1 or not 0 <= start <= len(image)-2*count0
                       for start in (payload0, payload1))):
            continue
        if any(hashlib.sha256(image[start:start+2*count0]).hexdigest() != digest
               for start, digest in zip((payload0, payload1), payload_hashes)):
            continue
        return {'completion': completion, 'entry': entry, 'descriptors': (desc, desc+8),
                'payloads': (payload0, payload1), 'pairs': count0//2}
    return None
