"""Whole-source contracts for halfword page LCD boot diagnostics."""
from __future__ import annotations
import hashlib
import struct
from .arm import arm_b_target, thumb_normalized_source_shape

_TEMPLATES = (({'command': (2996, (8, 'cd43751f713396bdd108a69eb801052d10089183cf80201684a149b25830e3a9', (), ()), (), ()),
   'data': (3004, (8, 'b41d0e48c4aafb4577f766aac19b5ac01e8714a608866df48e1beaa18d11419e', (), ()), (), ()),
   'download_owner': (2468,
                      (72, 'd004c5e72da014591b0acad452877a3c997614708281e32f2f6444a844e3e890',
                       (20, 28, 36, 44, 52, 56, 60, 64), (0, 2, 12)),
                      ((20, 3022), (28, 3234), (36, 3234), (44, 3234), (52, 3234), (56, 2608), (60, 2644), (64, 2360)),
                      ((0, 2540, 4099), (2, 2544, 50333280), (12, 2544, 50333280))),
   'init': (3022,
            (212, '71431734554653d9a2f173a9ebee92ea8a68acec9f173bc5a4af3d09a03cdd1d',
             (4, 10, 16, 22, 28, 34, 40, 46, 52, 60, 66, 74, 80, 88, 94, 100, 106, 112, 124, 134, 142, 148, 166, 176,
              184, 190, 202),
             ()),
            ((4, 2996), (10, 2996), (16, 2996), (22, 2996), (28, 2996), (34, 2996), (40, 2996), (46, 2996), (52, 2996),
             (60, 4580), (66, 2996), (74, 4580), (80, 2996), (88, 4580), (94, 2996), (100, 2996), (106, 2996),
             (112, 2996), (124, 2996), (134, 2996), (142, 2996), (148, 3004), (166, 2996), (176, 2996), (184, 2996),
             (190, 3004), (202, 2996)),
            ()),
   'keyscan': (1076,
               (52, '9e1f904392a545722ba53f36e5072788963d8b086ab893234a9c6fbf7042bc41', (38,), (0, 10, 14, 18, 22, 36)),
               ((38, 4580),),
               ((0, 1128, 50333280), (10, 1132, 18935), (14, 1136, 65023), (18, 1140, 27922), (22, 1144, 65535),
                (36, 1148, 40000))),
   'text': (3234,
            (162, 'e70e8314cf44165ec9ab2201f8915ac9be97d0a3cef83766832ffd416d8cbba6',
             (50, 64, 74, 92, 106, 112, 118, 130), (4, 80)),
            ((50, 2996), (64, 2996), (74, 2996), (92, 3004), (106, 2996), (112, 2996), (118, 2996), (130, 3004)),
            ((4, 3396, 50333184), (80, 3400, 12068))),
   'uart_init': (2644,
                 (152, 'c0943db61f12824bc61c77279a091fee17c023961a178f8c7828a5b59a38ff3d', (36,),
                  (0, 18, 28, 40, 56, 64, 78, 86, 122)),
                 ((36, 2608),),
                 ((0, 2796, 50333504), (18, 2800, 895), (28, 2800, 895), (40, 2796, 50333504), (56, 2796, 50333504),
                  (64, 2796, 50333504), (78, 2796, 50333504), (86, 2796, 50333504), (122, 2804, 50333184))),
   'uart_tx_wait': (2608, (30, '3e0a224f0b28a954b4076d672376de5a6d67771c2e228d205c5761048af33f35', (), (2,)), (),
                    ((2, 2640, 50333184),))},
  (3592, 212, '11bb1fb09f847c31d5dff809e3a760571fb1368eb87db294b053fcfdabeeb8b3',
   ((0, 4104, 1025, 3852419072), (8, 4108, 3613, 362799104), (12, 4112, 3616, 94363648), (24, 4116, 1153, 3852419072),
    (32, 4120, 3637, 362799104), (36, 4124, 3640, 94363648), (48, 4128, 777, 3852419072), (56, 4132, 3661, 362799104),
    (60, 4136, 3664, 94363648), (72, 4140, 837, 3852419072), (80, 4144, 3685, 362799104), (84, 4148, 3688, 94363648),
    (96, 4152, 4244, 3852419072), (104, 4156, 3709, 362799104), (108, 4160, 3712, 94363648),
    (132, 4084, 17560184, 3852455936), (140, 4164, 17560440, 3852455936), (148, 4168, 17559784, 3852455936),
    (152, 4172, 1269, 3852419072), (160, 4176, 3765, 362799104), (164, 4180, 3768, 94363648),
    (176, 4184, 1077, 3852419072), (184, 4188, 3789, 362799104), (188, 4192, 3792, 94363648)),
   ((124, 3804, 436207616), (204, 3804, 436207616), (208, 65536, 3925868544))),
  9, 1),
 ({'command': (3008, (8, 'cd43751f713396bdd108a69eb801052d10089183cf80201684a149b25830e3a9', (), ()), (), ()),
   'data': (3016, (8, 'b41d0e48c4aafb4577f766aac19b5ac01e8714a608866df48e1beaa18d11419e', (), ()), (), ()),
   'download_owner': (2492,
                      (36, '096cf6505f531f811088524a6661f7a620025c5d2cc66c508249996b44a465f7', (20, 24, 28), (2, 12)),
                      ((20, 2532), (24, 2656), (28, 2384)), ((2, 2528, 50333280), (12, 2528, 50333280))),
   'init': (3024,
            (356, 'b16ae4040d261fe86c0aafc60bf09b33ce511b76c2bf109b8dee9e4cfe9b533b',
             (4, 10, 16, 22, 28, 34, 40, 46, 52, 58, 64, 70, 76, 82, 88, 94, 100, 106, 112, 118, 126, 132, 140, 146,
              154, 160, 166, 172, 178, 184, 190, 196, 202, 208, 214, 220, 226, 232, 238, 244, 250, 256, 262, 268, 274,
              280, 286, 298, 308, 316, 322, 328, 346),
             ()),
            ((4, 3008), (10, 3008), (16, 3008), (22, 3008), (28, 3008), (34, 3008), (40, 3008), (46, 3008), (52, 3008),
             (58, 3008), (64, 3008), (70, 3008), (76, 3008), (82, 3008), (88, 3008), (94, 3008), (100, 3008),
             (106, 3008), (112, 3008), (118, 3008), (126, 4812), (132, 3008), (140, 4812), (146, 3008), (154, 4812),
             (160, 3008), (166, 3008), (172, 3008), (178, 3008), (184, 3008), (190, 3008), (196, 3008), (202, 3008),
             (208, 3008), (214, 3008), (220, 3008), (226, 3008), (232, 3008), (238, 3008), (244, 3008), (250, 3008),
             (256, 3008), (262, 3008), (268, 3008), (274, 3008), (280, 3008), (286, 3008), (298, 3008), (308, 3008),
             (316, 3008), (322, 3016), (328, 3016), (346, 3008)),
            ()),
   'keyscan': (1076,
               (76, '7ab22745f9dd3360cd70cccd35379e32d032a9a06d40e0136d864632fce2ce4e', (48, 56, 62),
                (0, 10, 14, 18, 22, 38, 60)),
               ((48, 3024), (56, 3380), (62, 4812)),
               ((0, 1152, 50333280), (10, 1156, 18935), (14, 1160, 65023), (18, 1164, 27922), (22, 1168, 65535),
                (38, 1172, 17821692), (60, 1196, 40000))),
   'text': (3380,
            (246, 'f984241fa63dd9be3b6b9d91379959a032ba392ddbb5a60c192fd49396f98a9a',
             (24, 34, 42, 48, 54, 72, 130, 144, 154, 168, 174, 188, 194, 200, 208, 214), (4, 76, 82, 160)),
            ((24, 3008), (34, 3008), (42, 3008), (48, 3016), (54, 3016), (72, 3008), (130, 3008), (144, 3008),
             (154, 3008), (168, 3016), (174, 3016), (188, 3008), (194, 3008), (200, 3008), (208, 3016), (214, 3016)),
            ((4, 3628, 17821724), (76, 3628, 17821724), (82, 3632, 50333184), (160, 3636, 12296))),
   'uart_init': (2656,
                 (152, 'cbca6a65d27a76f7afc5cef10d3d4f06ff73d5b8235b3d3d4eb8a8e46bc29407', (36,),
                  (0, 18, 28, 40, 56, 64, 78, 86, 122)),
                 ((36, 2532),),
                 ((0, 2808, 50333504), (18, 2812, 895), (28, 2812, 895), (40, 2808, 50333504), (56, 2808, 50333504),
                  (64, 2808, 50333504), (78, 2808, 50333504), (86, 2808, 50333504), (122, 2816, 50333184))),
   'uart_tx_wait': (2532, (30, '3e0a224f0b28a954b4076d672376de5a6d67771c2e228d205c5761048af33f35', (), (2,)), (),
                    ((2, 2564, 50333184),))},
  (3824, 212, '11bb1fb09f847c31d5dff809e3a760571fb1368eb87db294b053fcfdabeeb8b3',
   ((0, 4336, 1025, 3852419072), (8, 4340, 3845, 362799104), (12, 4344, 3848, 94363648), (24, 4348, 1201, 3852419072),
    (32, 4352, 3869, 362799104), (36, 4356, 3872, 94363648), (48, 4360, 777, 3852419072), (56, 4364, 3893, 362799104),
    (60, 4368, 3896, 94363648), (72, 4372, 837, 3852419072), (80, 4376, 3917, 362799104), (84, 4380, 3920, 94363648),
    (96, 4384, 4476, 3852419072), (104, 4388, 3941, 362799104), (108, 4392, 3944, 94363648),
    (132, 4316, 17822336, 3852455936), (140, 4396, 17822592, 3852455936), (148, 4400, 17821936, 3852455936),
    (152, 4404, 1293, 3852419072), (160, 4408, 3997, 362799104), (164, 4412, 4000, 94363648),
    (176, 4416, 1077, 3852419072), (184, 4420, 4021, 362799104), (188, 4424, 4024, 94363648)),
   ((124, 4036, 436207616), (204, 4036, 436207616), (208, 65536, 3925868544))),
  16, 2))


def _arm_match(image, source):
    at,size,digest,literals,branches = source
    if at & 3 or not 0 <= at <= len(image)-size or arm_b_target(image,0) != at:
        raise ValueError('boot-page-reset')
    normalized=bytearray(image[at:at+size]);pools=[]
    expected_literals={offset:(pool,value,opcode)for offset,pool,value,opcode in literals}
    expected_branches={offset:(target,opcode)for offset,target,opcode in branches}
    seen_literals=set();seen_branches=set()
    for offset in range(0,size,4):
        word=struct.unpack_from('<I',normalized,offset)[0]
        if word & 0x0f7f0000 == 0x051f0000:
            pool=at+offset+8+(word&4095)*(1 if word&0x800000 else -1)
            if pool&3 or not 0 <= pool <= len(image)-4:
                raise ValueError('boot-page-reset-pool')
            value=struct.unpack_from('<I',image,pool)[0]
            if expected_literals.get(offset) != (pool,value,word&~4095):
                raise ValueError('boot-page-reset-literal')
            seen_literals.add(offset);pools.append((pool,pool+4))
            struct.pack_into('<I',normalized,offset,word&~4095)
        elif word & 0x0e000000 == 0x0a000000:
            delta=word&0xffffff
            if delta&0x800000:delta-=0x1000000
            target=at+offset+8+delta*4
            if not at <= target < at+size:
                if (expected_branches.get(offset) != (target,word&0xff000000)
                        or target&3 or not 0 <= target <= len(image)-4):
                    raise ValueError('boot-page-reset-branch')
                seen_branches.add(offset)
                struct.pack_into('<I',normalized,offset,word&0xff000000)
    if (seen_literals != set(expected_literals) or seen_branches != set(expected_branches)
            or hashlib.sha256(normalized).hexdigest() != digest):
        raise ValueError('boot-page-reset-body')
    return pools


def find_boot_page_profile(image: bytes):
    if not isinstance(image,bytes):
        return None,'boot-page-primary-bytes-required'
    for functions,reset,pages,planes in _TEMPLATES:
        try:
            pools=_arm_match(image,reset);code=[(0,4),(reset[0],reset[0]+reset[1])];ram=[]
            for role,(at,shape,links,literals) in functions.items():
                match=thumb_normalized_source_shape(image,at,shape)
                if match is None:
                    raise ValueError('boot-page-body')
                calls,values,observed_pools=match
                if (calls != dict(links) or values != {offset:value for offset,pool,value in literals}
                        or observed_pools != [(pool,pool+4)for offset,pool,value in literals]):
                    raise ValueError('boot-page-links')
                code.append((at,at+shape[0]));pools.extend(observed_pools)
                # Helpers execute in the guest. This observer only checks their
                # source call relations; it never replaces or invokes a helper.
                ram.extend((value,value+1)for offset,pool,value in literals
                           if 0x01000000 <= value < 0x02000000)
            command=functions['command'][0]+4;data=functions['data'][0]+4
            if (struct.unpack_from('<H',image,command)[0] != 0x8008
                    or struct.unpack_from('<H',image,data)[0] != 0x8048):
                raise ValueError('boot-page-store')
            return dict(signature='source-halfword-boot-page128-v1',admission='temporary-evidence-gated',
                width=128,height=pages*8,clear_pages=pages,planes=planes,
                command_port=0x02000000,data_port=0x02000002,access_width=2,
                code_intervals=tuple(sorted(set(code))),literal_intervals=tuple(sorted(set(pools))),
                ram_intervals=tuple(sorted(set(ram))),data_intervals=(),
                source_pcs={role:entry[0]for role,entry in functions.items()},optical_properties=None), 'source-boot-page-candidate'
        except (ValueError,IndexError,struct.error):
            pass
    return None,'boot-page-source-unclosed'
