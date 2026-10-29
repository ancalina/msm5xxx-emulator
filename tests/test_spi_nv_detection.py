"""Synthetic relocated typed producers; no original files needed."""
import base64
import struct
import unittest
import zlib

from msm5xxx_emulator.detection.spi_nv import find_spi_nv_profile

_FIXTURE_0 = (
    'c-rmUeQX<N0mt#@u^lIIoEN8=<4dmDrAeElX-m3kCE-Q5DU2jqUl7|rOqD8uV1Gdh)9U_33Je8-L|Rm-Nl^hI*tGITBsyAzGO`z@'
    'p`y&`sMI9|xueuV&Cr9?)h!Rr@jSMZI&B3)Nb3}RKhovSe(rfLK3n&Dp7WCk0RR910036Ikr&T@O3pPa?c1emFp^5PHSLHDSEf34'
    '_dO#z<!rP1hbep4Z#QMZVp-pTLdj)QlJTY6G7w1BnX<sJNV!9G`$d;6J#R{9eW#?&zWs%IZ<vzT{57WJNW~G6FZpVr<Ts||v}v(A'
    '-{Sm^rlf7N_vu25zwk$<gz#&H+!q!>Stn$fSw_tEqIpi3?T}e`R{;R{&nB1hU)#mq*_8^I)OC_w!(Az7_fje=Q@WtzkF}a4x23Ja'
    't;<>djt+Z4HE;Hq*QK?W>Yg(tGuqa4c9hn8T~C@Ux0$_fDZc>#!26j0O=j$GmwV@blTxO1!M|7jH>r30kQY$%W{-LQ?)-03=S<0r'
    'e`o$Tsn>n-9{_;+od4P`Ei3ZB`F8%B(gmHkcm8W>^Ir?|^Mcv$g1%QT;7wC<R^QzVcvVX^WqShj0{{Sc->7{4J7(-}mzG^yi`l(('
    'c<XZhJ7)avnDPI;^4~Gz|1wXSv423lt;<|TUGPiWSZd)-)56)i?gBXKRln0!+y?*v;Qr*lE_b7$_Gmn`E$XQ2x?{zifb~PMVvb+c'
    'j>_tF`8j=dcAlNP_ux>hnC2IC!1M*qYcC?zIqii-jZ`yQw4ds)m<wk1xgm3e8`<8y(v16aSx3FH;$A_`a)0BDIm#(rb=S;6N1fC{'
    '{mfS@?ibiKeFp#l{@46Zn6dxu{7<Os{)QF#-(JlBgu3b{RMu}@k^e2l{7<Nhe$W%@yzfPXI_KN`7iz}8GykP}P4_;L%O=z-D`pH-'
    '7xO=%&X}W|@*{WUe?pxk`vCy>zl|;BzaDQF9nbYgO-`rW^6)2WZe$m8N>7(h*UDMxjZJZ`003BB<Nro8{x1t}u4z;^{je+AyLVS?'
    '+Fls3huck0pi#Z+_Z3I#eZzgr_X8T$U;GiTGg+N(G-Ln1lx%Z$*z&c@<!|}XOrx4HWrG!i!j?5Im;KIfR4?b-E!2uFmz?pR6886b'
    '$sBpIq;6z+kLP@`#jbx^azEhCg?ASKfd7*JT6BnZXQ#8PVpI2u<X0=cqu*N0->mLAIMS9#2GhOvTmFvn9gW4m|95tj?)R21-xNrv'
    'guSEi$87J4xqh5|008c1{>Ss*|9^Y(&}4OJbF?lbqGIg3lhR8DUmlDdezsrE$)i=7*m&hZ*(GP?(XxzedouX9rpi!dR346v4~>R5'
    'oEfY;EZR>GexpB_j!o1b3~X$fl@lLrJ056ChRs&h@pFm7qgc9PG}u{wG1yslv1+2rJvq?k#?`c6H~zvvT)pJ?xb>52swE>Qf^Elx'
    'w`&(3)!$M3M85V<OznAZM8wsJeEmOXpY0FKNl%Q)j4(fs4%C{Z#w^uiM~9+Es*Z`yuchPakpF|BSgOwST4KYo)ZwAn)3)CdR|ou%'
    'SK0devWjn29rHTnoY_C)dEwBu=tB5%&5s>n&XL#I@F&j`&30CU&V5d=bGzJL_g3x+y_ox~*16B<hnl;bUguWsF&)n6+@OA_xW^~8'
    '@FHW+42YEIY@8MC6`R(S%#RrH;_Bo67tGI(`Txpo@$Gjofmvy4h|EHEL&lbG_G^!QY0$3KTG1)y%6q2k0-^e-+!9FdaqZTa7)jXm'
    'p0y$~k+EAf;{j7MZrTj_OW*56#v<lS)SFiv^&cM)qakx<L*~qOxz)!+n^+fD*B0x>AM}zku5K+Zos+ow>*CO0r1&2i?fi^SFQ2)&'
    'MPXX3PTN@@k(IMP$19!a#Gc3B%L*?xUNLOXM&Nm&rv529A4vC_qc6R$+Xn2hMQdEWXpa7{`BeOJQReG}JoDMOQrNafXel{D-(J(&'
    '-b4Ls(w!x3$?^3Ag;(-@)7GFT%q#icqHX67S1x7c_^2cEpW^48GV|I0ty6Vuq}jf^RbvZRbnYvQ!t8naiunvlk+D-uqzsw$7ftWA'
    '!mN|#@rYTXwk%or|C6?FJ8hnOBp?d=FZXw)tTX$4GgNrKA;Xjv03U$-*EY-RZGv=sJ^10Bzc!g4bt^O72W7XMjk=+H;-77D&6W1c'
    'qdmLrqZ9psboaqPw=-*Vy)7A<{dqp&A5PX5ufS#I3LLz+!CZgiDy{q6_2x=Gqr;w>N@Q%B7wXt8Tc@R@j+?LZD^sW0)H!A9T+Z5K'
    'j@!OSo5+|e`bIe`ytlKWyFT5W65X}w*r3>0l@4b<@7mu|e#E|-_p()cgTu1tT2^Lm<wi~JPG?K6<q5NnmKCnYuGy})+ezjU0svOI'
    'eEvUR#{VKLYHT0i(4;t-7=G$exo$D1d^stY`3C^NYR&)r_}^y!b)Uos0AO{Kt=|a-2eyyMR=HoaZr`7K)I8~N{~G{+)vWOSe}ftS'
    '-^kt6V*Q$3j|}^{Yr1|Q<kk;~)?2y1`{l0mdWOY^V(A8TQ`eNt66<rT2D)9bu0dVWk-^A7gSx6;@P5?xq`Z`P<3N6{zwJvTh4k0t'
    'dmGZT-@BXThhfe=0000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    '0000000000000000000000000000000000000000000000000000000000000000000000000000000000000004jwwtoYcIT{-'
)
_ENTRIES_0 = {'init': 4096, 'wren': 6144, 'wrdi': 8192, 'wrsr0': 10240, 'status': 12288, 'write_data': 14336, 'read_data': 16384, 'ready_poll': 18432, 'tx_byte': 20480, 'rx_byte': 22528, 'write_root': 24576, 'read_root': 26624, 'scalar_write': 28672, 'scalar_read': 30720, 'geometry_init': 32768, 'outer_init': 34816}
_POOLS_0 = {('init', 14): 4276, ('init', 26): 4280, ('init', 42): 4284, ('init', 70): 4288, ('init', 82): 4292, ('init', 98): 4296, ('init', 124): 4300, ('init', 152): 4304, ('wren', 14): 6272, ('wren', 28): 6276, ('wren', 44): 6280, ('wrdi', 14): 8320, ('wrdi', 28): 8324, ('wrdi', 44): 8328, ('wrsr0', 14): 10376, ('wrsr0', 28): 10380, ('wrsr0', 44): 10384, ('status', 14): 12424, ('status', 28): 12428, ('status', 44): 12432, ('write_data', 24): 14520, ('write_data', 38): 14524, ('write_data', 54): 14528, ('write_data', 68): 14532, ('write_data', 140): 14536, ('write_data', 156): 14540, ('read_data', 24): 16564, ('read_data', 38): 16568, ('read_data', 54): 16572, ('read_data', 68): 16576, ('read_data', 140): 16580, ('read_data', 156): 16584, ('tx_byte', 22): 20676, ('tx_byte', 54): 20680, ('tx_byte', 86): 20684, ('tx_byte', 114): 20688, ('tx_byte', 140): 20692, ('tx_byte', 174): 20696, ('rx_byte', 14): 22644, ('rx_byte', 16): 22648, ('write_root', 32): 25384, ('write_root', 74): 25388, ('write_root', 80): 25392, ('write_root', 132): 25396, ('write_root', 142): 25400, ('write_root', 194): 25404, ('write_root', 232): 25408, ('write_root', 236): 25412, ('write_root', 240): 25416, ('write_root', 244): 25420, ('write_root', 258): 25424, ('write_root', 270): 25428, ('write_root', 380): 25432, ('write_root', 444): 25436, ('write_root', 524): 25440, ('write_root', 570): 25444, ('write_root', 584): 25448, ('write_root', 650): 25452, ('write_root', 662): 25456, ('write_root', 676): 25460, ('write_root', 726): 25464, ('write_root', 740): 25468, ('read_root', 22): 26868, ('read_root', 54): 26872, ('read_root', 88): 26876, ('read_root', 100): 26880, ('read_root', 110): 26884, ('read_root', 140): 26888, ('read_root', 152): 26892, ('read_root', 162): 26896, ('read_root', 204): 26900, ('geometry_init', 4): 32788, ('outer_init', 16): 34912, ('outer_init', 24): 34916, ('outer_init', 28): 34920, ('outer_init', 50): 34924, ('outer_init', 64): 34928, ('outer_init', 74): 34932, ('outer_init', 76): 34936}
_SITES_0 = {'shadow': [4276, 4284, 4288, 4296, 4300, 4304, 6272, 6280, 8320, 8328, 10376, 10384, 12424, 12432, 14520, 14528, 14540, 16564, 16572, 16584, 20676, 22644, 25424, 25444], 'constant': [4280, 4292, 6276, 8324, 10380, 12428, 14524, 14532, 14536, 16568, 16576, 16580, 20680, 20684, 20688, 20692, 20696, 22648, 25400, 25428, 25436, 25448, 25460, 26884, 26896, 34920, 34936], 'descriptor': [25384, 26868, 32788, 34912], 'rom_0': [25388, 26872, 34932], 'ram_0': [25392, 25440, 25452, 25464, 26876, 26888, 34924], 'rom_1': [25396], 'rom_2': [25404], 'ram_1': [25408], 'ram_2': [25412], 'rom_3': [25416], 'cache': [25420, 26900, 34916], 'ram_3': [25432], 'rom_4': [25456], 'rom_5': [25468], 'rom_6': [26880], 'rom_7': [26892], 'rom_8': [34928]}

_FIXTURE_1 = (
    'c-rmUZERat9mnx=Y{z-9^VD{ZZ{l{>jn^biiyEO-Hg9kfF_J*nzTn}-R?!!L`UY@e>Rg1{RE%m9(nyOmC4;?)5ZXj1krxFjL8h{e'
    'u~DgWIx3Z9NZzA|)}k}1t2++O;T+q^;<h{qX%*G?BVGGC|8tM+dt3d^x%VbQ000000D#-w#4pZ&N-p#$ZQL?2){@Wmc8|2=n)7|T'
    'G6zJzobOTZ+1e$OvbA8XmU*yRdDB*kMkY3l2J#)Y7RZTwV!UI&7;x3|wmNUTRefgmSGRl7R-QL&ZRL2=aZ#y!vs(GJt^CUN*jnjv'
    'ailxz`b<Ai?eS?dF(-s+7jkb{1Z9Vi4R)EZ>r3`$!mfwx!cheP;9r|v&VTKe#Lj_yz^1O39moyjy<N+xtZen7j(s+1liXF4x#UWg'
    'zplf6P%YXPi+c6e%iEr_m9yGy>5Z)3?gc$-v)pC&-sSuT0019h{&(BCzgupe|J_R2>P2(2{O?w;n~)z+i?+q0xiSB{)j3-^Yp&1#'
    'ZuNp8{{aBF#rdz@vY{^jdp^v6TfL~`H_v}9UH)rfA1~N;7xc|W0WaIi8GYj@;5jYToEr%+4gdh)Bcm$$@7cM(TQ=M~RLkz6+|Ww?'
    'dv^Zs+4=v?^53)b{{~;$xqm?YNjD@sb-}FeW4VWyZ4YN|I1AvZ=S+V>aUK8wfLoLQx-k(ArJ}LW_Nb?>=)Sr$0e6je)^hw^?WvO9'
    'Sh=Uq-JR#|-Me$VvzF$s>VO>!oY#JfROhrG7Hv|U)gpCrxM?9++?xp5ceq+g?~!)iUoLs-*}8KDZ7buAQ}$g>>c|au4tnZ@7V4))'
    ')txVJ&x{=a0Qhh7KW^v#ALf5tT``;L@;_C}|G0YB#8t^8>+*j?E&t={RTK1uI&b_Iq0SkX|3aNL*XO@f&+GK(%cZz_w(gFB)>{6@'
    ')hYWfCr!%@`5#v&$bJ9-{%4cR`LCx_qVLJ!sLknoqA~o*wyUM3veKs;Pq)i?=}*qFuK)nJz2^U2cK+WG-rClsJ}}{gNDc04+OnfM'
    'V-Kh7NT5qyGMU;;J(J6<oDb+yZ<q<cKigX9vUC4TUiNw;uD*Vy{)&kfyVO}*8*3U9uGY0u`<>}hzpeCJ-Kuk?a?0!z?(;lj-+6Y`'
    'wk<0yo;2cP?)fLH&Ieq-aC89x_&52lMW0A{JH30GwhY!KzpA@NKUB-#lHPW3qBoum7Sir2e_!KBSMB%zy^+=JUeS$P0)@PAXB7Te'
    'O4r@%$KD43;8x~;taAPTq1hv|ZK3Vaj*y6o$?wlfKO3AGYd>~$ST4xNBE|OU=7VxT&dbLdin8~<;CtQ8q2{PO);>M<a5!~jI9PBk'
    '0t0L3<#c;*PtePT?ONpVN8+_tg&)j3IvP`FjGyS3RdZ{Layr=iqgCyyuNn*An_2WHL`?m%((*5*qr-s(>5EBO6!!7ZXxrqWvDRaU'
    '#-qn0Q=<P{g_wH6d}q8f-(g1|ow?5Zx5qmlaO01d`k@K=&B>P<njVTw`TcUiwlDgALuhOCa`?@*y`He&)$d>TXWth+?(PI#KA<-y'
    'h7#$-weo(wRQ`t6<*(_@JwsmFyH?((!$n>Gir!pnu~!SfW%5g-A}{*8=0&P$%i2}<IZXI5^+oe#`}hU(_wu-L*HQxW(rzJ&7fYLp'
    'uKsD$Hnn@qJ-@SF^oxbYZKpc|p*2ytHBi`{aBGudBJQ4duNTDwMYq;E9k5$&vwiwz`T9)DWQ*MsVf&3Yne8)o`dJxMy(`~6rdmyU'
    'tflrB72W+5cdzWBfDv}f)`CbqJ>0VD(`WX`Dd9yQ@BG~RCE>SEH|5;74m>5)TYnS%&4t9wUG`YMwInOGkl!(TN2$8*dRkN0lih01'
    'k>SQd`^=ax>?ixfl52nM?Mo#&m8~2DIhpgq_TS!NFEW+waX*Pnc9eAa=S#x2eCKU@+~rp*BStB+b`ja?-+FZ8$O-%U?tl=>ufH4O'
    '|1|*o$N8__-G6Ib^7I`JZr%ACoB7E^b8(=O_{l`5lK8Jx694NDKQkOC3?2*&cFenEk7Pshk5)4N<2K_D-g7jw!6w569ro2+d(mZj'
    'wS`-&ws<NNvn_saTU;u+capuLD0)So*evJMi8o4Oa7|$_F9zESt)CH_BZY8L4pqh)pKzb>{nGvShjMb;<x-%Sv?=_APA6U}*)L-='
    'BHAFt8oRiB;OGJX@K03o{|-C<7h%!nGWN)<I1$h7yGL$ZDk~#r1$X`d0C2nJzpl)$ZRTGwBt8HDw>O!5Bp4jsF(H$3zew)bU%p3F'
    '&ZDzu006jsRe%3~ot^(*Eq|beAKjJCnet^F84V>O<05&j{8uBBnVjfvD6CUgb>mpm=sI;p|I9z!d!KwQ{^Em^bCvNzR!GxsJ1k1^'
    '<1qUb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    '000000000000000000000000000000000000000000000000000000000000000000000000000006-MzkdK!aL!8'
)
_ENTRIES_1 = {'init': 4096, 'wren': 6144, 'wrdi': 8192, 'wrsr0': 10240, 'status': 12288, 'write_data': 14336, 'read_data': 16384, 'ready_poll': 18432, 'tx_byte': 20480, 'rx_byte': 22528, 'write_root': 24576, 'read_root': 26624, 'scalar_write': 28672, 'scalar_read': 30720, 'geometry_init': 32768, 'outer_init': 34816}
_POOLS_1 = {('init', 14): 4276, ('init', 26): 4280, ('init', 42): 4284, ('init', 70): 4288, ('init', 82): 4292, ('init', 98): 4296, ('init', 124): 4300, ('init', 152): 4304, ('wren', 14): 6272, ('wren', 28): 6276, ('wren', 44): 6280, ('wrdi', 14): 8320, ('wrdi', 28): 8324, ('wrdi', 44): 8328, ('wrsr0', 14): 10376, ('wrsr0', 28): 10380, ('wrsr0', 44): 10384, ('status', 14): 12424, ('status', 28): 12428, ('status', 44): 12432, ('write_data', 24): 14520, ('write_data', 38): 14524, ('write_data', 54): 14528, ('write_data', 68): 14532, ('write_data', 140): 14536, ('write_data', 156): 14540, ('read_data', 24): 16564, ('read_data', 38): 16568, ('read_data', 54): 16572, ('read_data', 68): 16576, ('read_data', 140): 16580, ('read_data', 156): 16584, ('tx_byte', 22): 20676, ('tx_byte', 54): 20680, ('tx_byte', 86): 20684, ('tx_byte', 114): 20688, ('tx_byte', 140): 20692, ('tx_byte', 174): 20696, ('rx_byte', 14): 22644, ('rx_byte', 16): 22648, ('write_root', 32): 25256, ('write_root', 112): 25260, ('write_root', 180): 25264, ('write_root', 184): 25268, ('write_root', 188): 25272, ('write_root', 202): 25276, ('write_root', 214): 25280, ('write_root', 324): 25284, ('write_root', 388): 25288, ('write_root', 490): 25292, ('write_root', 504): 25296, ('write_root', 572): 25300, ('read_root', 22): 26828, ('read_root', 86): 26832, ('read_root', 120): 26836, ('read_root', 160): 26840, ('geometry_init', 4): 32788, ('outer_init', 16): 34884, ('outer_init', 24): 34888, ('outer_init', 28): 34892, ('outer_init', 48): 34896, ('outer_init', 50): 34900}
_SITES_1 = {'shadow': [4276, 4284, 4288, 4296, 4300, 4304, 6272, 6280, 8320, 8328, 10376, 10384, 12424, 12432, 14520, 14528, 14540, 16564, 16572, 16584, 20676, 22644, 25276, 25292], 'constant': [4280, 4292, 6276, 8324, 10380, 12428, 14524, 14532, 14536, 16568, 16576, 16580, 20680, 20684, 20688, 20692, 20696, 22648, 25260, 25280, 25288, 25296, 25300, 26832, 26836, 34892, 34900], 'descriptor': [25256, 26828, 32788, 34884], 'ram_0': [25264], 'ram_1': [25268], 'cache': [25272, 26840, 34888], 'ram_2': [25284], 'rom_0': [34896]}


def _fixture(index=0):
    return bytearray(zlib.decompress(base64.b85decode((_FIXTURE_0, _FIXTURE_1)[index])))


def _bl(image, pc, target):
    displacement = target - pc - 4
    struct.pack_into('<HH', image, pc, 0xF000 | ((displacement >> 12) & 0x7FF),
                     0xF800 | ((displacement >> 1) & 0x7FF))


class SpiNVDetectionTests(unittest.TestCase):
    def assertRejected(self, image, reason=None):
        profile, actual = find_spi_nv_profile(bytes(image))
        self.assertIsNone(profile)
        self.assertTrue(actual.startswith('spi-nv-'), actual)
        if reason is not None:
            self.assertIn(reason, actual)

    def test_two_closed_layouts_and_relocation(self):
        for index in (0, 1):
            for shift in (0, 4, 0x1234):
                with self.subTest(index=index, shift=shift):
                    image = bytes(shift) + _fixture(index)
                    profile, reason = find_spi_nv_profile(image)
                    self.assertEqual(reason, 'accepted')
                    entries = (_ENTRIES_0, _ENTRIES_1)[index]
                    self.assertEqual(profile['source_root'], entries['write_root'] + shift)
                    self.assertEqual(profile['source_tx'], entries['tx_byte'] + shift)
                    self.assertEqual(profile['source_rx'], entries['rx_byte'] + shift)
                    self.assertEqual(profile['virtual_capacity'], 16384)
                    self.assertEqual(profile['page_size'], 32)
                    self.assertEqual(profile['geometry_mode'], 1)
                    self.assertEqual(profile['descriptor_address'], 0x1002000)
                    self.assertEqual(profile['pins']['cs_mask'], 0x40)
                    self.assertEqual(profile['pins']['miso_mask'], 0x80)
                    self.assertEqual(profile['admission'], 'candidate-only')
                    self.assertNotIn('write_cycle_ns', profile)

    def test_every_helper_required(self):
        for index, entries in enumerate((_ENTRIES_0, _ENTRIES_1)):
            for role, pc in entries.items():
                with self.subTest(index=index, role=role):
                    image = _fixture(index)
                    image[pc] ^= 1
                    self.assertRejected(image)

    def test_opcode_transfer_width_and_branch_near_misses(self):
        # TX wire producer LDRB/STRB, byte loop bound and conditional edge all matter.
        for index, entries in enumerate((_ENTRIES_0, _ENTRIES_1)):
            for role, offset in (('tx_byte', 0x20), ('tx_byte', 0x24),
                                 ('rx_byte', 0x16), ('wren', 0x44),
                                 ('write_data', 0x4E), ('read_data', 0x4E),
                                 ('geometry_init', 0), ('geometry_init', 8)):
                with self.subTest(index=index, role=role, offset=offset):
                    image = _fixture(index)
                    image[entries[role] + offset] ^= 1
                    self.assertRejected(image)

    def test_page_limit_and_geometry_mode_mutation(self):
        for index, entries in enumerate((_ENTRIES_0, _ENTRIES_1)):
            image = _fixture(index)
            # Geometry mode1 store has an independent fixed MOVS, not a profile marker.
            struct.pack_into('<H', image, entries['geometry_init'] + 8, 0x2102)
            self.assertRejected(image)
            image = _fixture(index)
            root = entries['write_root']
            marker = bytes.fromhex('2028')  # CMP r0,#32 in bounded page fragment loop.
            where = image.find(marker, root, root + 0x400)
            self.assertGreaterEqual(where, root)
            image[where] = 31
            self.assertRejected(image)

    def test_wire_width_masks_and_distinct_alternate_guards(self):
        for index, entries in enumerate((_ENTRIES_0, _ENTRIES_1)):
            for role, offset, word in (
                    ('tx_byte', 0x38, 0x8111),  # STRH instead of BYTE output.
                    ('tx_byte', 0x18, 0x2C07),  # Seven rather than eight bits.
                    ('tx_byte', 0x2C, 0x2304),  # Wrong clock mask.
                    ('write_root', (0x60, 0x58)[index], 0x230E),
                    ('read_root', (0x46, 0x40)[index], 0x230E)):
                with self.subTest(index=index, role=role, offset=offset):
                    image = _fixture(index)
                    struct.pack_into('<H', image, entries[role] + offset, word)
                    self.assertRejected(image)

    def test_shared_shadow_and_descriptor_disagreement(self):
        for index, pools in enumerate((_POOLS_0, _POOLS_1)):
            for role, offset in (('wren', 14), ('geometry_init', 4),
                                 ('read_root', 0x16)):
                with self.subTest(index=index, role=role):
                    image = _fixture(index)
                    pool = pools[(role, offset)]
                    struct.pack_into('<I', image, pool,
                                     struct.unpack_from('<I', image, pool)[0] + 4)
                    self.assertRejected(image)

    def test_bus_and_shadow_bounds(self):
        for index, pools in enumerate((_POOLS_0, _POOLS_1)):
            for value in (0x03000664, 0x03000760, 0xFFFFFFFF):
                image = _fixture(index)
                struct.pack_into('<I', image, pools[('init', 0x1A)], value)
                self.assertRejected(image)
            for value in (0xFFFFFF, 0x2000000, 0x1002001):
                image = _fixture(index)
                struct.pack_into('<I', image, pools[('geometry_init', 4)], value)
                self.assertRejected(image)

    def test_full_ram_spans_and_overlap(self):
        for index, sites in enumerate((_SITES_0, _SITES_1)):
            for tag, original, replacement, reason in (
                    ('descriptor', 0x1002000, 0x1FFFFFC, 'range'),
                    ('shadow', 0x1001000, 0x1000000, 'range'),
                    ('shadow', 0x1001000, 0x1FFFFFC, 'range'),
                    ('cache', 0x1004000, 0x1FFE001, 'range'),
                    ('descriptor', 0x1002000, 0x1001000, 'overlap'),
                    ('cache', 0x1004000, 0x1002000, 'overlap'),
                    ('cache', 0x1004000, 0x1001000, 'overlap')):
                with self.subTest(index=index, tag=tag, replacement=replacement):
                    image = _fixture(index)
                    for pool in sites[tag]:
                        old = struct.unpack_from('<I', image, pool)[0]
                        struct.pack_into('<I', image, pool, old - original + replacement)
                    self.assertRejected(image, 'descriptor-shadow-cache-' + reason)

    def test_external_calls_may_not_enter_helper_interior(self):
        for index, entries in enumerate((_ENTRIES_0, _ENTRIES_1)):
            image = _fixture(index)
            count = 0
            for pc in range(0, len(image) - 3, 2):
                hi, lo = struct.unpack_from('<HH', image, pc)
                if hi & 0xF800 != 0xF000 or lo & 0xF800 != 0xF800:
                    continue
                delta = ((hi & 0x7FF) << 12) | ((lo & 0x7FF) << 1)
                if delta & 0x400000:
                    delta -= 0x800000
                if pc + 4 + delta == 0x1D000:
                    _bl(image, pc, entries['tx_byte'] + 2)
                    count += 1
            self.assertGreater(count, 10)
            self.assertRejected(image, 'external-call-alias')

    def test_crosslinked_call_and_non_bl_rejected(self):
        for index, entries in enumerate((_ENTRIES_0, _ENTRIES_1)):
            for target in (entries['rx_byte'], len(_fixture(index)) + 4, 0):
                image = _fixture(index)
                _bl(image, entries['wren'] + 0x46, target)
                self.assertRejected(image)
            image = _fixture(index)
            image[entries['wren'] + 0x46:entries['wren'] + 0x4A] = bytes(4)
            self.assertRejected(image)

    def test_duplicate_geometry_rejected(self):
        for index, entries in enumerate((_ENTRIES_0, _ENTRIES_1)):
            image = _fixture(index)
            old = entries['geometry_init']
            new = 0x1C000
            image[new:new + 18] = image[old:old + 18]
            # New literal offset is generated for its own relocated pool.
            struct.pack_into('<H', image, new + 4, 0x4803)
            struct.pack_into('<I', image, new + 20, 0x1002000)
            self.assertRejected(image, 'geometry-ownership-nonunique')

    def test_duplicate_complete_groups_and_cross_layout_ambiguity(self):
        for second_index in (0, 1):
            second = _fixture(second_index)
            for tag, pools in (_SITES_0, _SITES_1)[second_index].items():
                if tag not in ('constant',) and not tag.startswith('rom_'):
                    for pool in pools:
                        struct.pack_into('<I', second, pool,
                                         struct.unpack_from('<I', second, pool)[0] + 0x40000)
            self.assertRejected(_fixture(0) + second, 'complete-groups-ambiguous')

    def test_truncated_root_calls_and_literal_pools(self):
        image = _fixture()
        for end in (0, 1, 0x1000, _ENTRIES_0['write_root'] + 20,
                    _ENTRIES_0['outer_init'] + 10):
            self.assertRejected(image[:end])
        # A typed literal at the very end may not wrap or use a negative slice.
        tail = bytes.fromhex('01214900018101214171002141717047')
        self.assertRejected(tail)

    def test_numeric_opcode_decoy_and_invalid_input(self):
        self.assertRejected(b''.join(bytes((value, 0x20, 0, 0xF0, 0, 0xF8))
                                     for value in range(1, 7)))
        self.assertEqual(find_spi_nv_profile(None), (None, 'spi-nv-image-not-bytes'))
        self.assertEqual(find_spi_nv_profile(bytearray()), (None, 'spi-nv-image-not-bytes'))


if __name__ == '__main__':
    unittest.main()
