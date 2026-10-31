"""Closed source graph for a copied TCM C80 interrupt experiment.

This recognizer does not change automatic configuration or the legacy routes.
Hashes cover complete producers, copy images, mixed veneers and callee entries;
separate pools preserve source ownership outside function extents.
"""
from __future__ import annotations
import hashlib
import struct

_SPANS = (('functions/timer_callback',
  1077036,
  98,
  'd22d01cb19c3ce4d5ad5cdf0c0cf62d8a5f727dfcc529ee5ab4480d6e7f1a658'),
 ('functions/timer_registration',
  1077160,
  38,
  '41f956dddf0179426f7cccf56c42efb22282948bcfd32c32fd133c1a3ba02091'),
 ('functions/irq_registrar',
  1908712,
  142,
  '54e900ef861d52cb037c1c27e9904ebb84c02d97107438c3dd6dddba83f44ab1'),
 ('functions/irq_header_halfword',
  1078728,
  12,
  '0538660df1d3340e19d22c5ce849fd91b85ce91db9d7a7f13513a316ee9e2581'),
 ('functions/timer_advance', 1665968, 76, '0f57e3664360af7f544204634b9eef12124936367dea44fcd7387c068c97bd01'),
 ('functions/compact_handler',
  1908168,
  392,
  '63be1ad6ecc13cb4d13876962fde4c6853a7f2f794d473d9ca189bfdba9aaac6'),
 ('functions/irq_drain', 1908124, 38, 'b8b4048028b1be9471e8fa8fe5de9a88b91d9f1c0164cd42fdbdf0058020467b'),
 ('functions/tick_counter', 1080916, 30, '598a6b6e7fad727e2c4320d8c05ffb85485e93956832d72c6adc3c623fafb940'),
 ('functions/timer_list_tick',
  1080108,
  114,
  '4d2019837ed5e595ec360fcc21d2dc118c7bdbc11df00d0f90be3742fb4fd194'),
 ('functions/timer_list_insert',
  1079936,
  90,
  '68fe1bedcf74c284312d55500a2d0b8c46d0e2cd9873795cdb91cde7385d094d'),
 ('functions/timer_list_remove',
  1080036,
  66,
  '121c6aae9bd76fe54bac6fdf094dffe8cc70fb47284e713160d16750809aecdf'),
 ('functions/queue_post', 1908892, 92, 'f0255dd8283c255d9c1781e3f714d5f60ecb40ea800c6f040ae1c36a3ebe2a2b'),
 ('functions/bx_r0_thunk', 2264568, 2, '81904e68a8b9a2427e9e87e2c61b1098057608d18357d70d9281e8513941cf53'),
 ('functions/bx_r2_thunk', 2264572, 2, 'dd9261f0471768edc33bf979649f6297463be423da17c3f881684f5747e163a1'),
 ('arm/root_copy_path', 7100, 436, '5d39815e0ab47288ae6464bf98a2c256d4f2496ece855341571037f6e7266f48'),
 ('arm/bootstrap_memset', 3474384, 152, '1ba438e3ac103b994da7f149c6da6e5becccf8e9434973f1822e90f55394f883'),
 ('arm/bootstrap_memcpy', 3474536, 120, '1b8a6db8175c65bbe3fbe378ddff4b5fc08fc8f3b87bceeb5c4b82c4a8e29037'),
 ('arm/irq_wrapper', 3530816, 260, '37903ca969addf802c91280b993c9044ea7da347ec783a7d5da68ffe94dd8000'),
 ('arm/irq_disable', 3531308, 20, 'a28a74d99483b6248b1f1a2ab98c2761d430292a639b4809dbd943f8933db59b'),
 ('arm/irq_restore', 3531332, 20, '2c95c11e666d59150521a003886c81d97a6bf7456e9ff2d1fa25752b3361c4af'),
 ('arm/queue_dequeue', 3499452, 92, 'c0cdbff43c0eb54aceee35fd95cf56b47a69eb0efe489d019fcdbfa52ff02383'),
 ('arm/signal_set', 3501060, 100, 'b281212f15bf1d1670ab7b1bd2dfc25b7837bc373dc390ec478a2ab46434f92a'),
 ('arm/signal_get', 3501164, 8, '687b83fbb1b1084c4b61325547b5f8fadfb354f0d8aa39fcef5ecb6ba6b86ed1'),
 ('disable_veneer', 8832, 16, 'a5e2781432f4a8a0b3ac4eb6d6e9e9583e87da61dd05913008b5b245c9b6d083'),
 ('restore_veneer', 8848, 16, '5d05812109c4807519c68adf3579bc64256dee58fec4b24371283255ffbbaf68'),
 ('signal_set_veneer', 2263428, 12, '16345a907619b14fb81ba3d4a40e358be20e1e1dca91c45eca6c47e493ced8a0'),
 ('dequeue_veneer', 2263488, 12, 'ab9efc1182688f0c395f9cc4ca2c6a2a1eaae8a0dedffc78132201abf78556ec'),
 ('signal_get_veneer', 2263620, 12, 'ce7ef3f49a46f36bc387deb37d2a8e3b58c3733eeaa84855e20a636c6e867462'),
 ('bootstrap', 3474380, 280, '60f23c778c8da25cd4361620235f23ce78d41249355c6b29b9e428f3d74946a5'),
 ('tcm_image', 3475064, 63448, '8bbfc8a2d9c4d3255a05ae8f7a12d10c756ba612874f523a9939a1edfec347ab'),
 ('vector_image', 3431296, 43064, 'e892145a92b0dc11139a34fe04f626ee911e91044e7004df831ff79e96f79c53'),
 ('bootstrap_restore', 3474660, 404, '22d418188dbaaf8dcd0e3969baf808ff8d30fe9025ba1642378b82d9ea9b1eee'),
 ('callee', 8832, 8, '67ff945412b5acb3d9c25f795641219c7a67caf21f10e40c260132c5f688e394'),
 ('callee', 1080916, 8, 'd8b062a9c560553c5c80aecf6c0cde99c78acac8b54bb5316697e842cf0d2a44'),
 ('callee', 2263620, 8, 'bf1f24845bec959b53dfb798b98593982c6b13b4a32bf1334000945955fdd3d7'),
 ('callee', 1665968, 8, '01a8245911cf2a45b57bd1053c7f2f735a8805c2a72e1c67cde4c3f7861f9c18'),
 ('callee', 1080108, 8, 'fe33e94af89babc23c5d4953d131ded0c5d7832fc45401c94f443f080f481fd3'),
 ('callee', 8848, 8, '67ff945412b5acb3d9c25f795641219c7a67caf21f10e40c260132c5f688e394'),
 ('callee', 2263344, 8, 'bf1f24845bec959b53dfb798b98593982c6b13b4a32bf1334000945955fdd3d7'),
 ('callee', 1908712, 8, '7096177f2a6662ef515b48409a6a7455978b18fa6667ac2f9f48d2047e72fb14'),
 ('callee', 7044, 8, 'a007353a87e965ee8ac0b60fa65cbb36013765df148899f2c7395096fcc45db0'),
 ('callee', 8728, 8, '190381998a96529395649688f1207287f5f5e27041fc8171a2f9b9c482148b50'),
 ('callee', 868320, 8, 'e631cb45ffd2a9ef6ede3668e5d3fbf381674ec3f6b556542265d209919b89e6'),
 ('callee', 1555812, 8, '19e4c2343c77ffaba22c0a72986adcee9098f2c63b209bc64307c238116f09ac'),
 ('callee', 2263428, 8, 'bf1f24845bec959b53dfb798b98593982c6b13b4a32bf1334000945955fdd3d7'),
 ('callee', 1078728, 8, '13603bafd2474f0286c3fd97b3e9c1dd0cb00ef349b7668a7a4e6217c3c16ff2'),
 ('callee', 2264568, 8, 'bbbbd260e115cae417d17834cfc4d4ff481040d07628126abc199181327df8a5'),
 ('callee', 1908124, 8, 'aa12e7366dd9f80a83e6344c1836525a1f02f15c26f5ea745d509fdfdea8f507'),
 ('callee', 2263488, 8, 'bf1f24845bec959b53dfb798b98593982c6b13b4a32bf1334000945955fdd3d7'),
 ('callee', 2264572, 8, '8f92379e72b00c63551023618b5ae8d73f4060ffed2c38fee53170e4f67b6d6e'),
 ('callee', 1080036, 8, 'c9696b860682c67fd506956de90ce2b3c3cd1b58d24682dc182e3064ddb8ed3d'),
 ('callee', 1079936, 8, 'ae088c37a407fae05fb14a86f91f4a975db020d5e64be480cfc6653695f13024'),
 ('callee', 1908892, 8, 'e0f2a978ea1927afe0da09240bdca8ea8576a3c1a9664b5c9a0e4ea86f78024a'),
 ('callee', 8864, 8, 'bf1f24845bec959b53dfb798b98593982c6b13b4a32bf1334000945955fdd3d7'),
 ('callee', 1555788, 8, 'c1c1556c6f49bc7bf32f0d6cba9a69745d93398dc1bc770134a31551cbddc87a'),
 ('callee', 1111632, 8, 'a570f9c9a9bb20910be57dfa48798091a9a98069eb2b18d6f9dbf03725293e4f'),
 ('callee', 2263500, 8, 'bf1f24845bec959b53dfb798b98593982c6b13b4a32bf1334000945955fdd3d7'),
 ('arm-callee', 7596, 8, '82735647d94f4becbe135e77ca0efaf6d6fee5bab79d9d272f1f2c10a9d3b7c0'),
 ('arm-callee', 7536, 8, 'd8af48d9e79d4654e57f461ac39c2bbc75bbfa05027b39131092bdffcbf4b075'),
 ('arm-callee', 3531576, 8, 'e8c968b1c0e2eb8c47edf56001d7a29395359d831cfa8528bd272323b413e77c'),
 ('arm-callee', 3531588, 8, 'e8c968b1c0e2eb8c47edf56001d7a29395359d831cfa8528bd272323b413e77c'),
 ('arm-callee', 3531892, 8, 'e8c968b1c0e2eb8c47edf56001d7a29395359d831cfa8528bd272323b413e77c'))

_POOLS = ((8024, 2293), (8028, 7121), (8032, 7124), (8036, 2573), (8040, 7145), (8044, 7148), (8048, 2309), (8052, 7169), (8056, 7172), (8060, 2381), (8064, 7193), (8068, 7196), (8072, 8304), (8076, 7217), (8080, 7220), (8084, 3474380), (8088, 58720256), (8092, 280), (8096, 3475064), (8100, 58721280), (8104, 63448), (8108, 58720412), (8112, 7325), (8116, 7328), (8120, 16820280), (8124, 889076), (8128, 58720260), (8132, 7361), (8136, 7364), (8140, 17709376), (8144, 3416), (8148, 7397), (8152, 7400), (8156, 3431296), (8160, 16777216), (8164, 43064), (8168, 7433), (8172, 7436), (8176, 3474360), (8180, 17709356), (8184, 20), (8188, 7469), (8192, 7472), (8196, 3474660), (8200, 58720256), (8204, 404), (1077136, 17183084), (1077140, 17244092), (1077144, 16796928), (1077148, 16796924), (1077152, 16796864), (1077156, 16796788), (1077200, 17183076), (1077204, 17183084), (1077208, 50333600), (1077212, 1077037), (1078740, 16796792), (1080028, 16796864), (1080032, 16796864), (1080104, 16796864), (1080948, 4294966296), (1666044, 17615264), (1908164, 17681124), (1908560, 16807100), (1908564, 50334848), (1908568, 17615404), (1908572, 16807984), (1908576, 16807112), (1908580, 17681116), (1908856, 1908065), (1908876, 3308044), (1908880, 529), (1908884, 16807112), (1908888, 16807932), (1908984, 16801952), (1908988, 3308052), (1908992, 613), (1908996, 17681124), (3474528, 58720256), (3474656, 58720408), (3501160, 17615208), (3531452, 17615404), (3531456, 17615396), (3531460, 58777097), (3531464, 58777100), (3531468, 16804464), (3531472, 17615204), (3531476, 17615208))

_CONTRACT = {'callback': 1077037,
 'callback_slot': 16807972,
 'copied_branch_target': 16777224,
 'handler_rom': 1908168,
 'handler_slot': 17615396,
 'interrupt_enable': 50334868,
 'interrupt_mask': 512,
 'interrupt_status': 50334848,
 'pending_semantics': 'latched W1C',
 'registrar': 1908712,
 'row': 30,
 'row_rom': 3462032,
 'row_runtime': 16807952,
 'row_size': 28,
 'table_runtime': 16807112,
 'timer_control': 50333600,
 'timer_control_value': 2,
 'timer_control_width': 2,
 'timer_control_write_pc': 1077184,
 'vector': 24,
 'vector_target': 16777216,
 'veneer_literal_address': 16777228,
 'wrapper_rom': 3530816,
 'wrapper_runtime': 58777032}


def find_copied_c80_irq_profile(image: bytes):
    for _role, at, size, digest in _SPANS:
        if not 0 <= at <= len(image) - size:
            return None, 'copied-irq-source-truncated'
        if hashlib.sha256(image[at:at+size]).hexdigest() != digest:
            return None, 'copied-irq-source-body-mismatch'
    for at, value in _POOLS:
        if not 0 <= at <= len(image) - 4 or struct.unpack_from('<I', image, at)[0] != value:
            return None, 'copied-irq-source-pool-mismatch'
    return dict(_CONTRACT, signature='source-copied-tcm-c80-halfword-v1',
                accepted=True, active=False, interval_ns=5_000_000,
                wrapper_size=0x104, handler_size=0x188,
                vector_rom=0x345b80), None
