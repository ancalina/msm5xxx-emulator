"""Experimental QEMU matrix input packet checks."""
from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path
import queue
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from corpus import snippet
from unittest import mock
from unicorn import UC_ARCH_ARM, UC_MODE_THUMB, Uc

from msm5xxx_emulator.detection.boot import (
    DMD_DOWNLOAD_5500_LITERALS,
    PRIMARY_FLASH_PROBE_SIGNATURE,
)


NATIVE = Path(__file__).parents[1] / "native/qemu"
TRANSPORT_SOURCE = Path(__file__).parents[1] / "src/msm5xxx_emulator/qemu/transport.py"
MODULE = importlib.import_module("msm5xxx_emulator.qemu.live_display")


class QEMUInputTransportTests(unittest.TestCase):
    def test_distributed_sideband_source_admission_and_release(self):
        from copy import deepcopy
        from msm5xxx_emulator.devices.input import InputMixin
        from corpus import firmware_path
        image = firmware_path("SPH-X4500.bin").read_bytes()
        profile, status, _ = MODULE.resolve_distributed_matrix_input(image)
        self.assertEqual(status, "static-candidate")
        config = SimpleNamespace(load_address=0, flash_size=0x400000,
                                 ram_base=0x1000000, ram_size=0x800000,
                                 board_status_input=None)
        prop, reject = MODULE.qemu_distributed_matrix_property(image, config, profile)
        self.assertIsNone(reject)
        self.assertTrue(prop.endswith(":80:10"))
        producer, reject = MODULE.qemu_distributed_sideband_producer(image, config, profile)
        self.assertIsNone(reject)
        for key, value in (("mask", 0x20), ("register_width", True),
                           ("event", 0x52), ("press_callsite", 0x80666)):
            with self.subTest(key=key):
                changed = deepcopy(profile)
                changed["sideband_producers"][0][key] = value
                fallback, reject = MODULE.qemu_distributed_matrix_property(image, config, changed)
                self.assertIsNotNone(reject)
                self.assertEqual(fallback, prop.rsplit(":", 1)[0])
        limited = SimpleNamespace(**vars(config))
        for boundary in (profile["sense_site"] + 4, 0x80668):
            limited.flash_size = boundary
            self.assertIsNone(MODULE.qemu_distributed_sideband_producer(image, limited, profile)[0])
            fallback, reject = MODULE.qemu_distributed_matrix_property(image, limited, profile)
            self.assertIsNotNone(reject)
            self.assertEqual(fallback, prop.rsplit(":", 1)[0])
        transport = object.__new__(MODULE.Transport)
        transport.matrix_input_profile = profile
        transport.matrix_input_sideband_producer = producer
        transport.matrix_held, transport.sideband_held = {}, set()
        transport.decoder = InputMixin()
        transport.decoder.direct_input_profile = None
        transport.decoder.input_error = ""
        packets = []
        transport.input_socket = SimpleNamespace(sendall=packets.append)
        self.assertTrue(transport.can_set_key(7))
        self.assertTrue(transport.set_key(7, True))
        self.assertFalse(transport.set_key(15, True))
        transport.matrix_input_profile = None
        transport.matrix_input_sideband_producer = None
        transport.input_socket = SimpleNamespace(sendall=mock.Mock(side_effect=OSError("send")))
        self.assertFalse(transport.set_key(7, False))
        self.assertEqual(transport.sideband_held, {7})
        transport.input_socket = SimpleNamespace(sendall=packets.append)
        self.assertTrue(transport.set_key(7, False))
        self.assertEqual(packets, [bytes.fromhex("8001ff10"), bytes.fromhex("80000000")])
        self.assertEqual(transport.sideband_held, set())

    def test_gdb_remote_tcp_nodelay_preserves_stream_contract(self):
        from msm5xxx_emulator.qemu.gdb_remote import Remote

        families = [MODULE.socket.AF_INET, MODULE.socket.AF_INET6, None]
        if hasattr(MODULE.socket, "AF_UNIX"):
            families.append(MODULE.socket.AF_UNIX)
        for family in families:
            with self.subTest(family=family):
                sent = []
                incoming = bytearray(b"+$00000000#80")
                option = mock.Mock()
                sock = SimpleNamespace(
                    sendall=sent.append,
                    recv=lambda size: bytes((incoming.pop(0),)),
                )
                if family is not None:
                    sock.family = family
                    sock.setsockopt = option
                remote = Remote(sock)
                self.assertIs(remote.sock, sock)
                self.assertEqual(sent, [])
                if family in (MODULE.socket.AF_INET, MODULE.socket.AF_INET6):
                    option.assert_called_once_with(
                        MODULE.socket.IPPROTO_TCP, MODULE.socket.TCP_NODELAY, 1
                    )
                else:
                    option.assert_not_called()
                self.assertEqual(remote.command("p0"), "00000000")
                self.assertEqual(sent, [b"$p0#a0", b"+"])
                self.assertEqual(incoming, b"")

        failure = OSError("TCP option failed")
        sock = SimpleNamespace(
            family=MODULE.socket.AF_INET,
            setsockopt=mock.Mock(side_effect=failure),
            close=mock.Mock(),
        )
        with self.assertRaises(OSError) as caught:
            Remote(sock)
        self.assertIs(caught.exception, failure)
        sock.close.assert_not_called()

    def test_loop_status_requires_matching_temporary_class_and_preserves_explicit_level(self):
        image = bytes(0x600)
        matrix = dict(grammar='indirect-halfword-loop-six-row-v1',
                      promotion='temporary-evidence-gated',
                      descriptor=0x1000000, queue_sink='0x500')
        candidate = dict(grammar='indirect-halfword-loop-status-events-v1',
                         descriptor=0x1000000, queue_sink=0x500,
                         mask=16, width=2, pointer_offset=4,
                         promotion='temporary-evidence-gated',
                         runtime_admitted=False, default_level=None, physical_role=None)
        helper = MODULE.qemu_halfword_status_property
        with mock.patch('msm5xxx_emulator.qemu.transport.resolve_indirect_board_status',
                        return_value=(candidate,'static-candidate',[])) as resolver:
            for profile in (None, dict(matrix, promotion=None),
                            dict(matrix, grammar='indirect-halfword-six-row-v1')):
                self.assertEqual(helper(image,0,profile,None),(None,None))
            resolver.assert_not_called()
            self.assertEqual(helper(image,0,matrix,None),
                ('board-status-input=3000720:10:10,board-status-descriptor=1000000',None))
            self.assertEqual(helper(image,0,matrix,None,object()),
                             (None,'conflicting-status-profile'))
            for level in (0,16):
                self.assertEqual(helper(image,0,matrix,level),
                    (f'board-status-input=3000720:10:{level:x},board-status-descriptor=1000000',None))
            for level in (True,False,4,-16,17,16.0,'16'):
                self.assertEqual(helper(image,0,matrix,level),(None,'invalid-level'))
            self.assertEqual(helper(image,0,matrix,16,object()),(None,'conflicting-status-profile'))
            for changed in ({'grammar':'unknown'}, {'grammar':'indirect-halfword-mapped-row-v1'}):
                self.assertEqual(helper(image,0,dict(matrix,**changed),16),
                                 (None,'halfword-matrix-not-admitted'))
            for changed in ({'descriptor':0x1000100},{'descriptor':True},
                            {'descriptor':0x2000000-0x34},{'queue_sink':'0x502'},
                            {'queue_sink':None}):
                self.assertEqual(helper(image,0,dict(matrix,**changed),16),
                                 (None,'matrix-status-mismatch'))
            for changed in ({'grammar':'indirect-halfword-status-events-v1'}, {'mask':4},
                            {'mask':True},{'width':1},{'width':True},{'pointer_offset':8},
                            {'promotion':'accepted'},{'runtime_admitted':True},
                            {'default_level':16},{'physical_role':'fold'}):
                resolver.return_value=(dict(candidate,**changed),'static-candidate',[])
                self.assertEqual(helper(image,0,matrix,16),
                                 (None,'unsupported-loop-status-contract'))
            resolver.return_value=(None,'ambiguous-status-helpers',[])
            self.assertEqual(helper(image,0,matrix,16),(None,'ambiguous-status-helpers'))
        # Proves level16 passes only constructor argument validation. No runtime starts.
        with mock.patch('msm5xxx_emulator.qemu.transport.detect',side_effect=RuntimeError('detect-sentinel')) as detector:
            with self.assertRaisesRegex(RuntimeError,'detect-sentinel'):
                MODULE.Transport(Path('unused'),Path('unused'),experimental_halfword=True,
                                 experimental_status_level=16)
            detector.assert_called_once()
        for options in (dict(experimental_status_level=16),
                        dict(experimental_halfword=True,experimental_status_level=True)):
            with self.assertRaisesRegex(ValueError,'status level requires'):
                MODULE.Transport(Path('unused'),Path('unused'),**options)

    def test_distributed_matrix_memory_rows_and_numeric_packets(self):
        image = bytearray(0x100)
        struct.pack_into('<HH', image, 0x10, 0x480B, 0x7901)
        struct.pack_into('<HH', image, 0x20, 0x4807, 0x7900)
        struct.pack_into('<I', image, 0x40, 0x3000690)
        config = SimpleNamespace(load_address=0, flash_size=len(image),
                                 ram_base=0x1000000, ram_size=0x800000,
                                 board_status_input=None)
        profile = dict(grammar='distributed-six-byte-numeric-v1', rows=6,
                       columns=4, register_width=1, no_key=15,
                       single_key_column_sense=[14, 13, 11, 7],
                       register=0x3000694, presence_site=0x12, sense_site=0x22,
                       scanner_state=0x1000100, batch_state=0x1000200,
                       producer=dict(family='distributed-filtered-byte-ring32-v1',
                                     slots=32, wrap_mask=31,
                                     state=0x1000300, ring=0x1000400),
                       gpio_ports=[dict(address=address, mask=mask, shadow=0x1000500+i)
                                   for i, (address, mask) in enumerate(
                                       ((0x300066c, 0x62), (0x3000668, 6), (0x3000664, 0x80)))],
                       row_values=[[0x60,6,0x80], [0x42,6,0x80], [0x22,6,0x80],
                                   [0x62,4,0x80], [0x62,2,0x80], [0x62,6,0]],
                       global_values=[0,0,0],
                       token_cells=[dict(event=event, row=i % 6, column=i // 6)
                                    for i, event in enumerate(b'123456789*0#')])
        helper = MODULE.qemu_distributed_matrix_property
        self.assertEqual(helper(bytes(image), config, profile),
                         ('matrix-gpio=3000694:12:22:300066c:62:3000668:6:3000664:80', None))
        for changed, reason in (
            ({'grammar': 'unknown'}, 'unsupported-distributed-contract'),
            ({'register': 0x3000695}, 'invalid-gpio-ports'),
            ({'gpio_ports': []}, 'invalid-gpio-ports'),
            ({'row_values': list(reversed(profile['row_values']))}, 'invalid-gpio-row-order'),
            ({'global_values': [1,0,0]}, 'invalid-gpio-row-order'),
            ({'scanner_state': 0x1800000-9}, 'state-outside-ram'),
            ({'batch_state': None}, 'state-outside-ram'),
            ({'producer': None}, 'unclosed-ring-profile'),
            ({'sense_site': True}, 'sense-outside-primary-nor'),
            ({'sense_site': 0x12}, 'sense-outside-primary-nor'),
        ):
            self.assertEqual(helper(bytes(image), config, dict(profile, **changed)), (None, reason))
        config.board_status_input = SimpleNamespace(address=0x3000668)
        self.assertEqual(helper(bytes(image), config, profile), (None, 'conflicting-status-profile'))
        config.board_status_input.address = 0x3000670
        self.assertIsNotNone(helper(bytes(image), config, profile)[0])
        image[0x22] ^= 1
        self.assertEqual(helper(bytes(image), config, profile), (None, 'sense-load-shape-mismatch'))

        transport = object.__new__(MODULE.Transport)
        transport.matrix_input_profile = profile
        transport.matrix_held, transport.sideband_held = {}, set()
        transport.decoder = SimpleNamespace(input_error='')
        packets = []
        transport.input_socket = SimpleNamespace(sendall=packets.append)
        for i, bit in enumerate(range(11, 23)):
            self.assertTrue(transport.can_set_key(bit))
            self.assertTrue(transport.set_key(bit, True))
            self.assertFalse(transport.set_key(11 if bit != 11 else 12, True))
            self.assertTrue(transport.set_key(bit, False))
            self.assertEqual(packets[-2:], [bytes((0x80, 1, i % 6, [14,13][i // 6])),
                                           bytes((0x80, 0, 0, 0))])
        for bit in range(11):
            self.assertFalse(transport.can_set_key(bit))
        profile['token_cells'].append(dict(event=0x53, row=1, column=1))
        self.assertFalse(transport.can_set_key(5, 0x53))  # No inferred OK alias.
        profile['token_cells'].append(dict(profile['token_cells'][0]))
        self.assertFalse(transport.can_set_key(11))
        with self.assertRaisesRegex(ValueError, 'distributed matrix setting'):
            MODULE.Transport(None, None, experimental_distributed=1)

    def test_distributed_functional_controls_require_paired_evidence_and_six_row_cells(self):
        from copy import deepcopy

        events = [99,102,49,52,55,42,91,83,50,53,56,48,101,80,51,54,57,35,135,100,82,0,84,85]
        profile = dict(
            grammar='distributed-six-byte-numeric-v1', rows=6, columns=4, no_key=15,
            single_key_column_sense=[14,13,11,7], event_codes=events,
            menu_mapping_status='accepted-provisional', ok_mapping_status='accepted-provisional',
            provisional_mappings={
                0: dict(event=0x5B, rule='same-image-distributed-functional-menu-v1',
                        semantic_status='temporary-evidence-gated-provisional', functional_only=True),
                5: dict(event=0x53, rule='same-image-distributed-functional-confirm-v1',
                        semantic_status='temporary-evidence-gated-provisional', functional_only=True)},
            token_cells=[dict(token=chr(v),event=v,row=events.index(v)%6,column=events.index(v)//6)
                         for v in b'123456789*0#']
                        + [dict(token='M',event=0x5B,row=0,column=1),
                           dict(token='O',event=0x53,row=1,column=1)],
        )
        transport = object.__new__(MODULE.Transport)
        transport.matrix_input_profile = profile
        transport.matrix_held, transport.sideband_held = {}, set()
        transport.decoder = SimpleNamespace(input_error='')
        packets = []
        transport.input_socket = SimpleNamespace(sendall=packets.append)
        for bit,row in ((0,0),(5,1)):
            self.assertTrue(transport.can_set_key(bit))
            self.assertTrue(transport.set_key(bit,True))
            self.assertFalse(transport.set_key(5 if bit==0 else 0,True))
            self.assertTrue(transport.set_key(bit,False))
            self.assertEqual(packets[-2:],[bytes((0x80,1,row,13)),bytes((0x80,0,0,0))])
        self.assertTrue(transport.can_set_key(15))
        self.assertTrue(transport.can_set_key(5,0x35))  # Preserve explicit numeric override.
        for bit,event in ((True,0x53),(False,0x5B),(0,0x53),(5,0x5B),(1,0x53)):
            self.assertFalse(transport.can_set_key(bit,event))
        variants = []
        for field,value in (('rows',7),('rows',6.0),('columns',3),
                            ('menu_mapping_status','rejected'),('ok_mapping_status','rejected')):
            changed=deepcopy(profile);changed[field]=value;variants.append(changed)
        for key in (0,5):
            for field,value in (('event',True),('semantic_status','unverified'),
                                ('functional_only',False),('rule','same-image-mapped-functional-confirm-v1')):
                changed=deepcopy(profile);changed['provisional_mappings'][key][field]=value;variants.append(changed)
            changed=deepcopy(profile);del changed['provisional_mappings'][key];variants.append(changed)
        for token_index in (-1,-2):
            for field,value in (('event',float(profile['token_cells'][token_index]['event'])),
                                ('row',0.0),('column',2)):
                changed=deepcopy(profile);changed['token_cells'][token_index][field]=value;variants.append(changed)
            changed=deepcopy(profile);changed['token_cells'].append(changed['token_cells'][token_index].copy());variants.append(changed)
            changed=deepcopy(profile);changed['token_cells'].pop(token_index);variants.append(changed)
        changed=deepcopy(profile);changed['event_codes'][0]=0x53;variants.append(changed)
        changed=deepcopy(profile);changed['event_codes'][0]=99.0;variants.append(changed)
        changed=deepcopy(profile);changed['event_codes'].pop();variants.append(changed)
        for changed in variants:
            with self.subTest(profile=changed):
                transport.matrix_input_profile=changed
                self.assertFalse(transport.can_set_key(0))
                self.assertFalse(transport.can_set_key(5))
                self.assertTrue(transport.can_set_key(15))
        for cells in (None, [None], profile['token_cells'] + [None],
                      profile['token_cells'] + [{}]):
            transport.matrix_input_profile=dict(profile,token_cells=cells)
            self.assertFalse(transport.can_set_key(0))
            self.assertFalse(transport.can_set_key(5))
            self.assertEqual(transport.can_set_key(15), isinstance(cells,list) and len(cells)>1)
        transport.matrix_input_profile=profile
        transport.input_socket=SimpleNamespace(sendall=lambda packet: (_ for _ in ()).throw(OSError('send-failed')))
        self.assertFalse(transport.set_key(0,True))
        self.assertEqual(transport.matrix_held,{})

    def distributed_navigation_profile(self):
        events = [99,102,49,52,55,42,91,83,50,53,56,48,101,80,51,54,57,35,135,100,82,0,84,85]
        controls = ((0, 'M', 91, 'menu'), (5, 'O', 83, 'confirm'))
        directions = ((1, 'U', 99), (9, 'D', 100), (4, 'L', 101), (6, 'R', 102))
        mappings = {bit: dict(event=raw, rule=f'same-image-distributed-functional-{role}-v1',
                             semantic_status='temporary-evidence-gated-provisional', functional_only=True)
                    for bit, _, raw, role in controls}
        mappings.update({bit: dict(event=raw, rule='same-image-distributed-functional-navigation-v1',
                                  semantic_status='temporary-evidence-gated-provisional', functional_only=True)
                         for bit, _, raw in directions})
        tokens = [(chr(v), v) for v in b'123456789*0#']
        tokens += [(token, raw) for _, token, raw, _ in controls]
        tokens += [(token, raw) for _, token, raw in directions]
        profile = dict(grammar='distributed-six-byte-numeric-v1', rows=6, columns=4, no_key=15,
                       single_key_column_sense=[14,13,11,7], event_codes=events,
                       menu_mapping_status='accepted-provisional', ok_mapping_status='accepted-provisional',
                       navigation_mapping_status='accepted-provisional', provisional_mappings=mappings,
                       control_consumer=dict(grammar='distributed-queued-direct-word-controls-v1',
                                             confirm_handler=0x6400, confirm_status=0x1003500,
                                             global_word=0x1003100),
                       navigation_consumer=dict(grammar='distributed-menu-grid-navigation-v1',
                                                handler=0x6400, status=0x1003500,
                                                global_word=0x1003100, grid_stride=3),
                       token_cells=[dict(token=t,event=v,row=events.index(v)%6,column=events.index(v)//6)
                                    for t,v in tokens])
        return profile, events, directions

    def test_distributed_navigation_pair_preserves_controls_and_numeric_fallback(self):
        from copy import deepcopy

        profile, events, directions = self.distributed_navigation_profile()
        t = object.__new__(MODULE.Transport)
        t.matrix_input_profile = profile
        t.matrix_held, t.sideband_held = {}, set()
        t.decoder = SimpleNamespace(input_error='')
        packets = []
        t.input_socket = SimpleNamespace(sendall=packets.append)
        for bit, _, raw in directions:
            index = events.index(raw)
            self.assertEqual(t._matrix_input_position(bit, None), (raw,index%6,index//6))
            self.assertTrue(t.set_key(bit, True))
            self.assertFalse(t.set_key(0, True))
            self.assertTrue(t.set_key(bit, False))
            self.assertEqual(packets[-2:], [bytes((0x80,1,index%6,[14,13,11,7][index//6])),
                                           bytes((0x80,0,0,0))])
        for bit in (2,3,7,True,False):
            self.assertFalse(t.can_set_key(bit))
        self.assertFalse(t.can_set_key(4,102))
        self.assertTrue(t.can_set_key(4,53))  # Explicit numeric override stays numeric.
        variants = []
        for field, value in (('navigation_mapping_status','rejected'), ('navigation_consumer',None)):
            changed=deepcopy(profile);changed[field]=value;variants.append(changed)
        for field, value in (('handler',0x6500), ('status',0x1003504), ('global_word',None),
                             ('grid_stride',3.0), ('grammar','unknown')):
            changed=deepcopy(profile);changed['navigation_consumer'][field]=value;variants.append(changed)
        for bit, token, raw in directions:
            changed=deepcopy(profile);del changed['provisional_mappings'][bit];variants.append(changed)
            for field, value in (('event',float(raw)), ('functional_only',1), ('rule','unknown')):
                changed=deepcopy(profile);changed['provisional_mappings'][bit][field]=value;variants.append(changed)
            changed=deepcopy(profile)
            cell=next(c for c in changed['token_cells'] if c['token']==token)
            changed['token_cells'].append(cell.copy());variants.append(changed)
            for field, value in (('row',0.0), ('column',False), ('event',float(raw)),
                                 ('event',53), ('event',83)):
                changed=deepcopy(profile)
                next(c for c in changed['token_cells'] if c['token']==token)[field]=value
                variants.append(changed)
            changed=deepcopy(profile)
            cell=next(c for c in changed['token_cells'] if c['token']==token)
            changed['token_cells'].append(dict(cell,token='junk'));variants.append(changed)
            for field, value in (('row',0.0), ('column',False), ('event',float(raw))):
                changed=deepcopy(profile)
                cell=next(c for c in changed['token_cells'] if c['token']==token)
                changed['token_cells'].append(dict(cell,**{field:value}));variants.append(changed)
        changed=deepcopy(profile);changed['provisional_mappings'][True]=changed['provisional_mappings'].pop(1)
        variants.append(changed)
        for changed in variants:
            with self.subTest(profile=changed):
                t.matrix_input_profile=changed
                self.assertTrue(all(not t.can_set_key(bit) for bit,_,_ in directions))
                self.assertTrue(all(t.can_set_key(bit) for bit in (0,5,15)))
        t.matrix_input_profile=profile
        self.assertTrue(t.set_key(4,True))
        t.matrix_input_profile=variants[0]
        self.assertTrue(t.set_key(4,False))  # Always release the original held cell.
        t.matrix_input_profile=profile
        t.input_socket=SimpleNamespace(sendall=lambda packet: (_ for _ in ()).throw(OSError('send-failed')))
        self.assertFalse(t.set_key(6,True))
        self.assertEqual(t.matrix_held,{})

    def test_distributed_back_rejection_preserves_other_keys_and_release(self):
        from copy import deepcopy

        profile, events, _ = self.distributed_navigation_profile()
        profile.update(back_mapping_status='accepted-provisional',
                       back_consumer=dict(grammar='distributed-saved-menu-back-v1',
                                          handler=0x6400, status=0x1003500,
                                          global_word=0x1003100, history=0x1004000,
                                          comparison_descriptor=0x1005000, saved_menu_comparison=0x1006000))
        profile['provisional_mappings'][2] = dict(
            event=82, rule='same-image-distributed-functional-back-v1',
            semantic_status='temporary-evidence-gated-provisional', functional_only=True)
        cell = dict(token='C',event=82,row=2,column=3)
        profile['token_cells'].append(cell)
        t = object.__new__(MODULE.Transport)
        t.matrix_input_profile = profile
        t.matrix_held, t.sideband_held = {}, set()
        t.decoder = SimpleNamespace(input_error='')
        packets = []
        t.input_socket = SimpleNamespace(sendall=packets.append)
        self.assertEqual(t._matrix_input_position(2,None), (82,2,3))
        self.assertTrue(t.set_key(2,True))
        self.assertTrue(t.set_key(2,False))
        self.assertEqual(packets, [bytes((0x80,1,2,7)),bytes((0x80,0,0,0))])
        self.assertFalse(t.can_set_key(2,83))
        self.assertTrue(t.can_set_key(2,53))
        variants = []
        for field,value in (('back_mapping_status','rejected'),('back_consumer',None)):
            changed=deepcopy(profile); changed[field]=value; variants.append(changed)
        for field,value in (('handler',0x6500),('status',True),('global_word',0),
                            ('history',0),('history',0x1004002),('comparison_descriptor',4.0),
                            ('saved_menu_comparison',None),('grammar','unknown')):
            changed=deepcopy(profile); changed['back_consumer'][field]=value; variants.append(changed)
        for field,value in (('event',82.0),('functional_only',1),('rule','unknown')):
            changed=deepcopy(profile); changed['provisional_mappings'][2][field]=value; variants.append(changed)
        changed=deepcopy(profile); del changed['provisional_mappings'][2]; variants.append(changed)
        changed=deepcopy(profile); changed['token_cells'].pop(); variants.append(changed)
        for field,value in (('row',2.0),('column',True),('event',82.0),
                            ('event',53),('event',83),('event',99)):
            changed=deepcopy(profile); changed['token_cells'][-1][field]=value; variants.append(changed)
            changed=deepcopy(profile); changed['token_cells'].append(dict(cell,**{field:value})); variants.append(changed)
        changed=deepcopy(profile); changed['token_cells'].append(cell.copy()); variants.append(changed)
        changed=deepcopy(profile); changed['token_cells'].append(dict(cell,token='junk')); variants.append(changed)
        for changed in variants:
            with self.subTest(profile=changed):
                t.matrix_input_profile=changed
                self.assertFalse(t.can_set_key(2))
                self.assertTrue(all(t.can_set_key(bit) for bit in (0,5,15,1,9,4,6)))
        changed=deepcopy(profile); changed['navigation_mapping_status']='rejected'
        t.matrix_input_profile=changed
        self.assertFalse(t.can_set_key(2))
        self.assertTrue(all(t.can_set_key(bit) for bit in (0,5,15)))
        t.matrix_input_profile=profile
        self.assertTrue(t.set_key(2,True))
        t.matrix_input_profile=variants[0]
        self.assertTrue(t.set_key(2,False))
        t.matrix_input_profile=profile
        t.input_socket=SimpleNamespace(sendall=lambda packet: (_ for _ in ()).throw(OSError('send-failed')))
        self.assertFalse(t.set_key(2,True))
        self.assertEqual(t.matrix_held,{})

    def test_distributed_call_is_independent_optional_context_exit(self):
        from copy import deepcopy

        profile, events, _ = self.distributed_navigation_profile()
        profile.update(back_mapping_status='accepted-provisional',
                       back_consumer=dict(grammar='distributed-saved-menu-back-v1',
                                          handler=0x6400, status=0x1003500,
                                          global_word=0x1003100, history=0x1004000,
                                          comparison_descriptor=0x1005000, saved_menu_comparison=0x1006000),
                       call_mapping_status='accepted-provisional',
                       call_consumer=dict(grammar='distributed-queued-context-exit-v1',
                                          handler=0x6400, status=0x1003500,
                                          global_word=0x1003100, event=0x50, request_code=0x32))
        profile['provisional_mappings'][2] = dict(event=82,
            rule='same-image-distributed-functional-back-v1',
            semantic_status='temporary-evidence-gated-provisional', functional_only=True)
        profile['token_cells'].append(dict(token='C', event=82, row=2, column=3))
        profile['provisional_mappings'][3] = dict(event=80,
            rule='same-image-distributed-functional-call-v1',
            semantic_status='temporary-evidence-gated-provisional', functional_only=True)
        cell = dict(token='S', event=80, row=1, column=2)
        profile['token_cells'].append(cell)
        t = object.__new__(MODULE.Transport)
        t.matrix_input_profile = profile
        t.matrix_held, t.sideband_held = {}, set()
        sideband = dict(semantic_key=7, event=81)
        t.matrix_input_sideband_producer = sideband
        t.decoder = SimpleNamespace(input_error='',
            _direct_sideband_producer=lambda bit, event, selected: sideband if bit == 7 else None)
        packets = []
        t.input_socket = SimpleNamespace(sendall=packets.append)
        self.assertEqual(t._matrix_input_position(3,None), (80,1,2))
        self.assertTrue(t.can_set_key(3,80))
        self.assertTrue(t.set_key(3,True))
        self.assertTrue(t.set_key(3,False))
        self.assertEqual(packets, [bytes((0x80,1,1,11)), bytes((0x80,0,0,0))])
        for bit, event in ((0,80),(5,80),(2,80),(1,80),(True,80),(3,83)):
            self.assertFalse(t.can_set_key(bit,event))
        variants = []
        for field, value in (('call_mapping_status','rejected'),('call_consumer',None)):
            changed=deepcopy(profile);changed[field]=value;variants.append(changed)
        for field, value in (('handler',0x6500),('handler',True),('status',0),
                             ('global_word',0x1003104),('request_code',0x31),
                             ('request_code',50.0),('event',True),('event',83),
                             ('grammar','unknown')):
            changed=deepcopy(profile);changed['call_consumer'][field]=value;variants.append(changed)
        for field, value in (('event',80.0),('event',True),('functional_only',1),
                             ('rule','unknown'),('semantic_status','unknown')):
            changed=deepcopy(profile);changed['provisional_mappings'][3][field]=value;variants.append(changed)
        changed=deepcopy(profile);del changed['provisional_mappings'][3];variants.append(changed)
        changed=deepcopy(profile);changed['token_cells'].pop();variants.append(changed)
        changed=deepcopy(profile);changed['token_cells'].append(cell.copy());variants.append(changed)
        changed=deepcopy(profile);changed['token_cells'].append(dict(cell,token='junk'));variants.append(changed)
        changed=deepcopy(profile);changed['event_codes'][21]=80;variants.append(changed)
        for field, value in (('row',6),('column',4),('row',1.0),('column',False),
                             ('row',2),('event',80.0),('event',83),('event',82),('event',99)):
            changed=deepcopy(profile);changed['token_cells'][-1][field]=value;variants.append(changed)
            changed=deepcopy(profile);changed['token_cells'].append(dict(cell,**{field:value}));variants.append(changed)
        for changed in variants:
            with self.subTest(profile=changed):
                t.matrix_input_profile=changed
                self.assertFalse(t.can_set_key(3))
                self.assertFalse(t.can_set_key(3,80))
                self.assertTrue(all(t.can_set_key(bit) for bit in (0,5,15,1,9,4,6,2,7)))
        for field,value in (('rows',7),('columns',3)):
            t.matrix_input_profile=dict(profile,**{field:value})
            self.assertFalse(t.can_set_key(3))
            self.assertTrue(t.can_set_key(15))
        # Call depends on controls, not optional navigation/BACK admission.
        t.matrix_input_profile=dict(profile,navigation_mapping_status='rejected',back_mapping_status='rejected')
        self.assertTrue(t.can_set_key(3))
        t.matrix_input_profile=profile
        self.assertTrue(t.set_key(3,True))
        t.matrix_input_profile=variants[0]
        self.assertTrue(t.set_key(3,False))  # Release cached original physical cell.
        self.assertEqual(t.matrix_held,{})
        t.matrix_input_profile=profile
        t.input_socket=SimpleNamespace(sendall=lambda packet: (_ for _ in ()).throw(OSError('send-failed')))
        self.assertFalse(t.set_key(3,True))
        self.assertEqual(t.matrix_held,{})

    def test_low5_matrix_uses_actual_load_sites_and_scoped_packets(self):
        image = bytearray(0x100)
        image[0x10:0x14] = bytes.fromhex('416b0988')
        image[0x20:0x24] = bytes.fromhex('406b0088')
        config = SimpleNamespace(load_address=0, flash_size=len(image),
                                 ram_base=0x1800000, ram_size=0x800000,
                                 board_status_input=None)
        profile = dict(grammar='lg-descriptor-low5-6x5-raw-v1', rows=6,
                       columns=5, sense_bits=5, no_key=31,
                       single_key_column_sense=[30, 29, 27, 23, 15],
                       register=0x300072c, descriptor_pointer=0x1800100,
                       descriptor_mmio_provenance='ROM descriptor initializer',
                       event_sink_validation='validated-raw-enqueue-callsites',
                       timer_bridge={'scanner': 0},
                       global_sense_sites=[0x10], row_sense_sites=[0x20])
        helper = MODULE.qemu_low5_matrix_property
        self.assertEqual(helper(bytes(image), config, profile),
                         ('matrix-low5=1800100:12:22', None))
        for changed, reason in (
            ({'descriptor_pointer': 0x2000000}, 'descriptor-outside-ram'),
            ({'timer_bridge': None}, 'unclosed-scanner-profile'),
            ({'single_key_column_sense': [30, 29, 27, 23, 31]}, 'invalid-sense-table'),
            ({'row_sense_sites': [0x20, 0x30]}, 'ambiguous-sense-roles'),
            ({'row_sense_sites': [0x10]}, 'ambiguous-sense-roles'),
            ({'row_sense_sites': [0x100]}, 'sense-outside-primary-nor'),
        ):
            self.assertEqual(helper(bytes(image), config, dict(profile, **changed)),
                             (None, reason))
        image[0x22] ^= 1  # Changed LDRH destination cannot use this native gate.
        self.assertEqual(helper(bytes(image), config, profile),
                         (None, 'sense-load-shape-mismatch'))
        self.assertEqual(helper(bytes(image), config, self.PROFILE), (None, None))
        config.board_status_input = object()
        self.assertEqual(helper(bytes(image), config, profile),
                         (None, 'conflicting-status-profile'))

        transport = object.__new__(MODULE.Transport)
        transport.matrix_input_profile = profile
        transport.matrix_input_sideband_producer = None
        transport.matrix_held, transport.sideband_held = {}, set()
        cells = {0: (9, 5, 3), 1: (133, 2, 0), 5: (141, 3, 4)}
        transport.decoder = SimpleNamespace(input_error='',
            _direct_matrix_position=lambda bit, event: cells.get(bit),
            _direct_sideband_producer=lambda bit, event: None)
        packets = []
        transport.input_socket = SimpleNamespace(sendall=packets.append)
        for bit, row, sense in ((0, 5, 23), (1, 2, 30), (5, 3, 15)):
            self.assertTrue(transport.can_set_key(bit))
            self.assertTrue(transport.set_key(bit, True))
            self.assertFalse(transport.set_key(22, True))  # One held key.
            self.assertTrue(transport.set_key(bit, False))
            self.assertEqual(packets[-2:],
                             [bytes((0x80, 1, row, sense)), bytes((0x80, 0, 0, 0))])
        self.assertFalse(transport.can_set_key(22))
        with self.assertRaises(ValueError):
            MODULE.matrix_senses(dict(profile, grammar='direct-low-nibble-6-row-v1'))

    def test_loop_matrix_property_and_numeric_packets(self):
        image = bytearray(0x100)
        for site in (0x12, 0x22, 0x32):
            image[site-2:site+2] = bytes.fromhex('686b0088')
        for off, port in ((0,0x3000720),(8,0x300072c),(0x20,0x3000728),(0x34,0x300072c)):
            struct.pack_into('<I', image, 0x40+off, port)
        config = SimpleNamespace(flash_size=len(image), ram_base=0x1000000,
                                 ram_size=0x800000, board_status_input=None)
        profile = dict(grammar='indirect-halfword-loop-six-row-v1', rows=6,
                       columns=4, no_key=31, single_key_column_sense=[30,29,27,23],
                       promotion='temporary-evidence-gated',
                       descriptor=0x1000100, copied_descriptor=0x17fe000,
                       descriptor_copy=dict(copy_loop=0x80,source=0x40,target=0x17fe000,size=0x54),
                       contact_site=0x12,presence_site=0x22,sense_site=0x32,
                       token_cells=[dict(event=v,row=i%6,column=i//6)
                                    for i,v in enumerate(b'123456789*0#')])
        helper=MODULE.qemu_halfword_matrix_property
        self.assertEqual(helper(bytes(image),config,profile),
                         ('matrix-halfword-loop=1000100:12:22:32',None))
        self.assertEqual(helper(bytes(image),config,profile,enabled=False),
                         ('matrix-halfword-loop=1000100:12:22:32',None))
        for changed in ({'grammar':'indirect-halfword-six-row-v1'},
                        {'grammar':'indirect-halfword-mapped-row-v1'},
                        {'grammar':'unknown'}, {'promotion':'experimental-only'},
                        {'promotion':None}):
            self.assertEqual(helper(bytes(image),config,dict(profile,**changed),enabled=False),
                             (None,'experimental-only-halfword-profile'))
        for changed,reason in (({'rows':7},'invalid-loop-row-contract'),
                               ({'no_key':15},'invalid-loop-row-contract'),
                               ({'single_key_column_sense':[30,29,27,15]},'invalid-loop-row-contract'),
                               ({'contact_site':0x22},'sense-load-shape-mismatch'),
                               ({'contact_site':True},'sense-load-shape-mismatch'),
                               ({'copied_descriptor':0x1800000},'unclosed-descriptor-copy'),
                               ({'descriptor_copy':None},'unclosed-descriptor-copy')):
            self.assertEqual(helper(bytes(image),config,dict(profile,**changed)),(None,reason))
        image[0x32]^=1
        self.assertEqual(helper(bytes(image),config,profile),(None,'sense-load-shape-mismatch'))
        image[0x32]^=1;image[0x40]^=1
        self.assertEqual(helper(bytes(image),config,profile),(None,'descriptor-port-mismatch'))
        transport=object.__new__(MODULE.Transport)
        transport.matrix_input_profile=profile
        transport.matrix_held,transport.sideband_held={},set()
        transport.decoder=SimpleNamespace(input_error='')
        packets=[];transport.input_socket=SimpleNamespace(sendall=packets.append)
        for i,bit in enumerate(range(11,23)):
            self.assertTrue(transport.can_set_key(bit))
            self.assertTrue(transport.set_key(bit,True))
            self.assertFalse(transport.set_key(12 if bit==11 else 11,True))
            self.assertTrue(transport.set_key(bit,False))
            self.assertEqual(packets[-2:],[bytes((0x80,1,i%6,[30,29][i//6])),bytes((0x80,0,0,0))])
        for bit in range(11): self.assertFalse(transport.can_set_key(bit))
        for event in (0x51,0x53,0x54): self.assertFalse(transport.can_set_key(1,event))
        profile['token_cells'].append(dict(profile['token_cells'][0]))
        self.assertFalse(transport.can_set_key(11))
        for column,sense in enumerate((30,29,27,23)):
            self.assertEqual(MODULE.matrix_input_command(profile,(49,5,column),True),bytes((0x80,1,5,sense)))
        with self.assertRaises(ValueError): MODULE.matrix_input_command(profile,(49,6,0),True)

    def test_status_option_is_explicit_detector_gated_and_non_fold(self):
        matrix = dict(grammar="indirect-halfword-six-row-v1",
                      descriptor=0x1000000, queue_sink="0x500")
        candidate = dict(descriptor=0x1000000, queue_sink=0x500)
        helper = MODULE.qemu_halfword_status_property
        with mock.patch('msm5xxx_emulator.qemu.transport.resolve_indirect_board_status',
                        return_value=(candidate, 'static-candidate', [])) as resolver:
            self.assertEqual(helper(b'', 0, matrix, None), (None, None))
            resolver.assert_not_called()
            for level in (0, 4):
                self.assertEqual(helper(b'', 0, matrix, level), (
                    f'board-status-input=3000720:4:{level:x},board-status-descriptor=1000000', None))
            for level in (False, True, 1, -1, 4.0, '4'):
                self.assertEqual(helper(b'', 0, matrix, level), (None, 'invalid-level'))
            self.assertEqual(helper(b'', 0, None, 4), (None, 'halfword-matrix-not-admitted'))
            self.assertEqual(helper(b'', 0, matrix, 4, object()), (None, 'conflicting-status-profile'))
            self.assertEqual(helper(b'', 0, dict(matrix, descriptor=0x1000100), 4),
                             (None, 'matrix-status-mismatch'))
            resolver.return_value = (None, 'ambiguous-status-helpers', [])
            self.assertEqual(helper(b'', 0, matrix, 4), (None, 'ambiguous-status-helpers'))
        for options in (dict(experimental_status_level=4),
                        dict(experimental_halfword=True, experimental_status_level=True)):
            with self.assertRaisesRegex(ValueError, 'status level requires'):
                MODULE.Transport(Path('unused'), Path('unused'), **options)
        # Electrical experiment does not install a config profile or expose fold UI.
        transport = object.__new__(MODULE.Transport)
        transport.config = SimpleNamespace(board_status_input=None)
        transport.board_status_snapshot = None
        self.assertFalse(transport.can_set_fold())

    def test_mapped_physical_menu_requires_closed_mapping_and_unique_cell(self):
        from copy import deepcopy

        events = [0, 0, 0, 103, 84, 85, 100, 42, 55, 52, 49, 80, 101, 91,
                  48, 56, 53, 50, 82, 138, 99, 35, 57, 54, 51, 0, 102, 83]
        profile = dict(
            grammar='indirect-halfword-mapped-row-v1', rows=7, columns=4,
            no_key=15, single_key_column_sense=[14, 13, 11, 7], event_codes=events,
            menu_mapping_status='accepted-provisional',
            provisional_mappings={0: dict(
                event=0x5B, rule='same-image-mapped-physical-menu-v1',
                semantic_status='temporary-evidence-gated-provisional',
                physical_only=True)},
            token_cells=[dict(token=chr(event), event=event,
                              row=events.index(event) % 7,
                              column=events.index(event) // 7)
                         for event in b'123456789*0#']
                        + [dict(token='M', event=0x5B, row=6, column=1)],
        )
        transport = object.__new__(MODULE.Transport)
        transport.matrix_input_profile = profile
        transport.matrix_held, transport.sideband_held = {}, set()
        transport.decoder = SimpleNamespace(input_error='')
        packets = []
        transport.input_socket = SimpleNamespace(sendall=packets.append)
        self.assertTrue(transport.can_set_key(0))
        self.assertTrue(transport.can_set_key(0, 0x5B))
        self.assertTrue(transport.set_key(0, True))
        self.assertTrue(transport.set_key(0, False))
        self.assertEqual(packets, [bytes((0x80, 1, 6, 13)), bytes((0x80, 0, 0, 0))])
        self.assertEqual(transport.matrix_held, {})
        for bit in range(1, 11):
            self.assertFalse(transport.can_set_key(bit))
        self.assertFalse(transport.can_set_key(False))
        self.assertFalse(transport.can_set_key(0, 0x53))
        mutations = []
        for field, value in (('menu_mapping_status', 'rejected'),
                             ('provisional_mappings', {}),
                             ('grammar', 'distributed-six-byte-numeric-v1')):
            changed = deepcopy(profile); changed[field] = value; mutations.append(changed)
        for field, value in (('event', 0x53), ('event', True), ('rule', 'unknown'),
                             ('semantic_status', 'unverified'), ('physical_only', False)):
            changed = deepcopy(profile)
            changed['provisional_mappings'][0][field] = value; mutations.append(changed)
        changed = deepcopy(profile); changed['event_codes'][0] = 0x5B; mutations.append(changed)
        changed = deepcopy(profile); changed['event_codes'].pop(); mutations.append(changed)
        changed = deepcopy(profile); changed['token_cells'][-1]['row'] = 5; mutations.append(changed)
        changed = deepcopy(profile); changed['token_cells'].append(dict(changed['token_cells'][-1])); mutations.append(changed)
        changed = deepcopy(profile); changed['token_cells'].pop(); mutations.append(changed)
        for changed in mutations:
            with self.subTest(profile=changed):
                transport.matrix_input_profile = changed
                self.assertFalse(transport.can_set_key(0))
                self.assertFalse(transport.can_set_key(0, 0x5B))
                self.assertTrue(transport.can_set_key(15))

    def test_mapped_functional_confirm_keeps_seven_row_namespace_and_fallback(self):
        from copy import deepcopy

        events = [0, 0, 0, 103, 84, 85, 100, 42, 55, 52, 49, 80, 101, 91,
                  48, 56, 53, 50, 82, 138, 99, 35, 57, 54, 51, 0, 102, 83]
        profile = dict(
            grammar='indirect-halfword-mapped-row-v1', rows=7, columns=4,
            no_key=15, single_key_column_sense=[14, 13, 11, 7], event_codes=events,
            menu_mapping_status='accepted-provisional',
            ok_mapping_status='accepted-provisional',
            provisional_mappings={
                0: dict(event=0x5B, rule='same-image-mapped-physical-menu-v1',
                        semantic_status='temporary-evidence-gated-provisional',
                        physical_only=True),
                5: dict(event=0x53, rule='same-image-mapped-functional-confirm-v1',
                        semantic_status='temporary-evidence-gated-provisional',
                        functional_only=True)},
            token_cells=[dict(token=chr(event), event=event,
                              row=events.index(event) % 7,
                              column=events.index(event) // 7)
                         for event in b'123456789*0#']
                        + [dict(token='M', event=0x5B, row=6, column=1),
                           dict(token='O', event=0x53, row=6, column=3)],
        )
        transport = object.__new__(MODULE.Transport)
        transport.matrix_input_profile = profile
        transport.matrix_held, transport.sideband_held = {}, set()
        transport.decoder = SimpleNamespace(input_error='')
        packets = []
        transport.input_socket = SimpleNamespace(sendall=packets.append)
        self.assertTrue(transport.can_set_key(5))
        self.assertTrue(transport.can_set_key(5, 0x53))
        self.assertTrue(transport.set_key(5, True))
        self.assertTrue(transport.set_key(5, False))
        self.assertEqual(packets, [bytes((0x80, 1, 6, 7)), bytes((0x80, 0, 0, 0))])
        self.assertEqual(transport.matrix_held, {})
        for bit, event in ((0, 0x53), (5, 0x5B), (1, 0x53), (True, 0x53)):
            self.assertFalse(transport.can_set_key(bit, event))

        variants = []
        for field, value in (('ok_mapping_status', 'rejected'), ('rows', 6),
                             ('columns', 3)):
            changed = deepcopy(profile); changed[field] = value; variants.append(changed)
        for field, value in (('event', True), ('event', 0x54), ('rule', 'unknown'),
                             ('rule', 'same-image-loop-functional-confirm-v1'),
                             ('semantic_status', 'unverified'), ('functional_only', False)):
            changed = deepcopy(profile)
            changed['provisional_mappings'][5][field] = value; variants.append(changed)
        changed = deepcopy(profile); del changed['provisional_mappings'][5]; variants.append(changed)
        changed = deepcopy(profile); changed['event_codes'][0] = 0x53; variants.append(changed)
        changed = deepcopy(profile); changed['event_codes'].pop(); variants.append(changed)
        changed = deepcopy(profile); changed['token_cells'][-1]['row'] = 3; variants.append(changed)
        changed = deepcopy(profile); changed['token_cells'][-1]['column'] = 2; variants.append(changed)
        changed = deepcopy(profile); changed['token_cells'].append(changed['token_cells'][-1].copy()); variants.append(changed)
        changed = deepcopy(profile); changed['token_cells'].pop(); variants.append(changed)
        for changed in variants:
            with self.subTest(profile=changed):
                transport.matrix_input_profile = changed
                self.assertFalse(transport.can_set_key(5))
                self.assertFalse(transport.can_set_key(5, 0x53))
                self.assertTrue(transport.can_set_key(15))
                if len(changed['event_codes']) == 28:
                    self.assertTrue(transport.can_set_key(0))

    def test_loop_functional_confirm_requires_matching_evidence_and_unique_cell(self):
        from copy import deepcopy

        events = [0x51, 0x53, *b'123456789*0#',
                  0x52, 0x54, 0x55, 0x56, 0x57, 0x5B, 0x61, 0x62, 0x63, 0x64]
        profile = dict(
            grammar='indirect-halfword-loop-six-row-v1', rows=6, columns=4, no_key=31,
            event_codes=events, single_key_column_sense=[30, 29, 27, 23],
            ok_mapping_status='accepted-provisional',
            provisional_mappings={5: dict(
                event=0x53, rule='same-image-loop-functional-confirm-v1',
                semantic_status='temporary-evidence-gated-provisional', functional_only=True)},
            token_cells=[dict(token=chr(v), event=v, row=events.index(v) % 6,
                              column=events.index(v) // 6) for v in b'123456789*0#']
                        + [dict(token='O', event=0x53, row=1, column=0)])
        transport = object.__new__(MODULE.Transport)
        transport.matrix_input_profile = profile
        transport.matrix_held, transport.sideband_held = {}, set()
        transport.decoder = SimpleNamespace(input_error='')
        packets = []
        transport.input_socket = SimpleNamespace(sendall=packets.append)
        for override in (None, 0x53):
            self.assertTrue(transport.can_set_key(5, override))
            self.assertTrue(transport.set_key(5, True, override))
            self.assertTrue(transport.set_key(5, False))
            self.assertEqual(packets[-2:], [bytes((0x80, 1, 1, 30)), bytes((0x80, 0, 0, 0))])
        self.assertTrue(transport.can_set_key(5, 0x35))  # Existing manual numeric override.
        for bit, event in ((1, 0x53), (5, 0x54), (5, 83.0), (5, '83')):
            self.assertFalse(transport.can_set_key(bit, event))
        variants = []
        for field, value in (
                ('provisional_mappings', {}), ('ok_mapping_status', 'rejected'),
                ('grammar', 'indirect-halfword-mapped-row-v1'),
                ('grammar', 'distributed-six-byte-numeric-v1'), ('event_codes', None)):
            changed = deepcopy(profile); changed[field] = value; variants.append(changed)
        for field, value in (('rule', 'unproven'), ('event', 0x54),
                             ('semantic_status', 'unproven'), ('functional_only', False)):
            changed = deepcopy(profile)
            changed['provisional_mappings'][5][field] = value
            variants.append(changed)
        for field, value in (('token', '?'), ('row', 2), ('column', 1)):
            changed = deepcopy(profile); changed['token_cells'][-1][field] = value
            variants.append(changed)
        changed = deepcopy(profile); changed['event_codes'][0] = 0x53; variants.append(changed)
        changed = deepcopy(profile); changed['token_cells'].append(changed['token_cells'][-1].copy())
        variants.append(changed)
        for changed in variants:
            with self.subTest(changed=changed):
                transport.matrix_input_profile = changed
                self.assertFalse(transport.can_set_key(5))
                self.assertFalse(transport.can_set_key(5, 0x53))
                self.assertTrue(transport.can_set_key(15))

    def test_automatic_mapped_scan_gates_require_closed_copy_and_mmio_owner(self):
        from copy import deepcopy
        image = bytearray(0x400)
        for site in (0x12, 0x22, 0x32):
            image[site - 2:site + 2] = bytes.fromhex('706b0088')
        image[0x40:0x44] = bytes.fromhex('406a0088')
        descriptor, state = 0x1000628, 0x100221c
        for offset, port in ((8, 0x300072c), (0x24, 0x3000728), (0x34, 0x300072c)):
            struct.pack_into('<I', image, 0x128 + offset, port)
        config = SimpleNamespace(flash_size=len(image), ram_base=0x1000000,
                                 ram_size=0x800000, board_status_input=None,
                                 ready_poll=None, load_address=0)
        gates = dict(grammar='mapped-halfword-contact-status-gates-v1',
                     promotion='temporary-evidence-gated', runtime_admitted=False,
                     physical_role=None, default_level=None,
                     descriptor=descriptor, scanner_state=state, queue_sink=0x60,
                     contact_site=0x32, status_site=0x42,
                     contact_mask=16, status_mask=2, contact_pointer_offset=0x34,
                     configuration_pointer_offset=8, status_pointer_offset=0x24,
                     contact_width=2, status_width=2, status_state_offset=8,
                     status_set_bit_state=0, status_clear_bit_state=1,
                     ram_spans=[[descriptor, 0x38], [state, 0x20], [0x1003000, 4]])
        profile = dict(grammar='indirect-halfword-mapped-row-v1', rows=7,
                       columns=4, no_key=15, single_key_column_sense=[14, 13, 11, 7],
                       descriptor=descriptor, presence_site=0x12, sense_site=0x22,
                       row_select_mask=0x3b03, row_select_bits=[0, 1, 8, 9, 11, 12, 13],
                       queue_sink='0x60', scan_gates=gates,
                       descriptor_copy=dict(descriptor_rom=0x128, descriptor_ram=descriptor,
                                            source=0x100, target=0x1000600, size=0x100))
        helper = MODULE.qemu_halfword_matrix_property
        owner = (0x3000720, 0, 0x20, 0, 0x40, 0xc, 0x8000)
        with mock.patch('msm5xxx_emulator.qemu.transport.eeprom_gpio_profile', return_value=(owner, None)):
            self.assertEqual(helper(bytes(image), config, profile, enabled=False),
                             ('matrix-halfword=1000628:12:22:3b03,'
                              'experimental-matrix-contact=32:10,'
                              'experimental-matrix-status=42:2', None))
            self.assertEqual(helper(bytes(image), config, profile, enabled=True),
                             ('matrix-halfword=1000628:12:22:3b03', None))
            for changed in ({'scan_gates': None}, {'scan_gates': {}}, {'grammar': 'unknown'}):
                self.assertIsNone(helper(bytes(image), config, dict(profile, **changed), enabled=False)[0])
            for changed in ({'contact_mask': True}, {'status_mask': 4},
                            {'scanner_state': 0x1800000}, {'scanner_state': descriptor},
                            {'status_site': 0x32}, {'queue_sink': 0x62},
                            {'physical_role': 'assumed'}, {'runtime_admitted': True},
                            {'ram_spans': None}, {'ram_spans': [[descriptor, 0x38]]},
                            {'ram_spans': [[descriptor, 0x38], [state, 0x20], [True, 4]]},
                            {'ram_spans': [[descriptor, 0x38], [state, 0x20], [0x1003000, 0]]},
                            {'ram_spans': [[descriptor, 0x38], [state, 0x20], [state + 4, 4]]},
                            {'ram_spans': [[descriptor, 0x38], [state, 0x20], [0x1800000, 4]]}):
                bad = deepcopy(profile); bad['scan_gates'].update(changed)
                with self.subTest(gate=changed):
                    self.assertIsNone(helper(bytes(image), config, bad, enabled=False)[0])
            for changed in ({'source': 0x104}, {'size': 0x20}, {'descriptor_ram': descriptor + 4}):
                bad = deepcopy(profile); bad['descriptor_copy'].update(changed)
                self.assertIsNone(helper(bytes(image), config, bad, enabled=False)[0])
            malformed = bytearray(image); malformed[0x42] ^= 1
            self.assertIsNone(helper(bytes(malformed), config, profile, enabled=False)[0])
            self.assertIsNone(helper(bytes(image), SimpleNamespace(**dict(vars(config), load_address=4)), profile, enabled=False)[0])
            bad_port = bytearray(image); struct.pack_into('<I', bad_port, 0x128 + 0x24, 0x300072c)
            self.assertIsNone(helper(bytes(bad_port), config, profile, enabled=False)[0])
            self.assertIsNone(helper(bytes(image), SimpleNamespace(**dict(vars(config), board_status_input=object())), profile, enabled=False)[0])
        for bad_owner in (None, (0x300072a, 0, 0x20, 0, 0x40, 0xc, 0x8000),
                          (0x3000720, 8, 2, 0, 0x40, 0xc, 0x8000),
                          (0x3000720, 0, 0x10, 0, 0x40, 0xc, 0x8000)):
            with self.subTest(owner=bad_owner), mock.patch('msm5xxx_emulator.qemu.transport.eeprom_gpio_profile', return_value=(bad_owner, None)):
                self.assertIsNone(helper(bytes(image), config, profile, enabled=False)[0])

    def test_halfword_public_key_api_requires_unique_semantic_cell(self):
        transport = object.__new__(MODULE.Transport)
        transport.matrix_input_profile = {
            "grammar": "indirect-halfword-six-row-v1", "rows": 6,
            "no_key": 15, "single_key_column_sense": [14, 13, 11, 7],
            "token_cells": [{"token": "F", "event": 0x54, "row": 4, "column": 3}],
        }
        transport.matrix_held = {}
        transport.sideband_held = set()
        packets = []
        transport.input_socket = SimpleNamespace(sendall=packets.append)
        transport.decoder = SimpleNamespace(input_error="")
        self.assertTrue(transport.can_set_key(1))
        self.assertFalse(transport.can_set_key(2))
        self.assertFalse(transport.can_set_key(2, 0x52))
        self.assertTrue(transport.set_key(1, True))
        self.assertTrue(transport.set_key(1, False))
        self.assertEqual(packets, [bytes((0x80, 1, 4, 7)), bytes((0x80, 0, 0, 0))])
        transport.matrix_input_profile["token_cells"].append(
            {"token": "alias", "event": 0x54, "row": 4, "column": 3})
        self.assertFalse(transport.can_set_key(1))

    def test_mapped_halfword_property_and_numeric_keys_preserve_native_fallback(self):
        image = bytearray(0x100)
        image[0x10:0x14] = image[0x20:0x24] = bytes.fromhex('706b0088')
        config = SimpleNamespace(flash_size=len(image), ram_base=0x1000000,
                                 ram_size=0x800000)
        profile = dict(grammar='indirect-halfword-mapped-row-v1', rows=7,
                       columns=4, no_key=15, single_key_column_sense=[14, 13, 11, 7],
                       descriptor=0x1000628, presence_site=0x12, sense_site=0x22,
                       row_select_mask=0x3b03, row_select_bits=[0, 1, 8, 9, 11, 12, 13],
                       token_cells=[dict(event=event, row=i % 7, column=i // 7)
                                    for i, event in enumerate(b'123456789*0#')])
        helper = MODULE.qemu_halfword_matrix_property
        self.assertEqual(helper(bytes(image), config, profile),
                         ('matrix-halfword=1000628:12:22:3b03', None))
        self.assertEqual(helper(bytes(image), config, dict(profile,
                         grammar='indirect-halfword-six-row-v1', rows=6)),
                         ('matrix-halfword=1000628:12:22', None))
        for changed, reason in (
            ({'grammar': 'unknown'}, 'unsupported-halfword-grammar'),
            ({'descriptor': 0x1800000}, 'outside-memory-map'),
            ({'sense_site': 0x23}, 'outside-memory-map'),
            ({'sense_site': True}, 'outside-memory-map'),
            ({'rows': 6}, 'invalid-mapped-row-contract'),
            ({'row_select_mask': 0x13b03}, 'invalid-mapped-row-contract'),
            ({'row_select_mask': 0x3b02}, 'invalid-mapped-row-contract'),
            ({'row_select_bits': [1, 0, 8, 9, 11, 12, 13]}, 'invalid-mapped-row-contract'),
            ({'single_key_column_sense': [14, 13, 11, 15]}, 'invalid-mapped-row-contract'),
            ({'sense_site': 0x12}, 'sense-load-shape-mismatch'),
        ):
            self.assertEqual(helper(bytes(image), config, dict(profile, **changed)),
                             (None, reason))
        image[0x22] ^= 1
        self.assertEqual(helper(bytes(image), config, profile),
                         (None, 'sense-load-shape-mismatch'))
        with mock.patch('msm5xxx_emulator.qemu.transport.resolve_indirect_board_status') as resolver:
            self.assertEqual(MODULE.qemu_halfword_status_property(b'', 0, profile, 4),
                             (None, 'halfword-matrix-not-admitted'))
            resolver.assert_not_called()

        transport = object.__new__(MODULE.Transport)
        transport.matrix_input_profile = profile
        transport.matrix_held, transport.sideband_held = {}, set()
        transport.decoder = SimpleNamespace(input_error='')
        packets = []
        transport.input_socket = SimpleNamespace(sendall=packets.append)
        for i, bit in enumerate(range(11, 23)):
            self.assertTrue(transport.can_set_key(bit))
            self.assertTrue(transport.set_key(bit, True))
            self.assertFalse(transport.set_key(11 if bit != 11 else 12, True))
            self.assertTrue(transport.set_key(bit, False))
            self.assertEqual(packets[-2:], [bytes((0x80, 1, i % 7, [14, 13][i // 7])),
                                           bytes((0x80, 0, 0, 0))])
        for bit in range(11):
            self.assertFalse(transport.can_set_key(bit))
        # Function-key event values never inherit the ring32 key labels.
        profile['token_cells'].append(dict(event=0x54, row=6, column=3))
        self.assertFalse(transport.can_set_key(1, 0x54))
        profile['token_cells'].append(dict(profile['token_cells'][0]))
        self.assertFalse(transport.can_set_key(11))

    PROFILE = {
        "rows": 6,
        "no_key": 0x0F,
        "single_key_column_sense": (0x0E, 0x0D, 0x0B, 0x07),
    }

    def test_ready_poll_property_is_explicit_and_fail_closed(self) -> None:
        compact = {
            "signature": "thumb-lsrs-bhs-pulse-v1",
            "status_address": 0x030007B4,
            "mask": 8,
            "pulse_address": 0x03000600,
            "entries": [0x100],
        }
        control = {
            "signature": "thumb-byte-ready-pulse-control-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x03000F14,
            "mask": 8,
            "pulse_address": 0x03000700,
            "control_address": 0x03000F1C,
            "control_value": 0x20,
            "status_read_pc_offset": 4,
            "pulse_set_pc_offset": 0x18,
            "pulse_clear_pc_offset": 0x1C,
            "control_pc_offset": 0x22,
            "entries": [0xD5C],
        }
        control_uart = {
            **control,
            "signature": "thumb-byte-ready-pulse-control-uart-empty-v1",
            "uart_rx_empty_read_pc_offset": 0x96,
        }
        rotated = {
            "signature": "thumb-lsrs-bcc-pulse-rotated-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x03000F14,
            "mask": 8,
            "pulse_address": 0x03000700,
            "status_read_pc_offset": 0x10,
            "pulse_set_pc_offset": 0x0C,
            "pulse_clear_pc_offset": 0x0E,
            "entries": [0x1100],
        }
        uart = {
            "signature": "thumb-uart-csr-sr-rx-empty-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x030007B4,
            "mask": 8,
            "pulse_address": 0x03000600,
            "status_read_pc_offset": 2,
            "pulse_set_pc_offset": 0x0C,
            "pulse_clear_pc_offset": 0x10,
            "uart_rx_empty_read_pc_offset": 0xA0,
            "entries": [0x2314],
        }
        uart_framed = {
            **uart,
            "uart_rx_empty_frame_read_pc_offset": 0x100,
        }
        lcd = {
            "signature": "thumb-lcd-halfword-busy-clear-v1",
            "admission": "temporary-evidence-gated",
            "status_address": 0x0280000C,
            "mask": 8,
            "command_address": 0x02800008,
            "command_value": 8,
            "status_read_pc_offset": 6,
            "command_write_pc_offset": 4,
            "entries": [0x1B437A],
        }
        self.assertEqual(MODULE.qemu_ready_poll_property(compact), (
            "ready-poll=30007b4:8:3000600:100", None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property(control), (
            "ready-poll-control=3000f14:8:3000700:3000f1c:20:d5c:4:18:1c:22",
            None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property(control_uart), (
            "ready-poll-control=3000f14:8:3000700:3000f1c:20:d5c:4:18:1c:22:96",
            None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property(rotated), (
            "ready-poll=3000f14:8:3000700:1100:10:c:e", None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property(uart), (
            "ready-poll=30007b4:8:3000600:2314:2:c:10:a0", None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property(uart_framed), (
            "ready-poll=30007b4:8:3000600:2314:2:c:10:a0:100", None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **rotated,
            "signature": "thumb-lsrs-bcc-pulse-rotated-followup-v1",
            "followup_entry": 0x11A8,
            "followup_mask": 1,
        }), (None, "unsupported-signature"))
        self.assertEqual(MODULE.qemu_ready_poll_property(lcd), (
            "lcd-status-poll=280000c:8:2800008:8:1b437a:6:4", None,
        ))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **compact, "signature": "future-ready-v2",
        }), (None, "unsupported-signature"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **compact, "entries": [0x100, 0x200],
        }), ("ready-poll-sites=30007b4:8:3000600:100;200", None))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **rotated, "entries": [0x100, 0x200],
        }), (None, "ambiguous-entry-count"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **compact, "entries": [0x100, 0x100],
        }), (None, "malformed-entries"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **compact, "entries": [0x100 + 2 * index for index in range(9)],
        }), (None, "entry-count-limit"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **compact, "entries": (0x100,),
        }), (None, "malformed-entries"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **compact, "mask": "8",
        }), (None, "malformed-fields"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **control, "admission": "experimental-only",
        }), (None, "unsupported-admission"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **rotated, "admission": "experimental-only",
        }), (None, "unsupported-admission"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **lcd, "admission": "experimental-only",
        }), (None, "unsupported-admission"))
        self.assertEqual(MODULE.qemu_ready_poll_property({
            **uart, "admission": "experimental-only",
        }), (None, "unsupported-admission"))

    def test_uart_csr_write_does_not_leak_into_sr_readback(self) -> None:
        source = (NATIVE / "msm5xxx-poc.c").read_text()
        start = source.index("static uint64_t msm5xxx_poc_ready_status_read")
        end = source.index("\nstatic ", start + 1)
        read_body = source[start:end]
        uart_start = read_body.index("if (s->ready_uart_rx_empty_enabled")
        uart_end = read_body.index("if (!primary_read)", uart_start)
        uart_body = read_body[uart_start:uart_end]

        self.assertIn("#define MSM5XXX_POC_UART_SR_IDLE 0x0c", source)
        self.assertIn("return MSM5XXX_POC_UART_SR_IDLE;", uart_body)
        self.assertNotIn("ready_status_backing", uart_body)

    def test_sbi_property_keeps_legacy_and_closes_bootstrap_only(self) -> None:
        profile = {
            "signature": "thumb-sbi-bootstrap-only-v1",
            "admission": "temporary-evidence-gated",
            "accepted": True,
            "base_address": 0x03000780,
            "bootstrap": [
                [0, 1, 0x45], [0, 1, 0xC5], [4, 2, 0x085F],
                [0x0C, 2, 0x041F], [0x10, 1, 0], [0x10, 1, 1],
            ],
            "validation": [[0, 2, None], [0x0C, 2, 0x0900], [0, 2, None]],
            "entries": [0x580],
        }
        legacy = SimpleNamespace(
            chipset="MSM5000", board_adc_reader_address=0x4050,
            sbi_bootstrap_profile=profile,
        )
        self.assertEqual(MODULE.qemu_sbi_property(legacy), ("sbi=on", None))
        bootstrap_only = SimpleNamespace(
            chipset="MSM5000", board_adc_reader_address=None,
            sbi_bootstrap_profile=profile,
        )
        self.assertEqual(MODULE.qemu_sbi_property(bootstrap_only), (
            "sbi=on,sbi-bootstrap-only=on", None,
        ))
        bootstrap_only.sbi_bootstrap_profile = {**profile, "entries": [0x581]}
        self.assertEqual(MODULE.qemu_sbi_property(bootstrap_only),
                         (None, "malformed-entries"))
        bootstrap_only.sbi_bootstrap_profile = profile
        for chipset in ("MSM5100", "MSM5xxx"):
            bootstrap_only.chipset = chipset
            self.assertEqual(MODULE.qemu_sbi_property(bootstrap_only), (
                "sbi=on,sbi-bootstrap-only=on", None,
            ))
            self.assertEqual(bootstrap_only.chipset, chipset)
        bootstrap_only.board_adc_reader_address = 0x4050
        bootstrap_only.sbi_bootstrap_profile = None
        self.assertEqual(MODULE.qemu_sbi_property(bootstrap_only), (None, None))
        bootstrap_only.sbi_bootstrap_profile = {
            **profile, "bootstrap": [[0, True, 0x45], *profile["bootstrap"][1:]],
        }
        self.assertEqual(MODULE.qemu_sbi_property(bootstrap_only),
                         (None, "malformed-contract"))
        bootstrap_only.sbi_bootstrap_profile = {**profile, "base_address": float(0x03000780)}
        self.assertEqual(MODULE.qemu_sbi_property(bootstrap_only),
                         (None, "malformed-contract"))
        bootstrap_only.sbi_bootstrap_profile = {**profile, "accepted": False}
        self.assertEqual(MODULE.qemu_sbi_property(bootstrap_only),
                         (None, "unsupported-contract"))

    def test_sbi_raw_input_is_source_scoped_and_preserves_bootstrap_fallback(self) -> None:
        from msm5xxx_emulator.detection.input import SBI_BOOTSTRAP, SBI_BOOTSTRAP_VALIDATION
        raw = dict(signature="thumb-sbi-raw-sample-086a-v1",
                   admission="temporary-evidence-gated", accepted=True,
                   policy="configured-virtual-raw-byte-uncalibrated",
                   base_address=0x03000780, control=0x086A,
                   clock_values=[0x4A, 0xCA],
                   request_prefix=0x0A80, read_command=0x8B00,
                   selector_mask=0x60, source_selector=0x40, selector_value=0x40,
                   entry=0x100, read_pc=0x186, entries=[0x100])
        base = dict(signature="thumb-sbi-bootstrap-only-v1",
                    admission="temporary-evidence-gated", accepted=True,
                    base_address=0x03000780, entries=[0x20],
                    bootstrap=[list(row) for row in SBI_BOOTSTRAP],
                    validation=[list(row) for row in SBI_BOOTSTRAP_VALIDATION])
        config = SimpleNamespace(chipset="MSM5xxx", confidence="unknown",
                                 board_adc_reader_address=None, board_adc_value=194,
                                 flash_size=0x400, load_address=0,
                                 sbi_bootstrap_profile={**base, "raw_input": raw})
        self.assertEqual(MODULE.qemu_sbi_property(config),
                         ("sbi=on,sbi-raw-input-profile=186:60:40", None))
        self.assertEqual((config.chipset, config.confidence), ("MSM5xxx", "unknown"))
        for field, value in (("accepted", False), ("policy", "physical-voltage"),
                             ("control", 0x085F), ("selector_mask", True),
                             ("clock_values", None), ("clock_values", (0x4A, 0xCA)),
                             ("clock_values", [0x4A, 0xCB]),
                             ("clock_values", [float(0x4A), 0xCA]),
                             ("source_selector", False), ("selector_value", 0x20),
                             ("read_pc", 0x188), ("read_pc", True),
                             ("entries", [True])):
            config.sbi_bootstrap_profile = {**base, "raw_input": {**raw, field: value}}
            prop, reject = MODULE.qemu_sbi_property(config)
            self.assertEqual(prop, "sbi=on,sbi-bootstrap-only=on")
            self.assertTrue(reject.startswith("raw-input-"))
        config.sbi_bootstrap_profile = {**base, "raw_input": raw}
        config.load_address = 0x800000
        self.assertEqual(MODULE.qemu_sbi_property(config),
                         ("sbi=on,sbi-bootstrap-only=on", "raw-input-unverified-code-layout"))
        config.load_address = 0
        config.board_adc_value = None
        self.assertEqual(MODULE.qemu_sbi_property(config),
                         ("sbi=on,sbi-bootstrap-only=on", "raw-input-byte-unavailable"))
        config.chipset = "MSM5000"
        config.board_adc_reader_address = 0x4050
        self.assertEqual(MODULE.qemu_sbi_property(config), ("sbi=on", None))

    def test_board_revision_property_is_complete_and_fail_closed(self) -> None:
        config = SimpleNamespace(
            board_revision_register=0x0300075C,
            board_revision_value=0x20F5,
        )
        self.assertEqual(MODULE.qemu_board_revision_property(config), (
            "board-revision=300075c:20f5", None,
        ))
        config.board_revision_value = None
        self.assertEqual(MODULE.qemu_board_revision_property(config),
                         (None, "malformed-pair"))
        config.board_revision_register = 0x0300075D
        config.board_revision_value = 0x20F5
        self.assertEqual(MODULE.qemu_board_revision_property(config),
                         (None, "unsupported-register"))
        config.board_revision_register = 0x04000000
        self.assertEqual(MODULE.qemu_board_revision_property(config),
                         (None, "unsupported-register"))

    def test_adjacent_amd_secondary_nor_requires_closed_class(self) -> None:
        config = SimpleNamespace(
            chipset="MSM5500",
            load_address=0,
            flash_size=0x800000,
            secondary_flash_address=0x800000,
            secondary_flash_size=0x800000,
            ram_base=0x1000000,
            flash_id_value=0x227E0001,
        )
        image = b"fsd_amd.c\0...\x0b$USER_DIRS\0"
        self.assertEqual(
            MODULE.adjacent_amd_x16_flash_ids(config, image),
            (0x0001, 0x227E),
        )
        for field, value in (
                ("chipset", "MSM5100"),
                ("secondary_flash_address", 0x900000),
                ("ram_base", 0x1100000),
                ("flash_id_value", 0x22500001)):
            rejected = SimpleNamespace(**vars(config))
            setattr(rejected, field, value)
            self.assertIsNone(
                MODULE.adjacent_amd_x16_flash_ids(rejected, image)
            )
        self.assertIsNone(MODULE.adjacent_amd_x16_flash_ids(
            config, b"\x0b$USER_DIRS\0",
        ))
        self.assertIsNone(MODULE.adjacent_amd_x16_flash_ids(
            config, b"fsd_amd.c\0",
        ))
        exact = SimpleNamespace(**vars(config))
        exact.chipset = "MSM5100"
        profile = (0x800000, 0x800000, 0x0001, 0x227E)
        function_globals = MODULE.adjacent_amd_x16_flash_ids.__globals__
        with mock.patch.dict(function_globals, {
                "find_adjacent_amd_x16_nor": mock.Mock(return_value=profile),
        }):
            self.assertEqual(
                MODULE.adjacent_amd_x16_flash_ids(exact, b"firmware"),
                (0x0001, 0x227E),
            )
        with mock.patch.dict(function_globals, {
                "find_adjacent_amd_x16_nor": mock.Mock(return_value=None),
        }):
            self.assertIsNone(
                MODULE.adjacent_amd_x16_flash_ids(exact, b"firmware")
            )

    def test_dmd_5500_bridge_requires_exact_static_and_runtime_class(
            self) -> None:
        routine = bytearray(b"\xff" * 0x54)
        for offset, value in {
                0: bytes.fromhex("b0b50020"),
                4: bytes.fromhex("00f000f8"),
                8: bytes.fromhex("002803d10c480088"),
                16: bytes.fromhex("6c2803d00020b0bc08bc1847094800248480"),
                34: bytes.fromhex("00f000f8"),
                38: bytes.fromhex("084f084d02e0381c"),
                46: bytes.fromhex("00f000f8"),
                50: bytes.fromhex("e889064b9842f8d1ec810120eae7"),
                64: DMD_DOWNLOAD_5500_LITERALS,
        }.items():
            routine[offset:offset + len(value)] = value
        image = bytearray(b"\xff" * 0x400)
        image[0x100:0x154] = routine
        image[0x300:0x310] = b"dmddown_5500.c\0"
        config = SimpleNamespace(
            chipset="MSM5500", dmd_download_address=0x100,
            load_address=0, flash_size=len(image),
        )

        self.assertEqual(
            MODULE.qemu_dmd_5500_property(bytes(image), config),
            ("dmd-5500=100:6c", None),
        )
        config.dmd_download_address += 2
        self.assertEqual(
            MODULE.qemu_dmd_5500_property(bytes(image), config),
            (None, "address-mismatch"),
        )
        config.dmd_download_address -= 2
        config.chipset = "MSM5100"
        self.assertEqual(
            MODULE.qemu_dmd_5500_property(bytes(image), config),
            (None, "unsupported-chipset"),
        )
        image[0x100 + 17] ^= 1
        self.assertEqual(
            MODULE.qemu_dmd_5500_property(bytes(image), config),
            (None, None),
        )

        source = (NATIVE / "msm5xxx-poc.c").read_text()
        self.assertIn("qemu_in_vcpu_thread()", source)
        self.assertIn("msm5xxx_poc_dmd_5500_pc_is(s, 0x20)", source)
        self.assertIn("old == UINT16_MAX", source)
        self.assertIn("!s->dmd_5500_pending", source)
        self.assertIn("msm5xxx_poc_dmd_5500_pc_is(s, 0x32)", source)

    def test_loopback_transport_and_cancelled_picker(self) -> None:
        listener = MODULE.loopback_listener()
        try:
            self.assertEqual(listener.family, MODULE.socket.AF_INET)
            self.assertEqual(listener.getsockname()[0], "127.0.0.1")
        finally:
            listener.close()
        argv = ["live_display.py", "--qemu", "qemu-system-arm"]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(MODULE, "choose_firmware",
                               return_value=None) as chooser, \
             mock.patch.object(MODULE, "Transport") as transport:
            self.assertEqual(MODULE.main(), 0)
        chooser.assert_called_once_with()
        transport.assert_not_called()

    def test_launcher_uses_persistent_state_by_default(self) -> None:
        argv = [
            "live_display.py", "phone.bin",
            "--qemu", "qemu-system-arm",
        ]
        state_root = Path("/tmp/msm5xxx-state-root")
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(MODULE, "DEFAULT_STATE_ROOT", state_root), \
             mock.patch.object(MODULE.tk, "Tk") as make_root, \
             mock.patch.object(MODULE, "LiveWindow") as make_window:
            self.assertEqual(MODULE.main(), 0)
        make_window.assert_called_once_with(
            make_root.return_value,
            Path("phone.bin").resolve(),
            Path("qemu-system-arm").resolve(),
            (state_root / "qemu-state").resolve(),
            False,
        )
        make_window.return_value._close.assert_called_once_with()

    def test_qemu_gui_disables_partial_source_updates(self) -> None:
        with mock.patch.object(MODULE.threading, "Thread") as thread:
            MODULE.LiveWindow._check_for_update(object())
        thread.assert_not_called()

    def test_secondary_display_refresh_follows_primary_not_metrics(self) -> None:
        window = MODULE.LiveWindow.__new__(MODULE.LiveWindow)
        window.emulator = object()
        window._refresh_secondary_display = mock.Mock()
        with mock.patch.object(MODULE.Window, '_refresh_display') as primary:
            window._refresh_display()
        primary.assert_called_once_with()
        window._refresh_secondary_display.assert_called_once_with(window.emulator)
        window.emulator = None
        window._refresh_secondary_display.reset_mock()
        with mock.patch.object(MODULE.Window, '_refresh_display'):
            window._refresh_display()
        window._refresh_secondary_display.assert_not_called()

    def test_transport_accept_reports_early_qemu_exit(self) -> None:
        transport = object.__new__(MODULE.Transport)
        transport.process = SimpleNamespace(poll=lambda: 2)
        transport.stderr = io.StringIO("bad QEMU option")
        listener = mock.Mock()
        listener.accept.side_effect = MODULE.socket.timeout

        with self.assertRaisesRegex(RuntimeError, "bad QEMU option"):
            transport._accept_qemu(listener)
        listener.settimeout.assert_called_once_with(0.1)

    def test_transport_timeout_retains_channel_and_process_diagnostics(self) -> None:
        transport = object.__new__(MODULE.Transport)
        transport.process = SimpleNamespace(poll=lambda: None)
        transport.stderr = io.StringIO('waiting for device initialization')
        listener = mock.Mock()
        listener.accept.side_effect = MODULE.socket.timeout
        with self.assertRaisesRegex(TimeoutError, r'\(LCD\).*still running'):
            transport._accept_qemu(listener, 'LCD')
        self.assertEqual(transport.stderr.tell(), 0)  # Child owns the live offset.
        self.assertEqual(listener.accept.call_count, 50)
        transport.process = mock.Mock()
        transport.process.poll.side_effect = [None] * 50 + [2]
        with self.assertRaisesRegex(RuntimeError, r'status 2.*\(LCD\)'):
            transport._accept_qemu(listener, 'LCD')

    def test_startup_failure_reaps_qemu_before_reading_stderr(self) -> None:
        for failure in (ConnectionResetError(10054, "connection reset"),
                        TimeoutError("waiting for LCD connection")):
            for status in (None, 1):
                with self.subTest(failure=failure, status=status):
                    transport = object.__new__(MODULE.Transport)
                    transport.process = SimpleNamespace(poll=lambda: status)
                    transport.stderr = io.StringIO()
                    def terminate():
                        transport.stderr.write("device initialization failed")
                    transport._terminate_process = mock.Mock(side_effect=terminate)
                    result = transport._startup_error(failure)
                    transport._terminate_process.assert_called_once_with()
                    self.assertIsInstance(result, RuntimeError)
                    self.assertIn(str(failure), str(result))
                    self.assertIn("QEMU stderr:\ndevice initialization failed", str(result))
                    self.assertEqual("QEMU exit status 1" in str(result), status == 1)

    def test_qemu_state_directory_is_firmware_scoped(self) -> None:
        first = SimpleNamespace(firmware_sha256="a" * 64)
        second = SimpleNamespace(firmware_sha256="b" * 64)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(MODULE.qemu_state_directory(root, first),
                             root / ("a" * 64))
            (root / "primary-writable.raw").write_bytes(b"legacy")
            self.assertEqual(MODULE.qemu_state_directory(root, first), root)
            self.assertEqual(MODULE.qemu_state_directory(root, first), root)
            self.assertEqual(MODULE.qemu_state_directory(root, second),
                             root / ("b" * 64))
            self.assertEqual(
                (root / MODULE.LEGACY_STATE_OWNER).read_text().strip(),
                "a" * 64,
            )
            self.assertIsNone(MODULE.qemu_state_directory(None, first))
            with self.assertRaises(ValueError):
                MODULE.qemu_state_directory(root, SimpleNamespace(
                    firmware_sha256="../shared"
                ))

    def test_qemu_state_directory_recovers_flat_mapped_primary_state(self) -> None:
        first = SimpleNamespace(firmware_sha256="a" * 64)
        second = SimpleNamespace(firmware_sha256="b" * 64)
        for name in (
                "mapped-primary-x16.raw",
                "mapped-primary-x16-upper.raw"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / name).write_bytes(b"legacy")

                self.assertEqual(MODULE.qemu_state_directory(root, first), root)
                self.assertEqual(MODULE.qemu_state_directory(root, second),
                                 root / ("b" * 64))

    def test_primary_x16_detectors_must_agree(self) -> None:
        legacy = (0x10000, 0x40000, 0x10000, 0x98, 0x84)
        uniform = (0x10000, 0x40000, ((4, 0x10000),), 0x98, 0x84)
        segmented = (
            0x10000, 0x40000,
            ((2, 0x10000), (16, 0x2000)), 0x98, 0x84,
        )
        self.assertEqual(
            MODULE.select_primary_x16_nor_profile(legacy, uniform),
            (legacy, uniform[2], None),
        )
        self.assertEqual(
            MODULE.select_primary_x16_nor_profile(legacy, segmented),
            (None, None, "detector-conflict"),
        )
        self.assertEqual(
            MODULE.select_primary_x16_nor_profile(None, segmented),
            ((0x10000, 0x40000, 0x10000, 0x98, 0x84), segmented[2], None),
        )

    def test_qemu_detector_image_matches_canonical_normalization(self) -> None:
        header = b"dump-header"
        flash_size = ram_image_offset = 0x80000
        ram_base, ram_image_size = 0x01000000, 0x100
        image = bytearray(b"\xff" * (flash_size + ram_image_size))
        struct.pack_into("<I", image, 0, 0xEA000006)
        for index in range(1, 8):
            target = 0x4000 + index * 4
            displacement = (target - (index * 4 + 8)) // 4
            struct.pack_into(
                "<I", image, index * 4,
                0xEA000000 | (displacement & 0xFFFFFF),
            )
        boot_table_loop = snippet("test_qemu_input_transport", "detector_normalization_code")
        image[0x11C:0x11C + len(boot_table_loop)] = boot_table_loop
        struct.pack_into("<I", image, 0x1D8, 0x1158)
        struct.pack_into(
            "<8I", image, 0x1158,
            0x048000A0, 6, 0x03000738, 0x1F,
            0x0300073C, 0x2001, 0, 0,
        )
        for index in range(8):
            struct.pack_into("<I", image, 0x4000 + index * 4, 0xEA000000)

        probe, entry = 0x800, 0x2000
        sectors = 71 * [0x1000]
        descriptor, name = entry + 0x124, entry + 0x15C
        image[probe:probe + len(PRIMARY_FLASH_PROBE_SIGNATURE)] = (
            PRIMARY_FLASH_PROBE_SIGNATURE
        )
        struct.pack_into(
            "<3I", image, probe + len(PRIMARY_FLASH_PROBE_SIGNATURE),
            descriptor - 0x24, ram_base + 0x10, ram_base + 0x20,
        )
        struct.pack_into("<2I", image, entry, name, len(sectors))
        struct.pack_into(f"<{len(sectors)}I", image, entry + 8, *sectors)
        struct.pack_into(
            "<14I", image, descriptor,
            0x00840098, 0, 1, 0, sum(sectors) // 2,
            *[0x301 + index * 0x20 for index in range(9)],
        )
        image[name:name + 8] = b"NOR X16\0"
        struct.pack_into("<I", image, ram_image_offset + 0x10, 0x10000)
        struct.pack_into("<2I", image, ram_image_offset + 0x20, entry, 0)

        sparse = bytes(image[:0x1000] + image[0x1020:])
        normalized = MODULE.detector_firmware_image(header + sparse, len(header))
        self.assertEqual(normalized, bytes(image))
        self.assertEqual(
            MODULE.primary_probe_x16_nor_profile(
                normalized, probe, 0, flash_size, 0, ram_base,
                ram_image_offset, ram_image_size,
            ),
            ((0x10000, sum(sectors), ((71, 0x1000),), 0x98, 0x84), None),
        )
        with self.assertRaisesRegex(ValueError, "image offset"):
            MODULE.detector_firmware_image(header + sparse, len(header + sparse))

    def test_settings_restart_replaces_transport_with_saved_profile(self) -> None:
        events: list[str] = []
        firmware = Path("/tmp/settings.bin")
        config = SimpleNamespace(
            model="Detected", verified_model=None, chipset="MSM5000",
            width=128, height=160,
        )
        old_transport = mock.Mock()
        old_transport.interrupt.side_effect = lambda: events.append("interrupt")
        old_transport.close.side_effect = lambda: events.append("close")
        old_worker = mock.Mock()
        worker_running = [True]
        old_worker.is_alive.side_effect = lambda: worker_running[0]

        def join_worker() -> None:
            events.append("join")
            worker_running[0] = False

        old_worker.join.side_effect = join_worker
        new_transport = mock.Mock(
            config=config, decoder=mock.Mock(), replay=mock.Mock()
        )
        new_worker = mock.Mock()
        new_worker.start.side_effect = lambda: events.append("start")

        window = MODULE.LiveWindow.__new__(MODULE.LiveWindow)
        window._prepared_profile = None
        window.firmware = firmware
        window.overrides = {"width": 128}
        window.generation = 3
        window.stop = mock.Mock()
        window.root = mock.Mock()
        window.pending_key_releases = {"5": "callback"}
        window.keyboard_bits = {"5": 15}
        window.keyboard_sources = {"5"}
        window.held = {15: {"5"}}
        window.commands = queue.SimpleQueue()
        window.transport = old_transport
        window.worker = old_worker
        window.emulator = old_transport.decoder
        window._active_firmware = firmware
        window._active_overrides = {"width": 96}
        window._render_cache = (object(), b"", 1, 1, 1, 1)
        window.qemu = Path("/tmp/qemu-system-arm")
        window.state_dir = Path("/tmp/qemu-state")
        window.experimental_c80 = True
        window.virtual_network_enabled = False
        window._active_virtual_network = False
        window.virtual_network_var = mock.Mock()
        window.ui_language = "en"
        window.model = mock.Mock()
        window.device_details = mock.Mock()
        window.status = mock.Mock()

        def create_transport(*_args: object, **_kwargs: object) -> object:
            events.append("create")
            return new_transport

        with mock.patch.object(MODULE, "_prepared_profile_matches",
                               return_value=False), \
             mock.patch.object(MODULE, "detect_profile",
                               return_value=(config, {"width": 128})) as detect, \
             mock.patch.object(MODULE, "Transport",
                               side_effect=create_transport) as transport, \
             mock.patch.object(MODULE.threading, "Thread",
                               return_value=new_worker):
            window._restart()

        detect.assert_called_once_with(firmware, {"width": 128})
        transport.assert_called_once_with(
            window.qemu, firmware, window.state_dir, True, config=config,
            virtual_cell=None,
        )
        self.assertEqual(
            events, ["interrupt", "join", "close", "create", "start"]
        )
        self.assertIs(window.transport, new_transport)
        self.assertIs(window.emulator, new_transport.decoder)
        self.assertEqual(window.generation, 4)
        window.root.after_cancel.assert_called_once_with("callback")
        self.assertEqual(window.keyboard_bits, {})
        self.assertEqual(window.keyboard_sources, set())
        self.assertEqual(window.held, {})
        window.closing = False
        window.overrides = {"framebuffer_format": "bgr565le"}
        window.commands.put(("framebuffer-format", "bgr565le"))
        window._forward_qemu_keys()
        new_transport.decoder.set_framebuffer_format.assert_called_once_with(
            "bgr565le"
        )
        self.assertEqual(window._active_overrides, window.overrides)

    def test_settings_restart_restores_previous_transport_on_launch_error(self) -> None:
        old_firmware = Path("/tmp/old.bin")
        new_firmware = Path("/tmp/new.bin")
        old_config = SimpleNamespace(
            model="Old", verified_model=None, chipset="MSM5000",
            width=96, height=64,
        )
        new_config = SimpleNamespace(
            model="New", verified_model=None, chipset="MSM5000",
            width=128, height=160,
        )
        restored = mock.Mock(
            config=old_config, decoder=SimpleNamespace(), replay=mock.Mock()
        )
        worker = mock.Mock()
        worker.is_alive.return_value = False

        window = MODULE.LiveWindow.__new__(MODULE.LiveWindow)
        window._prepared_profile = None
        window.firmware = new_firmware
        window.overrides = {"width": 128}
        window._active_firmware = old_firmware
        window._active_overrides = {"width": 96}
        window.generation = 1
        window.stop = mock.Mock()
        window.root = mock.Mock()
        window.pending_key_releases = {}
        window.keyboard_bits = {}
        window.keyboard_sources = set()
        window.held = {}
        window.commands = queue.SimpleQueue()
        window.transport = mock.Mock()
        window.worker = worker
        window.emulator = window.transport.decoder
        window._render_cache = None
        window.qemu = Path("/tmp/qemu-system-arm")
        window.state_dir = Path("/tmp/qemu-state")
        window.experimental_c80 = False
        window.virtual_network_enabled = True
        window._active_virtual_network = False
        window.virtual_network_var = mock.Mock()
        window.ui_language = "en"
        window.model = mock.Mock()
        window.device_details = mock.Mock()
        window.status = mock.Mock()
        window._save_config = mock.Mock()

        with mock.patch.object(MODULE, "_prepared_profile_matches",
                               return_value=False), \
             mock.patch.object(MODULE, "detect_profile",
                               side_effect=((new_config, {"width": 128}),
                                            (old_config, {"width": 96}))), \
             mock.patch.object(MODULE, "Transport",
                               side_effect=(RuntimeError("launch failed"),
                                            restored)) as transport, \
             mock.patch.object(MODULE.threading, "Thread",
                               return_value=mock.Mock()), \
             mock.patch.object(MODULE.messagebox, "showerror") as showerror:
            window._restart()

        self.assertEqual(window.firmware, old_firmware)
        self.assertEqual(window.overrides, {"width": 96})
        self.assertIs(window.transport, restored)
        self.assertEqual(transport.call_count, 2)
        self.assertEqual(transport.call_args_list[0].kwargs['virtual_cell'],
                         MODULE.virtual_cell_scenario(True))
        self.assertIsNone(transport.call_args_list[1].kwargs['virtual_cell'])
        self.assertFalse(window.virtual_network_enabled)
        window.virtual_network_var.set.assert_called_with(False)
        window._save_config.assert_called_once_with()
        showerror.assert_called_once()

    def test_virtual_network_toggle_saves_only_the_active_mode(self) -> None:
        window = MODULE.LiveWindow.__new__(MODULE.LiveWindow)
        window.virtual_network_enabled = False
        window.virtual_network_var = mock.Mock()
        window.virtual_network_var.get.return_value = True
        window._save_config = mock.Mock()
        window._restart = mock.Mock(side_effect=lambda: setattr(
            window, 'virtual_network_enabled', False))
        window._set_virtual_network()
        window._save_config.assert_not_called()
        window.virtual_network_var.set.assert_called_with(False)
        window._restart = mock.Mock()
        window._set_virtual_network()
        self.assertTrue(window.virtual_network_enabled)
        window._save_config.assert_called_once_with()
        window.virtual_network_var.set.assert_called_with(True)

    def test_memory_profile_fails_closed_outside_native_shape(self) -> None:
        config = SimpleNamespace(flash_size=0x01800000,
                                 ram_base=0x01800000,
                                 ram_size=0x00800000)
        registers = {name: 0 for name in MODULE.REGISTER_NAMES}
        registers.update(sp=0x01FFFFFC, cpsr=0xD3)
        self.assertEqual(
            MODULE.qemu_memory_profile(config, registers),
            "1800000:1800000:1fffffc",
        )
        for name, value in (("r0", 1), ("cpsr", 0x400001D3),
                            ("sp", 0x017FFFFC)):
            changed = {**registers, name: value}
            with self.subTest(name=name), self.assertRaises(ValueError):
                MODULE.qemu_memory_profile(config, changed)
        config.flash_size = config.ram_base + 1
        with self.assertRaises(ValueError):
            MODULE.qemu_memory_profile(config, registers)
        config.flash_size = 1
        with self.assertRaises(ValueError):
            MODULE.qemu_memory_profile(config, registers)

    def test_uis_idle_observer_requires_one_closed_pair(self) -> None:
        accepted = SimpleNamespace(
            uis_idle_entry_address=0x000CC348,
            uis_idle_body_address=0x000CC4A6,
        )
        self.assertEqual(
            MODULE.qemu_uis_idle_observer_addresses(accepted),
            (0x000CC348, 0x000CC4A6),
        )
        compact = SimpleNamespace(
            uis_idle_entry_address=0x000C1D88,
            uis_idle_body_address=0x000C1E86,
        )
        self.assertEqual(
            MODULE.qemu_uis_idle_observer_addresses(compact),
            (0x000C1D88, 0x000C1E86),
        )
        for delta in (0x8B8, 0x908):
            draw = SimpleNamespace(
                uis_idle_entry_address=0x000F0000,
                uis_idle_body_address=0x000F0000 + delta,
            )
            with self.subTest(delta=delta):
                self.assertEqual(
                    MODULE.qemu_uis_idle_observer_addresses(draw),
                    (0x000F0000, 0x000F0000 + delta),
                )
        for changed in (
                SimpleNamespace(uis_idle_entry_address=None,
                                uis_idle_body_address=0x000CC4A6),
                SimpleNamespace(uis_idle_entry_address=0x000CC349,
                                uis_idle_body_address=0x000CC4A6),
                SimpleNamespace(uis_idle_entry_address=0x000CC348,
                                uis_idle_body_address=0x000CC4A8)):
            with self.subTest(changed=changed):
                self.assertIsNone(MODULE.qemu_uis_idle_observer_addresses(
                    changed
                ))

    def test_rex_idle_candidate_observer_requires_even_address(self) -> None:
        accepted = SimpleNamespace(rex_idle_address=0x000DEF50)
        self.assertEqual(
            MODULE.qemu_rex_idle_candidate_observer_address(accepted),
            0x000DEF50,
        )
        for address in (None, 0, 0x000DEF51, 0x1_0000_0000, True):
            with self.subTest(address=address):
                self.assertIsNone(
                    MODULE.qemu_rex_idle_candidate_observer_address(
                        SimpleNamespace(rex_idle_address=address)
                    )
                )

    def test_upper_nor_accepts_only_the_detector_range(self) -> None:
        disabled = SimpleNamespace(upper_flash_address=None,
                                   upper_flash_size=0)
        accepted = SimpleNamespace(upper_flash_address=0x02800000,
                                   upper_flash_size=0x00800000)
        self.assertFalse(MODULE.qemu_upper_nor_enabled(disabled))
        self.assertTrue(MODULE.qemu_upper_nor_enabled(accepted))
        for changed in (
                SimpleNamespace(upper_flash_address=0x02801000,
                                upper_flash_size=0x00800000),
                SimpleNamespace(upper_flash_address=0x02800000,
                                upper_flash_size=0x00400000)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                MODULE.qemu_upper_nor_enabled(changed)

    def test_raw_nand_main_profile_requires_the_complete_closed_shape(
            self) -> None:
        image = bytearray(b"\xff" * 0x800)
        image[0x20:0x2B] = b"fs_ks_nand.c"
        for site in (0x100, 0x300):
            image[site:site + len(MODULE.RAW_NAND_STATUS_SIGNATURE)] = (
                MODULE.RAW_NAND_STATUS_SIGNATURE
            )
            reset = site + 0x30
            image[reset:reset + len(MODULE.RAW_NAND_RESET_SIGNATURE)] = (
                MODULE.RAW_NAND_RESET_SIGNATURE
            )
            image[site + 0x50:site + 0x54] = bytes.fromhex("29210905")
        for position in (0x500, 0x520):
            image[position:position + len(MODULE.RAW_NAND_PAGE_SIGNATURE)] = (
                MODULE.RAW_NAND_PAGE_SIGNATURE
            )
        image[0x600:0x606] = MODULE.RAW_NAND_BLOCK_PREFIX
        image[0x60A:0x614] = MODULE.RAW_NAND_BLOCK_SUFFIX
        image[0x680:0x684] = MODULE.RAW_NAND_X16_PREFIX
        image[0x688:0x68C] = MODULE.RAW_NAND_X16_TRANSFER
        config = SimpleNamespace(
            nand_enabled=True, flash_size=0x800000, nand_data_size=0x800000,
            nand_page_size=0x200, nand_pages_per_block=0x20,
            nand_bus_width=2, upper_flash_address=None,
        )

        self.assertEqual(MODULE.qemu_raw_nand_main_profile(image, config), (
            (0x02800000, 0x02900000, 0x02A00000,
             0x800000, 0x200, 0x20, 2),
            None,
        ))
        image[0x100] ^= 1
        image[0x300] ^= 1
        self.assertEqual(
            MODULE.qemu_raw_nand_main_profile(image, config),
            (None, "incomplete-status-reset-shape"),
        )

        low_image = bytearray(b"\xff" * 0x1000)
        low_image[0x20:0x2B] = b"fs_ks_nand.c"
        for position, signature in zip(
                (0x100, 0x200, 0x300, 0x500, 0x700),
                (MODULE.RAW_NAND_LOW_PORT_RESET_SIGNATURE,
                 MODULE.RAW_NAND_LOW_PORT_STATUS_SIGNATURE,
                 MODULE.RAW_NAND_LOW_PORT_READ_SIGNATURE,
                 MODULE.RAW_NAND_LOW_PORT_ERASE_SIGNATURE,
                 MODULE.RAW_NAND_LOW_PORT_PROGRAM_SIGNATURE)):
            low_image[position:position + len(signature)] = signature
        self.assertEqual(MODULE.qemu_raw_nand_main_profile(low_image, config), (
            (0x00800000, 0x00900000, 0x00A00000,
             0x800000, 0x200, 0x20, 2),
            None,
        ))
        low_image[0x500] ^= 1
        self.assertEqual(
            MODULE.qemu_raw_nand_main_profile(low_image, config),
            (None, "incomplete-status-reset-shape"),
        )

    def test_raw_nand_main_backend_is_named_and_non_orphaned(self) -> None:
        machine = (NATIVE / "msm5xxx-poc.c").read_text()
        start = machine.index(
            "s->raw_nand_blk = blk_by_name(MSM5XXX_POC_RAW_NAND_DRIVE)"
        )
        end = machine.index("if (s->eeprom_gpio_enabled) {", start)
        raw_nand_init = machine[start:end]

        self.assertIn(
            "blk_by_name(MSM5XXX_POC_RAW_NAND_DRIVE)", raw_nand_init,
        )
        self.assertNotIn("drive_get(IF_MTD", raw_nand_init)
        self.assertNotIn("msm5xxx_poc_raw_nand_set_ready", machine)
        transport = TRANSPORT_SOURCE.read_text()
        self.assertIn(
            '"id=msm5xxx-raw-nand-main"', transport,
        )
        self.assertNotIn(
            'f"file={raw_nand_state},if=mtd', transport,
        )
        setter_start = machine.index("static void msm5xxx_poc_set_raw_nand_main")
        setter_end = machine.index("static char *msm5xxx_poc_get_eeprom_gpio",
                                   setter_start)
        setter = machine[setter_start:setter_end]
        for name in ("DATA", "ADDRESS", "COMMAND"):
            self.assertIn(
                f"MSM5XXX_POC_RAW_NAND_LOW_PORT_{name}_BASE", setter,
            )

    def test_eeprom_gpio_reset_preserves_shared_msm_backing(self) -> None:
        machine = (NATIVE / "msm5xxx-poc.c").read_text()
        reset = machine[machine.index("static void msm5xxx_poc_reset"):
                        machine.index("static void msm5xxx_poc_init")]

        seed = reset.index("msm[0x72c] = 0x14;")
        copy = reset.index("memcpy(s->eeprom_gpio_backing,", seed)
        self.assertIn(
            "msm + s->eeprom_gpio_base - MSM5XXX_POC_MSM_BASE",
            reset[copy:copy + 240],
        )
        self.assertGreater(
            reset.index("msm5xxx_poc_eeprom_gpio_update(s);", copy), copy,
        )

    def test_mapped_primary_nor_persists_upper_bank_and_aliases_intel(self) -> None:
        machine = (NATIVE / "msm5xxx-poc.c").read_text()
        transport = TRANSPORT_SOURCE.read_text()

        self.assertIn("mapped-primary-x16-nor-upper", machine)
        self.assertIn("intel_x16_nor_data_alias", machine)
        self.assertIn("mapped-primary-x16-upper.raw", transport)
        self.assertIn("pflash_unit += 2", transport)

    def test_primary_nor_honors_suspend_write_descriptor_option(self) -> None:
        machine = (NATIVE / "msm5xxx-poc.c").read_text()
        transport = TRANSPORT_SOURCE.read_text()
        start = machine.index("    if (s->primary_x16_nor_enabled) {")
        end = machine.index("    if (s->record_x16_nor_enabled) {", start)
        primary_init = machine[start:end]
        transport_start = transport.index("        if primary_profile is not None:")
        transport_end = transport.index(
            "        if record_profile is not None:", transport_start
        )

        self.assertIn(
            'qdev_prop_set_bit(dev, "write-while-suspended", true);',
            primary_init,
        )
        self.assertIn(
            "if (s->primary_x16_write_while_suspended) {", primary_init,
        )
        self.assertIn(
            'object_class_property_add_bool(\n'
            '        oc, "primary-x16-write-while-suspended",',
            machine,
        )
        primary_transport = transport[transport_start:transport_end]
        regions_start = primary_transport.index(
            "            if primary_regions is not None:"
        )
        regions_end = primary_transport.index(
            "            storage_args.extend", regions_start
        )
        self.assertIn(
            'machine += ",primary-x16-write-while-suspended=on"',
            primary_transport[regions_start:regions_end],
        )
        self.assertEqual(
            transport.count("primary-x16-write-while-suspended=on"), 1,
        )

    def test_record_nor_is_descriptor_gated_and_identity_fail_closed(self) -> None:
        machine = (NATIVE / "msm5xxx-poc.c").read_text()
        transport = TRANSPORT_SOURCE.read_text()
        start = machine.index("    if (s->record_x16_nor_enabled) {")
        start = machine.index("    if (s->record_x16_nor_enabled) {", start + 1)
        end = machine.index(
            "    if (s->mapped_primary_x16_nor_enabled) {", start
        )
        record_init = machine[start:end]

        self.assertIn('"record-x16-nor"', machine)
        self.assertIn("TYPE_PFLASH_CFI02", record_init)
        self.assertEqual(record_init.count("UINT16_MAX"), 2)
        self.assertIn('"id0", s->record_x16_nor_id0', record_init)
        self.assertIn('"id1", s->record_x16_nor_id1', record_init)
        self.assertIn(
            "uint32_t parsed[5] = { 0, 0, 0, UINT16_MAX, UINT16_MAX };",
            machine,
        )
        self.assertIn('"unlock-addr0", 0x555', record_init)
        self.assertIn('"unlock-addr1", 0x2aa', record_init)
        self.assertIn("pow2ceil(s->record_x16_nor_size)", record_init)
        self.assertIn("record_x16_nor_alias", record_init)
        self.assertNotIn("sysbus_mmio_map_overlap", record_init)
        self.assertIn("find_record_amd_x16_nor", transport)
        self.assertIn("record-x16.raw", transport)
        self.assertIn("1 << (size - 1).bit_length()", transport)
        self.assertIn(
            "migrate_erased_raw_state(\n"
            "                                record_state, size, device_size",
            transport,
        )
        self.assertIn(
            "record_state, 0x200000, device_size,\n"
            "                                prepend=True",
            transport,
        )
        self.assertIn("record_base + record_size != primary_profile[0]",
                      transport)

    def test_secondary_nor_hides_power_of_two_backing_tail(self) -> None:
        machine = (NATIVE / "msm5xxx-poc.c").read_text()
        transport = TRANSPORT_SOURCE.read_text()
        start = machine.index("    if (s->fujitsu_x16_nor_enabled) {")
        end = machine.index("    if (upper_nor_enabled) {", start)
        secondary_init = machine[start:end]

        self.assertIn("pow2ceil(s->secondary_nor_size)", secondary_init)
        self.assertIn("secondary_nor_alias", secondary_init)
        self.assertIn("device_size / 0x10000", secondary_init)
        self.assertIn("device_size != s->secondary_nor_size", secondary_init)
        self.assertIn(
            "s->secondary_nor_size == 0x800000 &&\n"
            "                s->secondary_nor_base < s->secondary_primary_size",
            secondary_init,
        )
        self.assertIn('"num-blocks2", 8', secondary_init)
        self.assertIn('"sector-length2", 0x2000', secondary_init)
        setter_start = machine.index(
            "static void msm5xxx_poc_set_fujitsu_x16_nor"
        )
        setter_end = machine.index(
            "static void msm5xxx_poc_set_primary_x16_nor", setter_start
        )
        setter = machine[setter_start:setter_end]
        self.assertNotIn("s->ram_base", setter)
        self.assertIn("s->secondary_primary_size = primary", setter)
        self.assertIn("if (!s->memory_profile_enabled)", setter)
        self.assertIn("size == 0x200000", setter)
        self.assertIn("size == 0x800000", setter)
        self.assertIn("(uint64_t)base + size == primary", setter)
        self.assertIn(
            "s->secondary_primary_size != s->primary_nor_size", machine
        )
        self.assertIn(
            "s->secondary_nor_base >= s->ram_base || end > s->ram_base",
            machine,
        )
        self.assertIn("find_catalog_amd_x16_nor", transport)
        self.assertIn('"catalog-x16.raw"', transport)
        self.assertIn("f\"{secondary_base:x}:{secondary_size:x}:\"", transport)
        self.assertIn(
            "find_embedded_fujitsu_x16_nor(\n"
            "                bytes(self.decoder.flash.data), "
            "self.config.flash_size",
            transport,
        )

    def test_raw_nand_state_is_observable_without_ready_synthesis(self) -> None:
        machine = (NATIVE / "msm5xxx-poc.c").read_text()
        start = machine.index("    case 0xac:")
        end = machine.index("    default:", start)
        telemetry = machine[start:end]

        for field in (
            "raw_nand_reads", "raw_nand_writes", "raw_nand_rejections",
            "raw_nand_mode", "raw_nand_status", "raw_nand_address_count",
            "raw_nand_cursor_valid", "raw_nand_spare_selected",
        ):
            self.assertIn(f"s->{field}", telemetry)
        self.assertNotIn("board_status_input", telemetry)
        self.assertNotIn("msm5xxx_poc_raw_nand_set_ready", machine)

    def test_eeprom_gpio_profile_accepts_split_bank_open_drain_shape(
            self) -> None:
        image = bytearray(b"\xff" * 0x1400)
        write, read = 0x800, 0xEB0
        writer, ack, reader = write - 0x12C, write - 0x1D2, read - 0x718
        image[write:write + len(MODULE.EEPROM_24LCXX_X430_WRITE_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X430_WRITE_PREFIX
        )
        image[read:read + len(MODULE.EEPROM_24LCXX_X430_READ_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X430_READ_PREFIX
        )
        shapes = (
            (writer, "f0b5071c8025"),
            (writer + 0x16, "0122087810430870087826490871"),
            (writer + 0x2E, "202108431070107821490870"),
            (writer + 0x44, "202311789943117011781b4a1170"),
            (writer + 0x5A, "0878400840000870087815490871"),
            (writer + 0x72, "202108431070107810490870"),
            (writer + 0x88, "202311789943117011780a4a1170"),
            (ack, "f0b5"),
            (ack + 0x06, "234a11784908490011701178214a1172"),
            (ack + 0x24, "202229781c4c114329702978103c2170"),
            (ack + 0x40, "21790126301c490800d2002007063f0e"),
            (ack + 0x5A, "20239943297029782170"),
            (ack + 0x78, "0a7832430a700978064a1172"),
            (reader, "f0b50027164d"),
            (reader + 0x10, "20220878104308700878114904390870"),
            (reader + 0x28, "28783f0e400801d301200743"),
            (reader + 0x36, "20230878984308700878074904390870"),
        )
        for position, value in shapes:
            image[position:position + len(bytes.fromhex(value))] = bytes.fromhex(value)
        MODULE.struct.pack_into("<I", image, writer + 0xBC, 0x03000660)
        MODULE.struct.pack_into("<I", image, ack + 0x9A, 0x03000670)
        MODULE.struct.pack_into("<I", image, reader + 0x60, 0x03000664)
        config = SimpleNamespace(
            eeprom_read_address=read, eeprom_write_address=write,
            eeprom_geometry_address=0x01001000, load_address=0,
        )

        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            ((0x03000660, 4, 1, 0, 0x20, 0x18, 0x8000), None),
        )
        MODULE.struct.pack_into("<I", image, ack + 0x9A, 0x03000674)
        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            (None, "gpio-line-shape-mismatch"),
        )

    def test_eeprom_gpio_profile_accepts_x270_protocol_class(self) -> None:
        image = bytearray(b"\xff" * 0x3000)
        write, read, initializer = 0x1000, 0x16D0, 0x2400
        writer, reader = write - 0x2DC, read - 0x7F8
        geometry = 0x0119BA08
        image[write:write + len(MODULE.EEPROM_24LCXX_X270_WRITE_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X270_WRITE_PREFIX
        )
        image[read:read + len(MODULE.EEPROM_24LCXX_X270_READ_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X270_READ_PREFIX
        )
        image[initializer:initializer + 18] = bytes.fromhex(
            "01200449c0030880012088700020c8707047"
        )
        for position in (write + 0x3EC, read + 0x3EC,
                         initializer + 0x14):
            MODULE.struct.pack_into("<I", image, position, geometry)
        image[0x2E00:0x2E0B] = b"nv24lcxx.c\0"

        shapes = (
            (writer, "f0b5071c"),
            (writer + 0x18, "2b7808263343"),
            (writer + 0x28, "2b702b782372"),
            (writer + 0x2E, "13780b43137013782373"),
            (writer + 0x3E, "137013782373"),
            (reader, "f0b50027"),
            (reader + 0x0E, "0a782a430a700b78"),
            (reader + 0x1A, "1373"),
            (reader + 0x1C, "2678330900d38027"),
            (reader + 0x24, "0b785b085b000b700b781373"),
            (write + 0xBE, "08251178294311701178"),
            (write + 0xCA, "1173"),
            (read + 0x304, "082311789943117011"),
            (read + 0x310, "1173"),
            (read + 0x324, "2070"),
        )
        for position, value in shapes:
            raw = bytes.fromhex(value)
            image[position:position + len(raw)] = raw
        MODULE.struct.pack_into("<H", image, writer + 0x12, 0x4C66)
        MODULE.struct.pack_into("<I", image, writer + 0x1AC, 0x03000660)
        MODULE.struct.pack_into("<H", image, reader + 0x04, 0x4C46)
        MODULE.struct.pack_into("<H", image, reader + 0x16, 0x4A42)
        MODULE.struct.pack_into("<I", image, reader + 0x120, 0x03000668)
        MODULE.struct.pack_into("<H", image, write + 0xC8, 0x4A01)
        MODULE.struct.pack_into("<I", image, write + 0xD0, 0x03000670)
        MODULE.struct.pack_into("<H", image, read + 0x30E, 0x4A02)
        MODULE.struct.pack_into("<I", image, read + 0x318, 0x03000670)
        displacement = reader - (read + 0x320 + 4)
        MODULE.struct.pack_into(
            "<2H", image, read + 0x320,
            0xF000 | (displacement >> 12 & 0x7FF),
            0xF800 | (displacement >> 1 & 0x7FF),
        )
        config = SimpleNamespace(
            eeprom_read_address=read, eeprom_write_address=write,
            eeprom_geometry_address=geometry, load_address=0,
        )

        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            ((0x03000660, 8, 8, 0xC, 1, 0x1C, 0x8000), None),
        )
        image[reader + 0x1E] ^= 1
        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            (None, "gpio-line-shape-mismatch"),
        )

    def test_eeprom_gpio_profile_accepts_f6f7_protocol_class(self) -> None:
        image = bytearray(b"\xff" * 0x4000)
        write, read, initializer = 0x1000, 0x16D0, 0x2400
        geometry = 0x0119BA08
        image[write:write + len(MODULE.EEPROM_24LCXX_F6F7_WRITE_PREFIX)] = (
            MODULE.EEPROM_24LCXX_F6F7_WRITE_PREFIX
        )
        image[read:read + len(MODULE.EEPROM_24LCXX_X270_READ_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X270_READ_PREFIX
        )
        image[initializer:initializer + 18] = bytes.fromhex(
            "01200449c0030880012088700020c8707047"
        )
        for position in (write + 0x3E8, read + 0x3EC,
                         initializer + 0x14):
            MODULE.struct.pack_into("<I", image, position, geometry)
        image[0x3A00:0x3A0B] = b"nv24lcxx.c\0"

        low_write, low_read = 0x2C00, 0x2D00
        image[low_write:low_write + 8] = bytes.fromhex(
            "f0b5071c1e481f49"
        )
        MODULE.struct.pack_into("<2I", image, low_write + 0x80,
                                0x03000660, 0x03000668)
        image[low_read:low_read + 6] = bytes.fromhex("f0b500271e48")
        MODULE.struct.pack_into("<I", image, low_read + 0x80, 0x03000668)

        def call(position: int, target: int) -> None:
            displacement = target - (position + 4)
            MODULE.struct.pack_into(
                "<2H", image, position,
                0xF000 | (displacement >> 12 & 0x7FF),
                0xF800 | (displacement >> 1 & 0x7FF),
            )

        for index in range(16):
            call(0x1400 + index * 4, low_write)
        for index in range(2):
            call(0x1480 + index * 4, low_read)
        config = SimpleNamespace(
            eeprom_read_address=read, eeprom_write_address=write,
            eeprom_geometry_address=geometry, load_address=0,
        )

        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            ((0x03000660, 8, 8, 0xC, 1, 0x1C, 0x8000), None),
        )
        MODULE.struct.pack_into("<I", image, low_write + 0x80, 0x03000728)
        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            (None, "transport-entry-signature-mismatch"),
        )

    def test_eeprom_gpio_profile_accepts_x7700_protocol_class(self) -> None:
        image = bytearray(b"\xff" * 0x5000)
        write, read, initializer = 0x1000, 0x16B0, 0x3000
        writer, reader = write - 0x160, read - 0x728
        geometry, descriptor = 0x01002000, 0x01000100
        image[write:write + len(MODULE.EEPROM_24LCXX_X7700_WRITE_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X7700_WRITE_PREFIX
        )
        image[read:read + len(MODULE.EEPROM_24LCXX_X7700_READ_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X7700_READ_PREFIX
        )
        image[initializer:initializer + 18] = bytes.fromhex(
            "01200449c0030880012088700020c8707047"
        )
        for position in (write + 0x3EC, read + 0x3E8,
                         initializer + 0x14):
            MODULE.struct.pack_into("<I", image, position, geometry)
        image[0x3F00:0x3F0B] = b"nv24lcxx.c\0"
        shapes = (
            (writer, "f0b5071c80260724"),
            (writer + 0x18, "324a202391891943918191891268"),
            (writer + 0x3A, "2a4a402391891943918191891268"),
            (writer + 0x5A, "224a402391899943918191891268"),
            (writer + 0x74, "1b4a202391899943918191891268"),
            (writer + 0x96, "134a402391891943918191891268"),
            (writer + 0xB6, "0b4a402391899943918191891268"),
            (reader, "f0b500271a4e0024"),
            (reader + 0x12, "184a402391891943918191891268"),
            (reader + 0x32, "30783f0e800901d301200743"),
            (reader + 0x42, "0c4a402391899943918191891268"),
        )
        for position, value in shapes:
            raw = bytes.fromhex(value)
            image[position:position + len(raw)] = raw
        MODULE.struct.pack_into("<I", image, writer + 0xE4, descriptor)
        MODULE.struct.pack_into("<II", image, reader + 0x70,
                                0x03000720, descriptor)
        MODULE.struct.pack_into("<III", image, 0x3900,
                                0x03000720, 0x03000720, 0x0300072C)
        config = SimpleNamespace(
            eeprom_read_address=read, eeprom_write_address=write,
            eeprom_geometry_address=geometry, load_address=0,
            linker=SimpleNamespace(
                data_source=0x3800, data_target=0x01000000,
                data_size=0x1000,
            ),
        )

        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            ((0x03000720, 0, 0x20, 0, 0x40, 0xC, 0x8000), None),
        )
        image[reader + 0x34] ^= 1
        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            (None, "gpio-line-shape-mismatch"),
        )

    def test_eeprom_gpio_profile_accepts_f7f6_protocol_class(self) -> None:
        image = bytearray(b"\xff" * 0x1800)
        write, read, initializer = 0x400, 0xAD8, 0x1200
        writer, ack, reader = write - 0x16C, write - 0x216, read - 0x754
        geometry = 0x01208494
        image[write:write + len(MODULE.EEPROM_24LCXX_X7700_WRITE_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X7700_WRITE_PREFIX
        )
        image[read:read + len(MODULE.EEPROM_24LCXX_X430_READ_PREFIX)] = (
            MODULE.EEPROM_24LCXX_X430_READ_PREFIX
        )
        image[initializer:initializer + 18] = bytes.fromhex(
            "01200449c0030880012088700020c8707047"
        )
        for position in (write + 0x3EC, read + 0x3E8,
                         initializer + 0x14):
            MODULE.struct.pack_into("<I", image, position, geometry)
        image[0x1700:0x170B] = b"nv24lcxx.c\0"
        shapes = (
            (writer, "f0b5071c80260724"),
            (writer + 0x1A, "01231178194311701178304a1171"),
            (writer + 0x3C, "20231178194311701178"),
            (writer + 0x5C, "20231178994311701178"),
            (writer + 0x74, "1b4a11784908490011701178"),
            (writer + 0x98, "20231178194311701178"),
            (writer + 0xB8, "20231178994311701178"),
            (ack, "f0b5"),
            (ack + 0x06, "234a11784908490011701178214a1172"),
            (ack + 0x24, "202229781c4c114329702978103c2170"),
            (ack + 0x40, "21790126301c490800d2002007063f0e"),
            (ack + 0x5C, "20239943297029782170"),
            (ack + 0x7A, "0a7832430a700978054a1172"),
            (reader, "f0b500271b4e0024"),
            (reader + 0x12, "194a20231178194311701178154a043a1170"),
            (reader + 0x30, "7800070630783f0e400801d301200743"),
            (reader + 0x44, "0c4a20231178994311701178084a043a1170"),
        )
        for position, value in shapes:
            raw = bytes.fromhex(value)
            image[position:position + len(raw)] = raw
        for position, operation in zip(
                (writer + 0x46, writer + 0x66, writer + 0x80,
                 writer + 0xA2, writer + 0xC2),
                (0x4A28, 0x4A20, 0x4A19, 0x4A11, 0x4A09)):
            MODULE.struct.pack_into("<H", image, position, operation)
        MODULE.struct.pack_into("<I", image, writer + 0xE8, 0x03000660)
        MODULE.struct.pack_into("<I", image, ack + 0x9A, 0x03000670)
        MODULE.struct.pack_into("<I", image, reader + 0x74, 0x03000664)
        config = SimpleNamespace(
            eeprom_read_address=read, eeprom_write_address=write,
            eeprom_geometry_address=geometry, load_address=0,
        )

        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            ((0x03000660, 4, 1, 0, 0x20, 0x18, 0x8000), None),
        )
        image[reader + 0x32] ^= 1
        self.assertEqual(
            MODULE.eeprom_gpio_profile(bytes(image), config),
            (None, "gpio-line-shape-mismatch"),
        )

    def test_press_and_release_packets(self) -> None:
        self.assertEqual(MODULE.matrix_senses(self.PROFILE),
                         (0x0E, 0x0D, 0x0B, 0x07))
        self.assertEqual(
            MODULE.matrix_input_command(self.PROFILE, (0x53, 1, 1), True),
            bytes.fromhex("8001010d"),
        )
        self.assertEqual(
            MODULE.matrix_input_command(self.PROFILE, (0x53, 1, 1), False),
            bytes.fromhex("80000000"),
        )

    def test_gui_preserves_one_debounce_window_between_key_edges(self) -> None:
        window = MODULE.LiveWindow.__new__(MODULE.LiveWindow)
        window.closing = False
        window.root = mock.Mock()
        window.transport = mock.Mock()
        window.commands = queue.SimpleQueue()
        window.commands.put((15, True))
        window.commands.put((15, False))

        window._forward_qemu_keys()

        window.transport.set_key.assert_called_once_with(15, True, None)
        window.root.after.assert_called_once_with(20, window._forward_qemu_keys)
        window._forward_qemu_keys()
        self.assertEqual(
            window.transport.set_key.call_args_list,
            [mock.call(15, True, None), mock.call(15, False, None)],
        )

    def test_invalid_detector_position_fails_closed(self) -> None:
        for position in (None, (0x53, 6, 0), (0x53, 1, 4)):
            with self.subTest(position=position), self.assertRaises(ValueError):
                MODULE.matrix_input_command(self.PROFILE, position, True)
        for senses in ((), (0x0E, 0x0E), (0x0E, 0x0F), (0x0E, 0x10)):
            profile = {**self.PROFILE, "single_key_column_sense": senses}
            with self.subTest(senses=senses), self.assertRaises(ValueError):
                MODULE.matrix_senses(profile)

    def test_active_low_sideband_packets_fail_closed(self) -> None:
        producer = {
            "register_width": 1,
            "polarity": "active-low",
            "mask": 0x10,
        }
        self.assertEqual(
            MODULE.sideband_input_command(producer, True),
            bytes.fromhex("8001ff10"),
        )
        self.assertEqual(
            MODULE.sideband_input_command(producer, False),
            bytes.fromhex("80000000"),
        )
        for changed in (
                {**producer, "mask": 0x0F},
                {**producer, "mask": 0x30},
                {**producer, "polarity": "active-high"}):
            with self.subTest(producer=changed), self.assertRaises(ValueError):
                MODULE.sideband_input_command(changed, True)

    def test_transport_prefers_evidenced_sideband_over_matrix_cell(self) -> None:
        producer = {
            "register_width": 1,
            "polarity": "active-low",
            "mask": 0x10,
        }
        packets: list[bytes] = []
        transport = object.__new__(MODULE.Transport)
        transport.matrix_input_profile = self.PROFILE
        transport.matrix_input_sideband_producer = producer
        transport.matrix_held = {}
        transport.sideband_held = set()
        transport.input_socket = SimpleNamespace(sendall=packets.append)
        transport.decoder = SimpleNamespace(
            input_error="",
            _direct_sideband_producer=(
                lambda bit, event: (
                    producer if bit == 7 and event in (None, 0x51) else None
                )
            ),
            _direct_matrix_position=(
                lambda bit, event: (
                    None if event == 0x51 else (0x87, 0, 3)
                )
            ),
        )

        self.assertTrue(transport.can_set_key(7))
        self.assertTrue(transport.can_set_key(7, 0x51))
        self.assertFalse(transport.can_set_key(5, 0x51))
        transport.matrix_input_sideband_producer = None
        self.assertFalse(transport.can_set_key(7, 0x51))
        self.assertFalse(transport.set_key(7, True, 0x51))
        transport.matrix_input_sideband_producer = producer
        self.assertTrue(transport.set_key(7, True, 0x51))
        self.assertTrue(transport.set_key(7, False))
        self.assertEqual(
            packets,
            [bytes.fromhex("8001ff10"), bytes.fromhex("80000000")],
        )
        self.assertEqual((transport.sideband_held, transport.matrix_held),
                         (set(), {}))

    def test_input_ack_preempts_lcd_replay_batch(self) -> None:
        stop = MODULE.threading.Event()
        seen: list[int] = []
        input_record = bytes([MODULE.INPUT_TELEMETRY]) + bytes(15)
        lcd_record = bytes([MODULE.LCD_WRITE]) + bytes(15)

        class Stream:
            def __init__(self, record: bytes, finish: bool = False) -> None:
                self.record = record
                self.finish = finish

            def recv(self, size: int) -> bytes:
                self.assert_size = size
                if self.finish:
                    stop.set()
                return self.record

        transport = object.__new__(MODULE.Transport)
        transport.input_socket = Stream(input_record)
        transport.lcd_socket = Stream(lcd_record, True)
        transport.process = SimpleNamespace(poll=lambda: None)
        transport._replay_record = lambda record: seen.append(record[0])

        with mock.patch.object(
                MODULE.select, "select",
                return_value=([transport.lcd_socket,
                               transport.input_socket], [], [])):
            transport.replay(stop)

        self.assertEqual(seen, [MODULE.INPUT_TELEMETRY, MODULE.LCD_WRITE])
        self.assertEqual(transport.input_socket.assert_size, 4096)
        self.assertEqual(transport.lcd_socket.assert_size, 4096)

    def test_input_eof_stops_qemu(self) -> None:
        stop = MODULE.threading.Event()
        input_socket = SimpleNamespace(recv=lambda size: b"")
        transport = object.__new__(MODULE.Transport)
        transport.input_socket = input_socket
        transport.lcd_socket = SimpleNamespace()
        transport.process = SimpleNamespace(poll=lambda: None)
        transport.decoder = SimpleNamespace(input_error="")
        terminated: list[bool] = []
        transport._terminate_process = lambda: terminated.append(True)

        with mock.patch.object(
                MODULE.select, "select",
                return_value=([input_socket], [], [])):
            transport.replay(stop)

        self.assertEqual(transport.decoder.input_error,
                         "QEMU input channel closed")
        self.assertEqual(terminated, [True])

    def test_qemu_input_framing_survives_reset_and_reentry(self) -> None:
        source = (NATIVE / "msm5xxx-poc.c").read_text()
        read_start = source.index("static void msm5xxx_poc_host_input_read")
        read_end = source.index("\nstatic ", read_start + 1)
        read_body = source[read_start:read_end]
        self.assertLess(
            read_body.index("s->matrix_input_buffer_length = 0;"),
            read_body.index("msm5xxx_poc_input_stream_write(s);"),
        )

        reset_start = source.index("static void msm5xxx_poc_reset")
        reset_end = source.index("\nstatic ", reset_start + 1)
        reset_body = source[reset_start:reset_end]
        self.assertNotIn("matrix_input_buffer_length = 0", reset_body)
        self.assertNotIn("matrix_input_ack_length = 0", reset_body)
        self.assertNotIn("g_source_remove(s->matrix_input_ack_watch)",
                         reset_body)
        self.assertIn("G_IO_HUP | G_IO_ERR | G_IO_NVAL", source)
        self.assertIn("CPUClass *cc = CPU_GET_CLASS(s->cpu);", reset_body)
        self.assertIn("s->reset_callbacks++;", reset_body)
        self.assertIn(
            "s->last_reset_callback_pc = cc->get_pc(CPU(s->cpu));",
            reset_body,
        )
        self.assertLess(
            reset_body.index("s->reset_callbacks++;"),
            reset_body.index("cpu_reset(CPU(s->cpu));"),
        )
        self.assertNotIn("s->reset_callbacks = 0", reset_body)
        self.assertNotIn("s->last_reset_callback_pc = 0", reset_body)

        mmio_start = source.index("\nstatic uint64_t msm5xxx_poc_read(")
        mmio_end = source.index("\nstatic ", mmio_start + 1)
        mmio_read = source[mmio_start:mmio_end]
        self.assertIn("case 0xbc:\n        return s->reset_callbacks;",
                      mmio_read)
        self.assertIn(
            "case 0xc0:\n        return s->last_reset_callback_pc;",
            mmio_read,
        )

    def test_qemu_sbi_adc_status_poll_preserves_completed_phase(self) -> None:
        source = (NATIVE / "msm5xxx-poc.c").read_text()
        read_start = source.index("static uint64_t msm5xxx_poc_sbi_read")
        read_end = source.index("\nstatic ", read_start + 1)
        read_body = source[read_start:read_end]
        self.assertIn("s->sbi_board_adc_phase != 5 &&", read_body)
        self.assertIn("s->sbi_board_adc_phase != 7 &&", read_body)
        self.assertIn("s->sbi_board_adc_phase != 9", read_body)

        write_start = source.index("static void msm5xxx_poc_sbi_write")
        write_end = source.index("\nstatic ", write_start + 1)
        write_body = source[write_start:write_end]
        self.assertIn("(value & 0xff80) == 0x0a80", write_body)
        self.assertIn("s->sbi_board_adc_selector = value;", write_body)
        self.assertIn(
            "value == (s->sbi_board_adc_selector & ~0x0080)", write_body,
        )
        self.assertNotIn("value == 0x0ada", write_body)
        self.assertNotIn("value == 0x0a5a", write_body)

    def test_legacy_state_import_reads_copy_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seed = b"\xff" * 0x1000
            state = root / "legacy.json"
            flash = MODULE.NORFlash(seed, state)
            flash.program(0x20, b"\xaa")
            flash.save()
            original = state.read_bytes()

            imported, loaded = MODULE.load_legacy_nor_state(seed, (state,))
            self.assertTrue(loaded)
            self.assertEqual(imported[0x20], 0xAA)
            self.assertEqual(state.read_bytes(), original)

            raw = root / "legacy.bin"
            raw.write_bytes(b"\x55" * 8)
            self.assertEqual(
                MODULE.load_legacy_raw_state(b"\xff" * 8, raw),
                (b"\x55" * 8, True),
            )

            self.assertTrue(MODULE.migrate_erased_raw_state(raw, 8, 16))
            backup = root / "legacy.bin.pre-00000008"
            self.assertEqual(raw.read_bytes(), b"\x55" * 8 + b"\xff" * 8)
            self.assertEqual(backup.read_bytes(), b"\x55" * 8)
            self.assertFalse(MODULE.migrate_erased_raw_state(raw, 8, 16))
            raw.write_bytes(b"\x44" * 8)
            with self.assertRaisesRegex(ValueError, "backup mismatch"):
                MODULE.migrate_erased_raw_state(raw, 8, 16)
            self.assertEqual(backup.read_bytes(), b"\x55" * 8)

            prefixed = root / "legacy-prefix.bin"
            prefixed.write_bytes(b"\x66" * 8)
            self.assertTrue(MODULE.migrate_erased_raw_state(
                prefixed, 8, 16, prepend=True,
            ))
            self.assertEqual(prefixed.read_bytes(), b"\xff" * 8 + b"\x66" * 8)

    def test_ram_argument_preserves_non_mib_byte_counts(self) -> None:
        for size, expected in ((0x800000, "8M"), (0x1000000, "16M"),
                               (0xFFC000, "16760832B"), (0x80000, "524288B"),
                               (0x1001, "4097B")):
            with self.subTest(size=size):
                self.assertEqual(MODULE.qemu_ram_argument(size), expected)
        for size in (0, -1, True, 1.5, None):
            with self.subTest(invalid=size), self.assertRaises(ValueError):
                MODULE.qemu_ram_argument(size)

    def test_raw_loader_splits_at_machine_ram_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "firmware.bin"
            image.write_bytes(bytes(range(10)))

            arguments = MODULE.raw_loader_arguments(image, 4, root)

            self.assertEqual(arguments[::2], ["-device"] * 3)
            self.assertEqual(
                [argument.rsplit("addr=", 1)[1].split(",", 1)[0]
                 for argument in arguments[1::2]],
                ["0x0", "0x4", "0x8"],
            )
            self.assertEqual(
                b"".join((root / f"primary-{offset:08x}.raw").read_bytes()
                         for offset in (0, 4, 8)),
                bytes(range(10)),
            )
            limited = MODULE.raw_loader_arguments(image, 4, root, 6)
            self.assertEqual(
                b"".join((root / f"primary-{offset:08x}.raw").read_bytes()
                         for offset in (0, 4)),
                bytes(range(6)),
            )
            self.assertEqual(len(limited), 4)
            excluded = MODULE.raw_loader_arguments(
                image, 4, root, exclude=(4, 6)
            )
            self.assertEqual(
                [argument.rsplit("addr=", 1)[1].split(",", 1)[0]
                 for argument in excluded[1::2]],
                ["0x0", "0x6"],
            )
            self.assertEqual(
                b"".join((root / f"primary-{offset:08x}.raw").read_bytes()
                         for offset in (0, 6)),
                bytes(range(4)) + bytes(range(6, 10)),
            )

    def test_primary_loader_uses_zero_based_sliced_seed_and_guest_ranges(
            self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "firmware.bin"
            prefix = b"capture-header"
            seed = bytes(range(0x30))
            trailer = b"ram-snapshot-trailer"
            original.write_bytes(prefix + seed + trailer)

            primary_raw = root / "primary.raw"
            primary_raw.write_bytes(seed)
            arguments = MODULE.raw_loader_arguments(
                primary_raw, 0x10, root, size=0x20, exclude=(0x08, 0x10)
            )
            entries = {}
            for argument in arguments[1::2]:
                path_text, address_text = argument.split(",addr=", 1)
                path = Path(path_text.removeprefix("loader,file="))
                address = int(address_text.split(",", 1)[0], 16)
                entries[address] = path.read_bytes()

            self.assertEqual(entries, {
                0x00: seed[0x00:0x08],
                0x10: seed[0x10:0x20],
            })
            self.assertNotEqual(original.read_bytes()[0], seed[0])
            emitted = b"".join(entries.values())
            self.assertNotIn(prefix, emitted)
            self.assertNotIn(trailer, emitted)

    def test_pause_timer_profile_requires_fixed_helper_and_long_caller(
            self) -> None:
        def thumb_bl(source: int, target: int) -> bytes:
            displacement = (target - source - 4) & 0x7FFFFF
            return MODULE.struct.pack(
                "<2H",
                0xF000 | displacement >> 12 & 0x7FF,
                0xF800 | displacement >> 1 & 0x7FF,
            )

        helper = snippet("test_qemu_input_transport", "pause_timer_profile_code")
        image = bytearray(b"\xff" * 0x800)
        caller, pool, start = 0x100, 0x180, 0x300
        ldr = 0x4800 | (pool - ((caller + 4) & ~3)) // 4
        MODULE.struct.pack_into("<H", image, caller, ldr)
        image[caller + 2:caller + 6] = thumb_bl(caller + 2, start)
        MODULE.struct.pack_into("<I", image, pool, 100_000)
        image[start:start + len(helper)] = helper
        config = SimpleNamespace(load_address=0, flash_size=len(image))

        expected = "4800020:4c4b4:300:3aa"
        self.assertEqual(
            MODULE.qemu_pause_timer_profile(bytes(image), config),
            (expected, None),
        )
        self.assertEqual(MODULE.qemu_pause_timer_profile(
            bytes(image), config, start + len(helper) - 1
        ), (None, "fixed-helper-outside-immutable-nor"))

        MODULE.struct.pack_into("<I", image, pool, 20_000)
        self.assertEqual(
            MODULE.qemu_pause_timer_profile(bytes(image), config),
            (None, "100ms-caller-not-found"),
        )
        MODULE.struct.pack_into("<I", image, pool, 100_000)
        image[start + 0x30] ^= 1
        self.assertEqual(
            MODULE.qemu_pause_timer_profile(bytes(image), config),
            (None, "fixed-helper-shape-mismatch"),
        )
        image[start + 0x30] ^= 1
        image[0x500:0x500 + len(helper)] = helper
        self.assertEqual(
            MODULE.qemu_pause_timer_profile(bytes(image), config),
            (None, "fixed-helper-ambiguous"),
        )

    def test_legacy_dmd_loader_patch_preserves_call_contract(self) -> None:
        load = 0x1000
        entry = load + 0x100
        completion = 0x01001020
        control = 0x03000050
        dmd = 0x030007E0
        filename = load + 0x600
        image = bytearray(b"\xff" * 0x1000)
        signature = MODULE.DMD_DOWNLOAD_SIGNATURE
        image[0x100:0x100 + len(signature)] = signature
        image[0x100 + 0xD4:0x100 + 0xD6] = b"\x06\x49"
        MODULE.struct.pack_into(
            "<4I", image, 0x100 + 0xE0,
            completion, control, 0, dmd,
        )
        MODULE.struct.pack_into("<I", image, 0x100 + 0xF0, filename)
        image[0x600:0x60C] = b"dmddown_510"
        config = SimpleNamespace(
            dmd_download_address=entry, load_address=load,
            flash_size=len(image), ram_base=0x01000000, ram_size=0x2000,
        )

        result = MODULE.legacy_dmd_loader_patch(bytes(image), config)
        self.assertIsNotNone(result)
        offset, patch = result
        self.assertEqual((offset, len(patch)), (0x100, 52))

        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        uc.mem_map(load, 0x1000)
        uc.mem_map(0x01000000, 0x2000)
        uc.mem_map(0x03000000, 0x1000)
        uc.mem_write(entry, patch)
        uc.mem_write(completion, b"\xaa\xbb\xcc\xdd")
        uc.mem_write(control + 0x0C, b"\xaa\xbb")
        uc.mem_write(dmd + 8, b"\xaa" * 8)
        from unicorn import arm_const as registers
        uc.reg_write(registers.UC_ARM_REG_CPSR, 0xA0000033)
        uc.reg_write(registers.UC_ARM_REG_SP, 0x01001FF0)
        uc.reg_write(registers.UC_ARM_REG_LR, 0x1201)
        uc.reg_write(registers.UC_ARM_REG_R1, 0x11111111)
        uc.reg_write(registers.UC_ARM_REG_R2, 0x22222222)
        flags = uc.reg_read(registers.UC_ARM_REG_CPSR) & 0xF0000000

        uc.emu_start(entry | 1, 0, count=14)

        self.assertEqual(uc.reg_read(registers.UC_ARM_REG_PC), 0x1200)
        self.assertEqual(uc.reg_read(registers.UC_ARM_REG_R0), 1)
        self.assertEqual(uc.reg_read(registers.UC_ARM_REG_R1), 0x11111111)
        self.assertEqual(uc.reg_read(registers.UC_ARM_REG_R2), 0x22222222)
        self.assertEqual(uc.reg_read(registers.UC_ARM_REG_SP), 0x01001FF0)
        self.assertEqual(
            uc.reg_read(registers.UC_ARM_REG_CPSR) & 0xF0000000, flags
        )
        self.assertEqual(bytes(uc.mem_read(completion, 4)),
                         b"\x02\xbb\xcc\xdd")
        self.assertEqual(bytes(uc.mem_read(control + 0x0C, 2)),
                         b"\x01\xbb")
        self.assertEqual(bytes(uc.mem_read(dmd + 8, 8)),
                         b"\0" * 6 + b"\xaa" * 2)

        image[0x600] = 0
        self.assertIsNone(
            MODULE.legacy_dmd_loader_patch(bytes(image), config)
        )
        image[0x600] = ord("d")
        self.assertIsNone(MODULE.legacy_dmd_loader_patch(
            bytes(image), config, 0x100 + len(patch) - 1
        ))

    def test_ma2_loader_patch_preserves_silent_boot_call_contract(self) -> None:
        load = 0x1000
        offset = 0x100
        entry = load + offset
        image = bytes(b"\xff" * 0x1000)
        config = SimpleNamespace(
            ma2_silent_boot_address=entry, load_address=load,
            flash_size=len(image),
        )
        with mock.patch.dict(
                MODULE.ma2_silent_boot_loader_patch.__globals__,
                {"find_ma2_silent_boot_wait": lambda _: offset}):
            result = MODULE.ma2_silent_boot_loader_patch(image, config)
            self.assertIsNotNone(result)
            patch_offset, patch = result
            self.assertEqual((patch_offset, len(patch)), (offset, 8))

            uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
            uc.mem_map(load, 0x1000)
            uc.mem_write(entry, patch)
            from unicorn import arm_const as registers
            uc.reg_write(registers.UC_ARM_REG_CPSR, 0xA0000033)
            uc.reg_write(registers.UC_ARM_REG_SP, 0x1FF0)
            uc.reg_write(registers.UC_ARM_REG_LR, 0x1201)
            uc.reg_write(registers.UC_ARM_REG_R0, 0xFFFFFFFF)
            uc.reg_write(registers.UC_ARM_REG_R1, 0x11111111)
            uc.reg_write(registers.UC_ARM_REG_R7, 0x77777777)
            flags = uc.reg_read(registers.UC_ARM_REG_CPSR) & 0xF0000000

            uc.emu_start(entry | 1, 0, count=2)

            self.assertEqual(uc.reg_read(registers.UC_ARM_REG_PC), 0x1200)
            self.assertEqual(uc.reg_read(registers.UC_ARM_REG_R0), 0)
            self.assertEqual(uc.reg_read(registers.UC_ARM_REG_R1), 0x11111111)
            self.assertEqual(uc.reg_read(registers.UC_ARM_REG_R7), 0x77777777)
            self.assertEqual(uc.reg_read(registers.UC_ARM_REG_SP), 0x1FF0)
            self.assertEqual(uc.reg_read(registers.UC_ARM_REG_LR), 0x1201)
            self.assertEqual(
                uc.reg_read(registers.UC_ARM_REG_CPSR) & 0xF0000000, flags
            )

            self.assertIsNone(MODULE.ma2_silent_boot_loader_patch(
                image, config, offset + len(patch) - 1
            ))
            config.ma2_silent_boot_address += 2
            self.assertIsNone(
                MODULE.ma2_silent_boot_loader_patch(image, config)
            )

    def test_c80_route_requires_explicit_closed_candidate(self) -> None:
        status = 0x03000C80
        candidate = {
            "signature": "static-c80-controller-callback-v1",
            "controller_class":
                "legacy-c80-index1e-delta5-controller-candidate-v1",
            "accepted": True,
            "active": False,
            "vector": 0x18,
            "vector_target": 0x01000000,
            "status": status,
            "status_banks": (status, status + 4),
            "enable": status + 0x14,
            "mask": 0x0200,
            "clear_banks": (status, status + 4),
            "controller_write_banks": (status + 0x14, status + 0x18),
            "controller_aperture": (status, status + 0x1A),
            "wrapper_file_offset": 0x1000,
            "wrapper_validation_size": 0x284,
            "handler_slot": 0x01001000,
            "handler_file_offset": 0x2000,
            "handler_validation_size": 0x100,
            "callback_slot": 0x01002000,
            "callback_file_offset": 0x3000,
            "callback_delta": 5,
            "callback_validation_size": 68,
        }
        config = SimpleNamespace(
            rex_static_controller_candidate=candidate,
            load_address=0, flash_size=0x10000,
            ram_base=0x01000000, ram_size=0x10000,
            rex_tick_address=None, rex_irq_wrapper_address=None,
            rex_irq_handler_address=None, rex_irq_handler_slot=None,
            rex_irq_callback_slot=None, rex_irq_status_address=None,
            rex_irq_enable_address=None, rex_irq_arm_address=None,
            rex_irq_mask=0,
        )

        self.assertIsNone(MODULE.c80_rex_irq_profile(config, False))
        self.assertEqual(
            MODULE.c80_rex_irq_profile(config, True),
            "3000c80:3000c94:200:4c4b40:1000000:1000:1001000:"
            "2000:100:1002000:3000",
        )
        candidate.update({
            "promotion": "temporary-evidence-gated",
            "status_bank_count": 2,
            "group_row_size": 10,
            "pending_read_semantics": "latched-read",
            "pending_ack_semantics": "write-one-to-clear",
            "time_tick_status_bank": status,
            "time_tick_clear_bank": status,
            "time_tick_mask": 0x0200,
        })
        self.assertEqual(
            MODULE.c80_rex_irq_profile(config, False),
            MODULE.c80_rex_irq_profile(config, True),
        )
        candidate["group_row_size"] = 12
        self.assertEqual(
            MODULE.c80_rex_irq_profile(config, False),
            MODULE.c80_rex_irq_profile(config, True),
        )
        candidate["group_row_size"] = 11
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, False))
        candidate["group_row_size"] = 10
        candidate["time_tick_mask"] = 0x0100
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, False))
        candidate["time_tick_mask"] = 0x0200
        candidate["wrapper_validation_size"] = config.flash_size
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, True))
        candidate["wrapper_validation_size"] = 0x284
        candidate["callback_slot"] += 2
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, True))
        candidate["callback_slot"] = 0x01802000
        candidate["handler_slot"] = 0x01801000
        candidate["vector_target"] = 0x01800000
        config.ram_base = 0x01000000
        config.ram_size = 0x01000000
        self.assertEqual(
            MODULE.c80_rex_irq_profile(config, True),
            "3000c80:3000c94:200:4c4b40:1800000:1000:1801000:"
            "2000:100:1802000:3000",
        )
        candidate["vector_target"] = 0x02000000
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, True))

        # The arm-gated FB0 variant is explicit-only, even with closed topology.
        status = 0x03000FB0
        candidate.update({
            "signature": "static-fb0-controller-callback-v1",
            "controller_class": "legacy-fb0-index1b-delta5-controller-candidate-v1",
            "promotion": "experimental-only",
            "vector_target": 0x01800000,
            "status": status, "enable": status + 0x14,
            "status_banks": (status, status + 4),
            "clear_banks": (status, status + 4),
            "controller_write_banks": (status + 0x14, status + 0x18),
            "controller_aperture": (status, status + 0x1A),
            "time_tick_status_bank": status, "time_tick_clear_bank": status,
            "time_tick_control_address": 0x030006E0,
            "handler_validation_size": 0x182,
        })
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, False))
        self.assertEqual(
            MODULE.c80_rex_irq_profile(config, True),
            "3000fb0:3000fc4:200:4c4b40:1800000:1000:1801000:"
            "2000:182:1802000:3000",
        )
        for key, bad in (("time_tick_control_address", 0x030007A0),
                         ("handler_validation_size", 0x100),
                         ("status_bank_count", 3),
                         ("pending_read_semantics", "read-consume"),
                         ("promotion", "temporary-evidence-gated")):
            with self.subTest(fb0_reject=key):
                original = candidate[key]
                candidate[key] = bad
                self.assertIsNone(MODULE.c80_rex_irq_profile(config, True))
                candidate[key] = original

    def test_c80_overlay_route_emits_runtime_addresses(self) -> None:
        status = 0x03000C80
        candidate = {
            "signature": "static-c80-overlay-controller-callback-v1",
            "controller_class": "legacy-c80-three-bank-group14-v1",
            "accepted": True, "active": False,
            "promotion": "temporary-evidence-gated",
            "vector": 0x18, "vector_target": 0x01200000,
            "status": status,
            "status_banks": (status, status + 4, status + 0x30),
            "enable": status + 0x14, "mask": 0x0200,
            "clear_banks": (status, status + 4, status + 0x4C),
            "controller_write_banks": (
                status + 0x14, status + 0x18, status + 0x44,
            ),
            "controller_aperture": (status, status + 0x4E),
            "status_bank_count": 3, "group_row_size": 14,
            "pending_read_semantics": "latched-read",
            "time_tick_status_bank": status,
            "time_tick_clear_bank": status,
            "time_tick_mask": 0x0200,
            "wrapper_file_offset": 0x4FC0,
            "wrapper_runtime_address": 0x4FC0,
            "wrapper_validation_size": 0x2F8,
            "handler_slot": 0x013466A8,
            "handler_file_offset": 0x7B48E8,
            "handler_runtime_address": 0x03800068,
            "handler_validation_size": 0x1EE,
            "callback_slot": 0x01206B80,
            "callback_file_offset": 0x23440,
            "callback_runtime_address": 0x23440,
            "callback_delta": 5,
            "callback_validation_size": 68,
        }
        config = SimpleNamespace(
            rex_static_controller_candidate=candidate,
            load_address=0, flash_size=0x800000,
            ram_base=0x01000000, ram_size=0x800000,
            linker=SimpleNamespace(
                data_source=0x78F51C, data_target=0x01200000,
                data_size=0x25364,
            ),
            overlays=[SimpleNamespace(
                source=0x7B4880, target=0x03800000, size=0x15A74,
            )],
            rex_tick_address=0xA7E04, rex_irq_wrapper_address=None,
            rex_irq_handler_address=None, rex_irq_handler_slot=None,
            rex_irq_callback_slot=None, rex_irq_status_address=None,
            rex_irq_enable_address=None, rex_irq_arm_address=None,
            rex_irq_mask=0,
        )

        self.assertIsNone(MODULE.c80_rex_irq_profile(config, False))
        self.assertEqual(
            MODULE.c80_rex_irq_profile(config, True),
            "3000c80:3000c94:200:4c4b40:1200000:4fc0:13466a8:"
            "3800068:1ee:1206b80:23440:3",
        )
        config.overlays[0].target += 0x1000
        self.assertIsNone(MODULE.c80_rex_irq_profile(config, True))

    def test_c80_machine_parser_consumes_optional_bank_count(self) -> None:
        source = (NATIVE / "msm5xxx-poc.c").read_text()
        start = source.index("static void msm5xxx_poc_set_rex_static_c80")
        end = source.index("\nstatic ", start + 1)
        setter = source[start:end]

        self.assertIn("%x:%x%n", setter)
        self.assertIn("consumed >= 0 && !value[consumed]", setter)
        self.assertNotIn("%x%c", setter)

    def test_read_consume_route_requires_copied_vector_relation(self) -> None:
        status = 0x03000620
        candidate = {
            "signature": "static-msm5000-620-controller-callback-v1",
            "controller_class":
                "legacy-msm5000-620-two-bank-read-consume-group10-v1",
            "accepted": True,
            "active": False,
            "promotion": "temporary-evidence-gated",
            "vector": 0x18,
            "vector_target": 0x01100000,
            "vector_copy_source": 0x0039519C,
            "vector_copy_size": 0xE5B0,
            "descriptor_file_offset": 0x003987C4,
            "descriptor_runtime_address": 0x01103628,
            "mask_table": 0x01103310,
            "status": status,
            "status_banks": (status, status + 4),
            "enable": status + 8,
            "mask": 0x0200,
            "mask_set_banks": (status, status + 4),
            "mask_output_banks": (status + 8, status + 0xC),
            "controller_aperture": (status, status + 0x10),
            "group_row_size": 10,
            "pending_read_semantics": "consume-on-read",
            "time_tick_control_address": 0x030006E0,
            "wrapper_file_offset": 0x0024BE14,
            "wrapper_validation_size": 0x234,
            "handler_slot": 0x0118867C,
            "handler_file_offset": 0x00098E04,
            "handler_validation_size": 0x178,
            "callback_slot": 0x0110363C,
            "callback_file_offset": 0x00016B64,
            "callback_delta": 5,
            "callback_validation_size": 68,
        }
        config = SimpleNamespace(
            rex_static_controller_candidate=candidate,
            load_address=0, flash_size=0x400000,
            ram_base=0x01000000, ram_size=0x200000,
            rex_tick_address=None, rex_irq_wrapper_address=None,
            rex_irq_handler_address=None, rex_irq_handler_slot=None,
            rex_irq_callback_slot=None, rex_irq_status_address=None,
            rex_irq_enable_address=None, rex_irq_arm_address=None,
            rex_irq_mask=0,
        )

        self.assertEqual(
            MODULE.read_consume_rex_irq_profile(config, False),
            "3000620:3000628:30006e0:200:4c4b40:1100000:24be14:"
            "118867c:98e04:178:110363c:16b64",
        )
        candidate["promotion"] = "experimental-only"
        self.assertIsNone(MODULE.read_consume_rex_irq_profile(config, False))
        self.assertEqual(
            MODULE.read_consume_rex_irq_profile(config, True),
            "3000620:3000628:30006e0:200:4c4b40:1100000:24be14:"
            "118867c:98e04:178:110363c:16b64",
        )
        candidate["promotion"] = "temporary-evidence-gated"
        candidate.update({
            "controller_class":
                "legacy-msm5000-620-two-bank-read-consume-v1",
            "group_row_size": 12,
        })
        self.assertEqual(
            MODULE.read_consume_rex_irq_profile(config, False),
            "3000620:3000628:30006e0:200:4c4b40:1100000:24be14:"
            "118867c:98e04:178:110363c:16b64",
        )
        candidate.update({
            "controller_class":
                "legacy-msm5000-620-two-bank-read-consume-group10-v1",
            "group_row_size": 10,
            "promotion": "experimental-only",
        })
        candidate["descriptor_runtime_address"] += 4
        self.assertIsNone(
            MODULE.read_consume_rex_irq_profile(config, True)
        )
        candidate["descriptor_runtime_address"] -= 4
        original_copy_size = candidate["vector_copy_size"]
        candidate["vector_copy_size"] = (
            candidate["descriptor_file_offset"]
            - candidate["vector_copy_source"] + 4
        )
        self.assertIsNone(
            MODULE.read_consume_rex_irq_profile(config, True)
        )
        candidate["vector_copy_size"] = original_copy_size
        candidate["promotion"] = "production"
        self.assertIsNone(
            MODULE.read_consume_rex_irq_profile(config, True)
        )
        candidate.update({
            "controller_class":
                "legacy-msm5000-620-two-bank-w1c-8call-v1",
            "promotion": "temporary-evidence-gated",
            "group_row_size": 12,
            "pending_read_semantics": "latched-read",
            "pending_ack_semantics": "write-one-to-clear",
            "clear_banks": (status, status + 4),
        })
        self.assertEqual(
            MODULE.w1c_rex_irq_profile(config),
            "3000620:3000628:30006e0:200:4c4b40",
        )
        candidate.update({
            "controller_class": "legacy-msm5000-620-two-bank-w1c-group10-v1",
            "group_row_size": 10,
            "handler_validation_size": 0x15A,
        })
        self.assertEqual(MODULE.w1c_rex_irq_profile(config),
                         "3000620:3000628:30006e0:200:4c4b40")
        candidate["group_row_size"] = 12
        self.assertIsNone(MODULE.w1c_rex_irq_profile(config))
        candidate["group_row_size"] = 10
        del candidate["pending_ack_semantics"]
        self.assertIsNone(MODULE.w1c_rex_irq_profile(config))


class RAMBootstrapTransportTests(unittest.TestCase):
    def test_reserved_ram_requires_same_image_layout_and_safe_stack(self):
        from copy import deepcopy
        from msm5xxx_emulator.core.config import LinkerLayout
        from test_bootstrap_sdram import synthetic_image

        image = synthetic_image()
        profile = MODULE.reset_copy_ram_profile(image)
        config = SimpleNamespace(
            load_address=0, flash_size=len(image), ram_base=profile['ram_base'],
            ram_size=profile['ram_size'], ram_bootstrap_profile=profile,
            linker=LinkerLayout(**profile['bootstrap_linker']),
        )
        self.assertEqual(MODULE.qemu_ram_reserved_property(image, config, 0x17ffffc),
                         'ram-reserved=1c00000:200000')
        for sp in (0x1bffffc, 0x1e00004, 0x1ffbffc):
            self.assertEqual(MODULE.qemu_ram_reserved_property(image, config, sp),
                             'ram-reserved=1c00000:200000')
        for sp in (True, 0x1000000, 0x1c00000, 0x1dffffc, 0x1e00000,
                   0x17ffffd, 0x2000000):
            with self.subTest(sp=sp), self.assertRaises(ValueError):
                MODULE.qemu_ram_reserved_property(image, config, sp)
        for key, value in (('reserved_base', 0x1a00000), ('reserved_size', 0x1000),
                           ('experimental', False), ('experimental', 1),
                           ('ram_size', float(profile['ram_size']))):
            changed = SimpleNamespace(**vars(config))
            changed.ram_bootstrap_profile = {**profile, key: value}
            with self.subTest(profile_key=key, value=value), self.assertRaises(ValueError):
                MODULE.qemu_ram_reserved_property(image, changed, 0x17ffffc)
        for key, value in (('ram_base', 0x1800000), ('ram_size', 0x800000),
                           ('flash_size', 4), ('load_address', False)):
            changed = SimpleNamespace(**{**vars(config), key: value})
            with self.subTest(config_key=key), self.assertRaises(ValueError):
                MODULE.qemu_ram_reserved_property(image, changed, 0x17ffffc)
        changed = SimpleNamespace(**vars(config))
        changed.linker = LinkerLayout(**{**profile['bootstrap_linker'], 'data_source': 0})
        with self.assertRaises(ValueError):
            MODULE.qemu_ram_reserved_property(image, changed, 0x17ffffc)
        with self.assertRaises(ValueError):
            MODULE.qemu_ram_reserved_property(b'\0' * 4 + image[4:], config, 0x17ffffc)
        self.assertIsNone(MODULE.qemu_ram_reserved_property(
            b'', SimpleNamespace(ram_bootstrap_profile=None), 0))

    def test_detection_preserves_overrides_and_loaded_nor_is_revalidated(self):
        import argparse
        from msm5xxx_emulator.qemu import transport as qemu_transport
        from msm5xxx_emulator.detection import detect
        from test_bootstrap_sdram import synthetic_image

        with tempfile.TemporaryDirectory() as directory:
            firmware = Path(directory) / 'anonymous.bin'
            image = bytearray(synthetic_image())
            reset = 8 + (struct.unpack_from('<I', image)[0] & 0xffffff) * 4
            for pc in range(4, 0x20, 4):
                struct.pack_into('<I', image, pc,
                                 0xea000000 | (((reset - pc - 8) // 4) & 0xffffff))
            image = bytes(image)
            firmware.write_bytes(image)
            config = detect(firmware)
            self.assertEqual((config.ram_base, config.ram_size), (0x1000000, 0xffc000))
            self.assertIsNotNone(config.ram_bootstrap_profile)
            self.assertIsNone(config.ready_poll)
            for overrides in (argparse.Namespace(ram_size=0x800000),
                              argparse.Namespace(ram_base=0x1800000),
                              argparse.Namespace(load_address=0x10000000)):
                changed = detect(firmware, overrides)
                self.assertIsNone(changed.ram_bootstrap_profile)
            firmware.write_bytes(b'\0' * 4 + image[4:])
            self.assertIsNone(detect(firmware).ram_bootstrap_profile)
            firmware.write_bytes(image)

            def changed_seed(seed, *_args):
                return b'\0' * 4 + seed[4:], True

            listeners = []
            make_listener = qemu_transport.loopback_listener
            def listener():
                channel = make_listener()
                listeners.append(channel)
                return channel

            with mock.patch.object(qemu_transport, 'load_legacy_nor_state', changed_seed), \
                 mock.patch.object(qemu_transport, 'loopback_listener', listener), \
                 mock.patch.object(qemu_transport.subprocess, 'Popen',
                                   side_effect=AssertionError('unexpected QEMU launch')) as launch:
                with self.assertRaisesRegex(ValueError, 'reset-linked RAM profile'):
                    MODULE.Transport(Path('/unused'), firmware, Path(directory) / 'state',
                                     config=config)
                launch.assert_not_called()
            self.assertGreaterEqual(len(listeners), 3)
            self.assertTrue(all(channel.fileno() == -1 for channel in listeners))


class FoldInputTransportTests(unittest.TestCase):
    def test_capability_readback_and_key_independence(self) -> None:
        transport = MODULE.Transport.__new__(MODULE.Transport)
        transport.config = SimpleNamespace(board_status_input=SimpleNamespace(
            address=0x03000688, mask=4, default=4))
        transport.board_status_snapshot = None
        transport.decoder = SimpleNamespace(input_error="")
        transport.input_socket = mock.Mock()
        transport.matrix_held = {1: (0, 0)}
        self.assertFalse(transport.set_fold(False))  # Old native: no capability.
        packet = bytes((10, 4, 4, 0)) + struct.pack("<III", 0x03000688, 0, 0)
        transport._replay_record(packet)
        self.assertTrue(transport.can_set_fold())
        self.assertTrue(transport.set_fold(False))
        transport.input_socket.sendall.assert_called_once_with(bytes((0x81, 0, 0, 0)))
        self.assertEqual(transport.matrix_held, {1: (0, 0)})
        self.assertEqual(transport.board_status_snapshot["level"], 4)
        transport._replay_record(bytes((10, 0, 4, 0)) + packet[4:])
        self.assertEqual(transport.board_status_snapshot["level"], 0)
        transport._replay_record(bytes((10, 8, 4, 0)) + packet[4:])
        self.assertEqual(transport.board_status_snapshot["level"], 0)
        self.assertFalse(transport.set_fold(1))


if __name__ == "__main__":
    unittest.main()
