"""QEMU MA2 sideband-to-PCM check."""
from __future__ import annotations

from pathlib import Path
import ast
from collections import deque
import importlib.util
import json
import socket
import struct
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from msm5xxx_emulator.devices.audio import AudioMixin
from msm5xxx_emulator.devices.audio_lle import AudioTransport


NATIVE = Path(__file__).parents[1] / "native/qemu"
TRANSPORT_SOURCE = Path(__file__).parents[1] / "src/msm5xxx_emulator/qemu/transport.py"
from msm5xxx_emulator.qemu.transport import (  # noqa: E402
    AUDIO_PACKET_BYTES, AUDIO_SOCKET_SEND_BUFFER,
    AUDIO_PCM_TELEMETRY, AUDIO_REJECT_TELEMETRY, AUDIO_STATUS,
    AUDIO_STATUS_NATIVE, AUDIO_STATUS_OVERFLOW, AUDIO_STATUS_REJECTED,
    AUDIO_STATUS_RESET, AUDIO_TIMING_TELEMETRY,
    AUDIO_WRITE, LCD_WRITE, TELEMETRY, Transport,
    bounded_audio_socket_pair, qemu_audio_sites, qemu_audio_irq_property,
    qemu_audio_packet_property, qemu_ma5_readback_property, qemu_ma5_gpio_irq_property,
    qemu_ma5_temporary_auto_property,
)

ANDROID_RUNTIME = (
    Path(__file__).parents[1]
    / "android/app/src/main/python/msm5xxx_android_runtime.py"
)


class QEMUAudioTransportTests(unittest.TestCase):
    def test_ma5_gpio_irq_serializes_exact_eighteen_field_abi(self):
        from test_ma5_gpio_irq import _fixture
        for witness in (0, 1):
            with self.subTest(witness=witness):
                image, fixture = _fixture(witness)
                config = SimpleNamespace(load_address=0, flash_size=len(image),
                                         ram_base=0x1000000, ram_size=0x1000000,
                                         rex_irq_status_address=0x03000C80,
                                         rex_irq_enable_address=0x03000C94)
                prop, reason = qemu_ma5_gpio_irq_property(image, config)
                self.assertIsNone(reason)
                entries = fixture['entries']
                expected = ([0x1819D18, 0x18CEEEC, 5, 0x1819CB0, 0x03000C84,
                             0x03000C98, 0x2000, 0x181997A, 0x1819980,
                             entries['gpio_dispatch'] | 1, entries['soc_dispatch'] | 1,
                             0x18BD314, entries['chip_isr'] | 1, entries['deferred'] | 1,
                             0x1816558, 0x1816575, 0x181C8E0, 0x18212D0]
                            if witness == 0 else
                            [0x1009114, 0x12DF36C, 2, 0x10090B0, 0x03000C84,
                             0x03000C98, 0x2000, 0x1008D7A, 0x1008D80,
                             entries['gpio_dispatch'] | 1, entries['soc_dispatch'] | 1,
                             0x12CEBB0, entries['chip_isr'] | 1, 0,
                             0x14E1C90, 0, 0, 0x1010C88])
                self.assertEqual(prop, 'experimental-ma5-irq-route=' +
                                 ':'.join(f'{value:x}' for value in expected))
                changed = bytearray(image)
                changed[fixture['entries']['gpio_dispatch'] + 8] ^= 1
                self.assertIsNone(qemu_ma5_gpio_irq_property(bytes(changed), config)[0])
                config.rex_irq_enable_address = 0x03000628
                self.assertEqual(qemu_ma5_gpio_irq_property(image, config)[1],
                                 'ma5-irq-controller-unverified')

    def test_ma5_gpio_irq_direct_registration_without_synthetic_flag(self):
        from copy import deepcopy
        from test_ma5_gpio_irq import _fixture
        from msm5xxx_emulator.detection.ma5_gpio_irq import find_ma5_gpio_irq_candidate
        image, _ = _fixture(1)
        from msm5xxx_emulator.detection.audio import find_ma5_readback_candidate
        route = find_ma5_gpio_irq_candidate(image, find_ma5_readback_candidate(image))
        config = SimpleNamespace(load_address=0, flash_size=len(image),
                                 ram_base=0x1000000, ram_size=0x1000000,
                                 rex_irq_status_address=0x03000C80,
                                 rex_irq_enable_address=0x03000C94)
        route['installation'].update(profile='direct-install-no-flag-v1',
                                     installed_flag=None, installed_value=None)
        with patch('msm5xxx_emulator.qemu.transport.find_ma5_gpio_irq_candidate', return_value=route):
            prop, reason = qemu_ma5_gpio_irq_property(image, config)
        self.assertIsNone(reason)
        fields = [int(value, 16) for value in prop.split('=')[1].split(':')]
        self.assertEqual(fields[13:17], [0, 0, 0, 0])
        for key, value in [('installed_flag', 0), ('installed_flag', 0x1000000),
                           ('installed_value', 1), ('deferred_callback', 0x3001),
                           ('direct_gate', {}), ('deferred_gate', {}),
                           ('trigger_argument', 1), ('polarity_argument', 1),
                           ('profile', 'explicit-sense-direct-install-v1')]:
            bad = deepcopy(route)
            bad['installation'][key] = value
            with self.subTest(key=key, value=value), patch(
                    'msm5xxx_emulator.qemu.transport.find_ma5_gpio_irq_candidate', return_value=bad):
                self.assertEqual(qemu_ma5_gpio_irq_property(image, config)[1],
                                 'ma5-irq-installation-unverified')

    def test_ma5_gpio_irq_static_controller_is_fresh_and_same_route(self):
        from copy import deepcopy
        from test_ma5_gpio_irq import _fixture
        from msm5xxx_emulator.detection.ma5_gpio_irq import find_ma5_gpio_irq_candidate
        from msm5xxx_emulator.detection.audio import find_ma5_readback_candidate
        image, _ = _fixture(1)
        route = find_ma5_gpio_irq_candidate(image, find_ma5_readback_candidate(image))
        controller = dict(signature='static-c80-controller-callback-v1',
                          status=0x03000C80, enable=0x03000C94,
                          handler_slot=route['parent']['exception_callback_slot'],
                          handler_file_offset=route['parent']['dispatcher'])
        config = SimpleNamespace(load_address=0, flash_size=len(image),
                                 ram_base=0x1000000, ram_size=0x1000000,
                                 rex_static_controller_candidate=controller)
        def check(fresh, profile='verified'):
            with patch('msm5xxx_emulator.qemu.transport.find_rex_static_controller_callback_candidate',
                       return_value=fresh) as finder, patch(
                       'msm5xxx_emulator.qemu.transport.c80_rex_irq_profile', return_value=profile):
                result = qemu_ma5_gpio_irq_property(image, config)
                finder.assert_called_once_with(image, ram_base=config.ram_base,
                                               ram_size=config.ram_size)
                return result
        self.assertIsNotNone(check(controller)[0])
        self.assertIsNone(check(None)[0])
        self.assertIsNone(check(controller, None)[0])
        for key, value in [('signature', 'static-fb0-controller-callback-v1'),
                           ('status', 0x03000620), ('enable', 0x03000628),
                           ('handler_slot', controller['handler_slot']+4),
                           ('handler_file_offset', controller['handler_file_offset']+2)]:
            changed = deepcopy(controller)
            changed[key] = value
            config.rex_static_controller_candidate = changed
            with self.subTest(key=key):
                self.assertIsNone(check(controller)[0])
                self.assertIsNone(check(changed)[0])
            config.rex_static_controller_candidate = controller

    def test_ma5_gpio_irq_bounds_and_fresh_image_are_required(self):
        from copy import deepcopy
        from test_ma5_gpio_irq import _fixture
        from msm5xxx_emulator.detection.audio import find_ma5_readback_candidate
        from msm5xxx_emulator.detection.ma5_gpio_irq import find_ma5_gpio_irq_candidate
        image, _ = _fixture(0)
        config = SimpleNamespace(load_address=0, flash_size=len(image),
                                 ram_base=0x1000000, ram_size=0x1000000,
                                 rex_irq_status_address=0x03000C80,
                                 rex_irq_enable_address=0x03000C94)
        audio = find_ma5_readback_candidate(image)
        route = find_ma5_gpio_irq_candidate(image, audio)
        with patch('msm5xxx_emulator.qemu.transport.find_ma5_gpio_irq_candidate', wraps=find_ma5_gpio_irq_candidate) as finder:
            first, reason = qemu_ma5_gpio_irq_property(image, config)
            self.assertIsNone(reason)
            finder.assert_called_once_with(image, audio)
        other, _ = _fixture(1)
        second, reason = qemu_ma5_gpio_irq_property(other, config)
        self.assertIsNone(reason)
        self.assertNotEqual(first, second)
        config.flash_size = 0x1000
        self.assertEqual(qemu_ma5_gpio_irq_property(image, config)[1], 'primary-nor-out-of-bounds')
        config.flash_size = len(image)
        config.ram_size = 0x800000
        self.assertEqual(qemu_ma5_gpio_irq_property(image, config)[1], 'consumer-state-unmapped')
        config.ram_size = 0x1000000
        config.load_address = 4
        self.assertEqual(qemu_ma5_gpio_irq_property(image, config)[1], 'primary-nor-unmapped')
        config.load_address = 0
        for field, value, reason in (
            ('nor_dependencies', [[len(image) - 1, 2]], 'primary-nor-out-of-bounds'),
            ('ram_dependencies', [[0x2000000, 1]], 'consumer-state-unmapped'),
            ('aux_addresses', [{'address': 0x2000000, 'width': None}], 'auxiliary-state-unmapped'),
            ('source_profile', 'unknown', 'ma5-irq-class-unavailable'),
            ('runtime_admitted', True, 'ma5-irq-class-unavailable'),
        ):
            bad = deepcopy(route)
            bad[field] = value
            with self.subTest(field=field), patch('msm5xxx_emulator.qemu.transport.find_ma5_gpio_irq_candidate', return_value=bad):
                self.assertEqual(qemu_ma5_gpio_irq_property(image, config)[1], reason)
        bad = deepcopy(route)
        bad['installation']['direct_gate']['any'][0]['address'] += 1
        with patch('msm5xxx_emulator.qemu.transport.find_ma5_gpio_irq_candidate', return_value=bad):
            self.assertEqual(qemu_ma5_gpio_irq_property(image, config)[1],
                             'ma5-irq-installation-unverified')
        # Unknown auxiliary object extent stays unknown; require only its address byte.
        minimal = deepcopy(route)
        minimal['aux_addresses'] = [{'address': 0x1FFFFFF, 'width': None}]
        with patch('msm5xxx_emulator.qemu.transport.find_ma5_gpio_irq_candidate', return_value=minimal):
            self.assertIsNotNone(qemu_ma5_gpio_irq_property(image, config)[0])

    def test_ma5_gpio_irq_opt_in_and_coupling_validate_before_io(self):
        import inspect
        self.assertIs(inspect.signature(Transport).parameters['experimental_ma5_irq'].default, False)
        cases = [{'experimental_ma5_irq': value} for value in (None, 0, 1, 'false')]
        cases.extend([
            {'experimental_ma5_irq': True},
            {'experimental_ma5_irq': True, 'experimental_ma5_byte_ns': 1000},
            {'experimental_ma5_irq': True, 'experimental_ma5_clki_hz': 19660800},
            {'experimental_ma5_irq': True, 'experimental_ma5_byte_ns': 1000,
             'experimental_ma5_clki_hz': True},
        ])
        with patch('msm5xxx_emulator.qemu.transport.detect') as detector, patch('msm5xxx_emulator.qemu.transport.tempfile.TemporaryDirectory') as temporary:
            for kwargs in cases:
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    Transport(Path('/unused-qemu'), Path('/unused-firmware'), **kwargs)
            detector.assert_not_called()
            temporary.assert_not_called()

    def test_ma5_pcm_output_requires_explicit_transport_and_host_pcm(self):
        import inspect
        self.assertIs(
            inspect.signature(Transport).parameters[
                'experimental_ma5_pcm_output'].default, False)
        cases = [
            {'experimental_ma5_pcm_output': value}
            for value in (None, 0, 1, 'false')
        ]
        cases.extend((
            {'experimental_ma5_pcm_output': True},
            {'experimental_ma5_pcm_output': True,
             'experimental_ma5_byte_ns': 1000, 'audio_pcm': False},
        ))
        with patch('msm5xxx_emulator.qemu.transport.detect') as detector, patch(
                'msm5xxx_emulator.qemu.transport.tempfile.TemporaryDirectory') as temporary:
            for kwargs in cases:
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    Transport(Path('/unused-qemu'), Path('/unused-firmware'), **kwargs)
            detector.assert_not_called()
            temporary.assert_not_called()

    def test_ma5_target_rate_opt_in_validates_before_io(self):
        import inspect
        self.assertIsNone(
            inspect.signature(Transport).parameters[
                'experimental_ma5_target_rate_hz'].default)
        cases = [
            {'experimental_ma5_target_rate_hz': value,
             'experimental_ma5_byte_ns': 1000}
            for value in (True, 0, 7999, 96001, '48000')
        ]
        cases.extend((
            {'experimental_ma5_target_rate_hz': 48000},
            {'experimental_ma5_target_rate_hz': 48000,
             'experimental_ma5_byte_ns': 1000,
             'experimental_ma5_clki_hz': 19660800},
        ))
        with patch('msm5xxx_emulator.qemu.transport.detect') as detector, patch(
                'msm5xxx_emulator.qemu.transport.tempfile.TemporaryDirectory') as temporary:
            for kwargs in cases:
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    Transport(Path('/unused-qemu'), Path('/unused-firmware'), **kwargs)
            detector.assert_not_called()
            temporary.assert_not_called()

    def test_native_ma5_pcm_ignores_unclassified_mmio_write_replay(self):
        transport = self.native_transport()
        transport.decoder = SimpleNamespace(audio_transport=None)
        transport.audio_native = True
        transport.audio_native_ma5_pcm = True
        record = bytearray(16)
        record[0:2] = bytes((AUDIO_WRITE, 1))
        struct.pack_into('<III', record, 4, 0x1234, 0x0080, 1)
        transport._replay_audio_write(record)
        self.assertEqual(transport.audio_stream_status, 'native')
        self.assertIsNone(transport.audio_stream_reject_reason)
        self.assertTrue(transport.audio_stream_seen)
        self.assertEqual(transport.audio_stream_order, 1)
        record[12:16] = (3).to_bytes(4, 'little')
        transport._replay_audio_write(record)
        self.assertEqual(transport.audio_stream_status, 'rejected')
        self.assertEqual(transport.audio_stream_reject_reason, 'qemu-audio-order-gap')

    def test_ma5_cold_property_requires_explicit_period_and_same_image_graph(self):
        from test_audio_transport import _ma5_readback_image
        image = _ma5_readback_image(0x2000)
        config = SimpleNamespace(load_address=0, flash_size=len(image),
                                 ram_base=0x1000000, ram_size=0x800000)
        self.assertEqual(qemu_ma5_readback_property(image, config, None), (None, None))
        for value in (True, 0, -1, 1_000_000_001, "10"):
            with self.subTest(period=value), self.assertRaises(ValueError):
                qemu_ma5_readback_property(image, config, value)
        prop, reason = qemu_ma5_readback_property(image, config, 1000)
        self.assertIsNone(reason)
        self.assertIn("audio-aperture=2a00000:2:ma5", prop)
        self.assertIn("experimental-ma5-byte-ns=1000", prop)
        target_rate, reason = qemu_ma5_readback_property(
            image, config, 1000, target_rate_hz=48000)
        self.assertIsNone(reason)
        self.assertIn("experimental-ma5-target-rate-hz=48000", target_rate)
        self.assertEqual(qemu_ma5_readback_property(
            image, config, 1000, upper_nor_present=True)[1],
            "aperture-unmapped-or-conflicting")
        self.assertEqual(len(prop.split("audio-sites=")[1].split(",")[0].split(";")), 5)
        changed = bytearray(image)
        # Break the reset-checker C default, preserving unrelated instruction graph.
        changed[0x2000 + 0x100 + 0x34] ^= 1
        self.assertEqual(qemu_ma5_readback_property(bytes(changed), config, 1000),
                         (None, "structural-none"))
        config.flash_size = 0x1000
        self.assertEqual(qemu_ma5_readback_property(image, config, 1000)[1],
                         "primary-nor-out-of-bounds")
        # Matched bodies fit, but an erased external BL dependency does not.
        short_image = _ma5_readback_image()
        config.flash_size = 0x1000
        self.assertEqual(qemu_ma5_readback_property(short_image, config, 1000)[1],
                         "primary-nor-out-of-bounds")
        config.flash_size = len(image); config.ram_size = 0x1000
        self.assertEqual(qemu_ma5_readback_property(image, config, 1000)[1],
                         "consumer-state-unmapped")
        config.ram_size = 0x2000000
        self.assertEqual(qemu_ma5_readback_property(image, config, 1000)[1],
                         "aperture-unmapped-or-conflicting")
        config.ram_size = 0x800000; config.load_address = 0x400000
        self.assertEqual(qemu_ma5_readback_property(image, config, 1000)[1],
                         "primary-nor-unmapped")

    def test_ma5_timed_stride_shared_lcd_requires_closed_graph(self):
        from test_ma5_timed_transport import fixture
        image, entries = fixture()
        config = SimpleNamespace(load_address=0, flash_size=len(image),
                                 ram_base=0x1000000, ram_size=0x800000)
        self.assertEqual(qemu_ma5_readback_property(image, config, None), (None, None))
        prop, reason = qemu_ma5_readback_property(image, config, 1000)
        self.assertIsNone(reason)
        self.assertIn("audio-aperture=2c00000:4:ma5", prop)
        from msm5xxx_emulator.detection.audio import find_ma5_readback_candidate
        candidate = find_ma5_readback_candidate(image)
        config.audio_transport = {"family": "ma5", "grammar": "indexed-rw-v1",
                                  "static_status": "accepted", "base": candidate['base'],
                                  "data_offset": 4, "sites": candidate['sites']}
        self.assertEqual(qemu_ma5_readback_property(image, config, 1000), (prop, None))
        config.audio_transport = {**config.audio_transport, "family": "ma2"}
        self.assertEqual(qemu_ma5_readback_property(image, config, 1000)[1],
                         "conflicting-audio-profile")
        config.audio_transport = None
        sites = prop.split("audio-sites=")[1].split(",")[0].split(";")
        self.assertEqual(len(sites), 5)
        self.assertEqual(sum(site.startswith("w4/") for site in sites), 2)
        self.assertEqual(qemu_ma5_readback_property(
            image, config, 1000, upper_nor_present=True)[1],
            "aperture-unmapped-or-conflicting")
        changed = bytearray(image)
        changed[entries['timed_block'] + 36] ^= 1
        self.assertEqual(qemu_ma5_readback_property(bytes(changed), config, 1000)[1],
                         "structural-none")
        config.ram_size = 0x2000000
        self.assertEqual(qemu_ma5_readback_property(image, config, 1000)[1],
                         "aperture-unmapped-or-conflicting")

    def test_ma5_counter_clock_requires_explicit_period_and_validated_aperture(self):
        from test_audio_transport import _ma5_readback_image
        image = _ma5_readback_image(0x2000)
        config = SimpleNamespace(load_address=0, flash_size=len(image),
                                 ram_base=0x1000000, ram_size=0x800000)
        for clock in (True, 0, -1, 1_000_000_001, "19660800"):
            with self.subTest(clock=clock), self.assertRaises(ValueError):
                qemu_ma5_readback_property(image, config, 1000, clki_hz=clock)
        with self.assertRaises(ValueError):
            qemu_ma5_readback_property(image, config, None, clki_hz=19660800)
        prop, reason = qemu_ma5_readback_property(image, config, 1000,
                                                 clki_hz=19660800)
        self.assertIsNone(reason)
        self.assertTrue(prop.endswith(",experimental-ma5-clki-hz=19660800"))
        self.assertEqual(qemu_ma5_readback_property(bytes(len(image)), config,
                                                  1000, clki_hz=19660800),
                         (None, "structural-none"))

    def test_ma5_temporary_auto_profile_is_signature_and_pcm_gated(self):
        from test_audio_transport import (
            _ma5_literal_readback_image, _ma5_readback_image,
        )
        image = _ma5_readback_image()
        config = SimpleNamespace(load_address=0, flash_size=len(image),
                                 ram_base=0x1000000, ram_size=0x1000000)
        prop, reason = qemu_ma5_temporary_auto_property(
            image, config, audio_pcm=True)
        self.assertIsNone(reason)
        self.assertIn("experimental-ma5-byte-ns=1000", prop)
        self.assertIn("experimental-ma5-target-rate-hz=48000", prop)
        self.assertNotIn("experimental-ma5-clki-hz=", prop)
        self.assertEqual(qemu_ma5_temporary_auto_property(
            image, config, audio_pcm=False), (None, None))
        literal = _ma5_literal_readback_image()
        literal_prop, reason = qemu_ma5_temporary_auto_property(
            literal, config, audio_pcm=True)
        self.assertIsNone(reason)
        self.assertIn("audio-aperture=2400000:80:ma5", literal_prop)
        self.assertIn("experimental-ma5-target-rate-hz=48000", literal_prop)
        self.assertEqual(qemu_ma5_temporary_auto_property(
            image, config, audio_pcm=True, upper_nor_present=True),
            (None, "aperture-unmapped-or-conflicting"))

    def test_ma5_direction_timed_transport_can_use_temporary_auto_profile(self):
        from test_ma5_timed_transport import fixture
        from msm5xxx_emulator.detection.audio import find_ma5_readback_candidate
        image, _ = fixture()
        config = SimpleNamespace(load_address=0, flash_size=len(image),
                                 ram_base=0x1000000, ram_size=0x1000000)
        candidate = find_ma5_readback_candidate(image)
        self.assertEqual(candidate["static_status"], "candidate")
        self.assertEqual(candidate["structural_evidence"]["transport_class"],
                         "local-counter-direction-timing-v1")
        prop, reason = qemu_ma5_temporary_auto_property(
            image, config, audio_pcm=True)
        self.assertIsNone(reason)
        self.assertIn("audio-aperture=2c00000:4:ma5", prop)
        self.assertIn("experimental-ma5-target-rate-hz=48000", prop)

    def test_ma5_literal_stride_property_maps_every_ram_dependency(self):
        from test_audio_transport import _ma5_literal_readback_image
        image = _ma5_literal_readback_image(0x1000)
        config = SimpleNamespace(load_address=0, flash_size=len(image),
                                 ram_base=0x1800000, ram_size=0x800000)
        prop, reason = qemu_ma5_readback_property(image, config, 1000)
        self.assertIsNone(reason)
        self.assertIn("audio-aperture=2400000:80:ma5", prop)
        self.assertEqual(qemu_ma5_readback_property(
            image, config, 1000, upper_nor_present=True), (prop, None))
        sites = prop.split("audio-sites=")[1].split(",")[0].split(";")
        self.assertEqual(len(sites), 5)
        self.assertEqual(sum(site.startswith("w80/") for site in sites), 2)
        self.assertEqual(sum(site.startswith("r80/") for site in sites), 1)
        config.ram_size = 0x360000
        self.assertEqual(qemu_ma5_readback_property(image, config, 1000)[1],
                         "consumer-state-unmapped")

    def test_sequence_receiver_property_rechecks_same_image_and_primary_nor(self):
        from copy import deepcopy
        from test_audio_transport import _sequence_image
        from msm5xxx_emulator.detection.audio import find_audio_transport
        image, roles = _sequence_image(0x2000)
        image = bytes(image)
        audio = find_audio_transport(image)
        config = SimpleNamespace(load_address=0, flash_size=0x4000,
                                 ram_base=0x1000000, ram_size=0x4000)
        prop, reason = qemu_audio_packet_property(image, config, audio)
        self.assertIsNone(reason)
        self.assertEqual(prop, 'experimental-audio-packet-bus=2606,audio-packet-sequence=on')
        for field, value in (("static_status", "rejected"), ("begin", 0x2608),
                             ("requires_runtime_reset", False),
                             ("protocol_status", "accepted"),
                             ("sequence_producer", roles["sequence"] + 2),
                             ("timer_producer", roles["timer"] + 2),
                             ("timer_stop_producer", roles["timer-stop"] + 2),
                             ("status_consumers", [roles["ready"] + 2])):
            bad = deepcopy(audio); bad[field] = value
            self.assertIsNone(qemu_audio_packet_property(image, config, bad)[0])
        changed = bytearray(image); changed[roles["sender"]] ^= 1
        self.assertIsNone(qemu_audio_packet_property(bytes(changed), config, audio)[0])
        config.load_address = 0x400000
        self.assertIsNone(qemu_audio_packet_property(image, config, audio)[0])
        config.load_address = 0; config.flash_size = roles["ready"] + 2
        self.assertIsNone(qemu_audio_packet_property(image, config, audio)[0])
        self.assertIsNone(qemu_audio_packet_property(image, config, None)[0])
        config.flash_size = 0x4000; config.ram_size = 0x200
        self.assertEqual(qemu_audio_packet_property(image, config, audio)[1],
                         "consumer-state-unmapped")
        # The shared return target is valid image code but outside primary NOR.
        image, roles = _sequence_image()
        image.extend(b"\xff" * 0x1800)
        image[0x2000:0x2002] = b"\x70\x47"
        from test_audio_transport import _thumb_bl
        for site in [roles["wrapper"] + n for n in (8, 24, 44, 60)] + [0x43c + 12, 0x49a + 12]:
            image[site:site + 4] = _thumb_bl(site, 0x2000)
        audio = find_audio_transport(bytes(image))
        self.assertEqual(audio["static_status"], "accepted")
        config.flash_size = 0x1000; config.ram_size = 0x4000
        self.assertEqual(qemu_audio_packet_property(bytes(image), config, audio)[1],
                         "primary-nor-out-of-bounds")
        # Both raw state pointers and their full consumer word windows must map.
        image, roles = _sequence_image()
        for role, literal in (("sender", 112), ("sequence", 88)):
            bad = bytearray(image)
            struct.pack_into("<I", bad, roles[role] + literal, 0x1003ffc)
            if role == "sequence":
                for name, pool in (("timer", 172), ("timer-stop", 76)):
                    struct.pack_into("<I", bad, roles[name] + pool, 0x1003ffc)
            audio = find_audio_transport(bytes(bad))
            self.assertEqual(qemu_audio_packet_property(bytes(bad), config, audio)[1],
                             "consumer-state-unmapped")

    def test_optional_clear_property_same_image_and_dependency_bounds(self):
        from copy import deepcopy
        from test_audio_transport import _sequence_clear_image
        from msm5xxx_emulator.detection.audio import find_audio_transport
        for shift in (0, 0x2000):
            image, roles = _sequence_clear_image(shift)
            image = bytes(image)
            audio = find_audio_transport(image)
            config = SimpleNamespace(load_address=0, flash_size=len(image),
                                     ram_base=0x1000000, ram_size=0x4000)
            old = f"experimental-audio-packet-bus={roles['wrapper'] + 6:x},audio-packet-sequence=on"
            self.assertEqual(audio["control_clear_status"], "accepted")
            self.assertEqual(qemu_audio_packet_property(image, config, audio),
                             (old + ",audio-packet-clear-pulse=on", None))
            for field, value in (("control_clear_status", "unavailable"),
                                 ("control_clear_producer", roles["clear"] + 2),
                                 ("control_clear_payload", 0x1000117),
                                 ("nor_dependencies", audio["nor_dependencies"][:-1]),
                                 ("ram_dependencies", audio["ram_dependencies"][:-1])):
                with self.subTest(shift=shift, field=field):
                    forged = deepcopy(audio); forged[field] = value
                    self.assertEqual(qemu_audio_packet_property(image, config, forged),
                                     (None, "same-image-contract-mismatch"))
            config.flash_size = roles["payload_rom"] + 2
            reason = ("primary-nor-unmapped" if config.flash_size < 0x1000
                      else "primary-nor-out-of-bounds")
            self.assertEqual(qemu_audio_packet_property(image, config, audio),
                             (None, reason))
            config.flash_size = len(image)
            config.ram_base = 0x1000117
            self.assertEqual(qemu_audio_packet_property(image, config, audio),
                             (None, "consumer-state-unmapped"))

    def test_missing_or_rejected_clear_keeps_old_sequence_property(self):
        from copy import deepcopy
        from test_audio_transport import _sequence_image, _sequence_clear_image
        from msm5xxx_emulator.detection.audio import find_audio_transport
        config = SimpleNamespace(load_address=0, flash_size=0x4000,
                                 ram_base=0x1000000, ram_size=0x4000)
        images = [_sequence_image()[0]]
        image, roles = _sequence_clear_image()
        image[roles["payload_rom"] + 2] ^= 1
        images.append(image)
        for image in images:
            image = bytes(image); audio = find_audio_transport(image)
            self.assertEqual(audio["static_status"], "accepted")
            self.assertEqual(audio["control_clear_status"], "unavailable")
            self.assertEqual(qemu_audio_packet_property(image, config, audio),
                             ("experimental-audio-packet-bus=606,audio-packet-sequence=on", None))
            forged = deepcopy(audio); forged["control_clear_status"] = "accepted"
            self.assertEqual(qemu_audio_packet_property(image, config, forged),
                             (None, "same-image-contract-mismatch"))

    def test_sequence_ready_byte_window_accepts_last_byte_and_rejects_unmapped(self):
        from test_audio_transport import _sequence_image
        from msm5xxx_emulator.detection.audio import find_audio_transport
        image, roles = _sequence_image()
        config = SimpleNamespace(load_address=0, flash_size=0x1000,
                                 ram_base=0x1000000, ram_size=0x4000)
        for pointer, accepted in ((0x1003fff, True), (0x1004000, False),
                                  (0xffffff, False), (0xffffffff, False)):
            with self.subTest(pointer=pointer):
                struct.pack_into("<I", image, roles["ready"] + 140, pointer)
                audio = find_audio_transport(bytes(image))
                prop, reason = qemu_audio_packet_property(bytes(image), config, audio)
                if accepted:
                    self.assertIsNotNone(prop)
                    self.assertIsNone(reason)
                else:
                    self.assertIsNone(prop)
                    self.assertEqual(reason, "consumer-state-unmapped")

    def test_irq_route_requires_owned_read_and_mapped_descriptor(self):
        from copy import deepcopy
        audio = dict(static_status='accepted', family='ma2', grammar='ma2-command-v1',
                     sites={'read_2': [0x120]}, irq_controller_candidate={
                         'status': 'candidate', 'profile': 'two-bank-callback-descriptor-v1',
                         'descriptor_address': 0x1000100,
                         'words': [0x3000624, 0x300062c, 2, 0x1000200, 0x1000202, 0, 0],
                         'dispatcher_offset': 0x200,
                         'callback_linkage': {'state_address': 0x1000300,
                                              'table_address': 0x1000400,
                                              'callback_offset': 0x300,
                                              'data_read_offset': 0x120}})
        config = SimpleNamespace(load_address=0, flash_size=0x1000000,
                                 ram_base=0x1000000, ram_size=0x800000,
                                 rex_irq_status_address=0x3000620,
                                 rex_irq_enable_address=0x3000628)
        value, reason = qemu_audio_irq_property(audio, config)
        self.assertIsNone(reason)
        self.assertEqual(value, 'audio-irq-route=1000100:3000624:300062c:2:1000200:1000202:200:1000300:1000400:300')
        bad = deepcopy(audio)
        bad['sites']['read_2'] = []
        self.assertIsNone(qemu_audio_irq_property(bad, config)[0])
        bad = deepcopy(audio)
        bad['irq_controller_candidate']['descriptor_address'] = 0x17ffff0
        self.assertIsNone(qemu_audio_irq_property(bad, config)[0])
        config.load_address = 0x400000
        self.assertIsNone(qemu_audio_irq_property(audio, config)[0])

    @staticmethod
    def native_transport() -> Transport:
        transport = object.__new__(Transport)
        transport.decoder = SimpleNamespace()
        transport.audio_stream_enabled = True
        transport.audio_stream_status = "native"
        transport.audio_stream_reject_reason = None
        transport.audio_stream_dropped = 0
        transport.audio_pcm_underflow_frames = 0
        transport.audio_pcm_overflow_frames = 0
        transport.audio_pcm_epoch = 0
        transport.audio_timing_late_events = 0
        transport.audio_timing_collapsed_events = 0
        transport.audio_timing_max_lateness_ns = 0
        transport.audio_reject_witness = None
        transport.audio_native = True
        transport.audio_native_ma5_pcm = False
        transport.audio_stream_seen = False
        transport.audio_stream_order = 0
        transport._audio_lock = threading.RLock()
        transport._audio_ready = threading.Condition(transport._audio_lock)
        transport.native_audio_packets = deque(maxlen=4)
        transport.native_audio_epoch = 0
        transport.native_audio_sequence = 0
        transport.native_audio_end_frame = 0
        transport.native_audio_reset_epoch = 0
        return transport

    @staticmethod
    def pcm_packet(epoch: int, sequence: int, start_frame: int) -> bytes:
        return struct.pack("<4sIQQQ", b"M5P2", 2, epoch, sequence,
                           start_frame) + bytes(441 * 4)

    def test_native_ma5_sink_stop_has_specific_failure_reason(self):
        record = bytes((AUDIO_STATUS, AUDIO_STATUS_REJECTED)) + bytes(14)
        for ma5, reason in ((True, "qemu-ma5-pcm-output-stopped"),
                            (False, "qemu-audio-status-shape")):
            with self.subTest(ma5=ma5):
                transport = self.native_transport()
                transport.audio_native_ma5_pcm = ma5
                transport._replay_audio_status(record)
                self.assertEqual(transport.audio_stream_status, "rejected")
                self.assertEqual(transport.audio_stream_reject_reason, reason)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux socket bound")
    def test_audio_socket_pair_bounds_qemu_sender(self) -> None:
        host, qemu = bounded_audio_socket_pair()
        try:
            self.assertEqual(AUDIO_SOCKET_SEND_BUFFER, 1048576)
            send_bound = qemu.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            self.assertLessEqual(
                send_bound, AUDIO_SOCKET_SEND_BUFFER * 2
            )
            qemu.setblocking(False)
            accepted = 0
            packet = bytes(AUDIO_PACKET_BYTES)
            while True:
                try:
                    written = qemu.send(packet)
                except BlockingIOError:
                    break
                self.assertGreater(written, 0)
                accepted += written
            self.assertLessEqual(accepted, send_bound + AUDIO_PACKET_BYTES)
        finally:
            host.close()
            qemu.close()

    def test_qemu_audio_sites_are_canonical_and_fail_closed(self) -> None:
        metadata = {
            "family": "ma2", "base": 0x02080000,
            "data_offset": 2,
            "sites": {
                "read_0": [0x10],
                "read_2": [0x14],
                "write_2": [0x102, 0x100],
                "write_0": [0x12],
            },
        }
        self.assertEqual(
            qemu_audio_sites(metadata), "r2/14;w0/12;w2/100;w2/102"
        )
        ma5 = {
            "family": "ma5", "base": 0x02840000,
            "data_offset": 2,
            "aperture_write_sites": {
                "write_0": [
                    0x582, 0x58A, 0x10566, 0x1056E, 0x37CAE2,
                ],
                "write_2": [
                    0x586, 0x58E, 0x1056A, 0x10572,
                    0x37CB1E, 0x37CB48, 0x37CB74,
                ],
            },
        }
        self.assertEqual(
            qemu_audio_sites(ma5),
            "w0/582;w0/58a;w0/10566;w0/1056e;w0/37cae2;"
            "w2/586;w2/58e;w2/1056a;w2/10572;w2/37cb1e;"
            "w2/37cb48;w2/37cb74",
        )
        opaque = {
            "family": "opaque", "grammar": "command-status-data-v1",
            "base": 0x02880000, "data_offset": 2,
            "begin": 0x406, "end": 0x43C,
            "sites": {
                "read_0": [0x416], "read_2": [0x43A],
                "write_0": [0x406], "write_2": [0x42A],
            },
        }
        self.assertEqual(
            qemu_audio_sites(opaque), "r0/416;r2/43a;w0/406;w2/42a"
        )
        self.assertIsNone(qemu_audio_sites({
            **opaque,
            "sites": {**opaque["sites"], "read_2": [0x438]},
        }))
        for invalid in (
            {**ma5, "base": 0x0283FFFE},
            {**ma5, "base": 0x02BFFFFE},
            {**ma5, "base": 0x02C00001},
            {**ma5, "data_offset": 4},
        ):
            self.assertIsNone(qemu_audio_sites(invalid))
        self.assertIsNone(qemu_audio_sites({
            **ma5, "base": 0x02C00000, "data_offset": 4,
            "aperture_write_sites": {
                "write_0": [0x100], "write_4": [0x102],
            },
        }))
        self.assertIsNone(qemu_audio_sites({
            **ma5,
            "aperture_write_sites": {
                **ma5["aperture_write_sites"],
                "read_2": [0x37CB00],
            },
        }))
        self.assertIsNone(qemu_audio_sites({
            **ma5,
            "aperture_write_sites": {
                **ma5["aperture_write_sites"],
                "write_2": ma5["aperture_write_sites"]["write_2"][:-1],
            },
        }))
        invalid = (
            {**metadata, "sites": {"write_2": [0x100]}},
            {**metadata, "sites": {"write_0": [0x100]}},
            {**metadata, "sites": {
                "write_0": [0x100], "write_2": [0x101],
            }},
            {**metadata, "sites": {
                "write_0": [0x100], "write_2": [0x100],
            }},
            {**metadata, "sites": {
                "write_0": [0x100], "write_2": [0x100000000],
            }},
            {**metadata, "sites": {
                "write_0": [0x100], "write_3": [0x102],
                "write_2": [0x104],
            }},
            {**metadata, "base": 0x02000000},
            {**metadata, "family": "ma2", "data_offset": 4},
            {**metadata, "family": "ma5", "data_offset": 1},
            {**metadata, "family": "ma5", "data_offset": 2},
            {**metadata, "base": 0x02200000},
            {**metadata, "base": 0x021FFFFF},
            {**metadata, "base": 0x027FFFFE},
        )
        for value in invalid:
            with self.subTest(value=value):
                self.assertIsNone(qemu_audio_sites(value))
        overflow = {
            "family": "ma2", "base": 0x02080000,
            "data_offset": 2,
            "sites": {
                "write_0": [0x100],
                "write_2": list(range(0x200, 0x200 + 64 * 2, 2)),
            },
        }
        self.assertIsNone(qemu_audio_sites(overflow))
        source = (TRANSPORT_SOURCE).read_text(
            encoding="utf-8"
        )
        audio_block = source[source.index("audio = self.config.audio_transport"):]
        audio_block = audio_block[:audio_block.index("        rex_fields =")]
        sites_gate = audio_block.index("if audio_sites is not None:")
        self.assertGreater(audio_block.index("audio-aperture=", sites_gate),
                           sites_gate)
        self.assertGreater(audio_block.index("self.audio_stream_enabled = True",
                                             sites_gate), sites_gate)
        self.assertIn('"qemu-audio-adapter-unsupported"', audio_block)
        self.assertIn('"qemu-audio-detector-"', audio_block)
        self.assertIn('machine += ",audio-pcm=off"', audio_block)
        self.assertIn('machine += ",experimental-ma5-pcm-output=on"', audio_block)
        self.assertIn('if experimental_ma5_pcm_output or ma5_auto_profile:', audio_block)
        self.assertIn("if audio_stream and audio_pcm:", source)
        constructor = next(node for node in ast.walk(ast.parse(source))
                           if isinstance(node, ast.FunctionDef) and node.name == "__init__"
                           and any(isinstance(item, ast.Assign)
                                   and any(isinstance(target, ast.Name)
                                           and target.id == "decoder_options"
                                           for target in item.targets)
                                   for item in node.body))
        start = next(i for i, node in enumerate(constructor.body)
                     if isinstance(node, ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "decoder_options"
                             for target in node.targets))
        setup = ast.Module(body=constructor.body[start:start + 3], type_ignores=[])
        for profile in (None, {"experimental": True}):
            config = SimpleNamespace(native_nand_profile=profile)
            decoder = Mock()
            exec(compile(setup, str(TRANSPORT_SOURCE), "exec"),
                 {"self": SimpleNamespace(config=config), "GenericMSMEmulator": decoder})
            expected = {"approximate_audio": False}
            if profile is not None:
                expected["native_nand"] = True
            decoder.assert_called_once_with(config, **expected)
        self.assertIn("bounded_audio_socket_pair()", source)
        self.assertIn('"pass_fds": (audio_qemu_socket.fileno(),)', source)
        self.assertIn("AUDIO_PACKET_BYTES - len(pending)", source)
        java = (Path(__file__).parents[1]
                / "android/app/src/main/java/org/msm5xxx/emulator/"
                "MainActivity.java").read_text(encoding="utf-8")
        self.assertIn("new ArrayBlockingQueue<>(4)", java)
        self.assertIn("audioSink.start(opened);", java)
        self.assertIn('"msm5xxx-audio-input"', java)
        self.assertIn("byte[] pcm = source.audio()", java)
        self.assertIn("if (pcm.length == 0) {", java)
        self.assertIn("Thread.sleep(1);", java)
        session_loop = java[java.index("while (generation == sessionGeneration)"):
                            java.index("        } catch (IOException", java.index(
                                "while (generation == sessionGeneration)"))]
        self.assertIn('"native".equals(status.audioStatus)', session_loop)
        self.assertIn('"rejected".equals(status.audioStatus)', session_loop)
        self.assertIn("audioSink.start(opened);", session_loop)
        self.assertIn("audioSink.close();", session_loop)
        self.assertNotIn("audioSink.start(opened);",
                         java[:java.index("while (generation == sessionGeneration)")])
        self.assertNotIn("opened.audio()", session_loop)
        self.assertIn("pending.remainingCapacity() > 0", java)
        self.assertIn("if (!pending.offer(packet))", java)
        self.assertNotIn("audioDeadline", java)
        self.assertNotIn("offeredEpoch", java)
        offer = java[java.index("        void offer(byte[] pcm)"):
                     java.index("        private void run()")]
        self.assertNotIn("pending.clear();", offer)
        self.assertIn("data.length != PACKET_BYTES", java)
        self.assertIn("private volatile AudioTrack activeTrack", java)
        self.assertIn("if (track == null) {\n                            track = createTrack()", java)
        self.assertIn("track.pause();\n                            track.flush();", java)
        self.assertIn("android.os.Process.THREAD_PRIORITY_AUDIO", java)
        self.assertIn("private static final int PREBUFFER_MILLIS = 60", java)
        self.assertIn("private static final int BUFFER_MILLIS = 80", java)
        self.assertIn("track.getUnderrunCount()", java)
        self.assertIn('"M5P2 ingress gapMs="', java)
        self.assertIn("cadenceLogs < 8", java)
        self.assertIn("underrunLogs < 8", java)
        self.assertIn("long spanStartFrame = -1", java)
        self.assertIn('"AudioTrack span epoch="', java)
        self.assertIn('" elapsedNanos="', java)
        create_track = java[java.index("private static AudioTrack createTrack()"):
                            java.index("        void disable()")]
        self.assertNotIn("track.play()", create_track)
        self.assertIn("* PREBUFFER_MILLIS / 1000", java)
        self.assertIn("pauseTrack(track);", java)
        self.assertIn("input.interrupt();", java)
        self.assertIn("worker.interrupt();", java)
        self.assertIn("worker.isAlive() || (input != null && input.isAlive())", java)
        self.assertNotIn("while (!closed && !disabled", java)
        self.assertNotIn("pending.clear();\n            pending.offer", java)
        bridge = (Path(__file__).parents[1]
                  / "android/app/src/main/java/org/msm5xxx/emulator/"
                  "BackendBridge.java").read_text(encoding="utf-8")
        self.assertIn("private static PythonSession activeSession", bridge)
        self.assertIn("static synchronized Session open", bridge)
        self.assertIn("if (activeSession != this)", bridge)
        runtime_java = (Path(__file__).parents[1]
                        / "android/app/src/main/java/org/msm5xxx/emulator/"
                        "PythonRuntime.java").read_text(encoding="utf-8")
        self.assertIn("new ReentrantLock(true)", runtime_java)
        self.assertIn("static byte[] audio()", runtime_java)
        self.assertNotIn("static synchronized byte[] audio()", runtime_java)
        self.assertEqual(runtime_java.count("AUDIO_GATE.lock();"), 3)
        self.assertEqual(runtime_java.count("AUDIO_GATE.unlock();"), 3)
        self.assertIn("static synchronized String key(", runtime_java)
        self.assertIn("static synchronized String canKey(", runtime_java)
        korean = (Path(__file__).parents[1]
                  / "android/app/src/main/res/values-ko/strings.xml"
                  ).read_text(encoding="utf-8")
        self.assertIn("u%2$d/o%3$d/e%4$d/l%5$d", korean)
        self.assertIn('"coreaudio,id=msm5xxx"', source)
        self.assertIn('"out.buffer-length=40000"', source)
        self.assertIn('"in.voices=0," if desktop_audio_driver == "dsound"', source)
        stage = (NATIVE / 'stage_qemu_source.sh').read_text()
        self.assertIn('patch -p1 -d "$OUTPUT" < "$DSOUND_PATCH"', stage)
        patch = NATIVE / 'qemu-10.2.1-dsound-playback-only.patch'
        self.assertIn('if (dso->in->voices)', patch.read_text())
        replay = source[source.index("    def replay("):
                        source.index("    def _queue_native_audio(")]
        self.assertIn('name="msm5xxx-qemu-audio-replay"', replay)
        android_runtime = ANDROID_RUNTIME.read_text(encoding="utf-8")
        self.assertNotIn('qemu_prefix=("/system/bin/nice"', android_runtime)
        self.assertNotIn("icount_shift=", android_runtime)
        self.assertIn('f"shift={icount_shift},align=on,sleep=on"', source)
        machine = (NATIVE / "msm5xxx-poc.c").read_text(encoding="utf-8")
        synth_header = (NATIVE / "msm5xxx-audio-synth.h").read_text(
            encoding="utf-8")
        self.assertIn("MSM5XXX_AUDIO_TARGET_FRAMES", machine)
        self.assertIn("MSM5XXX_AUDIO_SAMPLE_RATE * 80u / 1000u",
                      synth_header)

    def test_m5p2_fragment_sequence_epoch_and_bound(self) -> None:
        transport = self.native_transport()
        transport.input_socket, input_peer = socket.socketpair()
        transport.lcd_socket, lcd_peer = socket.socketpair()
        transport.audio_socket, audio_peer = socket.socketpair()
        transport.process = SimpleNamespace(poll=lambda: None)
        stop = threading.Event()
        worker = threading.Thread(target=transport.replay, args=(stop,))
        packet = self.pcm_packet(1, 1, 0)
        try:
            worker.start()
            audio_peer.sendall(packet[:17])
            audio_peer.sendall(packet[17:777])
            audio_peer.sendall(packet[777:])
            self.assertEqual(transport.take_native_audio(1.0), packet)
        finally:
            stop.set()
            worker.join(1)
            for stream in (transport.input_socket, input_peer,
                           transport.lcd_socket, lcd_peer,
                           transport.audio_socket, audio_peer):
                stream.close()
        self.assertFalse(worker.is_alive())

        transport = self.native_transport()
        first = self.pcm_packet(1, 1, 0)
        second = self.pcm_packet(1, 2, 441)
        resync = self.pcm_packet(2, 1, 50_000)
        transport._queue_native_audio(first)
        transport._queue_native_audio(second)
        self.assertEqual(len(transport.native_audio_packets), 2)
        transport._queue_native_audio(resync)
        self.assertEqual(list(transport.native_audio_packets), [resync])
        transport._queue_native_audio(self.pcm_packet(2, 3, 50_441))
        self.assertEqual(transport.audio_stream_status, "rejected")
        self.assertEqual(transport.audio_stream_reject_reason,
                         "qemu-audio-pcm-sequence")
        self.assertEqual(list(transport.native_audio_packets), [])
        self.assertEqual(transport.take_native_audio(), b"")
        self.assertEqual(transport.native_audio_packets.maxlen, 4)

        transport = self.native_transport()
        transport.native_audio_epoch = 1
        transport.native_audio_sequence = 9
        transport.native_audio_end_frame = 10_000
        transport.native_audio_reset_epoch = 2
        newer = self.pcm_packet(3, 1, 50_000)
        transport._queue_native_audio(newer)
        self.assertEqual(transport.take_native_audio(), newer)
        self.assertEqual(transport.native_audio_reset_epoch, 0)

    def test_m5p2_delivery_does_not_wait_for_lcd_decode(self) -> None:
        transport = self.native_transport()
        transport.input_socket, input_peer = socket.socketpair()
        transport.lcd_socket, lcd_peer = socket.socketpair()
        transport.audio_socket, audio_peer = socket.socketpair()
        transport.process = SimpleNamespace(poll=lambda: None)
        lcd_entered = threading.Event()
        lcd_release = threading.Event()

        def block_lcd(*_args) -> None:
            lcd_entered.set()
            lcd_release.wait(1)

        transport.decoder = SimpleNamespace(
            uc=None, input_error=None, _lcd_write=block_lcd,
        )
        stop = threading.Event()
        worker = threading.Thread(target=transport.replay, args=(stop,))
        lcd_write = bytearray(16)
        lcd_write[0] = LCD_WRITE
        packet = self.pcm_packet(1, 1, 0)
        try:
            worker.start()
            lcd_peer.sendall(lcd_write)
            self.assertTrue(lcd_entered.wait(1))
            audio_peer.sendall(packet)
            self.assertEqual(transport.take_native_audio(0.2), packet)
        finally:
            lcd_release.set()
            stop.set()
            worker.join(1)
            for stream in (transport.input_socket, input_peer,
                           transport.lcd_socket, lcd_peer,
                           transport.audio_socket, audio_peer):
                stream.close()
        self.assertFalse(worker.is_alive())

    def test_replay_yields_once_per_complete_batch_only_with_audio(self) -> None:
        records = [bytes((index,)) * 16 for index in range(1, 7)]
        for audio_enabled in (False, True):
            with self.subTest(audio_enabled=audio_enabled):
                transport = self.native_transport()
                transport.input_socket = Mock()
                transport.lcd_socket = Mock()
                transport.input_socket.recv.side_effect = [
                    records[0][:5], records[0][5:] + records[1], records[2]]
                transport.lcd_socket.recv.side_effect = [
                    records[3][:7], records[3][7:] + records[4] + records[5][:4],
                    records[5][4:]]
                transport.audio_socket = Mock() if audio_enabled else None
                transport.process = SimpleNamespace(poll=lambda: None)
                transport._terminate_process = Mock()
                replayed = []
                transport._replay_record = replayed.append
                stop = threading.Event()
                batches = iter(((transport.input_socket, transport.lcd_socket),
                                (transport.input_socket,),
                                (transport.input_socket, transport.lcd_socket),
                                (transport.lcd_socket,)))
                completed = []
                yields = []

                def select_batch(readers, _writers, _errors, timeout):
                    self.assertEqual(readers, (transport.input_socket, transport.lcd_socket))
                    self.assertEqual(timeout, 0.02)
                    readable = next(batches, None)
                    if readable is None:
                        completed.append(True)
                        stop.set()
                        return [], [], []
                    return readable, [], []

                def yield_to_audio(delay):
                    self.assertEqual(delay, 0)
                    yields.append(len(replayed))

                audio_worker = Mock()
                audio_worker.is_alive.return_value = False
                with patch('msm5xxx_emulator.qemu.transport.select.select', side_effect=select_batch) as select_mock, \
                        patch('msm5xxx_emulator.qemu.transport.threading.Thread', return_value=audio_worker) as start_worker, \
                        patch('msm5xxx_emulator.qemu.transport.time', SimpleNamespace(sleep=yield_to_audio), create=True):
                    transport.replay(stop)
                self.assertEqual(replayed, records)
                self.assertEqual(completed, [True])
                self.assertEqual(select_mock.call_count, 5)
                self.assertEqual(transport.input_socket.recv.call_count, 3)
                self.assertEqual(transport.lcd_socket.recv.call_count, 3)
                self.assertTrue(stop.is_set())
                transport._terminate_process.assert_not_called()
                if audio_enabled:
                    start_worker.assert_called_once()
                    audio_worker.start.assert_called_once()
                    audio_worker.join.assert_called_once_with(1)
                    transport.audio_socket.shutdown.assert_called_once_with(socket.SHUT_RDWR)
                    transport.audio_socket.close.assert_called_once()
                else:
                    start_worker.assert_not_called()
                self.assertEqual(yields, [2, 3, 5, 6] if audio_enabled else [])

    def test_audio_channel_close_rejects_only_audio(self) -> None:
        transport = self.native_transport()
        transport.input_socket, input_peer = socket.socketpair()
        transport.lcd_socket, lcd_peer = socket.socketpair()
        transport.audio_socket, audio_peer = socket.socketpair()
        transport.process = SimpleNamespace(poll=lambda: None)
        terminated = []
        transport._terminate_process = lambda: terminated.append(True)
        stop = threading.Event()
        worker = threading.Thread(target=transport.replay, args=(stop,))
        try:
            worker.start()
            audio_peer.close()
            deadline = time.monotonic() + 1
            while (transport.audio_stream_status != "rejected"
                   and time.monotonic() < deadline):
                time.sleep(0.01)
            self.assertEqual(transport.audio_stream_status, "rejected")
            self.assertEqual(
                transport.audio_stream_reject_reason,
                "qemu-audio-channel-closed",
            )
            self.assertFalse(stop.is_set())
            self.assertTrue(worker.is_alive())
            self.assertEqual(terminated, [])
        finally:
            stop.set()
            worker.join(1)
            for stream in (transport.input_socket, input_peer,
                           transport.lcd_socket, lcd_peer,
                           transport.audio_socket, audio_peer):
                stream.close()
        self.assertFalse(worker.is_alive())

    def test_audio_worker_error_closes_only_audio_channel(self) -> None:
        transport = self.native_transport()
        transport.input_socket, input_peer = socket.socketpair()
        transport.lcd_socket, lcd_peer = socket.socketpair()
        transport.audio_socket, audio_peer = socket.socketpair()
        transport.process = SimpleNamespace(poll=lambda: None)
        transport._replay_native_audio = lambda _stop: (_ for _ in ()).throw(
            OSError("injected audio read failure")
        )
        terminated = []
        transport._terminate_process = lambda: terminated.append(True)
        stop = threading.Event()
        worker = threading.Thread(target=transport.replay, args=(stop,))
        try:
            worker.start()
            deadline = time.monotonic() + 1
            while (transport.audio_stream_status != "rejected"
                   and time.monotonic() < deadline):
                time.sleep(0.01)
            self.assertEqual(
                transport.audio_stream_reject_reason,
                "qemu-audio-channel-error",
            )
            self.assertFalse(stop.is_set())
            self.assertTrue(worker.is_alive())
            self.assertEqual(terminated, [])
            audio_peer.settimeout(1)
            # TCP may accept a final write after peer shutdown on Windows.
            self.assertEqual(audio_peer.recv(1), b"")
        finally:
            stop.set()
            worker.join(1)
            for stream in (transport.input_socket, input_peer,
                           transport.lcd_socket, lcd_peer,
                           transport.audio_socket, audio_peer):
                stream.close()
        self.assertFalse(worker.is_alive())

    def test_audio_channel_close_error_is_best_effort(self) -> None:
        transport = self.native_transport()
        closed = []

        def fail_close() -> None:
            closed.append(True)
            raise OSError("injected close failure")

        transport.audio_socket = SimpleNamespace(
            shutdown=lambda _how: None,
            close=fail_close,
        )
        transport._close_audio_channel()
        self.assertEqual(closed, [True])

    def test_qemu_path_never_calls_python_renderer(self) -> None:
        closed = []
        decoder = SimpleNamespace(
            _lcd_page_flush_current=lambda: None,
            _flush_indexed_frame=lambda: None,
            _flush_audio_transport_renderer=lambda: self.fail(
                "native audio must not call Python renderer"
            ),
            audio_player=SimpleNamespace(close=lambda: closed.append(True)),
        )
        transport = self.native_transport()
        transport.decoder = decoder
        transport.audio_native = False
        transport.audio_stream_status = "pending"
        telemetry = bytearray(16)
        telemetry[0] = TELEMETRY
        transport._replay_record(telemetry)
        status = bytearray(16)
        status[0:2] = bytes((AUDIO_STATUS, AUDIO_STATUS_NATIVE))
        transport._replay_record(status)
        transport._replay_record(telemetry)
        self.assertTrue(transport.audio_native)
        self.assertEqual(transport.audio_stream_status, "native")
        self.assertEqual(closed, [True])
        self.assertIsNone(decoder.audio_player)
        pcm_telemetry = bytearray(16)
        pcm_telemetry[0] = AUDIO_PCM_TELEMETRY
        struct.pack_into("<III", pcm_telemetry, 4, 441, 882, 3)
        transport._replay_record(pcm_telemetry)
        self.assertEqual(
            transport.audio_pcm_snapshot(),
            (441, 882, 3),
        )
        timing_telemetry = bytearray(16)
        timing_telemetry[0] = AUDIO_TIMING_TELEMETRY
        struct.pack_into("<III", timing_telemetry, 4, 4, 2, 3_000_000)
        transport._replay_record(timing_telemetry)
        self.assertEqual(
            transport.audio_timing_snapshot(),
            (4, 2, 3_000_000),
        )

    def test_reset_flushes_old_epoch_and_restarts_write_order(self) -> None:
        owner = AudioMixin()
        owner.audio_transport = AudioTransport({
            "family": "ma2", "grammar": "ma2-command-v1",
            "static_status": "accepted", "reject_reason": None,
            "base": 0x02080000, "data_offset": 2,
            "sites": {"write_0": [0x100]}, "block_write_offsets": [],
        })
        transport = self.native_transport()
        transport.decoder = owner
        transport.audio_stream_enabled = True
        transport.audio_stream_seen = True
        transport.audio_stream_order = 7
        transport.audio_stream_dropped = 3
        transport.audio_pcm_underflow_frames = 441
        transport.audio_pcm_overflow_frames = 882
        transport.audio_pcm_epoch = 1
        transport.audio_timing_late_events = 4
        transport.audio_timing_collapsed_events = 2
        transport.audio_timing_max_lateness_ns = 3_000_000
        transport._queue_native_audio(self.pcm_packet(1, 1, 0))

        reset = bytearray(16)
        reset[0:2] = bytes((AUDIO_STATUS, AUDIO_STATUS_RESET))
        struct.pack_into("<Q", reset, 4, 2)
        transport._replay_record(reset)

        self.assertEqual(transport.audio_stream_status, "native")
        self.assertTrue(transport.audio_native)
        self.assertEqual(transport.audio_stream_reject_reason, None)
        self.assertEqual((transport.audio_stream_seen,
                          transport.audio_stream_order,
                          transport.audio_stream_dropped),
                         (False, 0, 0))
        self.assertEqual(transport.audio_pcm_snapshot(), (0, 0, 0))
        self.assertEqual(transport.audio_timing_snapshot(), (0, 0, 0))
        self.assertEqual(list(transport.native_audio_packets), [])

        transport._queue_native_audio(self.pcm_packet(1, 2, 441))
        self.assertEqual(transport.audio_stream_status, "native")
        self.assertEqual(list(transport.native_audio_packets), [])
        fresh = self.pcm_packet(2, 1, 50_000)
        transport._queue_native_audio(fresh)
        self.assertEqual(transport.take_native_audio(), fresh)

        write = bytearray(16)
        write[0:2] = bytes((AUDIO_WRITE, 1))
        struct.pack_into("<III", write, 4, 0x100, 0x0F00, 1)
        transport._replay_record(write)
        self.assertEqual(transport.audio_stream_order, 1)
        self.assertEqual(owner.audio_transport.counts["raw-writes"], 1)

        raced = self.native_transport()
        raced.decoder = SimpleNamespace()
        raced.audio_stream_enabled = True
        raced._queue_native_audio(self.pcm_packet(1, 1, 0))
        first = self.pcm_packet(3, 1, 50_000)
        raced._queue_native_audio(first)
        raced._replay_record(reset)
        raced._queue_native_audio(self.pcm_packet(2, 1, 50_000))
        self.assertEqual(list(raced.native_audio_packets), [first])
        latest_reset = bytearray(reset)
        struct.pack_into("<Q", latest_reset, 4, 3)
        raced._replay_record(latest_reset)
        raced._replay_record(latest_reset)
        second = self.pcm_packet(3, 2, 50_441)
        raced._queue_native_audio(second)
        self.assertEqual(list(raced.native_audio_packets), [first, second])
        self.assertEqual(raced.audio_stream_status, "native")

        recovered = self.native_transport()
        recovered._reject_audio_stream("qemu-audio-order-gap")
        recovered._replay_record(reset)
        recovered._queue_native_audio(fresh)
        self.assertEqual(recovered.take_native_audio(), fresh)
        self.assertEqual(recovered.audio_stream_status, "native")
        self.assertIsNone(recovered.audio_stream_reject_reason)

    def test_native_ma5_desktop_status_preserves_strict_admission(self) -> None:
        def status(kind, order=0, dropped=0, detail=0):
            return struct.pack("<BB2xIII", AUDIO_STATUS, kind,
                               order, dropped, detail)

        def desktop():
            transport = self.native_transport()
            transport.audio_stream_enabled = False
            transport.audio_native_ma5_pcm = True
            return transport

        native = status(AUDIO_STATUS_NATIVE)
        reset = status(AUDIO_STATUS_RESET, 7, 1)
        transport = desktop()
        player = Mock()
        transport.decoder.audio_player = player
        transport._replay_record(native)
        self.assertEqual(transport.audio_stream_status, "native")
        self.assertIsNone(transport.audio_stream_reject_reason)
        self.assertTrue(transport.audio_native)
        player.close.assert_called_once_with()
        self.assertIsNone(transport.decoder.audio_player)

        transport.audio_pcm_underflow_frames = 441
        transport._replay_record(status(AUDIO_STATUS_REJECTED))
        self.assertEqual(transport.audio_stream_status, "rejected")
        self.assertEqual(transport.audio_stream_reject_reason,
                         "qemu-ma5-pcm-output-stopped")
        self.assertFalse(transport.audio_native)
        transport._replay_record(native)
        self.assertEqual(transport.audio_stream_status, "rejected")
        transport._replay_record(reset)
        self.assertEqual(transport.audio_stream_status, "native")
        self.assertIsNone(transport.audio_stream_reject_reason)
        self.assertTrue(transport.audio_native)
        self.assertEqual(transport.audio_pcm_snapshot(), (0, 0, 0))
        self.assertEqual(transport.native_audio_reset_epoch, (1 << 32) | 7)
        self.assertEqual(list(transport.native_audio_packets), [])
        self.assertFalse(transport.audio_stream_enabled)
        self.assertFalse(hasattr(transport, "audio_socket"))

        reserved = bytearray(native)
        reserved[2] = 1
        for record in (reserved, status(AUDIO_STATUS_NATIVE, detail=1),
                       status(AUDIO_STATUS_RESET),
                       status(AUDIO_STATUS_RESET, 7, detail=1),
                       status(AUDIO_STATUS_REJECTED, detail=1),
                       status(AUDIO_STATUS_OVERFLOW), status(255)):
            with self.subTest(malformed=bytes(record)):
                rejected = desktop()
                rejected._replay_record(record)
                self.assertEqual(rejected.audio_stream_status, "rejected")
                self.assertEqual(rejected.audio_stream_reject_reason,
                                 "qemu-audio-status-shape")

        for flag in (False, None, 1, "ma5"):
            for record in (native, reset):
                with self.subTest(unadmitted=flag, record=record):
                    disabled = desktop()
                    disabled.audio_native_ma5_pcm = flag
                    disabled.audio_stream_status = "disabled"
                    disabled._replay_record(record)
                    self.assertEqual(disabled.audio_stream_status, "rejected")
                    self.assertEqual(disabled.audio_stream_reject_reason,
                                     "qemu-audio-status-shape")

        ma2 = self.native_transport()
        ma2._replay_record(native)
        ma2._replay_record(reset)
        self.assertEqual(ma2.audio_stream_status, "native")
        self.assertTrue(ma2.audio_stream_enabled)
        self.assertFalse(ma2.audio_native_ma5_pcm)

    def test_disabled_audio_ignores_only_canonical_reset_status(self) -> None:
        reset = bytearray(16)
        reset[0:2] = bytes((AUDIO_STATUS, AUDIO_STATUS_RESET))

        disabled = self.native_transport()
        disabled.audio_stream_enabled = False
        disabled.audio_stream_status = "disabled"
        disabled._replay_record(reset)
        self.assertEqual(disabled.audio_stream_status, "disabled")
        self.assertIsNone(disabled.audio_stream_reject_reason)
        self.assertEqual(disabled.audio_stream_dropped, 0)
        self.assertEqual(list(disabled.native_audio_packets), [])

        malformed = []
        reserved = bytearray(reset)
        reserved[2] = 1
        malformed.append(reserved)
        for offset in (4, 8, 12):
            nonzero = bytearray(reset)
            struct.pack_into("<I", nonzero, offset, 1)
            malformed.append(nonzero)
        active_zero_epoch = self.native_transport()
        active_zero_epoch._replay_record(reset)
        self.assertEqual(active_zero_epoch.audio_stream_status, "rejected")
        for record in malformed:
            transport = self.native_transport()
            transport.audio_stream_enabled = False
            transport.audio_stream_status = "disabled"
            transport._replay_record(record)
            self.assertEqual(transport.audio_stream_status, "rejected")
            self.assertEqual(
                transport.audio_stream_reject_reason,
                "qemu-audio-status-shape",
            )

    def test_android_audio_only_exposes_accepted_ma2_pcm(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "msm5xxx_android_audio_test", ANDROID_RUNTIME
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        packet = struct.pack("<4sIQQQ", b"M5P2", 2, 1, 1, 0) \
            + b"\x01\0\x02\0" * 441
        metadata = {"family": "ma2", "static_status": "accepted"}
        transport = SimpleNamespace(
            family="ma2", static_status="accepted",
            renderer_status="submitted", renderer_reject_reason=None,
        )
        process = SimpleNamespace(poll=lambda: None)
        audio_timeouts = []

        def take_native_audio(timeout=0.0):
            audio_timeouts.append(timeout)
            return packet

        runtime._session = SimpleNamespace(
            config=SimpleNamespace(audio_transport=metadata),
            decoder=SimpleNamespace(
                audio_transport=transport,
                frame_sequence=7,
                lcd_writes=9,
                secondary_display_snapshot=lambda: None,
            ),
            can_set_fold=lambda: False,
            take_native_audio=take_native_audio,
            audio_pcm_snapshot=lambda: (441, 882, 3),
            audio_stream_reject_reason=None,
            audio_stream_enabled=True,
            audio_stream_status="active",
            virtual_cell_status="native",
            input_host_events=4,
            input_rejections=5,
            instructions=6,
            pc=8,
            process=process,
        )
        try:
            status = json.loads(runtime.session_status())
            self.assertEqual(status["virtual_cell_status"], "native")
            self.assertEqual(
                (status["audio_underflow_frames"],
                 status["audio_overflow_frames"], status["audio_epoch"],
                 status["audio_status"], status["audio_reject_reason"]),
                (441, 882, 3, "active", ""),
            )
            self.assertEqual(runtime.session_audio(), packet)
            self.assertEqual(audio_timeouts, [0.02])
            metadata["family"] = "ma5"
            self.assertEqual(runtime.session_audio(), b"")
            metadata["family"] = "ma2"
            runtime._session.audio_stream_status = "rejected"
            self.assertEqual(runtime.session_audio(), b"")
            runtime._session.audio_stream_status = "active"
            runtime._session.take_native_audio = lambda _timeout=0.0: b"bad"
            self.assertEqual(runtime.session_audio(), b"")
            runtime._session.take_native_audio = \
                lambda _timeout=0.0: packet[:32]
            self.assertEqual(runtime.session_audio(), b"")
            runtime._session.take_native_audio = lambda _timeout=0.0: packet
            transport.family = "ma5"
            self.assertEqual(runtime.session_audio(), b"")
            transport.family = "ma2"
            overflow = struct.pack(
                "<4sIQQQ", b"M5P2", 2, 1, 1, (1 << 63) - 1
            ) + packet[32:]
            runtime._session.take_native_audio = \
                lambda _timeout=0.0: overflow
            self.assertEqual(runtime.session_audio(), b"")
            runtime._session.take_native_audio = lambda _timeout=0.0: packet
            runtime._session_error = "RuntimeError"
            self.assertEqual(runtime.session_audio(), b"")
            runtime._session_error = None
            process.poll = lambda: 1
            self.assertEqual(runtime.session_audio(), b"")
        finally:
            runtime._session = None
            runtime._session_error = None

    def test_android_audio_exposes_only_admitted_native_ma5_pcm(self) -> None:
        spec = importlib.util.spec_from_file_location(
            'msm5xxx_android_native_ma5_audio_test', ANDROID_RUNTIME)
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        packet = self.pcm_packet(1, 1, 0)
        receiver = Mock(return_value=packet)
        session = SimpleNamespace(
            config=SimpleNamespace(audio_transport=None),
            decoder=SimpleNamespace(audio_transport=None),
            process=SimpleNamespace(poll=lambda: None),
            audio_stream_enabled=True, audio_stream_status='native',
            audio_native=True, audio_native_ma5_pcm=True,
            take_native_audio=receiver,
        )
        runtime._session = session
        try:
            self.assertEqual(runtime.session_audio(), packet)
            receiver.assert_called_once_with(0.02)
            del session.config.audio_transport
            del session.decoder.audio_transport
            self.assertEqual(runtime.session_audio(), packet)
            for field in ('audio_native', 'audio_native_ma5_pcm'):
                for invalid in (False, None, 0, 1, 'true'):
                    setattr(session, field, invalid)
                    receiver.reset_mock()
                    with self.subTest(field=field, value=invalid):
                        self.assertEqual(runtime.session_audio(), b'')
                        receiver.assert_not_called()
                setattr(session, field, True)
            for status in ('pending', 'active', 'rejected', 'disabled'):
                session.audio_stream_status = status
                receiver.reset_mock()
                with self.subTest(status=status):
                    self.assertEqual(runtime.session_audio(), b'')
                    receiver.assert_not_called()
            session.audio_stream_status = 'native'
            session.config.audio_transport = {'family': 'ma5', 'static_status': 'accepted'}
            session.decoder.audio_transport = SimpleNamespace(family='ma5', static_status='accepted')
            session.audio_native = session.audio_native_ma5_pcm = False
            self.assertEqual(runtime.session_audio(), b'')
            session.audio_native = session.audio_native_ma5_pcm = True
            self.assertEqual(runtime.session_audio(), packet)
            invalid_packets = [b'bad', packet[:32], packet + b'\0', bytearray(packet)]
            invalid_packets += [struct.pack('<4sIQQQ', *header) + packet[32:] for header in (
                (b'BAD!', 2, 1, 1, 0), (b'M5P2', 1, 1, 1, 0),
                (b'M5P2', 2, 0, 1, 0), (b'M5P2', 2, 1, 0, 0),
                (b'M5P2', 2, 1, 1, (1 << 63) - 1))]
            for invalid in invalid_packets:
                receiver.return_value = invalid
                with self.subTest(packet_length=len(invalid)):
                    self.assertEqual(runtime.session_audio(), b'')
            boundary = self.pcm_packet(1, 1, (1 << 63) - 1 - 441)
            receiver.return_value = boundary
            self.assertEqual(runtime.session_audio(), boundary)
            receiver.return_value = packet
            for failure in ('backend', 'session', 'disabled'):
                session.process.poll = lambda: 1 if failure == 'backend' else None
                runtime._session_error = 'own replay failure' if failure == 'session' else None
                session.audio_stream_enabled = failure != 'disabled'
                receiver.reset_mock()
                with self.subTest(failure=failure):
                    self.assertEqual(runtime.session_audio(), b'')
                    receiver.assert_not_called()
            session.process.poll = lambda: None
            runtime._session_error = None
            session.audio_stream_enabled = True
            session.take_native_audio = None
            self.assertEqual(runtime.session_audio(), b'')
        finally:
            runtime._session = None
            runtime._session_error = None

    def test_overflow_is_terminal(self) -> None:
        owner = AudioMixin()
        owner.audio_transport = AudioTransport({
            "family": "ma2", "grammar": "ma2-command-v1",
            "static_status": "accepted", "reject_reason": None,
            "base": 0x02080000, "data_offset": 2,
            "sites": {"write_0": [0x100]}, "block_write_offsets": [],
        })
        transport = object.__new__(Transport)
        transport.decoder = owner
        transport.audio_stream_enabled = True
        transport.audio_stream_seen = False
        transport.audio_stream_order = 0
        transport.audio_stream_status = "pending"
        transport.audio_stream_reject_reason = None
        transport.audio_stream_dropped = 0
        transport._audio_lock = threading.RLock()
        transport._audio_ready = threading.Condition(transport._audio_lock)
        transport.native_audio_packets = deque(maxlen=4)

        write = bytearray(16)
        write[0:2] = bytes((AUDIO_WRITE, 1))
        struct.pack_into("<III", write, 4, 0x100, 0x0F00, 1)
        transport._replay_record(write)
        overflow = bytearray(16)
        overflow[0:2] = bytes((AUDIO_STATUS, AUDIO_STATUS_OVERFLOW))
        struct.pack_into("<III", overflow, 4, 1, 1, 0)
        transport._replay_record(overflow)
        write[8:16] = struct.pack("<II", 0, 2)
        transport._replay_record(write)

        self.assertEqual(owner.audio_transport.counts["raw-writes"], 1)
        self.assertEqual(transport.audio_stream_status, "rejected")
        self.assertEqual(
            transport.audio_stream_reject_reason, "qemu-audio-overflow"
        )
        self.assertEqual(transport.audio_stream_dropped, 1)
        self.assertEqual(
            owner.audio_transport.counts["ma2-render-submission-rejections"],
            1,
        )

        transport.audio_stream_status = "active"
        witness = bytearray(16)
        witness[0:2] = bytes((AUDIO_REJECT_TELEMETRY, 0x5A))
        struct.pack_into("<III", witness, 4, 0x00123456, 8,
                         2 | 0xAB << 8 | 1 << 16 | 3 << 24)
        transport._replay_record(witness)
        rejected = bytearray(16)
        rejected[0:2] = bytes((AUDIO_STATUS, AUDIO_STATUS_REJECTED))
        struct.pack_into("<II", rejected, 4, 9, 2)
        struct.pack_into("<I", rejected, 12, 5)
        transport._replay_record(rejected)
        self.assertEqual(transport.audio_stream_status, "rejected")
        self.assertEqual(
            transport.audio_stream_reject_reason,
            "qemu-audio-core-rejected:0x00000005:order=8:"
            "pc=0x00123456:port=2:value=0xab:page=1:index=0x03:control=0x5a",
        )


if __name__ == "__main__":
    unittest.main()
