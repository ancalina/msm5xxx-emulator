"""Static contract for Android visible-frame diagnostics."""
from pathlib import Path
import importlib.util
import json
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


JAVA = (Path(__file__).parents[1]
        / "android-client/app/src/main/java/org/msm5xxx/emulator/"
        "MainActivity.java")


class AndroidFrameTransportTests(unittest.TestCase):
    def test_android_session_keeps_common_guest_cadence(self) -> None:
        path = JAVA.parents[4] / 'python/msm5xxx_android_runtime.py'
        spec = importlib.util.spec_from_file_location('android_cadence_runtime', path)
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        profile = {'test': 'cadence'}
        config = SimpleNamespace(diagnostic_config=lambda: profile, width=128,
                                 height=128, model='test', firmware_sha256='test')
        transport = SimpleNamespace(can_set_key=lambda bit: False,
                                    process=SimpleNamespace(poll=lambda: None),
                                    replay=lambda stop: stop.wait(),
                                    interrupt=lambda: None, close=lambda: None)
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'input.bin'
            binary.write_bytes(b'input')
            request = dict(experimental_rex=False, firmware=str(binary),
                           profile=profile, qemu=str(binary), state=None)
            with mock.patch('msm5xxx_emulator.detection.firmware.detect',
                            return_value=config), mock.patch(
                                'qemu_transport.Transport', return_value=transport) as constructor:
                try:
                    runtime.start_session(json.dumps(request))
                    self.assertNotIn('icount_shift', constructor.call_args.kwargs)
                    self.assertTrue(constructor.call_args.kwargs['audio_stream'])
                finally:
                    runtime.stop_session()

    def test_android_uses_selected_scanout_and_detects_power_without_sequence(self) -> None:
        path = JAVA.parents[4] / 'python/msm5xxx_android_runtime.py'
        spec = importlib.util.spec_from_file_location('android_frame_runtime', path)
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        frame = b'\x01\x02\x03' * 2
        decoder = SimpleNamespace(frame_sequence=7,
                                  display_snapshot=lambda: (2, 1, frame))
        runtime._session = SimpleNamespace(decoder=decoder,
                                           process=SimpleNamespace(poll=lambda: None))
        packet = runtime.session_frame()
        self.assertEqual(struct.unpack('<4I', packet[:16]), (1, 2, 1, 1))
        self.assertEqual(packet[16:], frame)
        self.assertEqual(len(runtime.session_frame()), 16)
        decoder.frame_sequence += 1  # Same visible frame: avoid Bitmap/hash work.
        self.assertEqual(len(runtime.session_frame()), 16)
        frame = bytes(6)  # Power changes need not increment firmware sequence.
        self.assertEqual(runtime.session_frame()[16:], frame)
        decoder.display_snapshot = lambda: (1, 2, frame)
        self.assertEqual(struct.unpack('<4I', runtime.session_frame()[:16]), (1, 1, 2, 3))
        decoder.display_snapshot = lambda: (2, 2, frame)
        with self.assertRaisesRegex(RuntimeError, 'inconsistent display snapshot'):
            runtime.session_frame()

    def test_secondary_power_and_fold_use_common_transport(self) -> None:
        path = JAVA.parents[4] / 'python/msm5xxx_android_runtime.py'
        spec = importlib.util.spec_from_file_location('android_secondary_runtime', path)
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        snapshot = dict(qualified=True, width=2, height=1,
                        frame=b'\x01\x02\x03' * 2, enabled=True)
        transitions = []
        transport = SimpleNamespace(
            decoder=SimpleNamespace(secondary_display_snapshot=lambda: snapshot),
            process=SimpleNamespace(poll=lambda: None),
            can_set_fold=lambda: True,
            set_fold=lambda opened: transitions.append(opened) or True)
        runtime._session = transport
        self.assertEqual(runtime.session_secondary_frame()[16:], snapshot['frame'])
        self.assertEqual(len(runtime.session_secondary_frame()), 16)
        snapshot['enabled'] = False
        self.assertEqual(runtime.session_secondary_frame()[16:], bytes(6))
        snapshot['qualified'] = False
        self.assertEqual(runtime.session_secondary_frame(), b'')
        snapshot['qualified'] = True
        self.assertEqual(len(runtime.session_secondary_frame()), 22)
        self.assertTrue(json.loads(runtime.session_fold('{"open":false}'))['accepted'])
        self.assertEqual(transitions, [False])
        for request in ('{"open":1}', '{"open":true,"extra":0}'):
            with self.assertRaises(ValueError):
                runtime.session_fold(request)
        transport.can_set_fold = lambda: False
        with self.assertRaisesRegex(ValueError, 'not detector-admitted'):
            runtime.session_fold('{"open":true}')
        self.assertEqual(transitions, [False])

    def test_visible_swap_keeps_packet_sequence_hash_and_generation(self) -> None:
        source = JAVA.read_text(encoding="utf-8")

        self.assertIn("int sequence = buffer.getInt();", source)
        self.assertIn(
            "digest.update(packet, offset, packet.length - offset);", source
        )
        self.assertIn("frameView.setFrame(frame, generation);", source)
        self.assertIn('"visible swap generation=" + generation', source)
        self.assertIn('" sequence=" + Integer.toUnsignedString(frame.sequence)',
                      source)
        self.assertIn('" sha256=" + frame.sha256', source)
        self.assertIn('" nonBlank=" + frame.nonBlank', source)
        self.assertIn('" geometry=" + bitmap.getWidth()', source)


if __name__ == "__main__":
    unittest.main()
