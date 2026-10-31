"""Static contracts for Android input admission and boundary telemetry."""
import importlib.util
import json
import struct
from types import SimpleNamespace
from pathlib import Path
import unittest

ROOT = Path(__file__).parents[1]
JAVA = ROOT / 'android/app/src/main/java/org/msm5xxx/emulator/PythonRuntime.java'
JNI = ROOT / 'android/app/src/main/c/msm5xxx_python.c'


def method(source, signature):
    start = source.index(signature)
    brace = source.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


class AndroidInputRuntimeTests(unittest.TestCase):
    def test_key_gate_does_not_use_frame_monitor(self):
        source = JAVA.read_text()
        self.assertIn('new ReentrantLock(true)', source)
        for name in ('key', 'canKey'):
            body = method(source, 'static String ' + name + '(')
            self.assertNotIn('synchronized', body)
            self.assertLess(body.index('KEY_GATE.lock()'), body.index('native'))
            self.assertIn('finally {\n            KEY_GATE.unlock();', body)
        for name in ('frame', 'secondaryFrame'):
            body = method(source, 'static synchronized byte[] ' + name + '(')
            self.assertNotIn('KEY_GATE', body)
        self.assertNotIn('KEY_GATE', method(source, 'static synchronized String status('))

    def test_lifecycle_excludes_key_and_audio_calls(self):
        source = JAVA.read_text()
        for signature, native in (('static synchronized String start(', 'nativeStart('),
                                  ('static synchronized void stop(', 'nativeStop(')):
            body = method(source, signature)
            self.assertLess(body.index('KEY_GATE.lock()'), body.index('AUDIO_GATE.lock()'))
            self.assertLess(body.index('AUDIO_GATE.lock()'), body.index(native))
            self.assertIn('finally {\n            AUDIO_GATE.unlock();\n            KEY_GATE.unlock();', body)

    def test_session_admission_excludes_close_without_frame_lock(self):
        source = (JAVA.parent / 'BackendBridge.java').read_text()
        for signature in ('public void setKey(', 'public boolean canSetKey('):
            body = method(source, signature)
            self.assertLess(body.index('synchronized (keyLifecycle)'),
                            body.index('requireOpen();'))
            self.assertNotIn('synchronized (BackendBridge.class)', body)
        close = method(source, 'public void close() throws IOException')
        self.assertLess(close.index('synchronized (keyLifecycle)'),
                        close.index('closed = true;'))
        self.assertLess(close.index('closed = true;'), close.index('PythonRuntime.stop();'))

    def test_key_boundary_telemetry_covers_gate_and_gil_wait(self):
        body = method(JAVA.read_text(), 'static String key(')
        self.assertLess(body.index('KEY_GATE.lock()'), body.index('monitor_entry_ns='))
        self.assertLess(body.index('monitor_wait_us='), body.index('nativeKey('))
        jni = JNI.read_text()
        start = jni.index('static jstring call_python(')
        body = jni[start:jni.index('static jbyteArray call_python_bytes(', start)]
        self.assertLess(body.index('monotonic_ns()'), body.index('PyGILState_Ensure()'))
        self.assertLess(body.index('gil_acquired_ns='), body.index('PyImport_ImportModule('))
        self.assertIn('gil_wait_us=', body)
        self.assertIn('"set_session_key"', body)
        self.assertIn('"MSM5xxxInput"', body)


class AndroidFramePartsTests(unittest.TestCase):
    def setUp(self):
        path = ROOT / 'android/app/src/main/python/msm5xxx_android_runtime.py'
        spec = importlib.util.spec_from_file_location('android_parts_runtime', path)
        self.runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.runtime)

    def test_key_response_exposes_send_boundaries_without_stale_duplicate(self):
        transport = SimpleNamespace(can_set_key=lambda bit, event: True,
                                    input_send_completed_ns=0)

        def send_key(bit, pressed, event):
            transport.input_send_started_ns = 100
            transport.input_send_completed_ns = 150
            transport.input_send_duration_ns = 50
            return True

        transport.set_key = send_key
        self.runtime._session = transport
        request = json.dumps(dict(bit=1, event_code=None, pressed=True))
        response = json.loads(self.runtime.set_session_key(request))
        self.assertTrue(response['sent'])
        self.assertEqual(response['send_started_ns'], 100)
        self.assertEqual(response['send_completed_ns'], 150)
        self.assertEqual(response['send_duration_ns'], 50)
        transport.set_key = lambda *args: True
        duplicate = json.loads(self.runtime.set_session_key(request))
        self.assertFalse(duplicate['sent'])
        self.assertEqual(duplicate['send_completed_ns'], 0)
        self.assertEqual(duplicate['send_duration_ns'], 0)

    def test_parts_retain_frame_without_concatenation_and_coalesce(self):
        frame = bytes(range(6))
        decoder = SimpleNamespace(display_snapshot=lambda: (2, 1, frame))
        self.runtime._session = SimpleNamespace(
            decoder=decoder, process=SimpleNamespace(poll=lambda: None))
        header, pixels = self.runtime.session_frame_parts()
        self.assertEqual(struct.unpack('<4I', header), (1, 2, 1, 1))
        self.assertIs(pixels, frame)
        self.assertEqual(self.runtime.session_frame_parts(), (header, b''))
        frame = bytes(6)
        header, pixels = self.runtime.session_frame_parts()
        self.assertEqual(struct.unpack('<4I', header), (1, 2, 1, 2))
        self.assertIs(pixels, frame)
        decoder.display_snapshot = lambda: (3, 1, frame)
        with self.assertRaisesRegex(RuntimeError, 'inconsistent display snapshot'):
            self.runtime.session_frame_parts()

    def test_secondary_parts_preserve_power_and_disqualification(self):
        frame = bytes(range(6))
        snapshot = dict(qualified=True, width=2, height=1,
                        frame=frame, enabled=True)
        self.runtime._session = SimpleNamespace(
            decoder=SimpleNamespace(secondary_display_snapshot=lambda: snapshot),
            process=SimpleNamespace(poll=lambda: None))
        self.assertIs(self.runtime.session_secondary_frame_parts()[1], frame)
        self.assertEqual(self.runtime.session_secondary_frame_parts()[1], b'')
        snapshot['enabled'] = False
        self.assertEqual(self.runtime.session_secondary_frame_parts()[1], bytes(6))
        snapshot['qualified'] = False
        self.assertEqual(self.runtime.session_secondary_frame_parts(), (b'', b''))

    def test_jni_retains_both_parts_until_copy_completes(self):
        source = JNI.read_text()
        self.assertIn('call_python_bytes(env, "session_frame_parts")', source)
        self.assertIn('call_python_bytes(env, "session_secondary_frame_parts")', source)
        self.assertIn('call_python_bytes(env, "session_audio")', source)
        start = source.index('static jbyteArray call_python_bytes(')
        body = source[start:source.index('JNIEXPORT', start)]
        self.assertIn('INT_MAX - PyBytes_GET_SIZE(first)', body)
        begin = body.index('Py_BEGIN_ALLOW_THREADS')
        end = body.index('Py_END_ALLOW_THREADS')
        self.assertNotIn('PyBytes_', body[begin:end])
        self.assertNotIn('Py_DECREF', body[begin:end])
        self.assertGreater(body.index('    Py_DECREF(result);'), end)


if __name__ == '__main__':
    unittest.main()
