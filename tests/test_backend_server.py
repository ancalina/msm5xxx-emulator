import io
import json
import os
import tempfile
import unittest
from pathlib import Path


class BackendServerTests(unittest.TestCase):
    """Protocol framing and the methods that need no firmware or QEMU."""

    def run_lines(self, *requests):
        from msm5xxx_emulator.backend import server
        source = io.StringIO("".join(json.dumps(r) + "\n" for r in requests) + "not json\n")
        sink = io.StringIO()
        server.serve(server.Backend(Path("/nonexistent/qemu")), source, sink)
        return [json.loads(line) for line in sink.getvalue().splitlines()]

    def setUp(self):
        self.state = tempfile.TemporaryDirectory()
        from msm5xxx_emulator.backend import session
        self.saved = session.LAST_CONFIG
        session.LAST_CONFIG = Path(self.state.name) / "last_config.json"

    def tearDown(self):
        from msm5xxx_emulator.backend import session
        session.LAST_CONFIG = self.saved
        self.state.cleanup()

    def test_framing_errors_and_order(self):
        replies = self.run_lines({"id": 1, "method": "hello"}, {"id": 2, "method": "no.such"},
                                 {"id": 3, "method": "session.state"}, {"id": 4, "method": "hello", "params": {"x": 1}})
        self.assertEqual([r["id"] for r in replies], [1, 2, 3, 4, None])
        self.assertEqual(replies[0]["result"]["protocol"], 1)
        self.assertEqual(replies[1]["error"]["code"], "unknown_method")
        self.assertEqual(replies[2]["error"]["code"], "no_session")
        self.assertEqual(replies[3]["error"]["code"], "bad_params")
        self.assertEqual(replies[4]["error"]["code"], "bad_request")

    def test_layout_covers_every_key_once(self):
        layout = self.run_lines({"id": 1, "method": "ui.layout"})[0]["result"]
        self.assertEqual(sorted(k["bit"] for k in layout["keys"]), list(range(23)))
        self.assertEqual(layout["key_hold_ms"], 150)
        self.assertEqual({m["key"] for m in layout["metrics"]}, {"run", "pc", "lcd", "frame"})

    def test_settings_round_trip_and_validation(self):
        replies = self.run_lines(
            {"id": 1, "method": "settings.set", "params": {"key": "virtual_network", "value": True}},
            {"id": 2, "method": "settings.set", "params": {"key": "virtual_network", "value": "yes"}},
            {"id": 3, "method": "settings.set", "params": {"key": "network_start_time", "value": "2026-13-40 99:99"}},
            {"id": 4, "method": "settings.get"})
        self.assertNotIn("error", replies[0])
        self.assertEqual(replies[1]["error"]["code"], "invalid_setting")
        self.assertEqual(replies[2]["error"]["code"], "network_time_error")
        self.assertIs(replies[3]["result"]["virtual_network"], True)

    def test_backend_imports_no_ui_toolkit(self):
        import subprocess
        import sys
        code = "import sys, msm5xxx_emulator.backend.server; print('tkinter' in sys.modules)"
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                             env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")})
        self.assertEqual(out.stdout.strip(), "False", out.stderr)


if __name__ == "__main__":
    unittest.main()
