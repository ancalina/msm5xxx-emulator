"""Optional real-QEMU check of the generic GPIO aperture topology."""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import unittest


QEMU_ENV = "MSM5XXX_TEST_QEMU"
MSM_BASE = 0x03000000
GPIO_BASE = MSM_BASE + 0x720
GPIO_END = GPIO_BASE + 3
MSM_END = MSM_BASE + 0xFFFFFF


@unittest.skipUnless(os.environ.get(QEMU_ENV), "native QEMU not selected")
class GPIOAliasMachineMapTests(unittest.TestCase):
    @contextmanager
    def _session(self, machine_options: str = "", seed_bit9: bool = False,
                 ram_size: str = "32M"):
        native = Path(os.environ[QEMU_ENV]).resolve(strict=True)
        temporary = tempfile.TemporaryDirectory(prefix="gpio-map-qemu-")
        root = Path(temporary.name)
        qmp_path = root / "qmp.sock"
        machine = "msm5xxx-poc" + ("," + machine_options if machine_options else "")
        command = [
            str(native), "-M", machine, "-cpu", "ti925t", "-m", ram_size,
            "-S", "-display", "none", "-serial", "none", "-monitor", "none",
            "-qmp", f"unix:{qmp_path},server=on,wait=off",
        ]
        if seed_bit9:
            command.extend(("-device", "loader,addr=0x03000721,data=2,data-len=1"))
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE, text=True)
        connection = None
        reader = None
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    connection = socket.socket(socket.AF_UNIX)
                    connection.settimeout(2)
                    connection.connect(str(qmp_path))
                    break
                except OSError:
                    if connection is not None:
                        connection.close()
                    connection = None
                    if process.poll() is not None:
                        detail = process.stderr.read() if process.stderr else ""
                        self.fail(f"QEMU exited during startup: {detail}")
                    time.sleep(0.05)
            if connection is None:
                self.fail("QMP socket did not become available")
            reader = connection.makefile("r", encoding="utf-8", newline="\n")
            greeting = json.loads(reader.readline())
            self.assertIn("QMP", greeting)
            self._qmp(connection, reader, "qmp_capabilities")
            yield process, connection, reader
        finally:
            if connection is not None and reader is not None:
                try:
                    self._qmp(connection, reader, "quit")
                except (OSError, EOFError, ValueError, AssertionError, TimeoutError):
                    pass
            if process.poll() is None:
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
            if reader is not None:
                reader.close()
            if connection is not None:
                connection.close()
            if process.stderr is not None:
                process.stderr.close()
            temporary.cleanup()

    @staticmethod
    def _qmp(connection, reader, execute, arguments=None):
        request_id = int(time.monotonic_ns() & 0x7FFFFFFF)
        request = {"execute": execute, "id": request_id}
        if arguments is not None:
            request["arguments"] = arguments
        connection.sendall((json.dumps(request) + "\r\n").encode("utf-8"))
        while True:
            line = reader.readline()
            if not line:
                raise EOFError("QMP closed before returning a reply")
            response = json.loads(line)
            if response.get("id") != request_id:
                continue
            if "error" in response:
                raise AssertionError(response["error"])
            return response.get("return")

    def _hmp(self, connection, reader, command):
        return self._qmp(connection, reader, "human-monitor-command",
                         {"command-line": command})

    @staticmethod
    def _mtree_rows(output):
        rows = []
        mapped_tree = True
        pattern = re.compile(
            r"^\s*(?:0x)?([0-9a-fA-F]+)-(?:0x)?([0-9a-fA-F]+) "
            r"\(prio (-?\d+), ([^)]*)\): (.+)$")
        for line in output.splitlines():
            if line.startswith("address-space:"):
                mapped_tree = True
            elif line.startswith("memory-region:"):
                # Alias targets are listed separately from mapped address spaces.
                mapped_tree = False
            if not mapped_tree:
                continue
            match = pattern.match(line)
            if match:
                rows.append((int(match.group(1), 16), int(match.group(2), 16),
                             int(match.group(3)), match.group(4), match.group(5)))
        return rows

    def test_default_keeps_full_msm_ram_mapping(self):
        for ram_size in ("32M", "64M"):
            with self.subTest(ram_size=ram_size):
                with self._session(ram_size=ram_size) as session:
                    _process, connection, reader = session
                    rows = self._mtree_rows(
                        self._hmp(connection, reader, "info mtree"))
                    self.assertTrue(any(
                        start == MSM_BASE and end == MSM_END and
                        "ram" in kind and name == "msm5xxx-poc.msm"
                        for start, end, _prio, kind, name in rows))
                    self.assertEqual(
                        self._hmp(connection, reader,
                                  f"xp /1wx 0x{GPIO_BASE:x}")
                        .split(":")[-1].strip().split()[0], "0x00000000")

    def test_unprofiled_overlapping_ram_is_rejected_only_when_gpio_selected(self):
        native = Path(os.environ[QEMU_ENV]).resolve(strict=True)
        for gpio_property in (
                "gpio-ready-bit21=on",
                "experimental-contract-gpio-bit9-low=on"):
            with self.subTest(gpio_property=gpio_property):
                result = subprocess.run(
                    [
                        str(native), "-M", "msm5xxx-poc," + gpio_property,
                        "-cpu", "ti925t", "-m", "64M", "-S",
                        "-display", "none", "-serial", "none",
                        "-monitor", "none",
                    ],
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                    text=True, timeout=180)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "generic GPIO inputs require non-overlapping primary RAM",
                    result.stderr)

    def _assert_carved_gpio_aperture(self, options, expected, seed_bit9=False):
        with self._session(options, seed_bit9=seed_bit9) as session:
            _process, connection, reader = session
            rows = self._mtree_rows(self._hmp(connection, reader, "info mtree"))
            mapped = [row for row in rows
                      if row[0] <= GPIO_END and GPIO_BASE <= row[1]]
            # The system address-space container spans the aperture but is
            # not a decode owner; its children show the actual map entries.
            owners = [row for row in mapped if row[4] != "system"]
            self.assertEqual(len(owners), 1, owners)
            start, end, _prio, kind, name = owners[0]
            self.assertEqual((start, end), (GPIO_BASE, GPIO_END))
            self.assertIn("i/o", kind)
            self.assertEqual(name, "msm5xxx-poc.gpio-bank")
            self.assertFalse(any("ram" in row[3] and row[0] <= GPIO_END and
                                 GPIO_BASE <= row[1] for row in rows))
            value = self._hmp(connection, reader, f"xp /1wx 0x{GPIO_BASE:x}")
            self.assertIn(f"0x{expected:08x}", value)

    def test_bit21_read_and_ram_hole(self):
        self._assert_carved_gpio_aperture("gpio-ready-bit21=on", 1 << 21)

    def test_bit9_low_reads_composed_with_ready_input(self):
        self._assert_carved_gpio_aperture(
            "experimental-contract-gpio-bit9-low=on", 0, seed_bit9=True)
        self._assert_carved_gpio_aperture(
            "gpio-ready-bit21=on,experimental-contract-gpio-bit9-low=on",
            1 << 21, seed_bit9=True)


if __name__ == "__main__":
    unittest.main()
