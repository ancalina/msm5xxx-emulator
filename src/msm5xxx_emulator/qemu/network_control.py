"""Monitor control for the optional virtual network."""
import json
import socket
import threading
import time

from .virtual_cell import _crc30, host_sync_message_hex


def replace_sync_time(message, timestamp=None):
    """Preserve the configured network fields while replacing the clock fields."""
    source = bytes.fromhex(message)
    if len(source) != 26 or source[0] != 26 or source[1] != 1:
        raise ValueError("invalid sync message")
    current = int.from_bytes(source, "big")
    fresh = int(host_sync_message_hex(timestamp), 16)
    for start, width in ((72, 42), (114, 36), (150, 8), (158, 6), (164, 1)):
        shift = 208 - start - width
        mask = ((1 << width) - 1) << shift
        current = (current & ~mask) | (fresh & mask)
    prefix = current >> 30
    return ((prefix << 30) | _crc30(prefix, 178)).to_bytes(26, "big").hex()


class NetworkMonitor:
    def __init__(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(30)
        self.socket = self.reader = None
        self.lock = threading.Lock()
        self.sequence = 0

    def arguments(self):
        host, port = self.listener.getsockname()
        return ["-chardev", f"socket,id=networkqmp,host={host},port={port},server=off,nodelay=on",
                "-mon", "chardev=networkqmp,mode=control"]

    def connect(self):
        self.socket, _ = self.listener.accept()
        self.listener.close()
        self.listener = None
        self.socket.settimeout(3)
        self.reader = self.socket.makefile("rb")
        if "QMP" not in self._receive():
            raise RuntimeError("network monitor greeting missing")
        self._command("qmp_capabilities")

    def _receive(self):
        line = self.reader.readline(65537)
        if not line or len(line) > 65536 or not line.endswith(b"\n"):
            raise RuntimeError("invalid network monitor response")
        reply = json.loads(line)
        if not isinstance(reply, dict):
            raise RuntimeError("invalid network monitor response")
        return reply

    def _command(self, name, arguments=None):
        self.sequence += 1
        request = {"execute": name, "id": self.sequence}
        if arguments is not None:
            request["arguments"] = arguments
        self.socket.sendall((json.dumps(request) + "\n").encode())
        for _ in range(64):
            reply = self._receive()
            if reply.get("id") == self.sequence:
                if "error" in reply or "return" not in reply:
                    raise RuntimeError("network monitor: " + str(reply.get("error")))
                return reply["return"]
        raise RuntimeError("network monitor response limit")

    def update(self, timestamp=None, refresh=False):
        with self.lock:
            args = {"path": "/machine", "property": "decoder-sync-source"}
            source = self._command("qom-get", args)
            if not isinstance(source, str) or source.count(":") != 3:
                raise RuntimeError("network time update unavailable")
            route, message = source.rsplit(":", 1)
            self._command("qom-set", {**args, "value": route + ":" + replace_sync_time(message, timestamp)})
            if refresh:
                service = {"path": "/machine", "property": "virtual-service"}
                self._command("qom-set", {**service, "value": "off"})
                try:
                    time.sleep(3)
                finally:
                    self._command("qom-set", {**service, "value": "on"})

    def close(self):
        for channel in (self.reader, self.socket, self.listener):
            if channel is not None:
                channel.close()
        self.reader = self.socket = self.listener = None
