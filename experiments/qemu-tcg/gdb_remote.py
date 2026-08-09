"""Minimal GDB remote client for experimental QEMU control and checkpoints."""
from __future__ import annotations

import socket
import xml.etree.ElementTree as ET


class Remote:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    @staticmethod
    def _checksum(data: bytes) -> bytes:
        return f"{sum(data) & 0xff:02x}".encode()

    def _byte(self) -> bytes:
        value = self.sock.recv(1)
        if not value:
            raise ConnectionError("QEMU closed the GDB connection")
        return value

    def command(self, text: str) -> str:
        payload = text.encode()
        self.sock.sendall(b"$" + payload + b"#" + self._checksum(payload))
        while self._byte() != b"+":
            pass
        while self._byte() != b"$":
            pass
        raw = bytearray()
        wire = bytearray()
        escaped = False
        while True:
            byte = self._byte()
            if byte == b"#" and not escaped:
                break
            wire.extend(byte)
            if escaped:
                raw.append(byte[0] ^ 0x20)
                escaped = False
            elif byte == b"}":
                escaped = True
            else:
                raw.extend(byte)
        expected = self._byte() + self._byte()
        if self._checksum(wire) != expected.lower():
            self.sock.sendall(b"-")
            raise RuntimeError("GDB packet checksum mismatch")
        self.sock.sendall(b"+")
        return raw.decode()

    def _feature(self, name: str) -> str:
        chunks: list[str] = []
        offset = 0
        while True:
            reply = self.command(
                f"qXfer:features:read:{name}:{offset:x},1000"
            )
            if not reply or reply[0] not in "ml":
                raise RuntimeError(
                    f"target description unavailable: {name}: {reply}"
                )
            chunks.append(reply[1:])
            offset += len(reply[1:].encode())
            if reply[0] == "l":
                return "".join(chunks)

    def register_map(self) -> dict[str, int]:
        registers: dict[str, int] = {}

        def visit(name: str, next_number: int) -> int:
            root = ET.fromstring(
                self._feature(name).replace("xi:include", "include")
            )
            for element in root.iter():
                tag = element.tag.rsplit("}", 1)[-1]
                if tag == "include":
                    next_number = visit(element.attrib["href"], next_number)
                elif tag == "reg":
                    explicit = element.attrib.get("regnum")
                    number = (
                        int(explicit, 0)
                        if explicit is not None else next_number
                    )
                    registers[element.attrib["name"]] = number
                    next_number = number + 1
            return next_number

        visit("target.xml", 0)
        return registers

    def write_register(self, number: int, value: int) -> None:
        encoded = value.to_bytes(4, "little").hex()
        reply = self.command(f"P{number:x}={encoded}")
        if reply != "OK":
            raise RuntimeError(f"register {number} write failed: {reply}")

    def breakpoint(self, address: int, enabled: bool) -> None:
        kind = "Z" if enabled else "z"
        reply = self.command(f"{kind}0,{address:x},4")
        if reply != "OK":
            raise RuntimeError(
                f"breakpoint update failed at 0x{address:X}: {reply}"
            )

    def continue_execution(self) -> None:
        reply = self.command("c")
        if not reply.startswith(("S", "T")):
            raise RuntimeError(f"continue failed: {reply}")

    def step(self) -> None:
        reply = self.command("s")
        if not reply.startswith(("S", "T")):
            raise RuntimeError(f"step failed: {reply}")

    def write_memory(self, address: int, data: bytes) -> None:
        reply = self.command(f"M{address:x},{len(data):x}:{data.hex()}")
        if reply != "OK":
            raise RuntimeError(f"memory write failed at 0x{address:X}: {reply}")
