"""Deterministic write-side Yamaha transport state."""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass


_MA2_FIFO_NAMES = (
    "fm-0", "fm-1", "fm-2", "fm-3", "adpcm-sequence", "adpcm-wave",
)
_MA2_RENDER_FIFO_LIMIT = 0x10000
_MA2_RENDER_SNAPSHOT_LIMIT = 16


@dataclass(slots=True)
class _MA5FIFOReceiver:
    """Decode the bounded MA5 FIFO packet grammar."""

    state: int = 0
    delay: int = 0
    address: int = 0
    remaining: int = 0

    def _enter_payload(self, events: list[dict[str, int | str | bool]]) -> None:
        if self.state == 8:
            events.append({
                "kind": "ma5-register-packet",
                "delay": self.delay,
                "address": self.address,
            })
            self.state = 9
        elif self.state == 10:
            events.append({
                "kind": "ma5-voice-packet",
                "delay": self.delay,
                "address": self.address,
                "count": self.remaining,
            })
            self.state = 11

    def feed(self, raw: int) -> list[dict[str, int | str | bool]]:
        events: list[dict[str, int | str | bool]] = []
        raw &= 0xFF
        self._enter_payload(events)
        value = raw & 0x7F
        if self.state == 0:
            self.delay = value
            self.state = 3 if raw & 0x80 else 1
        elif self.state == 1:
            self.delay |= value << 7
            self.state = 3 if raw & 0x80 else 2
        elif self.state == 2:
            self.delay |= value << 14
            self.state = 3
        elif self.state == 3:
            self.address = value
            self.state = 8 if raw & 0x80 else 4
        elif self.state == 4:
            self.address |= value << 7
            self.state = 8 if raw & 0x80 else 5
        elif self.state == 5:
            self.address |= value << 14
            self.state = 6
        elif self.state == 6:
            self.remaining = value
            if raw & 0x80:
                self.state = 10 if self.remaining else 0
            else:
                self.state = 7
        elif self.state == 7:
            self.remaining |= value << 7
            self.state = 10 if self.remaining else 0
        elif self.state == 9:
            events.append({
                "kind": "ma5-register-write",
                "address": self.address,
                "value": value,
                "terminal": bool(raw & 0x80),
            })
            self.address += 1
            if raw & 0x80:
                self.state = 0
        elif self.state == 11:
            events.append({
                "kind": "ma5-voice-write",
                "address": self.address,
                "value": raw,
            })
            self.remaining -= 1
            if self.remaining:
                self.address += 1
            else:
                self.state = 0
        self._enter_payload(events)
        return events


class AudioTransport:
    """Normalize exact driver-site MMIO without synthesizing reads or IRQs."""

    def __init__(self, metadata: dict[str, object] | None) -> None:
        self.metadata = metadata or {
            "family": "unknown", "grammar": None,
            "static_status": "not-detected", "reject_reason": "marker-none",
        }
        self.family = str(self.metadata.get("family", "unknown"))
        self.grammar = self.metadata.get("grammar")
        self.static_status = str(
            self.metadata.get("static_status", "not-detected")
        )
        self.runtime_status = (
            "pending" if self.static_status == "accepted" else self.static_status
        )
        self.reject_reason = self.metadata.get("reject_reason")
        self.base = int(self.metadata.get("base", 0))
        self.data_offset = int(self.metadata.get("data_offset", 0))
        sites = self.metadata.get("sites", {})
        self.sites = {
            str(kind): frozenset(int(value) for value in values)
            for kind, values in sites.items()
        } if isinstance(sites, dict) else {}
        self.block_writes = frozenset(
            int(value) for value in self.metadata.get("block_write_offsets", ())
        )
        self.sequence = 0
        self.counts: Counter[str] = Counter()
        self.recent: deque[dict[str, int | str | bool | None]] = deque(maxlen=32)
        self.ma2_bank = 0
        self.ma2_index: int | None = None
        # Index stays selected; page-0 indexes 0..5 are FIFO ports.
        self.ma2_registers = bytearray(0x200)
        self._ma2_render_fifos = [bytearray() for _ in range(4)]
        self._ma2_render_overflow = [False] * 4
        self._ma2_render_timebase: int | None = None
        self._ma2_render_control = 0
        self._ma2_render_epoch = 0
        self._ma2_render_snapshots: deque[
            tuple[
                int, int, int | None, tuple[bytearray, ...],
                tuple[int, ...], tuple[bool, ...],
            ]
        ] = deque(maxlen=_MA2_RENDER_SNAPSHOT_LIMIT)
        self.renderer_status = (
            "pending"
            if self.family == "ma2" and self.static_status == "accepted"
            else "unsupported"
        )
        self.renderer_reject_reason: str | None = None
        self.ma5_index: int | None = None
        self.ma5_fifo = _MA5FIFOReceiver()
        self.ma5_registers = bytearray(0x234)
        self.ma5_voice_ram = bytearray(0x6000)

    def _site(self, kind: str, port: int, pc: int) -> bool:
        return pc in self.sites.get(f"{kind}_{port}", ())

    def owns_write(self, pc: int, address: int, size: int) -> bool:
        if self.static_status != "accepted" or size != 1:
            return False
        port = address - self.base
        return 0 <= port <= self.data_offset and self._site("write", port, pc)

    def owns_read(self, pc: int, address: int, size: int) -> bool:
        if self.static_status != "accepted" or size != 1:
            return False
        port = address - self.base
        return 0 <= port <= self.data_offset and self._site("read", port, pc)

    def _emit(self, event: dict[str, int | str | bool | None]) -> None:
        self.sequence += 1
        event["sequence"] = self.sequence
        self.recent.append(event)
        self.counts[str(event["kind"])] += 1

    def write(self, pc: int, address: int, size: int, value: int) -> bool:
        if not self.owns_write(pc, address, size):
            return False
        self.runtime_status = "active"
        port = address - self.base
        value &= 0xFF
        self.counts["raw-writes"] += 1
        if self.family == "ma2":
            self._write_ma2(port, value)
        elif self.family == "ma5":
            self._write_ma5(pc, port, value)
        return True

    def read(self, pc: int, address: int, size: int) -> bool:
        if not self.owns_read(pc, address, size):
            return False
        self.runtime_status = "active"
        port = address - self.base
        self.counts["raw-reads"] += 1
        event: dict[str, int | str | bool | None] = {
            "kind": "read-observed", "port": port, "value": None,
        }
        if self.family == "ma2" and port == self.data_offset:
            event.update(bank=self.ma2_bank, index=self.ma2_index)
        elif self.family == "ma5":
            event["index"] = self.ma5_index
        self._emit(event)
        return True

    def _write_ma2(self, port: int, value: int) -> None:
        if port == 0:
            self.ma2_index = value
            self._emit({"kind": "ma2-index", "value": value})
            return
        if port == 1:
            self._emit({"kind": "ma2-control", "value": value})
            return
        if port != self.data_offset or self.ma2_index is None:
            self.counts["unmatched-writes"] += 1
            return
        if self.ma2_index == 0x0F:
            self.ma2_bank = value & 1
            self._emit({
                "kind": "ma2-bank", "bank": self.ma2_bank, "value": value,
            })
            return
        index = self.ma2_index
        if self.ma2_bank == 0 and index <= 5:
            if index < len(self._ma2_render_fifos):
                fifo = self._ma2_render_fifos[index]
                if self._ma2_render_overflow[index]:
                    self.counts["ma2-render-discarded-bytes"] += 1
                elif len(fifo) < _MA2_RENDER_FIFO_LIMIT:
                    fifo.append(value)
                else:
                    self._ma2_render_fifos[index] = bytearray()
                    self._ma2_render_overflow[index] = True
                    self.counts["ma2-render-overflows"] += 1
            self._emit({
                "kind": "ma2-fifo-write",
                "bank": self.ma2_bank,
                "index": index,
                "fifo": index,
                "fifo_kind": _MA2_FIFO_NAMES[index],
                "value": value,
            })
            return
        address = self.ma2_bank << 8 | index
        self.ma2_registers[address] = value
        self._emit({
            "kind": "ma2-register-write",
            "bank": self.ma2_bank,
            "index": index,
            "address": address,
            "value": value,
        })
        if self.ma2_bank == 1 and index == 2:
            self._ma2_render_set_timebase(value)
        elif self.ma2_bank == 1 and index == 1:
            prior = self._ma2_render_control
            self._ma2_render_control = value
            if not prior & 1 and value & 1:
                if (self._ma2_render_snapshots.maxlen is not None
                        and len(self._ma2_render_snapshots)
                        == self._ma2_render_snapshots.maxlen):
                    self.counts["ma2-render-snapshot-drops"] += 1
                self._ma2_render_snapshots.append((
                    self._ma2_render_epoch,
                    self.sequence,
                    self._ma2_render_timebase,
                    tuple(self._ma2_render_fifos),
                    tuple(len(fifo) for fifo in self._ma2_render_fifos),
                    tuple(self._ma2_render_overflow),
                ))
                self.counts["ma2-render-start-edges"] += 1

    def _ma2_render_set_timebase(self, value: int) -> None:
        prior = self._ma2_render_timebase
        if prior is not None and prior != value:
            self._ma2_render_epoch += 1
            self._ma2_render_fifos = [bytearray() for _ in range(4)]
            self._ma2_render_overflow = [False] * 4
            self.counts["ma2-render-timebase-changes"] += 1
        elif prior is None and any(self._ma2_render_fifos):
            self._ma2_render_epoch += 1
            self._ma2_render_fifos = [bytearray() for _ in range(4)]
            self.counts["ma2-render-pre-timebase-bytes"] += 1
        self._ma2_render_timebase = value

    def drain_renderer_snapshots(self) -> tuple[dict[str, object], ...]:
        pending = tuple(self._ma2_render_snapshots)
        self._ma2_render_snapshots.clear()
        if not pending or self.family != "ma2":
            return ()
        snapshots = []
        last_rejection: str | None = None
        for epoch, sequence, timebase, buffers, lengths, overflow in pending:
            if timebase is None:
                last_rejection = "ma2-timebase-missing"
            elif (timebase >> 4) > 7 or (timebase & 0x0F) > 7:
                last_rejection = "ma2-timebase-unknown"
            elif any(overflow):
                last_rejection = "ma2-fifo-overflow"
            else:
                fifos = tuple(
                    bytes(fifo[:length])
                    for fifo, length in zip(buffers, lengths)
                )
                first = fifos[0]
                if (len(first) < 4 or first[:3] != b"\x00\xff\xf0"
                        or len(first) < 4 + first[3]):
                    last_rejection = "ma2-fifo-prefix-incomplete"
                else:
                    snapshots.append({
                        "kind": "ma2-fifo-snapshot",
                        "epoch": epoch,
                        "sequence": sequence,
                        "timebase": timebase,
                        "fifos": fifos,
                    })
                    self.counts["ma2-render-snapshots"] += 1
                    continue
            self.counts["ma2-render-rejections"] += 1
        if snapshots:
            self.renderer_status = "ready"
            self.renderer_reject_reason = None
        else:
            self.renderer_status = "rejected"
            self.renderer_reject_reason = last_rejection
        return tuple(snapshots)

    def renderer_submission(self, accepted: bool, reason: str | None = None) -> None:
        if accepted:
            self.renderer_status = "submitted"
            self.renderer_reject_reason = None
            self.counts["ma2-render-submissions"] += 1
            return
        self.renderer_status = "rejected"
        self.renderer_reject_reason = reason or "host-player-unavailable"
        self.counts["ma2-render-submission-rejections"] += 1

    def _write_ma5(self, pc: int, port: int, value: int) -> None:
        if port == 0:
            self.ma5_index = value
            self._emit({"kind": "ma5-index", "value": value})
            return
        if port != self.data_offset:
            self.counts["unmatched-writes"] += 1
            return
        self._emit({
            "kind": "ma5-data", "index": self.ma5_index, "value": value,
            "block": pc in self.block_writes,
        })
        if pc not in self.block_writes or self.ma5_index != 1:
            self.counts["ma5-immediate-writes"] += 1
            return
        self.counts["ma5-fifo-bytes"] += 1
        for event in self.ma5_fifo.feed(value):
            kind = str(event["kind"])
            address = int(event.get("address", -1))
            decoded_value = int(event.get("value", 0))
            if kind == "ma5-register-write" and 0 <= address < 0x234:
                self.ma5_registers[address] = decoded_value & 0x7F
            elif kind == "ma5-voice-write" and 0 <= address < 0x6000:
                self.ma5_voice_ram[address] = decoded_value & 0xFF
            self._emit(event)

    def telemetry(self, *, include_events: bool = True) -> dict[str, object]:
        result: dict[str, object] = {
            "family": self.family,
            "grammar": self.grammar,
            "base": f"0x{self.base:08X}" if self.base else None,
            "data_offset": self.data_offset if self.base else None,
            "static_status": self.static_status,
            "runtime_status": self.runtime_status,
            "reject_reason": self.reject_reason,
            "counts": dict(sorted(self.counts.items())),
            "ma2_page": self.ma2_bank if self.family == "ma2" else None,
            "ma5_fifo_state": self.ma5_fifo.state if self.family == "ma5" else None,
            "renderer_status": self.renderer_status,
            "renderer_reject_reason": self.renderer_reject_reason,
        }
        if include_events:
            result["recent_events"] = list(self.recent)
        return result


__all__ = ("AudioTransport",)
