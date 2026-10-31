"""Runtime behavior owned by audio."""
from __future__ import annotations


class AudioMixin:
    def _audio_transport_owns_write(
            self, uc: object | None, address: int, size: int) -> bool:
        transport = getattr(self, "audio_transport", None)
        if (transport is None
                or transport.static_status != "accepted"
                or size != 1
                or not transport.base <= address
                <= transport.base + transport.data_offset):
            return False
        return transport.owns_write(0, address, size)

    def _audio_transport_telemetry(
            self, *, include_events: bool = True) -> dict[str, object]:
        transport = getattr(self, "audio_transport", None)
        if transport is None:
            return {
                "family": "unknown", "grammar": None,
                "static_status": "not-detected",
                "runtime_status": "not-detected",
                "reject_reason": "not-initialized", "counts": {},
            }
        return transport.telemetry(include_events=include_events)
