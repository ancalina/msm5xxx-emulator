"""Runtime behavior owned by input."""
from __future__ import annotations

from ..core.constants import HANDSET_KEY_COUNT
from msm5xxx_emulator.detection.registry import device_domain

_selection = device_domain("input.selection")
SAMSUNG_RING32_KEY_EVENTS = _selection.SAMSUNG_RING32_KEY_EVENTS
DUAL_PLANE_5X6_KEY_EVENTS = _selection.DUAL_PLANE_5X6_KEY_EVENTS


class InputMixin:
    _init_input_state = _selection.init_input_state
    _direct_matrix_positions = staticmethod(_selection.direct_matrix_positions)
    _direct_matrix_position = _selection.direct_matrix_position
    _direct_sideband_producer = _selection.direct_sideband_producer
    _validated_direct_sideband_producers = _selection.validated_direct_sideband_producers
    _rex_legacy_irq_route_metadata_valid = staticmethod(
        _selection._rex_legacy_irq_route_metadata_valid
    )

    def can_set_key(self, bit: int, event_code: int | None = None) -> bool:
        """Report whether one GUI key can use an evidenced physical path."""
        if not 0 <= bit < HANDSET_KEY_COUNT:
            return False
        if self.config.key_register is not None:
            return event_code is None
        return (self._direct_sideband_producer(bit, event_code) is not None
                or self._direct_matrix_position(bit, event_code) is not None)
