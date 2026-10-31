"""Runtime behavior owned by input."""
from __future__ import annotations

from collections import Counter

from ..core.config import FirmwareConfig
from ..core.constants import HANDSET_KEY_COUNT
from ..detection.input import detect_input_profile
from ..detection.input_descriptor import resolve_lg_descriptor_input
from ..detection.input_matrix import UNCLASSIFIED
from ..detection.input_matrix import SAMSUNG_DUAL_PLANE_RING32
from ..detection.input_matrix import SAMSUNG_RING32
from ..detection.input_matrix import resolve_direct_matrix_input
from ..detection.rex import find_rex_legacy_5ms_irq_route
from ..detection.rex import find_rex_legacy_5ms_timer_bridge
import logging

LOGGER = logging.getLogger("msm5xxx")
SAMSUNG_RING32_KEY_EVENTS = {
    0: 0x5B, 1: 0x54, 2: 0x52, 3: 0x50, 4: 0x65, 6: 0x66, 9: 0x55,
    **dict(zip(range(11, 23), b"123456789*0#")),
}
DUAL_PLANE_5X6_KEY_EVENTS = {
    0: 0x5B, 2: 0x52, 3: 0x50, 4: 0x65, 6: 0x66,
    8: 0x55, 9: 0x64, 10: 0x54,
    **dict(zip(range(11, 23), b"123456789*0#")),
}


def _evidenced_key_events(profile: dict[str, object]) -> dict[int, int]:
    family = profile.get("event_sink_family", profile.get("family"))
    if family == SAMSUNG_RING32:
        return SAMSUNG_RING32_KEY_EVENTS
    if (family == SAMSUNG_DUAL_PLANE_RING32
            and profile.get("grammar") == "n330-5x6-dual-plane-ring32-v1"):
        return DUAL_PLANE_5X6_KEY_EVENTS
    return {}


def _evidenced_key_mapping(
        profile: dict[str, object], bit: int,
) -> dict[str, object] | None:
    event = _evidenced_key_events(profile).get(bit)
    if event is None:
        return None
    family = profile.get("event_sink_family", profile.get("family"))
    if family == SAMSUNG_RING32:
        semantic_class = "samsung-ring32-cross-firmware-key-events-v1"
        evidence = "4x6-scanner+ring32-queue+cross-firmware-runtime"
    else:
        semantic_class = "n330-5x6-native-enum-release-v1"
        evidence = "5x6-scanner+dual-plane-queue+event-plus-0x80-release"
    return {
        "event": event,
        "rule": semantic_class,
        "evidence": evidence,
    }


class InputMixin:
    def _init_input_state(self, config: FirmwareConfig) -> None:
        self.input_profile = detect_input_profile(self.image, config.load_address)
        if config.key_register is None:
            (
                self.direct_input_profile,
                self.direct_input_detection,
                self.direct_input_rejections,
            ) = resolve_direct_matrix_input(self.image, config.load_address)
            if self.direct_input_profile is None:
                descriptor, status, rejected = resolve_lg_descriptor_input(
                    self.image
                )
                self.direct_input_rejections.extend(rejected)
                if descriptor is not None:
                    overlays = config.overlays

                    def file_to_runtime(position: int) -> int:
                        for overlay in overlays:
                            if (overlay.source <= position
                                    < overlay.source + overlay.size):
                                return (
                                    overlay.target + position - overlay.source
                                )
                        layout = config.linker
                        if (layout is not None
                                and layout.data_source <= position
                                < layout.data_source + layout.data_size):
                            return (
                                layout.data_target
                                + position - layout.data_source
                            )
                        return config.load_address + position

                    def runtime_to_file(address: int) -> int | None:
                        for overlay in overlays:
                            if (overlay.target <= address
                                    < overlay.target + overlay.size):
                                return (
                                    overlay.source + address - overlay.target
                                )
                        layout = config.linker
                        if (layout is not None
                                and layout.data_target <= address
                                < layout.data_target + layout.data_size):
                            return (
                                layout.data_source
                                + address - layout.data_target
                            )
                        position = address - config.load_address
                        return position if 0 <= position < len(self.image) else None

                    bridge = find_rex_legacy_5ms_timer_bridge(
                        self.image, int(descriptor["function"]),
                        file_to_runtime, runtime_to_file,
                    )
                    route = (find_rex_legacy_5ms_irq_route(
                        self.image, bridge, file_to_runtime, runtime_to_file,
                    ) if bridge is not None else None)
                    reasons = []
                    if config.rex_idle_address is None:
                        reasons.append("rex-idle-address-missing")
                    if (descriptor.get("row_state_evidence") is None
                            and descriptor.get("row_register_evidence") is None):
                        reasons.append("row-source-unclosed")
                    global_senses = descriptor.get("global_sense_sites", ())
                    row_senses = descriptor.get("row_sense_sites", ())
                    if (len(global_senses) != 1 or not row_senses
                            or descriptor["sense_site"] not in row_senses):
                        reasons.append("sense-roles-unclosed")
                    if bridge is None:
                        reasons.append("legacy-timer-bridge-unclosed")
                    elif bridge["scanner"] != file_to_runtime(
                            int(descriptor["function"])):
                        reasons.append("scanner-timer-callback-mismatch")
                    elif route is None:
                        reasons.append("legacy-irq-route-unclosed")
                    elif route.get("controller_class") not in {
                            "legacy-c80-two-bank-group10-v1",
                            "legacy-c80-three-bank-group14-v1",
                    }:
                        reasons.append(
                            "legacy-irq-controller-class-unverified"
                        )
                    elif not self._rex_legacy_irq_route_metadata_valid(route):
                        reasons.append(
                            "legacy-irq-controller-class-unverified"
                        )
                    elif route.get("outer_callback") != bridge["outer_callback"]:
                        reasons.append("legacy-timer-route-mismatch")
                    elif (route["vector_target"] != config.ram_base
                          or not all(
                              config.ram_base <= int(route[field])
                              <= config.ram_base + config.ram_size - 4
                              for field in ("handler_slot", "callback_slot"))):
                        reasons.append("legacy-irq-route-ram-unclosed")
                    if reasons:
                        self.direct_input_rejections.append({
                            "function": descriptor["function"],
                            "grammar_fingerprint": descriptor[
                                "grammar_fingerprint"
                            ],
                            "reasons": reasons,
                        })
                        status = "rejected"
                    else:
                        scalar_fields = [
                            "function", "prologue", "sense_site",
                            "raw_enqueue", "raw_enqueue_callsite",
                        ]
                        scalar_fields.extend(
                            field for field in (
                                "raw_enqueue_store", "raw_dequeue",
                                "raw_dequeue_return", "raw_task_entry",
                            ) if descriptor.get(field) is not None
                        )
                        if descriptor.get("row_state_evidence") is not None:
                            scalar_fields.append("row_state_site")
                        list_fields = (
                            "sense_sites", "global_sense_sites",
                            "row_sense_sites", "raw_enqueue_callsites",
                        )
                        descriptor = {
                            **descriptor,
                            **{
                                field: file_to_runtime(int(descriptor[field]))
                                for field in scalar_fields
                            },
                            **{
                                field: [
                                    file_to_runtime(int(position))
                                    for position in descriptor[field]
                                ]
                                for field in list_fields
                            },
                            "register": int(
                                descriptor["absolute_roles"]["sense"]
                            ),
                            "event_sink_family": descriptor["family"],
                            "event_sink_validation":
                                "validated-raw-enqueue-callsites",
                            "timer_bridge": {**bridge, "irq_route": route},
                        }
                        descriptor["event_sink"] = descriptor["raw_enqueue"]
                        descriptor["event_sink_callsite"] = descriptor[
                            "raw_enqueue_callsite"
                        ]
                        descriptor["event_sink_callsites"] = descriptor[
                            "raw_enqueue_callsites"
                        ]
                        self.direct_input_profile = descriptor
                        config.rex_tick_address = int(bridge["outer_callback"])
                        config.rex_tick_ms = 5
                        config.rex_irq_wrapper_address = int(route["wrapper"])
                        config.rex_irq_handler_address = int(route["handler"])
                        config.rex_irq_handler_slot = int(route["handler_slot"])
                        config.rex_irq_callback_slot = int(route["callback_slot"])
                        config.rex_irq_status_address = int(route["status"])
                        config.rex_irq_enable_address = int(route["enable"])
                        config.rex_irq_mask = int(route["mask"])
                        config.rex_irq_arm_address = None
                        status = "accepted"
                if (status != "not-found"
                        or self.direct_input_detection == "not-found"):
                    self.direct_input_detection = status
        else:
            self.direct_input_profile = None
            self.direct_input_detection = "explicit-key-register-override"
            self.direct_input_rejections = []
        self.direct_input_positions = self._direct_matrix_positions(
            self.direct_input_profile
        )
        self.input_error = ""

    def can_set_key(self, bit: int, event_code: int | None = None) -> bool:
        """Report whether one GUI key can use an evidenced physical path."""
        if not 0 <= bit < HANDSET_KEY_COUNT:
            return False
        if self.config.key_register is not None:
            return event_code is None
        return (self._direct_sideband_producer(bit, event_code) is not None
                or self._direct_matrix_position(bit, event_code) is not None)


    @staticmethod
    def _direct_matrix_positions(
            profile: dict[str, object] | None) -> dict[int, tuple[int, int, int]]:
        if profile is None:
            return {}
        family = profile.get("event_sink_family", profile.get("family"))
        if family in (None, UNCLASSIFIED):
            return {}
        required = (
            "event_codes", "rows", "columns",
            "no_key",
        )
        if any(field not in profile for field in required):
            return {}
        events = list(profile["event_codes"])
        rows = int(profile["rows"])
        columns = int(profile["columns"])
        if rows <= 0 or columns <= 0:
            return {}
        senses = list(profile.get(
            "senses", profile.get("single_key_column_sense", ())
        ))
        cell_limit = min(len(events), rows * columns, rows * len(senses))
        cells = events[:cell_limit]
        event_counts = Counter(cells)
        fillers = {0, 0xFF, int(profile["no_key"]) & 0xFF}
        positions: dict[int, tuple[int, int, int]] = {}
        evidenced_events = _evidenced_key_events(profile)
        if evidenced_events:
            for bit, event in evidenced_events.items():
                if event_counts[event] != 1 or event in fillers:
                    continue
                index = cells.index(event)
                positions[bit] = (event, index % rows, index // rows)
        mappings = profile.get("provisional_mappings")
        if isinstance(mappings, dict) and mappings:
            for raw_bit, mapping in mappings.items():
                bit = int(raw_bit)
                if (not 0 <= bit < HANDSET_KEY_COUNT
                        or not isinstance(mapping, dict)):
                    continue
                event = int(mapping.get("event", -1))
                if event_counts[event] != 1 or event in fillers:
                    continue
                index = cells.index(event)
                positions[bit] = (event, index % rows, index // rows)
            return positions
        if positions:
            return positions
        candidates = (
            (int(event), index % rows, index // rows)
            for index, event in enumerate(cells)
            if (event_counts[event] == 1
                and int(event) not in fillers)
        )
        return dict(zip(range(HANDSET_KEY_COUNT), candidates))

    def _direct_matrix_position(
            self, bit: int, event_code: int | None
    ) -> tuple[int, int, int] | None:
        if event_code is None:
            return getattr(self, "direct_input_positions", {}).get(bit)
        profile = getattr(self, "direct_input_profile", None)
        if profile is None or not 0 <= event_code <= 0xFF:
            return None
        if event_code in {0, 0xFF, int(profile["no_key"]) & 0xFF}:
            return None
        events = list(profile["event_codes"])
        matches = [index for index, value in enumerate(events)
                   if value == event_code]
        if len(matches) != 1:
            return None
        rows = int(profile["rows"])
        columns = int(profile["columns"])
        index = matches[0]
        row, column = index % rows, index // rows
        if row >= rows or column >= columns:
            return None
        senses = list(profile.get(
            "senses", profile.get("single_key_column_sense", ())
        ))
        return ((event_code, row, column)
                if column < len(senses) else None)

    def _direct_sideband_producer(
            self, bit: int, event_code: int | None,
            profile: dict[str, object] | None = None,
    ) -> dict[str, object] | None:
        matches = [producer
                   for producer in self._validated_direct_sideband_producers(profile)
                   if (producer.get("semantic_key") == bit
                       and (event_code is None
                            or producer.get("event") == event_code))]
        return matches[0] if len(matches) == 1 else None

    def _validated_direct_sideband_producers(
            self, profile: dict[str, object] | None = None,
    ) -> tuple[dict[str, object], ...]:
        """Reject incomplete or mutually conflicting physical producers."""
        if profile is None:
            profile = getattr(self, "direct_input_profile", None)
        raw = (profile.get("sideband_producers", ())
               if isinstance(profile, dict) else ())
        matrix_events = (profile.get("event_codes", ())
                         if isinstance(profile, dict) else ())
        if any(isinstance(producer, dict)
               and producer.get("event") in matrix_events
               for producer in raw):
            return ()
        candidates: list[dict[str, object]] = []
        for producer in raw:
            if not isinstance(producer, dict):
                continue
            bit = producer.get("semantic_key")
            event = producer.get("event")
            register = producer.get("register")
            width = producer.get("register_width")
            mask = producer.get("mask")
            if (producer.get("semantic_status")
                    != "temporary-evidence-gated"
                    or type(bit) is not int
                    or not 0 <= bit < HANDSET_KEY_COUNT
                    or type(event) is not int or not 0 <= event <= 0xFF
                    or type(register) is not int or register < 0
                    or type(width) is not int or width not in (1, 2, 4)
                    or type(mask) is not int
                    or not 0 < mask < 1 << (width * 8)
                    or producer.get("polarity") not in {
                        "active-low", "active-high"
                    }
                    or not isinstance(producer.get("semantic_name"), str)
                    or not producer["semantic_name"]
                    or not isinstance(
                        producer.get("semantic_evidence"), str
                    )
                    or not producer["semantic_evidence"]):
                continue
            candidates.append(producer)
        conflicts: set[int] = set()
        for index, producer in enumerate(candidates):
            start = int(producer["register"])
            end = start + int(producer["register_width"])
            for other_index, other in enumerate(candidates[:index]):
                other_start = int(other["register"])
                other_end = other_start + int(other["register_width"])
                same_range = start == other_start and end == other_end
                overlap = max(start, other_start) < min(end, other_end)
                if (producer["semantic_key"] == other["semantic_key"]
                        or producer["event"] == other["event"]
                        or (overlap and (not same_range or int(producer["mask"])
                                        & int(other["mask"])))):
                    conflicts.update((index, other_index))
        return tuple(producer for index, producer in enumerate(candidates)
                     if index not in conflicts)


    @staticmethod
    def _rex_legacy_irq_route_metadata_valid(route: dict[str, object]) -> bool:
        """Validate the detector-closed interrupt controller grammar."""
        status = route.get("status")
        enable = route.get("enable")
        if not isinstance(status, int) or not isinstance(enable, int):
            return False
        controller_class = route.get("controller_class")
        if controller_class == "legacy-c80-two-bank-group10-v1":
            banks = (status, status + 4)
            clear_banks = banks
            writes = (enable, enable + 4)
            count, row_size, aperture = 2, 10, (status, enable + 6)
        elif controller_class == "legacy-c80-three-bank-group14-v1":
            banks = (status, status + 4, status + 0x30)
            clear_banks = (status, status + 4, enable + 0x38)
            writes = (enable, enable + 4, enable + 0x30)
            count, row_size, aperture = 3, 14, (status, enable + 0x3A)
        elif (controller_class
              == "legacy-msm5000-620-two-bank-read-consume-v1"):
            banks = (status, status + 4)
            count, row_size, aperture = 2, 12, (status, enable + 8)
            return (
                enable == status + 8
                and route.get("status_banks") == banks
                and route.get("mask_set_banks") == banks
                and route.get("mask_output_banks")
                == (enable, enable + 4)
                and route.get("controller_aperture") == aperture
                and route.get("status_bank_count") == count
                and route.get("group_row_size") == row_size
                and route.get("pending_read_semantics")
                == "consume-on-read"
            )
        else:
            return False
        return (
            route.get("status_banks") == banks
            and route.get("clear_banks") == clear_banks
            and route.get("controller_write_banks") == writes
            and route.get("controller_aperture") == aperture
            and route.get("status_bank_count") == count
            and route.get("group_row_size") == row_size
        )
