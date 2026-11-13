"""Project detector input evidence into host key events."""
from __future__ import annotations

REQUIRES = { "SAMSUNG_RING32_KEY_EVENTS": ("input.selection", "SAMSUNG_RING32_KEY_EVENTS"), }

def _matrix_input_position(self, bit: int, event_code: int | None,) -> tuple[int, int, int] | None:
    position = _evidenced_matrix_position(self, bit, event_code)
    return position if position is not None or event_code is None else _manual_event_position(self.matrix_input_profile, event_code)

def _manual_event_position(profile, event_code: int) -> tuple[int, int, int] | None:
    """A user-entered event byte goes to its one cell in the detected ROM key table, even
    when no key semantics were proven for it."""
    if profile is None or type(event_code) is not int or event_code in {0, 0xFF, profile.get("no_key")}:
        return None
    cells = [cell for cell in profile.get("token_cells") or () if isinstance(cell, dict) and cell.get("event") == event_code]
    if len(cells) == 1 and type(cells[0].get("row")) is int and type(cells[0].get("column")) is int:
        return event_code, cells[0]["row"], cells[0]["column"]
    events, rows = profile.get("event_codes"), profile.get("rows")
    if not isinstance(events, (list, tuple)) or type(rows) is not int or rows <= 0 or list(events).count(event_code) != 1:
        return None
    index = list(events).index(event_code)
    return event_code, index % rows, index // rows

def _evidenced_matrix_position(self, bit: int, event_code: int | None,) -> tuple[int, int, int] | None:
        profile = self.matrix_input_profile
        if profile is not None and profile.get("grammar") == "distributed-seven-byte-v1":
            mapping = profile["provisional_mappings"].get(bit)
            if mapping is None or (event_code is not None and event_code != mapping["event"]):
                return None
            event = mapping["event"]
            if profile["event_codes"].count(event) != 1:
                return None
            index = profile["event_codes"].index(event)
            return event, index % profile["rows"], index // profile["rows"]
        if profile is not None and profile.get("grammar") == "indirect-halfword-seven-row-ring32-v1":
            event = ({**SAMSUNG_RING32_KEY_EVENTS, 5: 0x53, 8: 0x64, 10: 0x63}.get(bit) if event_code is None else event_code)
            cells = [cell for cell in profile["token_cells"] if cell["event"] == event]
            return ((event, cells[0]["row"], cells[0]["column"]) if len(cells) == 1 else None)
        if profile is not None and profile.get("grammar") == "indirect-halfword-table7-v1":
            physical = {0: 0x5b, 1: 0x63, 2: 0x52, 3: 0x50, 4: 0x65, 5: 0x53, 6: 0x66, 8: 0x55, 9: 0x64, 10: 0x54, **dict(zip(range(11, 23), b"123456789*0#"))}
            event = physical.get(bit) if event_code is None else event_code
            # The host token identifies a physical contact in the ROM event table.
            # The firmware still scans GPIO and produces its own queue event.
            events = profile["event_codes"]
            if type(event) is not int or event not in physical.values() or events.count(event) != 1:
                return None
            index = events.index(event)
            return event, index % 7, index // 7
        if profile is not None and profile.get("grammar") == "descriptor-row734-low5-6x5-v1":
            position = self.decoder.direct_input_positions.get(bit) if type(bit) is int and 11 <= bit <= 22 else None
            if position is None or event_code is not None and event_code != position[0]:
                return None
            return position
        if profile is None or profile.get("grammar") not in ("indirect-halfword-six-row-v1", "indirect-halfword-mapped-row-v1",
            "indirect-halfword-loop-six-row-v1", "distributed-six-byte-numeric-v1"):
            return self.decoder._direct_matrix_position(bit, event_code)
        mappings = profile.get("provisional_mappings")
        confirm = mappings.get(5) if isinstance(mappings, dict) else None
        menu = mappings.get(0) if isinstance(mappings, dict) else None
        token_cells = profile.get("token_cells")
        complete_distributed_cells = True
        complete_navigation_cells = True
        back_cells, complete_back_cells = [], True
        call_cells, complete_call_cells = [], True
        if profile["grammar"] == "distributed-six-byte-numeric-v1":
            if not isinstance(token_cells, (list, tuple)):
                return None
            valid_cells = [cell for cell in token_cells if isinstance(cell, dict) and type(cell.get("event")) is int and type(cell.get("row")) is int and 0 <=
                cell["row"] < 6 and type(cell.get("column")) is int and 0 <= cell["column"] < 4]
            original_back = [cell for cell in token_cells if isinstance(cell, dict) and cell.get("token") == "C"]
            back_cells = [cell for cell in valid_cells if cell.get("token") == "C"]
            original_call = [cell for cell in token_cells if isinstance(cell, dict) and cell.get("token") == "S"]
            call_cells = [cell for cell in valid_cells if cell.get("token") == "S"]
            complete_call_cells = len(original_call) == len(call_cells)
            complete_back_cells = len(original_back) == len(back_cells)
            token_cells = [cell for cell in token_cells if cell not in original_back + original_call]
            valid_cells = [cell for cell in valid_cells if cell.get("token") not in ("C", "S")]
            base_cells = [cell for cell in token_cells if not (isinstance(cell, dict) and cell.get("token") in ("U", "D", "L", "R"))]
            complete_distributed_cells = len(base_cells) == sum(cell.get("token") not in ("U", "D", "L", "R") for cell in valid_cells)
            complete_navigation_cells = len(token_cells) - len(base_cells) == sum(cell.get("token") in ("U", "D", "L", "R") for cell in valid_cells)
            token_cells = valid_cells
        distributed_controls = (profile["grammar"] == "distributed-six-byte-numeric-v1" and type(profile.get("rows")) is int and profile["rows"] == 6 and type(profile.get("columns"))
            is int and profile["columns"] == 4 and complete_distributed_cells and profile.get("menu_mapping_status") == "accepted-provisional" and profile.get("ok_mapping_status")
            == "accepted-provisional" and isinstance(menu, dict) and isinstance(confirm, dict) and menu.get("rule") ==
            "same-image-distributed-functional-menu-v1" and confirm.get("rule") == "same-image-distributed-functional-confirm-v1" and all(mapping.get("semantic_status")
            == "temporary-evidence-gated-provisional" and mapping.get("functional_only") is True and type(mapping.get("event")) is int and mapping["event"] ==
            event for mapping, event in ((menu, 0x5B), (confirm, 0x53))))
        if distributed_controls:
            events = profile.get("event_codes")
            if (not isinstance(events, (list, tuple)) or len(events) != 24 or any(type(event) is not int or not 0 <= event <= 255 for event in events)):
                distributed_controls = False
            else:
                for token, event in (("M", 0x5B), ("O", 0x53)):
                    cells = [cell for cell in token_cells if cell.get("token") == token]
                    if (events.count(event) != 1 or len(cells) != 1 or type(cells[0].get("event")) is not int or type(cells[0].get("row")) is not int or type(cells[0].get("column"))
                        is not int or cells[0] != {"token": token, "event": event, "row": events.index(event) % 6, "column": events.index(event) // 6}):
                        distributed_controls = False
                        break
        navigation, navigation_token = None, None
        navigation_cells = ((1, "U", 0x63), (9, "D", 0x64), (4, "L", 0x65), (6, "R", 0x66))
        consumer = profile.get("navigation_consumer")
        control = profile.get("control_consumer")
        navigation_valid = (distributed_controls and complete_navigation_cells and profile.get("navigation_mapping_status") == "accepted-provisional" and
            isinstance(consumer, dict) and isinstance(control, dict) and consumer.get("grammar") == "distributed-menu-grid-navigation-v1" and control.get("grammar")
            == "distributed-queued-direct-word-controls-v1" and type(consumer.get("grid_stride")) is int and consumer["grid_stride"] == 3 and all(type(consumer.get(field))
            is int and consumer[field] > 0 and type(control.get(root)) is int and consumer[field] == control.get(root) for field, root in (("handler",
            "confirm_handler"), ("status", "confirm_status"), ("global_word", "global_word"))))
        if navigation_valid:
            for key, token, raw in navigation_cells:
                mapping = mappings.get(key)
                cells = [cell for cell in token_cells if cell.get("token") == token]
                if (not any(type(k) is int and k == key for k in mappings) or not isinstance(mapping, dict) or mapping.get("rule") !=
                    "same-image-distributed-functional-navigation-v1" or mapping.get("semantic_status") != "temporary-evidence-gated-provisional" or mapping.get("functional_only")
                    is not True or type(mapping.get("event")) is not int or mapping["event"] != raw or events.count(raw) != 1 or len(cells) != 1 or sum(cell["event"]
                    == raw for cell in token_cells) != 1 or cells[0] != {"token": token, "event": raw, "row": events.index(raw) % 6, "column": events.index(raw)
                    // 6}):
                    navigation_valid = False
                    break
            if navigation_valid and type(bit) is int:
                for key, token, _ in navigation_cells:
                    if bit == key:
                        navigation, navigation_token = mappings[key], token
                        break
        back = mappings.get(2) if isinstance(mappings, dict) else None
        back_consumer = profile.get("back_consumer")
        back_valid = (navigation_valid and complete_back_cells and profile.get("back_mapping_status") == "accepted-provisional" and isinstance(back_consumer,
            dict) and back_consumer.get("grammar") == "distributed-saved-menu-back-v1" and all(type(back_consumer.get(field)) is int and back_consumer[field] ==
            consumer[field] for field in ("handler", "status", "global_word")) and all(type(back_consumer.get(field)) is int and back_consumer[field] > 0 and
            back_consumer[field] % 4 == 0 for field in ("history", "comparison_descriptor", "saved_menu_comparison")) and any(type(key) is int and key == 2 for
            key in mappings) and isinstance(back, dict) and back.get("rule") == "same-image-distributed-functional-back-v1" and back.get("semantic_status") ==
            "temporary-evidence-gated-provisional" and back.get("functional_only") is True and type(back.get("event")) is int and back["event"] == 0x52 and
            events.count(0x52) == 1 and len(back_cells) == 1 and sum(cell["event"] == 0x52 for cell in token_cells) == 0 and back_cells[0] == {"token": "C",
            "event": 0x52, "row": events.index(0x52) % 6, "column": events.index(0x52) // 6})
        call_mapping = mappings.get(3) if isinstance(mappings, dict) else None
        call_consumer = profile.get("call_consumer")
        call_valid = (distributed_controls and complete_call_cells and profile.get("call_mapping_status") == "accepted-provisional" and isinstance(call_consumer,
            dict) and isinstance(control, dict) and call_consumer.get("grammar") == "distributed-queued-context-exit-v1" and control.get("grammar") ==
            "distributed-queued-direct-word-controls-v1" and all(type(call_consumer.get(field)) is int and 0 < call_consumer[field] <= 0xFFFFFFFF and type(control.get(root))
            is int and call_consumer[field] == control[root] for field, root in (("handler", "confirm_handler"), ("status", "confirm_status"), ("global_word",
            "global_word"))) and type(call_consumer.get("event")) is int and call_consumer["event"] == 0x50 and type(call_consumer.get("request_code")) is int
            and call_consumer["request_code"] == 0x32 and any(type(key) is int and key == 3 for key in mappings) and isinstance(call_mapping, dict) and
            call_mapping.get("rule") == "same-image-distributed-functional-call-v1" and call_mapping.get("semantic_status") ==
            "temporary-evidence-gated-provisional" and call_mapping.get("functional_only") is True and type(call_mapping.get("event")) is int and call_mapping["event"]
            == 0x50 and events.count(0x50) == 1 and len(call_cells) == 1 and sum(cell["event"] == 0x50 for cell in token_cells) == 0 and call_cells[0] == {"token":
            "S", "event": 0x50, "row": events.index(0x50) % 6, "column": events.index(0x50) // 6})
        functional_call = call_valid and type(bit) is int and bit == 3
        if call_valid:
            token_cells = token_cells + call_cells
        functional_back = back_valid and type(bit) is int and bit == 2
        if back_valid:
            token_cells = token_cells + back_cells
        if profile["grammar"] == "distributed-six-byte-numeric-v1" and not navigation_valid:
            token_cells = [cell for cell in token_cells if cell.get("token") not in ("U", "D", "L", "R")]
        functional_menu = distributed_controls and type(bit) is int and bit == 0
        functional_confirm = (type(bit) is int and bit == 5 and profile.get("ok_mapping_status") == "accepted-provisional" and isinstance(confirm, dict) and ((profile["grammar"]
            == "indirect-halfword-loop-six-row-v1" and confirm.get("rule") == "same-image-loop-functional-confirm-v1") or (profile["grammar"] ==
            "indirect-halfword-mapped-row-v1" and type(profile.get("rows")) is int and type(profile.get("columns")) is int and (profile.get("rows"), profile.get("columns"))
            == (7, 4) and profile.get("menu_mapping_status") == "accepted-provisional" and isinstance(menu, dict) and menu.get("rule") ==
            "same-image-mapped-physical-menu-v1" and menu.get("semantic_status") == "temporary-evidence-gated-provisional" and menu.get("physical_only") is True
            and type(menu.get("event")) is int and menu["event"] == 0x5B and confirm.get("rule") == "same-image-mapped-functional-confirm-v1") or
            distributed_controls) and confirm.get("semantic_status") == "temporary-evidence-gated-provisional" and confirm.get("functional_only") is True and
            type(confirm.get("event")) is int and confirm["event"] == 0x53)
        physical_menu = (profile["grammar"] == "indirect-halfword-mapped-row-v1" and type(bit) is int and bit == 0 and profile.get("menu_mapping_status") ==
            "accepted-provisional" and isinstance(menu, dict) and menu.get("rule") == "same-image-mapped-physical-menu-v1" and menu.get("semantic_status") ==
            "temporary-evidence-gated-provisional" and menu.get("physical_only") is True and type(menu.get("event")) is int and menu["event"] == 0x5B)
        event = (call_mapping["event"] if functional_call else back["event"] if functional_back else navigation["event"] if navigation is not None else confirm["event"]
            if functional_confirm else menu["event"] if physical_menu or functional_menu else SAMSUNG_RING32_KEY_EVENTS.get(bit)) if event_code is None else event_code
        if (profile["grammar"] in ("indirect-halfword-mapped-row-v1", "distributed-six-byte-numeric-v1", "indirect-halfword-loop-six-row-v1") and (type(event)
            is not int or event not in b"123456789*0#")):
            mapping = (call_mapping if functional_call else back if functional_back else navigation if navigation is not None else confirm if functional_confirm
                else menu if physical_menu or functional_menu else None)
            if type(event) is not int or mapping is None or event != mapping["event"]:
                return None
            events = profile.get("event_codes", ())
            token, rows = (("S", 6) if functional_call else ("C", 6) if functional_back else (navigation_token, 6) if navigation is not None else ("O", 7 if
                profile["grammar"] == "indirect-halfword-mapped-row-v1" else 6) if functional_confirm else ("M", 6 if functional_menu else 7))
            tokens = [cell for cell in token_cells if cell.get("token") == token]
            if (not isinstance(events, (list, tuple)) or len(events) != rows * 4 or events.count(event) != 1 or len(tokens) != 1):
                return None
            index = events.index(event)
            if tokens[0] != {"token": token, "event": event, "row": index % rows, "column": index // rows}:
                return None
        cells = [cell for cell in token_cells if cell["event"] == event]
        # No table-order fallback or ambiguous semantic aliases.
        if len(cells) != 1:
            return None
        cell = cells[0]
        return cell["event"], cell["row"], cell["column"]

def _sideband_input_producer(self, bit: int, event_code: int | None,) -> dict[str, object] | None:
        if (self.matrix_input_profile is not None and self.matrix_input_profile.get("sd810_end_contact") is True and bit == 7 and event_code in (None, 0x51)):
            return {"register_width": 1, "polarity": "active-low", "mask": 0x10}
        if (self.matrix_input_profile is not None and self.matrix_input_profile.get("grammar") == "distributed-seven-byte-v1"):
            contact = self.matrix_input_sideband_producer
            return contact if bit == 7 and (event_code is None or event_code == contact["event"]) else None
        if (self.matrix_input_profile is not None and self.matrix_input_profile.get("grammar") == "distributed-six-byte-numeric-v1"):
            if getattr(self, "matrix_input_sideband_producer", None) is None:
                return None
            producer = self.decoder._direct_sideband_producer(bit, event_code, self.matrix_input_profile)
            return (producer if producer == self.matrix_input_sideband_producer else None)
        if (self.matrix_input_profile is not None and self.matrix_input_profile.get("grammar") in ("indirect-halfword-six-row-v1",
            "indirect-halfword-mapped-row-v1", "indirect-halfword-loop-six-row-v1",)):
            return None
        producer = self.decoder._direct_sideband_producer(bit, event_code)
        return (producer if producer == self.matrix_input_sideband_producer else None)
