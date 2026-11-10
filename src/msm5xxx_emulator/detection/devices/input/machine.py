"""Admission and resource arbitration for native device properties."""
from __future__ import annotations
from msm5xxx_emulator.core.config import BoardStatusInput
from msm5xxx_emulator.core.constants import STABLE_MSM_MMIO

def select_inputs(self, detector_image, legacy_keypad, machine, experimental_distributed, experimental_halfword, experimental_low5, experimental_ma5_irq,
    experimental_status_level, temporary):
    direct = self.decoder.direct_input_profile
    seven_row, _ = find_seven_row_input_profile(detector_image, self.config.load_address)
    if seven_row is not None and self.config.board_status_input is None:
        lid = seven_row["lid_input"]
        self.config.board_status_input = BoardStatusInput(lid["address"], lid["mask"], lid["open_value"])
        self.config.detection_notes.append("source-closed seven-row scanner: default open lid contact")
    board_status = self.config.board_status_input
    if qemu_legacy_keypad_status_available(legacy_keypad, board_status):
        board_status = BoardStatusInput(0x03000664, 0x10, 0x10)
        machine += ",board-status-input-peer=300066c:20:20"
        direct = legacy_keypad
        self.decoder.direct_input_profile = direct
        self.decoder.direct_input_positions = self.decoder._direct_matrix_positions(direct)
        machine += (f",matrix-gpio=3000694:{direct['presence_site']:x}:"
                    f"{direct['sense_site'] + 2:x}:3000660:3f:0:0:0:0:10")
        self.matrix_input_profile = direct
        self.config.detection_notes.append("source GPIO keypad and external board inputs")
    else:
        legacy_keypad = None
    self._sd840_status_source_closed = bool(board_status is None and direct is not None and qemu_sd840_status_source(detector_image, self.config, direct))
    self._kp2100_status_source_closed = bool(board_status is None and direct is not None and qemu_kp2100_low5_property(detector_image, self.config, direct) is
        not None and qemu_kp2100_status_source(detector_image, self.config, direct) and qemu_lg_matrix_irq_property(self.config, direct) is not None and (self.rex_c80_profile
        is None or qemu_matching_lg_irq(self.rex_c80_profile, qemu_lg_matrix_irq_property(self.config, direct))) and self.rex_read_consume_profile is None and
        self.rex_w1c_profile is None and self.rex_stack_w1c_profile is None and not experimental_ma5_irq)
    if self._sd840_status_source_closed or self._kp2100_status_source_closed:
        # The scanner's admission gate consumes this active-high status.
        board_status = BoardStatusInput(0x03000720, 1, 1)
        self.config.board_status_input = board_status
    seven_row_status = find_seven_row_board_status(detector_image)
    sd810_status = (board_status is not None and getattr(self.config, "sd810_gpio_profile", None) == (0x03000720, 1, 1) and self.config.chipset == "MSM5100" and
        (board_status.address, board_status.mask, board_status.default) == (0x03000720, 1, 1))
    if board_status is not None:
        machine += ',' + _required_board_contact_property_value(board_status)
        if sd810_status or self._sd840_status_source_closed or self._kp2100_status_source_closed:
            # The firmware keeps the port pointer in descriptor + 4.
            # Native code verifies it before overlaying this input bit.
            descriptor = 0x01816618 if sd810_status else int(direct['descriptor_pointer'])
            machine += f",board-status-descriptor={descriptor:x}"
    fold_irq = None
    if (sd810_status and direct is not None and not experimental_ma5_irq and type(direct.get("raw_enqueue")) is int):
        bridge = direct.get("timer_bridge")
        route = bridge.get("irq_route") if isinstance(bridge, dict) else None
        if isinstance(route, dict):
            fold_irq = sd810_fold_irq_source(detector_image, int(direct["raw_enqueue"]) - self.config.load_address, route,)
    self._sd810_fold_source_closed = fold_irq is not None
    if fold_irq is not None:
        group, vector, callback, slot, handler = fold_irq
        callback = ((callback & ~1) + self.config.load_address) | 1
        handler = ((handler & ~1) + self.config.load_address) | 1
        machine += (f",sd810-fold-irq={group:x}:{vector:x}:{callback:x}:"
                    f"{slot:x}:{handler:x}")
    if (direct is not None and direct is not legacy_keypad and direct.get("grammar") == "direct-low-nibble-6-row-v1" and int(direct.get("sense_bits", 0)) == 4):
        register = int(direct["register"])
        reset = next((value[0] for address, value in STABLE_MSM_MMIO if address == register and len(value) == 1), None)
        if reset is not None:
            sideband_producers = [producer for producer in self.decoder._validated_direct_sideband_producers() if int(producer["register"]) == register and int(producer["register_width"])
                == 1 and producer["polarity"] == "active-low" and int(producer["mask"]) & 0x0f == 0 and int(producer["mask"]) & (int(producer["mask"]) - 1) == 0
                and int(producer["mask"]) & reset == int(producer["mask"])]
            sideband = (sideband_producers[0] if len(sideband_producers) == 1 else None)
            sideband_mask = int(sideband["mask"]) if sideband else 0
            sense_bitmap = sum(1 << sense for sense in matrix_senses(direct))
            machine += (
                f",matrix-input={register:x}:"
                f"{int(direct['sense_site']):x}:"
                f"{int(direct['no_key']):x}:{reset:x}:"
                f"{int(direct['row_register']):x}:"
                f"{int(direct['rows']):x}:{sideband_mask:x}:"
                f"{sense_bitmap:x}"
            )
            self.matrix_input_profile = direct
            self.matrix_input_sideband_producer = sideband
    sd840_source_closed = (direct is not None and qemu_sd840_low5_contacts(detector_image, self.config, direct) is not None)
    matrix_irq = qemu_lg_matrix_irq_property(self.config, direct)
    matrix_irq_available = bool(qemu_matching_lg_irq(self.rex_c80_profile, matrix_irq) or (self.rex_c80_profile is None and matrix_irq is not None and self.rex_read_consume_profile
        is None and self.rex_w1c_profile is None and self.rex_stack_w1c_profile is None and not experimental_ma5_irq))
    sd9210_source_closed = (direct is not None and qemu_sd9210_low5_contacts(detector_image, self.config, direct) is not None and matrix_irq_available)
    if sd840_source_closed or sd9210_source_closed:
        # The table proves digit identities, but not the nonnumeric
        # physical labels. Do not fall back to positional key numbering.
        direct = qemu_sd840_numeric_profile(direct)
        self.decoder.direct_input_profile = direct
        self.decoder.direct_input_positions = self.decoder._direct_matrix_positions(direct)
    kp_property = (qemu_kp_low5_property(detector_image, self.config, direct) if matrix_irq_available else None)
    if kp_property is not None:
        machine += f",{kp_property}"
        self.matrix_input_profile = direct
    kp2600_property = (qemu_kp2600_matrix_property(detector_image, self.config, direct) if qemu_kp2600_irq_compatible(self.rex_c80_profile, self.rex_read_consume_profile,
        self.rex_w1c_profile, self.rex_stack_w1c_profile, experimental_ma5_irq) else None)
    if kp2600_property is not None:
        machine += f",{kp2600_property}"
        self.matrix_input_profile = direct
    kp2100_property = (qemu_kp2100_low5_property(detector_image, self.config, direct) if matrix_irq_available else None)
    if kp2100_property is not None:
        direct = qemu_sd840_numeric_profile(direct)
        self.decoder.direct_input_profile = direct
        self.decoder.direct_input_positions = self.decoder._direct_matrix_positions(direct)
        machine += f",{kp2100_property}"
        self.matrix_input_profile = direct
    sv130_source_closed = bool(direct is not None and self.rex_c80_profile is None and self.rex_read_consume_profile is None and self.rex_w1c_profile is None
        and self.rex_stack_w1c_profile is None and not experimental_ma5_irq and self.config.rex_irq_arm_address is None and sv130_keypad_source(detector_image,
        self.config, direct) and _rex_legacy_irq_route_metadata_valid(direct['timer_bridge']['irq_route']))
    if sv130_source_closed:
        direct = qemu_sd840_numeric_profile(direct)
        self.decoder.direct_input_profile = direct
        self.decoder.direct_input_positions = self.decoder._direct_matrix_positions(direct)
        machine += ",matrix-sv130=on,rex-sv130=on"
        self.matrix_input_profile = direct
    if experimental_low5 or sd810_status or sd840_source_closed or sd9210_source_closed:
        low5_property, low5_reject = qemu_low5_matrix_property(detector_image, self.config, direct)
        if low5_property is not None:
            machine += f",{low5_property}"
            if sd810_status:
                verified = qemu_sd810_sxs_menu_selection(detector_image, self.config, direct)
                if verified is not None:
                    direct = verified
                    self.decoder.direct_input_profile = direct
                    self.decoder.direct_input_positions = (self.decoder._direct_matrix_positions(direct))
            self.matrix_input_profile = direct
            if sd810_status:
                # The pre-scan active-low contact emits the KEYEMUL E event.
                direct["sd810_end_contact"] = True
            self.config.detection_notes.append("QEMU five-column matrix temporary: descriptor/selector-gated electrical input")
            if (self.rex_c80_profile is None and self.rex_read_consume_profile is None and self.rex_w1c_profile is None and self.rex_stack_w1c_profile is None):
                input_rex_property, input_rex_reject = (qemu_low5_rex_c80_property(self.config, direct))
                if input_rex_property is not None:
                    self.rex_c80_profile = input_rex_property.split("=", 1)[1]
                    self.config.rex_static_controller_experimental = True
                    self.config.detection_notes.append("QEMU explicit low-five input enables its closed 5 ms C80 parent route; live vector and callback gates remain active")
                    seed_range = qemu_sv130_initial_ram_seed(detector_image, self.config, direct, input_rex_property, enabled=experimental_low5,)
                    if seed_range is not None:
                        seed_offset, seed_size, seed_base = seed_range
                        seed_path = temporary / "sv130-initial-ram-seed.raw"
                        seed_path.write_bytes(detector_image[seed_offset:seed_offset + seed_size])
                        self.ram_seed_loader_args = [
                            "-device",
                            f"loader,file={seed_path},addr=0x{seed_base:x},force-raw=on",
                        ]
                        self.config.detection_notes.append("QEMU explicit SV130 input experiment seeds the full validated RAM image; default RAM remains unseeded")
                elif input_rex_reject is not None:
                    self.config.detection_notes.append(
                        f"QEMU low-five C80 parent route rejected: {input_rex_reject}; scanner remains untriggered"
                    )
        elif low5_reject is not None:
            self.config.detection_notes.append(
                f"QEMU five-column matrix rejected: {low5_reject}; native fallback retained"
            )
    if (self.matrix_input_profile is not None and self.rex_c80_profile is None and matrix_irq_available and matrix_irq is not None):
        self.rex_c80_profile = matrix_irq
        self.config.rex_static_controller_experimental = True
    if experimental_halfword or direct is None:
        halfword, status, _ = resolve_indirect_matrix_input(detector_image, self.config.load_address)
        if halfword is not None and direct is None:
            halfword_property, status = qemu_halfword_matrix_property(detector_image, self.config, halfword, enabled=experimental_halfword)
            if halfword_property is not None:
                machine += f",{halfword_property}"
                self.matrix_input_profile = halfword
                self.config.detection_notes.append("QEMU halfword matrix temporary: static scanner; live descriptor gates")
                if not experimental_halfword and halfword.get("scan_gates") is not None:
                    self.config.detection_notes.append("QEMU mapped input provisional: scan-enabled contact/status levels; "
                        "physical roles unassigned; live descriptor/read-site gates")
        elif halfword is not None:
            status = "conflicting-direct-profile"
        if self.matrix_input_profile is not halfword or halfword is None:
            self.config.detection_notes.append(
                f"QEMU halfword matrix rejected: {status}; native fallback retained"
            )
    if experimental_distributed and seven_row is not None and direct is None and self.matrix_input_profile is None:
        machine += "," + qemu_seven_row_matrix_property(detector_image, self.config, seven_row)
        self.matrix_input_profile = seven_row
        contact = seven_row["sideband_input"]
        self.matrix_input_sideband_producer = { "register": contact["address"], "register_width": 1, "mask": contact["mask"], "polarity": "active-low",
            "semantic_key": 7, "event": contact["press_event"], }
        self.config.detection_notes.append("seven-row distributed GPIO keypad enabled; native seven-row support required")
    elif experimental_distributed:
        distributed, status, _ = resolve_distributed_matrix_input(detector_image, self.config.load_address)
        if distributed is not None and direct is None and self.matrix_input_profile is None:
            distributed_property, status = qemu_distributed_matrix_property(detector_image, self.config, distributed)
            if distributed_property is not None:
                machine += f",{distributed_property}"
                self.matrix_input_profile = distributed
                self.matrix_input_sideband_producer, _ = qemu_distributed_sideband_producer(detector_image, self.config, distributed)
                if status is not None:
                    self.config.detection_notes.append(
                        f"QEMU distributed sideband rejected: {status}; native fallback retained")
                self.config.detection_notes.append("QEMU distributed matrix temporary: numeric-only; live GPIO selectors")
        elif distributed is not None:
            status = "conflicting-matrix-profile"
        if distributed is None or self.matrix_input_profile is not distributed:
            self.config.detection_notes.append(
                f"QEMU distributed matrix rejected: {status}; native fallback retained"
            )
    if self.matrix_input_profile is None and direct is None:
        table7 = find_table7_matrix(detector_image)
        if table7 is not None:
            if (self.config.load_address == 0 and self.config.ram_base <= table7["descriptor"] <= self.config.ram_base + self.config.ram_size - 0x38 and all(0
                <= a <= min(len(detector_image), self.config.flash_size) - n for a, n in table7["dependencies"])):
                machine += (f",matrix-halfword={table7['descriptor']:x}:"
                            f"{table7['presence_site']:x}:{table7['sense_site']:x}:"
                            f"{table7['row_select_mask']:x},matrix-halfword-electrical=on")
                self.matrix_input_profile = table7
                self.config.detection_notes.append("Table-driven 7x4 GPIO matrix: released columns and separate "
                    "active-low scan contact; numeric semantics from same-image table")
    status_property, status_reject = qemu_halfword_status_property(detector_image, self.config.load_address, self.matrix_input_profile,
        experimental_status_level, board_status)
    if status_property is not None:
        machine += f",{status_property}"
        self.config.detection_notes.append("QEMU status input provisional: scan-enabled electrical level; " "live descriptor gate; physical role unassigned" if
            experimental_status_level is None else "QEMU status input experimental: explicit electrical level; "
            "live descriptor gate; physical role unassigned")
    elif status_reject is not None:
        self.config.detection_notes.append(
            f"QEMU status input rejected: {status_reject}; native fallback retained"
        )
    return (machine, legacy_keypad, board_status, seven_row_status, status_property,)

def project_boot_keys(self, machine, detector_image):
    boot_property, boot_reject = qemu_boot_keysense_property(self.config, detector_image, input_claimed=(self.matrix_input_profile is not None or self.decoder.direct_input_profile
        is not None),)
    if boot_property is not None:
        machine += "," + boot_property
        self.config.detection_notes.append("QEMU source-PC-bound boot key release enabled; active keys unchanged")
    elif boot_reject is not None:
        self.config.detection_notes.append(
            f"QEMU boot key release rejected: {boot_reject}; native fallback retained"
        )
    return machine, boot_property

def project_loaded_contact(self, machine, boot_property, detector_image, primary_seed, status_property, experimental_halfword, experimental_low5,
    experimental_status_level, eeprom_profile, ram_reserved, primary_profile, record_profile, mapped_primary_profile, upper_x16_profile, intel_profile,
    amd_profile):
    contact_candidate = getattr(self.config, "boot_keysense_release", None)
    if (isinstance(contact_candidate, dict) and contact_candidate.get("signature") == "arm-thumb-single-boot-contact-v1"):
        boot_property, contact_reject = qemu_boot_contact_property(self.config, detector_image, primary_seed, input_claimed=(self.matrix_input_profile is not
            None or self.decoder.direct_input_profile is not None or status_property is not None or experimental_halfword or experimental_low5 or
            experimental_status_level is not None), eeprom_window=eeprom_gpio_window(eeprom_profile), layout_claimed=any(value is not None for value in (ram_reserved,
            primary_profile, record_profile, mapped_primary_profile, upper_x16_profile, intel_profile, amd_profile, self.config.upper_flash_address, self.config.secondary_flash_address,
            self.config.native_nand_profile, self.config.nand_image)))
        if boot_property is not None:
            machine += "," + boot_property
            self.config.detection_notes.append("source-bound released boot contact enabled at its single guest read")
        elif contact_reject is not None:
            self.config.detection_notes.append(
                f"QEMU boot contact rejected: {contact_reject}; native fallback retained")
    return machine, boot_property

def validate_loaded_status(loaded, board_status, seven_row_status):
    if (seven_row_status is not None and board_status == seven_row_status and find_seven_row_board_status(loaded) != seven_row_status):
        raise ValueError('loaded seven-row lid source mismatch')

def project_row734(self, machine, detector_image, boot_property, status_property, experimental_halfword, experimental_low5, experimental_status_level,
    eeprom_profile):
    row_property, row_reject = qemu_row734_property(detector_image, self.config, self.row734_source_profile, input_claimed=(self.matrix_input_profile is not
        None or boot_property is not None or status_property is not None or experimental_halfword or experimental_low5 or experimental_status_level is not None),
        eeprom_window=eeprom_gpio_window(eeprom_profile))
    if row_property is not None:
        machine += "," + row_property
        self.matrix_input_profile = self.row734_source_profile
        direct_profile = dict(self.row734_source_profile, function=self.row734_source_profile["dispatcher"], event_sink_family=self.row734_source_profile["family"],
            evidence="source-bound descriptor/scanner/byte-ring; numeric mapping provisional", grammar_fingerprint=self.row734_source_profile["grammar"])
        self.decoder.direct_input_profile = direct_profile
        self.decoder.direct_input_positions = self.decoder._direct_matrix_positions(direct_profile)
        self.decoder.direct_input_detection = "source-native-row734"
        self.config.detection_notes.append("QEMU source-bound row734 matrix enabled; numeric mappings provisional, "
            "auxiliary identity and physical timing unverified; secondary UI consumer unverified")
    elif row_reject is not None:
        self.row734_reject_reason = row_reject
        self.config.detection_notes.append(
            f"QEMU row734 rejected: {row_reject}; native fallback retained")
    return machine

REQUIRES = {'find_seven_row_board_status': ('input.seven_row', 'find_seven_row_board_status'), 'find_seven_row_input_profile': ('input.distributed7',
    'find_seven_row_input_profile'), 'matrix_senses': ('input.transport_projection', 'matrix_senses'), 'qemu_distributed_matrix_property': ('input.transport_projection',
    'qemu_distributed_matrix_property'), 'qemu_distributed_sideband_producer': ('input.transport_projection', 'qemu_distributed_sideband_producer'),
    'qemu_halfword_matrix_property': ('input.transport_projection', 'qemu_halfword_matrix_property'), 'qemu_halfword_status_property': ('input.transport_projection',
    'qemu_halfword_status_property'), 'qemu_kp2100_low5_property': ('input.transport_projection', 'qemu_kp2100_low5_property'), 'qemu_kp2100_status_source': ('input.transport_projection',
    'qemu_kp2100_status_source'), 'qemu_kp2600_irq_compatible': ('input.transport_projection', 'qemu_kp2600_irq_compatible'), 'qemu_kp2600_matrix_property': ('input.transport_projection',
    'qemu_kp2600_matrix_property'), 'qemu_kp_low5_property': ('input.transport_projection', 'qemu_kp_low5_property'), 'qemu_legacy_keypad_status_available': ('input.transport_projection',
    'qemu_legacy_keypad_status_available'), 'qemu_lg_matrix_irq_property': ('input.transport_projection', 'qemu_lg_matrix_irq_property'),
    'qemu_low5_matrix_property': ('input.transport_projection', 'qemu_low5_matrix_property'), 'qemu_low5_rex_c80_property': ('input.transport_projection',
    'qemu_low5_rex_c80_property'), 'qemu_matching_lg_irq': ('input.transport_projection', 'qemu_matching_lg_irq'), 'qemu_sd810_sxs_menu_selection': ('input.transport_projection',
    'qemu_sd810_sxs_menu_selection'), 'qemu_sd840_low5_contacts': ('input.transport_projection', 'qemu_sd840_low5_contacts'), 'qemu_sd840_numeric_profile': ('input.transport_projection',
    'qemu_sd840_numeric_profile'), 'qemu_sd840_status_source': ('input.transport_projection', 'qemu_sd840_status_source'), 'qemu_sd9210_low5_contacts': ('input.transport_projection',
    'qemu_sd9210_low5_contacts'), 'qemu_seven_row_matrix_property': ('input.transport_projection', 'qemu_seven_row_matrix_property'),
    'qemu_sv130_initial_ram_seed': ('input.transport_projection', 'qemu_sv130_initial_ram_seed'), 'resolve_distributed_matrix_input': ('input.matrix',
    'resolve_distributed_matrix_input'), 'resolve_indirect_matrix_input': ('input.halfword', 'resolve_indirect_matrix_input'), 'sd810_fold_irq_source': ('input.sd810',
    'sd810_fold_irq_source'), 'sv130_keypad_source': ('input.sv130', 'sv130_keypad_source'), 'find_table7_matrix': ('input.table7', 'find_table7_matrix'),
    '_required_board_contact_property_value': ('board_contact', 'property_value'), '_rex_legacy_irq_route_metadata_valid': ('rex.route_metadata',
    'legacy_irq_route_metadata_valid'), 'qemu_boot_keysense_property': ('input.transport_projection', 'qemu_boot_keysense_property'),
    'qemu_boot_contact_property': ('external_bus.transport_projection', 'qemu_boot_contact_property'), 'eeprom_gpio_window': ('eeprom', 'eeprom_gpio_window'),
    'qemu_row734_property': ('input.transport_projection', 'qemu_row734_property')}

def single_boot_contact(config):
    profile = getattr(config, 'boot_keysense_release', None)
    return isinstance(profile, dict) and profile.get('signature') == 'arm-thumb-single-boot-contact-v1'
