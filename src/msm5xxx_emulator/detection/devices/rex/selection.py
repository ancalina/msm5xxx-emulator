"""Admission and resource arbitration for native device properties."""
from __future__ import annotations

def select_controller(self, detector_image, experimental_c80, source_limit):
    self.rex_c80_profile = c80_rex_irq_profile(self.config, experimental_c80 or self.boot_format_nor_profile is not None)
    controller = getattr(self.config, "rex_static_controller_candidate", None)
    if (self.rex_c80_profile is not None and isinstance(controller, dict) and controller.get("vector_source_chain") is not None and (source_limit is None or
        find_rex_static_controller_callback_candidate(detector_image[:source_limit], ram_base=self.config.ram_base, ram_size=self.config.ram_size) != controller)):
        self.rex_c80_profile = None
        self.config.detection_notes.append("REX NOR veneer/copy closure differs from source image")
    self.rex_read_consume_profile = read_consume_rex_irq_profile(self.config, experimental_c80)
    self.rex_w1c_profile = w1c_rex_irq_profile(self.config)
    self.rex_stack_w1c_profile = None
    self.rex_stack_corrected_automatic = False
    if self.rex_c80_profile is None and self.rex_w1c_profile is None:
        stack_candidate = qemu_stack_w1c_property(detector_image,self.config)
        if self.rex_read_consume_profile is None:
            self.rex_stack_w1c_profile = stack_candidate
        elif (stack_candidate is not None and not experimental_c80 and not self.config.rex_static_controller_experimental):
            # Canonical accepted telemetry can reach this branch only
            # through the exact power-task source proof above. Preserve
            # explicit controller choices; correct this automatic tag.
            self.rex_read_consume_profile = None
            self.rex_stack_corrected_automatic = True
            self.rex_stack_w1c_profile = stack_candidate
            self.config.detection_notes.append("source ACK/W1C proof supersedes automatic read-consume telemetry")
    self.config.rex_static_controller_experimental = (self.rex_c80_profile is not None or self.rex_read_consume_profile is not None)
    return (controller,)

def project_controller(self, machine, detector_image):
    rex_fields = (self.config.rex_irq_status_address, self.config.rex_irq_enable_address, self.config.rex_irq_arm_address, self.config.rex_idle_address,)
    if getattr(self.config, "rex_basic_irq_profile", None) is not None:
        basic_property, basic_reject = qemu_basic_row0_property(self.config, detector_image)
        if self.rex_c80_profile is not None or self.rex_read_consume_profile is not None:
            basic_property, basic_reject = None, "row0-controller-owner-conflict"
        if basic_property is not None:
            machine += "," + basic_property
        elif basic_reject is not None:
            self.config.detection_notes.append(
                f"QEMU row0 IRQ rejected: {basic_reject}; native fallback retained"
            )
    elif (self.config.rex_tick_ms == 5 and self.config.rex_irq_mask and all(isinstance(value, int) for value in rex_fields)):
        status, enable, arm, idle = rex_fields
        machine += (
            f",rex-irq={status:x}:{enable:x}:{arm:x}:"
            f"{self.config.rex_irq_mask:x}:"
            f"{self.config.rex_tick_ms * 1_000_000:x}:{idle:x}"
        )
    if self.rex_c80_profile is not None:
        machine += f",rex-static-c80={self.rex_c80_profile}"
    if self.rex_read_consume_profile is not None:
        machine += (
            ",rex-static-read-consume="
            f"{self.rex_read_consume_profile}"
        )
    if self.rex_w1c_profile is not None:
        machine += f",rex-irq={self.rex_w1c_profile}"
    elif self.rex_stack_w1c_profile is not None:
        machine += f",rex-irq={self.rex_stack_w1c_profile}"
        self.config.detection_notes.append("QEMU source-closed stack W1C timer route enabled; "
            "firmware enable/acknowledgement retained, physical cadence approximated at 5 ms")
    return machine

def loaded_controller_matches(self, loaded, limit, controller):
    return not (self.rex_c80_profile is not None and isinstance(controller, dict) and controller.get('vector_source_chain') is not None and
        find_rex_static_controller_callback_candidate(loaded[:limit], ram_base=self.config.ram_base, ram_size=self.config.ram_size) != controller)

def revalidate_loaded_stack(self, machine, original, loaded):
    if (self.rex_stack_w1c_profile is not None and qemu_stack_w1c_property(original, self.config, loaded=loaded) != self.rex_stack_w1c_profile):
        if self.rex_stack_corrected_automatic:
            raise ValueError('loaded W1C source route changed; refusing automatic controller correction')
        machine = machine.replace(',rex-irq=' + self.rex_stack_w1c_profile, '', 1)
        self.rex_stack_w1c_profile = None
        self.config.detection_notes.append('W1C source IRQ rejected: loaded route changed')
    return machine

REQUIRES = {'c80_rex_irq_profile': ('rex.transport_projection', 'c80_rex_irq_profile'), 'find_rex_static_controller_callback_candidate': ('rex.rules',
    'find_rex_static_controller_callback_candidate'), 'qemu_stack_w1c_property': ('rex.transport_projection', 'qemu_stack_w1c_property'),
    'read_consume_rex_irq_profile': ('rex.transport_projection', 'read_consume_rex_irq_profile'), 'w1c_rex_irq_profile': ('rex.transport_projection',
    'w1c_rex_irq_profile'), 'qemu_basic_row0_property': ('rex.transport_projection', 'qemu_basic_row0_property')}
