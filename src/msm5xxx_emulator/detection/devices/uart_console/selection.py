"""Device admission and property planning."""

def project_loaded_console(self, machine, detector_image, primary_seed, uart_property, uart_deferred, ram_reserved, mapped_primary_profile, upper_x16_profile,
    intel_profile, sharp_intel, amd_profile):
    if uart_property is not None and uart_deferred:
        loaded_uart, loaded_uart_reject = qemu_loaded_uart_console_property(self.config.uart_console, detector_image, primary_seed, self.config, ram_claimed=any(value
            is not None for value in (ram_reserved, mapped_primary_profile, upper_x16_profile, intel_profile if sharp_intel is None else None, amd_profile, self.config.upper_flash_address,
            self.config.secondary_flash_address, self.config.nand_image)), nor_overlay=(sharp_intel["geometry"][0], sum(sharp_intel["geometry"][:2])) if
            sharp_intel is not None else None)
        if loaded_uart is not None:
            machine += f",{loaded_uart}"
        else:
            self.config.detection_notes.append(
                f"QEMU UART console rejected: {loaded_uart_reject}; native fallback retained")
    return machine

REQUIRES = {'qemu_loaded_uart_console_property': ('uart_console', 'qemu_loaded_uart_console_property')}
