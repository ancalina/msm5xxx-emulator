from __future__ import annotations

from msm5xxx_emulator.detection.registry import device_domain

def _scan_drivers(layout):
    from . import DriverCapture, find_overlays
    rex_basic_irq_profile = None
    boot_keysense_release, _boot_key_reason = device_domain('input.capture').capture_boot_key(layout)
    spi_nv_profile, _spi_nv_reason = device_domain('storage.capture').capture_spi(layout)
    device_domain('input.capture').note_boot_key(layout, boot_keysense_release, _boot_key_reason)
    spi_nv_profile = device_domain('storage.capture').note_spi(layout, spi_nv_profile, _spi_nv_reason)
    ready_poll = device_domain('ready_poll.configuration').capture(layout)
    uart_console = device_domain('uart_console.configuration').capture(layout, ready_poll)
    (rex_static_controller_candidate, rex_static_c40_controller_observation) = (device_domain("rex.capture").capture_static(layout))
    guest_owned_status_72c, sd810_profile, board_status_input = device_domain('input.capture').capture_status(layout)
    (width, height,) = device_domain('display.capture').capture_hint(layout)
    revision = device_domain('identity.configuration').revision_text(layout.image)
    auto_relative: set[str] = set()
    def direct_signature(field: str, signature: bytes) -> int | None:
        position = layout.primary_image.find(signature)
        if (position < 0 or layout.primary_image.find(signature, position + 1) >= 0):
            return None
        auto_relative.add(field)
        return position
    audio_address = device_domain("audio.capture").capture_address(layout, direct_signature)
    (fast_boot_address, delay_address, busy_delay_address,) = device_domain('boot.capture').capture_timing(layout, direct_signature)
    (rex_tick_address, rex_idle_address, rex_5ms_pair, rex_irq_route, rex_irq_arm_address, rex_tick_ms) = device_domain("rex.capture").capture_tick(layout,
        direct_signature, auto_relative)
    (board_adc_address, board_adc_reader_position, dc0_board_adc_profile, sbi_bootstrap_profile) = (device_domain("sbi.configuration").capture_boot(layout,
        auto_relative))
    overlays = find_overlays(layout.primary_image, layout.requested_load_address)
    def mapped_position(position: int) -> tuple[int | None, bool]:
        if position < 0:
            return None, False
        for overlay in overlays:
            if overlay.source <= position < overlay.source + overlay.size:
                return overlay.target + position - overlay.source, False
        if (layout.linker is not None and layout.linker.data_source <= position < layout.linker.data_source + layout.linker.data_size):
            return layout.linker.data_target + position - layout.linker.data_source, False
        return position, True
    def runtime_position(field: str, position: int) -> int | None:
        address, relative = mapped_position(position)
        if address is not None and relative:
            auto_relative.add(field)
        return address
    def mapped_runtime(position: int) -> int | None:
        address, relative = mapped_position(position)
        if address is not None and relative:
            address += layout.requested_load_address
        return address
    def mapped_file(address: int) -> int | None:
        positions: list[int] = []
        for overlay in overlays:
            if overlay.target <= address < overlay.target + overlay.size:
                positions.append(overlay.source + address - overlay.target)
        if (layout.linker is not None and layout.linker.data_target <= address < layout.linker.data_target + layout.linker.data_size):
            positions.append(layout.linker.data_source + address - layout.linker.data_target)
        direct = address - layout.requested_load_address
        if 0 <= direct < len(layout.primary_image):
            positions.append(direct)
        candidates = { position for position in positions if mapped_runtime(position) == address }
        return next(iter(candidates)) if len(candidates) == 1 else None
    (uis_idle_entry_address, uis_idle_body_address, rex_static_controller_candidate) = device_domain("rex.capture").capture_mapped(layout, runtime_position,
        mapped_runtime, mapped_file, rex_static_controller_candidate)
    audio_transport = device_domain("audio.capture").capture_transport(layout, mapped_runtime)
    board_adc_reader_address = device_domain("sbi.configuration").project_reader(layout, runtime_position, board_adc_reader_position)
    (rex_basic_irq_profile, rex_idle_address, rex_tick_address, rex_irq_route, rex_irq_arm_address, rex_tick_ms) = (device_domain("rex.capture").capture_delivery(layout,
        rex_5ms_pair, rex_idle_address, rex_tick_address, rex_irq_route, rex_irq_arm_address, rex_tick_ms, rex_basic_irq_profile, overlays, mapped_runtime,))
    def runtime_signature(field: str, signature: bytes) -> int | None:
        position = layout.primary_image.find(signature)
        if (position < 0 or layout.primary_image.find(signature, position + 1) >= 0):
            return None
        return runtime_position(field, position)
    ma2_silent_boot_address = device_domain("audio.capture").capture_ma2(layout, runtime_position)
    (width, height, framebuffer, framebuffer_address, framebuffer_stride, framebuffer_format, framebuffer_flush_address, framebuffer_rect_flush_address,
        page_panel,) = device_domain('display.capture').capture_framebuffer(layout, runtime_position, width, height)
    return DriverCapture(audio_address=audio_address, audio_transport=audio_transport, auto_relative=auto_relative, board_adc_address=board_adc_address,
        board_adc_reader_address=board_adc_reader_address, board_status_input=board_status_input, boot_keysense_release=boot_keysense_release,
        busy_delay_address=busy_delay_address, dc0_board_adc_profile=dc0_board_adc_profile, delay_address=delay_address, fast_boot_address=fast_boot_address,
        framebuffer=framebuffer, framebuffer_address=framebuffer_address, framebuffer_flush_address=framebuffer_flush_address, framebuffer_format=framebuffer_format,
        framebuffer_rect_flush_address=framebuffer_rect_flush_address, framebuffer_stride=framebuffer_stride, guest_owned_status_72c=guest_owned_status_72c,
        height=height, ma2_silent_boot_address=ma2_silent_boot_address, mapped_file=mapped_file, mapped_position=mapped_position, mapped_runtime=mapped_runtime,
        overlays=overlays, page_panel=page_panel, ready_poll=ready_poll, revision=revision, rex_basic_irq_profile=rex_basic_irq_profile, rex_idle_address=rex_idle_address,
        rex_irq_arm_address=rex_irq_arm_address, rex_irq_route=rex_irq_route, rex_static_c40_controller_observation=rex_static_c40_controller_observation,
        rex_static_controller_candidate=rex_static_controller_candidate, rex_tick_address=rex_tick_address, rex_tick_ms=rex_tick_ms, runtime_position=runtime_position,
        runtime_signature=runtime_signature, sbi_bootstrap_profile=sbi_bootstrap_profile, sd810_profile=sd810_profile, spi_nv_profile=spi_nv_profile,
        uart_console=uart_console, uis_idle_body_address=uis_idle_body_address, uis_idle_entry_address=uis_idle_entry_address, width=width)

def _scan_resources(layout, drivers):
    from . import ResourceCapture
    (nand_bad_block_address, nand_read_address, nand_write_address, flash_id_address, descriptor_flash_id,) = device_domain('storage.capture').capture_identifiers(layout,
        drivers)
    crc16_address = device_domain('boot.capture').capture_checksum(layout, drivers)
    dmd_download_address = device_domain('dmd.configuration').capture_entry(layout, drivers)
    (primary_flash_probe_address, secondary_flash_read_address, secondary_flash_write_address, legacy_efs_page_read_address,) = device_domain('storage.capture').capture_nor(layout,
        drivers)
    (eeprom_read_address, eeprom_write_address, eeprom_geometry_address, eeprom_static_capacity,) = device_domain('eeprom.configuration').capture_entries(layout,
        drivers)
    (clear_layout, copy_layout, ramp_layout, memory_clear_addresses, memory_copy_addresses, register_ramp_addresses, arm_memory_copy_addresses,) = device_domain('memory.capture').capture_operations(layout,
        drivers)
    (raw_nand_ports, native_nand_profile, direct_middle_nand, guarded_nand, nand_enabled,) = device_domain('storage.capture').capture_nand(layout,
        nand_bad_block_address, nand_read_address, nand_write_address)
    revision_profile = device_domain('boot.capture').capture_revision(layout, drivers)
    (flash_size, adjacent, adjacent_amd, adjacent_secondary_size, compound_secondary_offset, compound_secondary_size, default_flash_state,
        default_secondary_state,) = device_domain('storage.capture').capture_geometry(layout)
    return ResourceCapture(adjacent=adjacent, adjacent_amd=adjacent_amd, adjacent_secondary_size=adjacent_secondary_size, arm_memory_copy_addresses=arm_memory_copy_addresses,
        clear_layout=clear_layout, compound_secondary_offset=compound_secondary_offset, compound_secondary_size=compound_secondary_size, copy_layout=copy_layout,
        crc16_address=crc16_address, default_flash_state=default_flash_state, default_secondary_state=default_secondary_state, descriptor_flash_id=descriptor_flash_id,
        direct_middle_nand=direct_middle_nand, dmd_download_address=dmd_download_address, eeprom_geometry_address=eeprom_geometry_address, eeprom_read_address=eeprom_read_address,
        eeprom_static_capacity=eeprom_static_capacity, eeprom_write_address=eeprom_write_address, flash_id_address=flash_id_address, flash_size=flash_size,
        guarded_nand=guarded_nand, legacy_efs_page_read_address=legacy_efs_page_read_address, memory_clear_addresses=memory_clear_addresses,
        memory_copy_addresses=memory_copy_addresses, nand_bad_block_address=nand_bad_block_address, nand_enabled=nand_enabled, nand_read_address=nand_read_address,
        nand_write_address=nand_write_address, native_nand_profile=native_nand_profile, primary_flash_probe_address=primary_flash_probe_address, ramp_layout=ramp_layout,
        register_ramp_addresses=register_ramp_addresses, revision_profile=revision_profile, secondary_flash_read_address=secondary_flash_read_address,
        secondary_flash_write_address=secondary_flash_write_address)
