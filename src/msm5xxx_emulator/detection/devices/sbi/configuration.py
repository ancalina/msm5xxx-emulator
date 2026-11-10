"""Projection of captured evidence into firmware configuration."""

def configuration_fields(layout, drivers, storage):
    from . import DEFAULT_ADC_VALUE
    return {'board_adc_address': drivers.board_adc_address, 'board_adc_reader_address': drivers.board_adc_reader_address, 'board_adc_value': DEFAULT_ADC_VALUE,
        'dc0_board_adc_profile': drivers.dc0_board_adc_profile, 'sbi_bootstrap_profile': drivers.sbi_bootstrap_profile}

def capture_boot(layout, auto_relative):
    from . import detect_profiles
    source = detect_profiles(layout.primary_image, layout.ram_base, layout.ram_size, layout.chipset)
    board_adc_address = source.board_adc_position
    if board_adc_address is not None:
        auto_relative.add("board_adc_address")
    board_adc_reader_position = source.board_adc_reader_position
    dc0_board_adc_profile = source.dc0_profile
    sbi_bootstrap_profile = source.bootstrap_profile
    layout.detection_notes.extend(source.notes)
    return (board_adc_address, board_adc_reader_position, dc0_board_adc_profile, sbi_bootstrap_profile,)

def project_reader(layout, runtime_position, board_adc_reader_position):
    from . import ADC_READER_NOTE
    address = (runtime_position("board_adc_reader_address", board_adc_reader_position) if board_adc_reader_position is not None else None)
    if address is not None:
        layout.detection_notes.append(ADC_READER_NOTE)
    return address
