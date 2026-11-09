"""Source evidence, parameters and machine projection for the SBI domain."""
from .bootstrap import (
    find_bootstraps, find_sbi_bootstrap_profile, bootstrap_layout_at,
    arm_sbi_bootstrap_at, find_arm_sbi_bootstraps,
)
from .raw import (
    find_sbi_raw_input_profile, qemu_sbi_raw_input_property,
    qemu_sbi_raw_input_property_for_images,
)
from .projection import (
    bootstrap_property, repeat_property, runtime_properties, sbi_plan,
    adc_properties, runtime_fragment,
)
from .adc import (
    board_adc_reader_at, board_adc_reader_read_offset_at,
    find_board_adc_reader, find_dc0_board_adc_profile,
    BOARD_ADC_SIGNATURE, BOARD_ADC_READER_READ_OFFSET,
)


from dataclasses import dataclass


DEFAULT_ADC_VALUE = 0xC2
ADC_READER_NOTE = "Thumb ADC reader shape and channel-gated MMIO data path detected"


@dataclass(frozen=True, slots=True)
class SourceSelection:
    board_adc_position: int | None
    board_adc_reader_position: int | None
    dc0_profile: dict | None
    bootstrap_profile: dict | None
    notes: tuple[str, ...]


def detect_profiles(image, ram_base, ram_size, chipset):
    """Collect SBI-family parameters and diagnostics from source code evidence."""
    positions = []
    cursor = image.find(BOARD_ADC_SIGNATURE)
    if cursor >= 0 and image.find(BOARD_ADC_SIGNATURE, cursor + 1) < 0:
        positions.append(cursor)
    adc = positions[0] if positions else None
    reader = find_board_adc_reader(image)
    dc0 = find_dc0_board_adc_profile(image)
    bootstrap = find_sbi_bootstrap_profile(image)
    notes = []
    if (bootstrap is not None
            and bootstrap.get('layout') == 'thumb-sbi-bootstrap-carry-loop-v1'
            and chipset not in ('MSM5100', 'MSM5105')):
        bootstrap = None
    if bootstrap is not None:
        raw, reason = find_sbi_raw_input_profile(image, bootstrap, ram_base, ram_size)
        if raw is not None:
            bootstrap['raw_input'] = raw
            notes.append('temporary source-bound SBI raw-byte consumer detected; '
                         'configured virtual input, physical channel and calibration unverified')
        else:
            bootstrap['raw_input_reject_reason'] = reason
    if dc0 is not None:
        if dc0['accepted']:
            notes.append('temporary selector-2 DC0 battery policy detected; '
                         'virtual full raw byte enabled')
        else:
            notes.append('selector-2 DC0 battery policy rejected: '+dc0['reject_reason'])
    if bootstrap is not None:
        notes.append('temporary exact SBI bootstrap-only class detected')
    return SourceSelection(adc, reader, dc0, bootstrap, tuple(notes))
