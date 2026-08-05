"""SoC behavior owned by adc."""
from __future__ import annotations

from ..detection.input import (
    BOARD_ADC_READER_DATA_ADDRESS, BOARD_ADC_READER_EXTENDED_SIZE,
    BOARD_ADC_READER_SIZE,
    BOARD_ADC_READER_VARIANT_SIZE, board_adc_reader_read_offset_at,
)
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn.arm_const import UC_ARM_REG_R0
from unicorn import Uc
from unicorn import UcError


class AdcMixin:
    def _board_adc_reader_entry(self, uc: Uc, address: int, size: int,
                                user_data: object) -> None:
        if not self._thumb_runtime_matches(
                uc, address, prefix_size=BOARD_ADC_READER_SIZE):
            self._board_adc_reader_channel = None
            return
        channel = uc.reg_read(UC_ARM_REG_R0)
        self._board_adc_reader_channel = channel
        self.board_adc_channel_entries[channel] += 1

    def _board_adc_reader_data_read(self, uc: Uc, address: int,
                                    size: int) -> None:
        reader = self.config.board_adc_reader_address
        original = (self._original_runtime_bytes(
            reader, BOARD_ADC_READER_EXTENDED_SIZE) if reader is not None else None)
        if original is None and reader is not None:
            original = self._original_runtime_bytes(
                reader, BOARD_ADC_READER_VARIANT_SIZE)
        if original is None and reader is not None:
            original = self._original_runtime_bytes(reader, BOARD_ADC_READER_SIZE)
        cache = getattr(self, "_board_adc_reader_layout_cache", None)
        if cache is not None and cache[0] == original:
            read_offset = cache[1]
        else:
            read_offset = (board_adc_reader_read_offset_at(original, 0)
                           if original is not None else None)
            self._board_adc_reader_layout_cache = (original, read_offset)
        if (reader is None
                or address != BOARD_ADC_READER_DATA_ADDRESS
                or size != 2
                or read_offset is None
                or uc.reg_read(UC_ARM_REG_PC) & ~1
                != reader + read_offset
                or not self._thumb_runtime_matches(
                    uc, reader, prefix_size=BOARD_ADC_READER_SIZE)):
            return
        channel = self._board_adc_reader_channel
        self._board_adc_reader_channel = None
        if channel != 2:
            return
        try:
            current = int.from_bytes(uc.mem_read(address, size), "little")
        except UcError:
            return
        value = (current & ~0xFF) | (self.config.board_adc_value & 0xFF)
        uc.mem_write(address, value.to_bytes(size, "little"))
        self.board_adc_reads += 1
