"""SoC behavior owned by adc."""
from __future__ import annotations

from ..detection.input import BOARD_ADC_READER_DATA_ADDRESS
from ..detection.boot import BOARD_ADC_READER_READ_OFFSET
from ..detection.input import BOARD_ADC_READER_SIZE
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
        self._board_adc_reader_channel = uc.reg_read(UC_ARM_REG_R0)

    def _board_adc_reader_data_read(self, uc: Uc, address: int,
                                    size: int) -> None:
        reader = self.config.board_adc_reader_address
        if (reader is None
                or address != BOARD_ADC_READER_DATA_ADDRESS
                or size != 2
                or uc.reg_read(UC_ARM_REG_PC) & ~1
                != reader + BOARD_ADC_READER_READ_OFFSET
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
