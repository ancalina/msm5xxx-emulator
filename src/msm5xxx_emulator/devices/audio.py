"""Runtime behavior owned by audio."""
from __future__ import annotations

from unicorn.arm_const import UC_ARM_REG_CPSR
from unicorn.arm_const import UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_R2
from unicorn import UC_HOOK_CODE
from unicorn import Uc
from unicorn import UcError


class AudioMixin:
    def _audio_play(self, uc: Uc, address: int, size: int,
                    user_data: object) -> None:
        self._play_mmf_arguments(uc)

    def _play_mmf_arguments(self, uc: Uc, discovery: bool = False,
                            submit: bool = True) -> bool:
        if self.audio_player is None:
            return False
        pointer = uc.reg_read(UC_ARM_REG_R1)
        requested = uc.reg_read(UC_ARM_REG_R2)
        if not 8 <= requested <= 0x01000000:
            return False
        try:
            header = bytes(uc.mem_read(pointer, 8))
            if header[:4] != b"MMMD":
                return False
            declared = int.from_bytes(header[4:8], "big") + 8
            if not 8 <= declared <= 0x01000000:
                return False
            if discovery and requested != declared:
                return False
            data = bytes(uc.mem_read(pointer, declared))
        except UcError:
            return False
        if submit:
            self.audio_play_requests += 1
            self.audio_last_size = len(data)
            self.audio_player.play_mmf(data)
        return True

    def _probe_audio_call(self, uc: Uc, address: int) -> None:
        if not uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
            return
        try:
            prologue = int.from_bytes(uc.mem_read(address, 2), "little")
        except UcError:
            return
        if (prologue & 0xFF00 != 0xB500
                or not self._play_mmf_arguments(uc, True, submit=True)):
            return
        self.audio_discovered_address = address
        self._audio_probe_hook = uc.hook_add(UC_HOOK_CODE, self._audio_play,
                                             begin=address, end=address)
