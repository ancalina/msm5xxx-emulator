"""Runtime behavior owned by audio."""
from __future__ import annotations

from unicorn.arm_const import UC_ARM_REG_CPSR
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn.arm_const import UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_R2
from unicorn import UC_HOOK_CODE
from unicorn import Uc
from unicorn import UcError


class AudioMixin:
    def _audio_transport_owns_write(
            self, uc: Uc | None, address: int, size: int) -> bool:
        transport = getattr(self, "audio_transport", None)
        if (uc is None or transport is None
                or transport.static_status != "accepted"
                or size != 1
                or not transport.base <= address
                <= transport.base + transport.data_offset):
            return False
        pc = uc.reg_read(UC_ARM_REG_PC) & ~1
        return transport.owns_write(pc, address, size)

    def _audio_transport_telemetry(
            self, *, include_events: bool = True) -> dict[str, object]:
        transport = getattr(self, "audio_transport", None)
        if transport is None:
            return {
                "family": "unknown", "grammar": None,
                "static_status": "not-detected",
                "runtime_status": "not-detected",
                "reject_reason": "not-initialized", "counts": {},
            }
        return transport.telemetry(include_events=include_events)

    def _audio_transport_write(
            self, uc: Uc, access: int, address: int, size: int,
            value: int, user_data: object) -> None:
        pc = uc.reg_read(UC_ARM_REG_PC) & ~1
        self.audio_transport.write(pc, address, size, value)

    def _audio_transport_read(
            self, uc: Uc, access: int, address: int, size: int,
            value: int, user_data: object) -> None:
        pc = uc.reg_read(UC_ARM_REG_PC) & ~1
        self.audio_transport.read(pc, address, size)

    def _flush_audio_transport_renderer(self) -> None:
        transport = getattr(self, "audio_transport", None)
        if transport is None:
            return
        snapshots = transport.drain_renderer_snapshots()
        if not snapshots:
            return
        player = getattr(self, "audio_player", None)
        if getattr(self, "fault", None) is not None:
            transport.renderer_submission(False, "guest-fault")
        elif player is None or not hasattr(player, "play_ma2_snapshots"):
            transport.renderer_submission(False, "host-player-unavailable")
        else:
            accepted = bool(player.play_ma2_snapshots(snapshots))
            transport.renderer_submission(
                accepted,
                None if accepted else getattr(
                    player, "last_submit_error", None
                ),
            )

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
        if prologue & 0xFF00 != 0xB500:
            if self.config.load_address <= address < self.primary_rom_end:
                self._audio_probe_rejections.add(address)
            return
        if not self._play_mmf_arguments(uc, True, submit=True):
            return
        self.audio_discovered_address = address
        self._audio_probe_hook = uc.hook_add(UC_HOOK_CODE, self._audio_play,
                                             begin=address, end=address)
