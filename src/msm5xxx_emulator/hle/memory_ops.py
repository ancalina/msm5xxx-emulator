"""HLE behavior owned by memory_ops."""
from __future__ import annotations

from ..detection.firmware import ADDRESS_SPACE
from ..detection.boot import ARM_MEMORY_CLEAR_CHUNK_SIGNATURE
from ..detection.boot import ARM_MEMORY_CLEAR_STROBE_PERIOD
from ..detection.memory_layout import ARM_MEMORY_COPY_SIGNATURE
from ..detection.memory_layout import ARM_MEMORY_COPY_TAIL
from ..detection.memory_layout import ARM_MEMORY_COPY_TAIL_OFFSET
from ..detection.boot import MEMORY_CLEAR_128_SIGNATURE
from ..detection.boot import MEMORY_CLEAR_LOOP_SIGNATURE
from ..detection.boot import MEMORY_COPY_LOOP_SIGNATURE
from ..detection.boot import REGISTER_RAMP_PREFIX
from ..core.constants import THUMB_LOW_REGISTERS
from unicorn.arm_const import UC_ARM_REG_CPSR
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn.arm_const import UC_ARM_REG_R0
from unicorn.arm_const import UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_R2
from unicorn.arm_const import UC_ARM_REG_R4
from unicorn.arm_const import UC_ARM_REG_R5
from unicorn.arm_const import UC_ARM_REG_R6
from unicorn.arm_const import UC_ARM_REG_R7
from unicorn import Uc
from unicorn import UcError
import struct


class MemoryOpsHleMixin:
    def _complete_hot_copy(self, uc: Uc, destination_register: int,
                           source_register: int, end_register: int,
                           source_temp: int, destination_temp: int,
                           exit_address: int) -> bool:
        """Bulk-complete one validated forward Thumb word copy loop."""
        registers = [uc.reg_read(register) & 0xFFFFFFFF
                     for register in THUMB_LOW_REGISTERS]
        destination = registers[destination_register]
        source = registers[source_register]
        limit = registers[end_register]
        length = limit - destination
        source_end = source + length
        bootstrap_stage = self._bootstrap_copy_stage(
            destination, source, limit, source_end, exit_address,
        )
        if (length <= 0 or length & 3 or length > self.config.ram_size
                or source_end > ADDRESS_SPACE
                or not (self._hle_destination_is_declared(destination, length)
                        or bootstrap_stage is not None)
                or not self._hle_source_is_safe(source, length)
                or max(destination, source) < min(limit, source_end)):
            return False
        try:
            data = bytes(uc.mem_read(source, length))
            # Validate the destination before changing it.  The range helper
            # is deliberately not a substitute for Unicorn's real mapping.
            uc.mem_read(destination, length)
        except UcError:
            return False
        uc.mem_write(destination, data)
        uc.ctl_remove_cache(destination, limit)
        # Preserve the instruction-order semantics of the final update block.
        uc.reg_write(THUMB_LOW_REGISTERS[source_temp], source_end)
        uc.reg_write(THUMB_LOW_REGISTERS[source_register],
                     uc.reg_read(THUMB_LOW_REGISTERS[source_temp]))
        uc.reg_write(THUMB_LOW_REGISTERS[destination_temp], limit)
        uc.reg_write(THUMB_LOW_REGISTERS[destination_register],
                     uc.reg_read(THUMB_LOW_REGISTERS[destination_temp]))
        self._set_thumb_cmp_equal_flags(uc)
        # In a block hook, an aligned PC write can make Unicorn clear T after
        # the flags register was sampled.  Commit Thumb state first and retain
        # the architectural branch bit on the target write.
        uc.reg_write(UC_ARM_REG_PC, exit_address | 1)
        if bootstrap_stage == "data":
            self._bootstrap_data_end = limit
            self._bootstrap_rom_end = source_end
        elif bootstrap_stage == "iram":
            self._bootstrap_iram_end = limit
        self.fast_memory_copies += 1
        return True

    def _complete_hot_clear(self, uc: Uc, destination_register: int,
                            temporary_register: int, zero_register: int,
                            stop: int, next_pc: int,
                            equal_flags: bool,
                            bootstrap_limit: int | None = None,
                            bootstrap_strobe: int | None = None) -> bool:
        """Clear a validated RAM span and resume at firmware-owned control flow."""
        destination = uc.reg_read(THUMB_LOW_REGISTERS[destination_register])
        length = stop - destination
        bootstrap_stage = self._bootstrap_clear_stage(
            destination, stop, bootstrap_limit, bootstrap_strobe,
        )
        if (length <= 0 or length & 3 or length > self.config.ram_size
                or not (self._hle_destination_is_declared(destination, length)
                        or bootstrap_stage is not None)):
            return False
        try:
            uc.mem_read(destination, length)
        except UcError:
            return False
        uc.mem_write(destination, b"\0" * length)
        uc.ctl_remove_cache(destination, stop)
        uc.reg_write(THUMB_LOW_REGISTERS[zero_register], 0)
        if equal_flags:
            # The native final update leaves both aliases pointing at ``stop``.
            uc.reg_write(THUMB_LOW_REGISTERS[temporary_register], stop)
            uc.reg_write(THUMB_LOW_REGISTERS[destination_register], stop)
            self._set_thumb_cmp_equal_flags(uc)
        else:
            uc.reg_write(THUMB_LOW_REGISTERS[destination_register], stop)
            uc.reg_write(UC_ARM_REG_CPSR, uc.reg_read(UC_ARM_REG_CPSR) | 0x20)
        uc.reg_write(UC_ARM_REG_PC, next_pc | 1)
        if bootstrap_stage == "open":
            assert bootstrap_limit is not None
            self._bootstrap_bss_end = bootstrap_limit
        if (bootstrap_stage in ("open", "continue")
                and self._bootstrap_bss_end is not None
                and stop == self._bootstrap_bss_end):
            self._bootstrap_bss_complete = True
        self.fast_memory_clears += 1
        return True

    def _try_hot_thumb_memory_loop(self, uc: Uc, address: int) -> bool:
        """Recognise tightly-scoped, compiler-shaped Thumb RAM init loops.

        Partial handset dumps often retain valid boot code but omit enough
        peripherals that spending millions of interpreted instructions in a
        BSS/scatter-load loop prevents reaching the first LCD task.  The HLE
        is intentionally structural rather than signature based: it accepts
        only pristine Thumb code, only after 64 repeated blocks, and only a
        fully verified header/update/body CFG whose destination is real RAM.
        """
        count = self.hot[address]
        if count < 64 or count & 0x3F:
            return False
        if not self._thumb_runtime_matches(uc, address, prefix_size=0x40):
            return False
        try:
            words = struct.unpack("<32H", uc.mem_read(address, 0x40))
        except UcError:
            return False
        compare, branch_high_or_same, skip_to_body = words[:3]
        if (compare & 0xFFC0 != 0x4280
                or branch_high_or_same & 0xFF00 != 0xD200):
            return False
        body = self._thumb_unconditional_target(address + 4, skip_to_body)
        exit_address = self._thumb_conditional_target(address + 2,
                                                      branch_high_or_same)
        if (body is None or exit_address is None
                or not address + 6 <= body <= address + 0x20
                or body >= exit_address):
            return False
        destination_register = compare & 7
        end_register = compare >> 3 & 7
        if destination_register == end_register:
            return False
        update = address + 6
        body_index = (body - address) // 2

        # Forward word copy:
        #   adds tmp,src,#4; adds src,tmp,#0;
        #   adds tmp2,dst,#4; adds dst,tmp2,#0; b header
        # body: ldr word,[src]; str word,[dst]; b update
        copy_adds = [self._thumb_add3(word) for word in words[3:7]]
        if (body == update + 10 and body_index == 8
                and all(item is not None for item in copy_adds)
                and self._thumb_unconditional_target(update + 8, words[7])
                == address and body_index + 2 < len(words)):
            source_temp, source_register, source_increment = copy_adds[0]  # type: ignore[misc]
            move_source, source_from_temp, source_move = copy_adds[1]  # type: ignore[misc]
            destination_temp, destination_from, destination_increment = copy_adds[2]  # type: ignore[misc]
            move_destination, destination_from_temp, destination_move = copy_adds[3]  # type: ignore[misc]
            load = self._thumb_memory_zero(words[body_index], 0x6800)
            store = self._thumb_memory_zero(words[body_index + 1], 0x6000)
            if (source_increment == destination_increment == 4
                    and source_move == destination_move == 0
                    and move_source == source_register
                    and source_from_temp == source_temp
                    and destination_from == destination_register
                    and move_destination == destination_register
                    and destination_from_temp == destination_temp
                    and self._thumb_unconditional_target(
                        body + 4, words[body_index + 2]
                    ) == update
                    and load is not None and store is not None
                    and load[1] == source_register and store[1] == destination_register
                    and load[0] == store[0]
                    and len({destination_register, source_register, end_register}) == 3
                    and source_temp not in {
                        destination_register, source_register, end_register
                    }
                    and destination_temp not in {
                        destination_register, source_register, end_register
                    }):
                return self._complete_hot_copy(
                    uc, destination_register, source_register, end_register,
                    source_temp, destination_temp, exit_address,
                )

        # Simple word clear:
        #   adds tmp,dst,#4; adds dst,tmp,#0; b header
        # body: movs zero,#0; str zero,[dst]; b update
        clear_adds = [self._thumb_add3(word) for word in words[3:5]]
        if (body == update + 6 and body_index == 6
                and all(item is not None for item in clear_adds)
                and self._thumb_unconditional_target(update + 4, words[5])
                == address and body_index + 2 < len(words)):
            temporary_register, source_register, increment = clear_adds[0]  # type: ignore[misc]
            move_destination, temporary_source, move = clear_adds[1]  # type: ignore[misc]
            zero_register = self._thumb_movs_zero(words[body_index])
            store = self._thumb_memory_zero(words[body_index + 1], 0x6000)
            if (increment == 4 and move == 0
                    and source_register == destination_register
                    and move_destination == destination_register
                    and temporary_source == temporary_register
                    and temporary_register not in {destination_register, end_register}
                    and zero_register is not None and store is not None
                    and store == (zero_register, destination_register)
                    and self._thumb_unconditional_target(
                        body + 4, words[body_index + 2]
                    ) == update):
                stop = uc.reg_read(THUMB_LOW_REGISTERS[end_register])
                return self._complete_hot_clear(
                    uc, destination_register, temporary_register, zero_register,
                    stop, exit_address, equal_flags=True,
                )

        # Progress clear, used by KP2000-like boot code.  Its zero-boundary
        # fallthrough often kicks a watchdog, so stop at the next boundary and
        # let the native firmware execute that single boundary iteration.
        if (body == update + 6 and body_index == 6
                and all(item is not None for item in clear_adds)
                and self._thumb_unconditional_target(update + 4, words[5])
                == address and body_index + 3 < len(words)):
            temporary_register, source_register, increment = clear_adds[0]  # type: ignore[misc]
            move_destination, temporary_source, move = clear_adds[1]  # type: ignore[misc]
            zero_register = self._thumb_movs_zero(words[body_index])
            store = self._thumb_memory_zero(words[body_index + 1], 0x6000)
            shift = self._thumb_lsls_immediate(words[body_index + 2])
            bne = words[body_index + 3]
            has_fallthrough_branch = any(
                self._thumb_unconditional_target(address + index * 2, word)
                == update
                for index, word in enumerate(words[body_index + 4:], body_index + 4)
                if address + index * 2 < exit_address
            )
            if (increment == 4 and move == 0
                    and source_register == destination_register
                    and move_destination == destination_register
                    and temporary_source == temporary_register
                    and temporary_register not in {destination_register, end_register}
                    and zero_register is not None and store is not None
                    and store == (zero_register, destination_register)
                    and shift is not None and shift[1] == destination_register
                    and 1 <= shift[2] <= 31
                    and bne & 0xFF00 == 0xD100
                    and self._thumb_conditional_target(body + 6, bne) == update
                    and has_fallthrough_branch):
                destination = uc.reg_read(THUMB_LOW_REGISTERS[destination_register])
                limit = uc.reg_read(THUMB_LOW_REGISTERS[end_register])
                period = 1 << (32 - shift[2])
                next_boundary = min(limit, (destination + period - 1) & -period)
                if next_boundary == destination:
                    return False
                return self._complete_hot_clear(
                    uc, destination_register, temporary_register, zero_register,
                    next_boundary, address, equal_flags=False,
                    bootstrap_limit=limit, bootstrap_strobe=body + 8,
                )
        return False

    def _try_hot_arm_memory_clear(self, uc: Uc, address: int) -> bool:
        """Skip one pristine ARM clear segment, preserving native strobes."""
        if uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
            return False
        try:
            expected = self._original_runtime_bytes(
                address, len(ARM_MEMORY_CLEAR_CHUNK_SIGNATURE)
            )
            if (expected != ARM_MEMORY_CLEAR_CHUNK_SIGNATURE
                    or bytes(uc.mem_read(address, len(expected))) != expected):
                return False
        except UcError:
            return False
        destination = uc.reg_read(UC_ARM_REG_R0)
        end = uc.reg_read(UC_ARM_REG_R1)
        if (uc.reg_read(UC_ARM_REG_R2) != 0
                or not self.config.ram_base <= destination < end
                <= self.config.ram_base + self.config.ram_size):
            return False
        remaining = end - destination
        boundary_remaining = remaining & -ARM_MEMORY_CLEAR_STROBE_PERIOD
        if boundary_remaining in (0, remaining):
            return False
        stop = end - boundary_remaining
        try:
            uc.mem_read(destination, stop - destination)
            uc.mem_write(destination, b"\0" * (stop - destination))
            uc.ctl_remove_cache(destination, stop)
        except UcError:
            return False
        uc.reg_write(UC_ARM_REG_R0, stop)
        uc.reg_write(UC_ARM_REG_PC, address)
        self.fast_memory_clears += 1
        return True

    def _fast_memory_clear(self, uc: Uc, address: int, size: int,
                           user_data: object) -> None:
        try:
            if not uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
                return
            old_loop = (bytes(uc.mem_read(
                address, len(MEMORY_CLEAR_LOOP_SIGNATURE)
            )) == MEMORY_CLEAR_LOOP_SIGNATURE)
            unrolled = bytes(uc.mem_read(address, 0x80))
        except UcError:
            return
        start = uc.reg_read(UC_ARM_REG_R4)
        end = uc.reg_read(UC_ARM_REG_R6)
        target = self._thumb_loop_exit(uc, address) if old_loop else None
        if (not old_loop
                and unrolled.startswith(MEMORY_CLEAR_128_SIGNATURE)
                and uc.reg_read(UC_ARM_REG_R0) == 0):
            tail = unrolled.find(bytes.fromhex("8034b442"))
            if 0 <= tail <= len(unrolled) - 6:
                branch = struct.unpack_from("<H", unrolled, tail + 4)[0]
                displacement = (branch & 0xFF) * 2
                if displacement & 0x100:
                    displacement -= 0x200
                branch_address = address + tail + 4
                if (branch & 0xFF00 == 0xD300
                        and branch_address + 4 + displacement <= address):
                    target = branch_address + 2
        ram_end = self.config.ram_base + self.config.ram_size
        if (target is None or not self.config.ram_base <= start <= end <= ram_end
                or end - start > self.config.ram_size):
            return
        length = end - start
        uc.mem_write(start, b"\0" * length)
        if length:
            uc.ctl_remove_cache(start, end)
        uc.reg_write(UC_ARM_REG_R4, end)
        uc.reg_write(UC_ARM_REG_PC, target)
        uc.reg_write(UC_ARM_REG_CPSR, uc.reg_read(UC_ARM_REG_CPSR) | 0x20)
        self.fast_memory_clears += 1

    def _fast_memory_copy(self, uc: Uc, address: int, size: int,
                          user_data: object) -> None:
        try:
            if (not uc.reg_read(UC_ARM_REG_CPSR) & 0x20
                    or bytes(uc.mem_read(address, len(MEMORY_COPY_LOOP_SIGNATURE)))
                    != MEMORY_COPY_LOOP_SIGNATURE):
                return
        except UcError:
            return
        destination = uc.reg_read(UC_ARM_REG_R4)
        source = uc.reg_read(UC_ARM_REG_R5)
        end = uc.reg_read(UC_ARM_REG_R6)
        target = self._thumb_loop_exit(uc, address)
        ram_end = self.config.ram_base + self.config.ram_size
        length = end - destination
        source_end = source + length
        source_ranges = [
            (self.config.ram_base, ram_end),
            (0x03800000, 0x03A00000),
            *((overlay.target, overlay.target + overlay.size)
              for overlay in self.config.overlays),
        ]
        if self.flash.phase == "idle":
            source_ranges.append((
                self.config.load_address,
                self.config.load_address + self.config.flash_size,
            ))
        secondary = self.config.secondary_flash_address
        if (secondary not in (None, 0) and self.secondary_flash is not None
                and self.secondary_flash.phase == "idle"):
            source_ranges.append((
                secondary, secondary + self.config.secondary_flash_size,
            ))
        source_is_backed = any(
            start <= source <= source_end <= stop for start, stop in source_ranges
        )
        overlaps = (destination != source
                    and max(destination, source) < min(end, source_end))
        if (target is None
                or not self.config.ram_base <= destination <= end <= ram_end
                or length > self.config.ram_size
                or source_end > ADDRESS_SPACE or not source_is_backed or overlaps):
            return
        try:
            data = bytes(uc.mem_read(source, length))
            if length:
                uc.mem_read(destination, length)
        except UcError:
            return
        uc.mem_write(destination, data)
        if length:
            uc.ctl_remove_cache(destination, end)
        uc.reg_write(UC_ARM_REG_R4, end)
        uc.reg_write(UC_ARM_REG_R5, source + len(data))
        uc.reg_write(UC_ARM_REG_PC, target)
        uc.reg_write(UC_ARM_REG_CPSR, uc.reg_read(UC_ARM_REG_CPSR) | 0x20)
        self.fast_memory_copies += 1

    def _fast_register_ramp(self, uc: Uc, address: int, size: int,
                            user_data: object) -> None:
        """Collapse redundant writes in a validated 50-count hardware ramp."""
        prefix_address = address - len(REGISTER_RAMP_PREFIX)
        if (not self._thumb_runtime_matches(
                uc, prefix_address, REGISTER_RAMP_PREFIX)
                or uc.reg_read(UC_ARM_REG_R0) <= 50):
            return
        try:
            loop = bytes(uc.mem_read(address, 8))
            if loop != bytes.fromhex("3c8032383228fbdc"):
                return
            target = uc.reg_read(UC_ARM_REG_R7)
            uc.mem_write(target, struct.pack("<H", uc.reg_read(UC_ARM_REG_R4) & 0xFFFF))
        except UcError:
            return
        value = uc.reg_read(UC_ARM_REG_R0)
        # Leave one final original loop iteration so flags and the following
        # interpolation calculation remain firmware-owned.
        uc.reg_write(UC_ARM_REG_R0, (value - 1) % 50 + 51)
        self.fast_register_ramps += 1

    def _fast_arm_memory_copy(self, uc: Uc, address: int, size: int,
                              user_data: object) -> None:
        """Accelerate the ARM ADS forward copier without hiding unsafe calls."""
        if uc.reg_read(UC_ARM_REG_CPSR) & 0x20:
            return
        try:
            runtime_prefix = bytes(uc.mem_read(
                address, len(ARM_MEMORY_COPY_SIGNATURE)
            ))
            runtime_tail = bytes(uc.mem_read(
                address + ARM_MEMORY_COPY_TAIL_OFFSET,
                len(ARM_MEMORY_COPY_TAIL),
            ))
        except UcError:
            return
        if (runtime_prefix != ARM_MEMORY_COPY_SIGNATURE
                or runtime_tail != ARM_MEMORY_COPY_TAIL):
            return
        destination = uc.reg_read(UC_ARM_REG_R0)
        source = uc.reg_read(UC_ARM_REG_R1)
        length = uc.reg_read(UC_ARM_REG_R2)
        destination_end = destination + length
        source_end = source + length
        ram_end = self.config.ram_base + self.config.ram_size
        destination_is_ram = (
            self.config.ram_base <= destination <= destination_end <= ram_end
            or 0x03800000 <= destination <= destination_end <= 0x03A00000
        )
        source_ranges = [
            (self.config.ram_base, ram_end),
            (0x03800000, 0x03A00000),
            *((overlay.target, overlay.target + overlay.size)
              for overlay in self.config.overlays),
        ]
        if self.flash.phase == "idle":
            source_ranges.append((
                self.config.load_address,
                self.config.load_address + self.config.flash_size,
            ))
        secondary = self.config.secondary_flash_address
        if (secondary not in (None, 0) and self.secondary_flash is not None
                and self.secondary_flash.phase == "idle"):
            source_ranges.append((
                secondary, secondary + self.config.secondary_flash_size,
            ))
        source_is_backed = any(
            start <= source <= source_end <= end for start, end in source_ranges
        )
        overlaps = (destination != source
                    and max(destination, source) < min(destination_end, source_end))
        if (not destination_is_ram or not source_is_backed
                or length > self.config.ram_size
                or destination_end > ADDRESS_SPACE or source_end > ADDRESS_SPACE
                or overlaps):
            return
        try:
            data = bytes(uc.mem_read(source, length))
            if length:
                # Validate the whole destination before changing any byte.
                uc.mem_read(destination, length)
                uc.mem_write(destination, data)
                uc.ctl_remove_cache(destination, destination_end)
        except UcError:
            return
        # The detected ADS routine advances both pointer arguments.  R2/R3/IP
        # are caller-clobbered; callers may still rely on the returned end ptr.
        uc.reg_write(UC_ARM_REG_R0, destination_end)
        uc.reg_write(UC_ARM_REG_R1, source_end)
        self._return_to_lr(uc, address, size, user_data)
        self.fast_arm_memory_copies += 1
