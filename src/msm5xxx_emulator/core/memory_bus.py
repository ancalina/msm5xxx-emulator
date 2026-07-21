"""GenericMSMEmulator memory bus methods."""
from __future__ import annotations

from collections import Counter
from .constants import LCD_MMIO_PRIMARY_COMMAND_SIZE
from .constants import LCD_MMIO_PRIMARY_END
from .constants import LCD_MMIO_PRIMARY_START
from .constants import MAX_DYNAMIC_PAGES
from .constants import PAGE
from unicorn import UC_MEM_FETCH_UNMAPPED
from unicorn import UC_MEM_READ_UNMAPPED
from unicorn import UC_PROT_READ
from unicorn import UC_PROT_WRITE
from unicorn import Uc
from unicorn import UcError
from unicorn.arm_const import UC_ARM_REG_LR
from unicorn.arm_const import UC_ARM_REG_PC
from unicorn.arm_const import UC_ARM_REG_R0
from unicorn.arm_const import UC_ARM_REG_R1
from unicorn.arm_const import UC_ARM_REG_R2
from unicorn.arm_const import UC_ARM_REG_R3
from unicorn.arm_const import UC_ARM_REG_R4
from unicorn.arm_const import UC_ARM_REG_R5
from unicorn.arm_const import UC_ARM_REG_R6
from unicorn.arm_const import UC_ARM_REG_R7
import struct
import logging

LOGGER = logging.getLogger("msm5xxx")


class MemoryBusMixin:
    def _unmapped(self, uc: Uc, access: int, address: int, size: int,
                  value: int, user_data: object) -> bool:
        event: dict[str, int | str] = {
            "access": access, "address": address, "size": size, "value": value,
        }
        pc = uc.reg_read(UC_ARM_REG_PC)
        if isinstance(pc, int):
            event["pc"] = pc & 0xFFFFFFFF
        self.last_unmapped = event
        if access == UC_MEM_FETCH_UNMAPPED:
            event["outcome"] = "fault-fetch"
            self.unmapped_accesses.append(event)
            self._chunk_unmapped = event
            return False
        if self._attach_lazy_secondary_nor(uc, access, address, size, value):
            event["outcome"] = "lazy-secondary-nor"
            self.unmapped_accesses.append(event)
            return True
        # Later MSM5500 boards use addresses throughout the primary LCD
        # controller aperture, not just its command page. It is already a
        # reserved non-executable device range and is covered by the LCD
        # observation hook, so expand it lazily as one RW bank rather than
        # consuming the general partial-dump map budget one 4 KiB page at a
        # time. This preserves bad-code-pointer detection while allowing the
        # real controller register bank to initialize.
        if (LCD_MMIO_PRIMARY_START + LCD_MMIO_PRIMARY_COMMAND_SIZE
                <= address < LCD_MMIO_PRIMARY_END):
            if not self._lcd_mmio_extended_mapped:
                try:
                    uc.mem_map(
                        LCD_MMIO_PRIMARY_START + LCD_MMIO_PRIMARY_COMMAND_SIZE,
                        LCD_MMIO_PRIMARY_END
                        - (LCD_MMIO_PRIMARY_START + LCD_MMIO_PRIMARY_COMMAND_SIZE),
                        UC_PROT_READ | UC_PROT_WRITE,
                    )
                except UcError:
                    event["outcome"] = "fault-lcd-map"
                    self.unmapped_accesses.append(event)
                    self._chunk_unmapped = event
                    return False
                self._lcd_mmio_extended_mapped = True
                LOGGER.info("lazy-mapped LCD MMIO aperture 0x%08X..0x%08X",
                            LCD_MMIO_PRIMARY_START + LCD_MMIO_PRIMARY_COMMAND_SIZE,
                            LCD_MMIO_PRIMARY_END)
            event["outcome"] = "lazy-lcd-mmio"
            self.unmapped_accesses.append(event)
            return True
        if address >= 0x80000000:
            event["outcome"] = "fault-high-address"
            self.unmapped_accesses.append(event)
            self._chunk_unmapped = event
            return False
        page = address & -PAGE
        first_dynamic_page = page not in self.dynamic_pages
        if first_dynamic_page and len(self.dynamic_pages) >= MAX_DYNAMIC_PAGES:
            self.fault = (f"dynamic data mapping limit ({MAX_DYNAMIC_PAGES * PAGE // 0x100000} MiB) "
                          f"at 0x{address:08X}")
            event["outcome"] = "fault-dynamic-limit"
            self.unmapped_accesses.append(event)
            self._chunk_unmapped = event
            return False
        try:
            # Dynamically discovered data/MMIO must never silently become
            # executable code when a partial dump later jumps into the hole.
            uc.mem_map(page, PAGE, UC_PROT_READ | UC_PROT_WRITE)
            self.dynamic_pages.add(page)
        except UcError:
            event["outcome"] = "fault-page-map"
            self.unmapped_accesses.append(event)
            self._chunk_unmapped = event
            return False
        event["outcome"] = "dynamic-rw-page"
        if first_dynamic_page:
            first_access = dict(event)
            first_access["page"] = page
            first_access["first_access"] = (
                "read" if access == UC_MEM_READ_UNMAPPED else "write"
            )
            self.dynamic_page_first_accesses.append(first_access)
        self.unmapped_accesses.append(event)
        return True

    def _trace(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        if self._flash_restore:
            self._restore_flash_once(uc, address, size, user_data)
        if self._rex_irq_pending[0] and self._rex_irq_boundary(uc, address):
            return
        self.tail.append(address)
        self.hot[address] += 1
        count = self.hot[address]
        if address == self.config.load_address + self.config.entry:
            self.reset_entries += 1
        if (getattr(self, "audio_player", None) is not None
                and self.config.audio_play_address is None
                and self.audio_discovered_address is None):
            self._probe_audio_call(uc, address)
        in_primary = (self.config.load_address <= address
                      < self.config.load_address + len(self.image))
        if in_primary and address < self.primary_rom_end:
            stream = b""
            zero_stream = False
            missing_overlay = None
        else:
            try:
                stream = bytes(uc.mem_read(address, min(max(size, 4), 16)))
                zero_stream = not any(stream)
            except UcError:
                stream = b""
                zero_stream = False
            missing_overlay = next((
                item for item in self.config.missing_overlays
                if item.target <= address < item.target + item.size
            ), None)
        if (missing_overlay is not None and stream
                and stream[0] in (0, 0xFF)
                and all(byte == stream[0] for byte in stream)):
            self.fault = self._missing_overlay_error(missing_overlay)
            uc.emu_stop()
            return
        if (self.primary_rom_end <= address
                < self.config.load_address + len(self.image)
                and stream and all(byte == 0xFF for byte in stream)):
            self.fault = (
                "execution entered erased NOR padding beyond partial dump at "
                f"0x{address:08X} (supplied end 0x{self.primary_rom_end:08X}; "
                f"flash end 0x{self.config.load_address + len(self.image):08X})"
            )
            uc.emu_stop()
            return
        if not in_primary and zero_stream:
            self.zero_fetches += 1
            if self.zero_fetches >= 8:
                dependency = next((item for item in self.config.runtime_overlays
                                   if item.target <= address
                                   < item.target + item.size), None)
                source_empty = False
                if dependency is not None:
                    try:
                        source_empty = not any(uc.mem_read(
                            dependency.source,
                            min(dependency.size, 64),
                        ))
                    except UcError:
                        source_empty = True
                if dependency is not None and source_empty:
                    self.fault = (
                        "runtime executable overlay source is zero-filled in "
                        "current SDRAM state: "
                        f"SDRAM 0x{dependency.source:08X}.."
                        f"0x{dependency.source + dependency.size:08X} has no "
                        "nonzero bytes before "
                        f"0x{address:08X} can execute"
                    )
                else:
                    self.fault = f"zero-filled instruction stream at 0x{address:08X}"
                uc.emu_stop()
        else:
            self.zero_fetches = 0
        if self.fault is None and count >= 64 and not count & 0x3F:
            if (self._try_hot_arm_memory_clear(uc, address)
                    or self._try_hot_thumb_memory_loop(uc, address)):
                self.hot_loop_hle_used = True

    def _read(self, uc: Uc, access: int, address: int, size: int,
              value: int, user_data: object) -> None:
        pc = uc.reg_read(UC_ARM_REG_PC) & ~1
        try:
            if struct.unpack("<H", uc.mem_read(pc + 2, 2))[0] == 0x4770:
                pc = uc.reg_read(UC_ARM_REG_LR) & ~1
        except UcError:
            pass
        self._record_key_register_read(address, size, pc)
        self._board_adc_reader_data_read(uc, address, size)
        self._refresh_board_status_input(uc, address, size)
        status = getattr(self.config, "rex_irq_status_address", None)
        controller = (status is not None
                      and max(address, status) < min(address + size, status + 0x10))
        masks = None if controller else self.ready_bits.get((address, size))
        if masks:
            current = int.from_bytes(uc.mem_read(address, size), "little")
            set_mask, clear_mask = masks
            uc.mem_write(address, ((current | set_mask) & ~clear_mask).to_bytes(size, "little"))
        self.mmio_reads[(pc, address, size)] += 1
        self.mmio_read_totals[(pc, address, size)] += 1

    def _record_key_register_read(self, address: int, size: int, pc: int) -> None:
        """Record a firmware read of the configured candidate key register."""
        key_register = getattr(self.config, "key_register", None)
        if (key_register is None
                or max(address, key_register) >= min(address + size, key_register + 4)):
            return
        self.key_register_reads = getattr(self, "key_register_reads", 0) + 1
        self.key_read_epoch = getattr(self, "key_read_epoch", 0) + 1
        self.key_register_read_pcs = getattr(self, "key_register_read_pcs", Counter())
        self.key_register_read_pcs[pc] += 1

    def _open_bus_read(self, uc: Uc, access: int, address: int, size: int,
                       value: int, user_data: object) -> None:
        if (self.secondary_flash is not None and self.secondary_base is not None
                and self.secondary_base <= address
                and address + size <= self.secondary_base + self.config.secondary_flash_size):
            return
        # A prior unmapped data access may have established writable RAM in a
        # nominal open-bus gap.  The broad read hook still covers that page;
        # preserve guest data instead of turning every later read into 0xFF.
        # Split accesses at page boundaries so a cross-page read cannot turn
        # the dynamic half into open-bus data either.
        end = address + size
        current = address
        while current < end:
            page = current & -PAGE
            next_page = min(end, page + PAGE)
            if page not in self.dynamic_pages:
                uc.mem_write(current, b"\xff" * (next_page - current))
            current = next_page

    @staticmethod
    def _stable_mmio_read(uc: Uc, access: int, address: int, size: int,
                          value: int, user_data: object) -> None:
        register, reset_value = user_data
        uc.mem_write(register, reset_value)

    def _board_revision_read(self, uc: Uc, access: int, address: int, size: int,
                             value: int, user_data: object) -> None:
        register = self.config.board_revision_register
        revision = self.config.board_revision_value
        if register is not None and revision is not None:
            uc.mem_write(register, struct.pack("<I", revision & 0xFFFFFFFF))

    def _refresh_board_status_input(self, uc: Uc, address: int | None = None,
                                    size: int = 0) -> None:
        status = getattr(self.config, "board_status_input", None)
        if status is None:
            return
        if address is not None and not address <= status.address < address + size:
            return
        current = uc.mem_read(status.address, 1)[0]
        uc.mem_write(status.address, bytes((current | status.default & status.mask,)))

    def _release_hardware_poll(self) -> bool:
        """Supply ready bits only when firmware is provably stuck polling MMIO."""
        if not self.mmio_reads:
            return False
        protected = (
            (self.config.load_address,
             self.config.load_address + self.config.flash_size),
            (self.config.ram_base,
             self.config.ram_base + self.config.ram_size),
        )
        secondary = self.config.secondary_flash_address
        if secondary not in (None, 0):
            protected += ((secondary,
                           secondary + self.config.secondary_flash_size),)
        status = getattr(self.config, "rex_irq_status_address", None)
        if status is not None:
            protected += ((status, status + 0x10),)
        key_start = self.config.key_register
        board = self.config.board_revision_register
        # A status-ready loop can be followed immediately by a device-ID/data
        # compare.  Once the first condition is already supplied, inspect the
        # next hottest exact poll instead of repeatedly selecting the same one.
        for (pc, address, size), count in self.mmio_reads.most_common(8):
            if count < 100 or not 0 < size <= 8:
                continue
            if (key_start is not None
                    and max(address, key_start) < min(address + size, key_start + 4)):
                continue
            if (board is not None
                    and max(address, board) < min(address + size, board + 4)):
                continue
            if any(max(address, start) < min(address + size, end)
                   for start, end in protected):
                continue  # ROM/NOR/SDRAM is never a hardware-ready bit
            if 0x03800000 <= address < 0x03A00000:
                continue  # internal RAM/software locks are not hardware polls
            inferred = self._infer_thumb_poll_value(pc, address, size)
            if inferred is None:
                continue
            value, bit, state = inferred
            set_mask, clear_mask = self.ready_bits.get((address, size), (0, 0))
            mask = 1 << bit
            if (state and set_mask & mask) or (not state and clear_mask & mask):
                continue
            candidate = (pc, address, size)
            self._poll_candidate_chunks[candidate] += 1
            if self._poll_candidate_chunks[candidate] < 2:
                continue
            del self._poll_candidate_chunks[candidate]
            if state:
                set_mask |= mask
                clear_mask &= ~mask
            else:
                clear_mask |= mask
                set_mask &= ~mask
            self.ready_bits[(address, size)] = (set_mask, clear_mask)
            self.uc.mem_write(address, value.to_bytes(size, "little"))
            event_key = (pc, address, size, bit, int(state))
            if (event_key not in self._poll_escape_keys
                    and len(self.poll_escapes) < 256):
                self._poll_escape_keys.add(event_key)
                self.poll_escapes.append({
                    "pc": pc, "address": address, "size": size,
                    "reads": count, "value": value, "bit": bit,
                    "state": int(state),
                })
            return True
        return False

    def _infer_thumb_poll_value(self, pc: int, address: int,
                                size: int) -> tuple[int, int, bool] | None:
        """Derive a polled bit from exact Thumb control-flow patterns."""
        try:
            words = struct.unpack("<6H", self.uc.mem_read(pc, 12))
        except UcError:
            return None
        read_register = words[0] & 7
        # Direct MMIO data/ID read followed by CMP #imm and a backward BEQ/BNE.
        # V540 uses this after its LCD serial-interface ready-bit handshake.
        compare = words[1]
        branch = words[2]
        condition = branch >> 8 & 0xF
        displacement = (branch & 0xFF) * 2
        if displacement & 0x100:
            displacement -= 0x200
        branch_address = pc + 4
        if (compare & 0xF800 == 0x2800
                and compare >> 8 & 7 == read_register
                and branch & 0xF000 == 0xD000 and condition in (0, 1)
                and branch_address + 4 + displacement <= pc):
            expected = compare & 0xFF
            wanted = expected if condition == 1 else (0 if expected else 1)
            if wanted < 1 << (size * 8):
                changed = wanted ^ int.from_bytes(
                    self.uc.mem_read(address, size), "little"
                )
                bit = ((changed & -changed).bit_length() - 1 if changed else 0)
                return wanted, bit, bool(wanted & (1 << bit))
        # LG MSM5100 boot code reads a byte, branches back to MOV/ANDS, and
        # exits through BNE once the live one-bit mask becomes ready.
        if words[0] & 0xF800 == 0x7800 and words[1] & 0xF800 == 0xE000:
            displacement = (words[1] & 0x7FF) * 2
            if displacement & 0x800:
                displacement -= 0x1000
            target = pc + 6 + displacement
            try:
                move, ands, branch = struct.unpack("<3H", self.uc.mem_read(target, 6))
            except UcError:
                pass
            else:
                scratch = move & 7
                mask_register = move >> 3 & 7
                branch_displacement = (branch & 0xFF) * 2
                if branch_displacement & 0x100:
                    branch_displacement -= 0x200
                exit_target = target + 8 + branch_displacement
                exact_loop = (
                    target < pc
                    and move & 0xFFC0 == 0x1C00  # ADDS Rd, Rm, #0 (MOV alias)
                    and ands & 0xFFC0 == 0x4000
                    and ands & 7 == scratch
                    and ands >> 3 & 7 == read_register
                    and branch & 0xFF00 == 0xD100  # BNE exit
                    and exit_target > pc + 2
                )
                if exact_loop:
                    registers = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                 UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                                 UC_ARM_REG_R6, UC_ARM_REG_R7)
                    mask = self.uc.reg_read(registers[mask_register])
                    if 0 < mask < 1 << (size * 8) and mask & (mask - 1) == 0:
                        current = int.from_bytes(self.uc.mem_read(address, size), "little")
                        bit = mask.bit_length() - 1
                        return current | mask, bit, True
        for index in range(1, 4):
            literal_load = words[index]
            if literal_load & 0xF800 != 0x4800:
                continue
            literal_register = literal_load >> 8 & 7
            literal_address = ((pc + index * 2 + 4) & ~3) + (literal_load & 0xFF) * 4
            expected = int.from_bytes(self.uc.mem_read(literal_address, 4), "little")
            compare = words[index + 1]
            branch = words[index + 2]
            compared = {compare & 7, compare >> 3 & 7}
            condition = branch >> 8 & 0xF
            displacement = (branch & 0xFF) * 2
            if displacement & 0x100:
                displacement -= 0x200
            branch_address = pc + (index + 2) * 2
            backward = branch_address + 4 + displacement <= pc
            if (compare & 0xFFC0 == 0x4280
                    and compared == {read_register, literal_register}
                    and condition == 1 and backward and expected < 1 << (size * 8)):
                return expected, 0, bool(expected & 1)
        # Some BSPs poll a halfword bit with a direct conditional
        # back-edge instead of an explicit unconditional retry branch.
        if len(words) >= 5:
            left, right, compare, branch = words[1:5]
            branch_displacement = (branch & 0xFF) * 2
            if branch_displacement & 0x100:
                branch_displacement -= 0x200
            branch_target = pc + 4 * 2 + 4 + branch_displacement
            exact_split_loop = (
                size == 2
                and words[0] & 0xF800 == 0x8800  # LDRH Rd, [Rb, #imm]
                and left & 0xF800 == 0x0000 and left >> 6 & 0x1F == 31
                and left & 7 == read_register and left >> 3 & 7 == read_register
                and right & 0xF800 == 0x0800 and right >> 6 & 0x1F == 31
                and right & 7 == read_register and right >> 3 & 7 == read_register
                and compare == (0x2800 | read_register << 8 | 1)
                and branch & 0xFF00 == 0xD000  # BEQ retry
                and branch_target == pc
            )
            if exact_split_loop:
                current = int.from_bytes(self.uc.mem_read(address, size), "little")
                return current & ~1, 0, False
        # Early MSM5000 BSPs normalize one status bit with LSLS/LSRS, compare
        # it with 0/1, take the conditional edge as the exit, and use an
        # explicit backward B for the polling edge.  This is the common form
        # used by LG-SD1020 around the 0x03000780 clock-status register.
        if len(words) >= 6:
            left, right, compare, branch, loop = words[1:6]
            left_register = left & 7
            left_source = left >> 3 & 7
            left_shift = left >> 6 & 0x1F
            right_register = right & 7
            right_source = right >> 3 & 7
            right_shift = right >> 6 & 0x1F
            condition = branch >> 8 & 0xF
            branch_displacement = (branch & 0xFF) * 2
            if branch_displacement & 0x100:
                branch_displacement -= 0x200
            exit_target = pc + 4 * 2 + 4 + branch_displacement
            loop_displacement = (loop & 0x7FF) * 2
            if loop_displacement & 0x800:
                loop_displacement -= 0x1000
            loop_address = pc + 5 * 2
            loop_target = loop_address + 4 + loop_displacement
            extracted_bit = right_shift - left_shift
            exact_extract = (
                words[0] & 7 == left_source
                and left & 0xF800 == 0x0000 and left_shift
                and right & 0xF800 == 0x0800
                and right_source == left_register
                and right_register == left_register
                and right_shift == left_shift
                and compare & 0xF800 == 0x2800
                and compare >> 8 & 7 == left_register
                and compare & 0xFF in (0, 1)
                and branch & 0xF000 == 0xD000 and condition in (0, 1)
                and exit_target > loop_address
                and loop & 0xF800 == 0xE000 and loop_target <= pc
                and 0 <= extracted_bit < size * 8
            )
            if exact_extract:
                compared_value = compare & 0xFF
                wanted = compared_value if condition == 0 else 1 - compared_value
                current = int.from_bytes(self.uc.mem_read(address, size), "little")
                mask = 1 << extracted_bit
                value = current | mask if wanted else current & ~mask
                return value, extracted_bit, bool(wanted)
        # Exact adjacent LSRS + BHS/BLO.  Allow LSRS at word zero when `_read`
        # moved the PC from a leaf MMIO accessor to its R0 consumer.
        for index in (0, 1):
            word = words[index]
            if word & 0xF800 != 0x0800:
                continue
            shift = (word >> 6) & 0x1F
            source_register = word >> 3 & 7
            if not shift or source_register != (0 if index == 0 else read_register):
                continue
            branch_word = words[index + 1]
            condition = branch_word >> 8 & 0xF
            if branch_word & 0xF000 != 0xD000 or condition not in (2, 3):
                continue
            displacement = (branch_word & 0xFF) * 2
            if displacement & 0x100:
                displacement -= 0x200
            branch = pc + (index + 1) * 2
            target = branch + 4 + displacement
            want_taken = target > branch
            # If conditional fallthrough contains an unconditional branch back
            # to the read, conditional edge is exit regardless of direction.
            for later, later_word in enumerate(words[index + 2:], index + 2):
                if later_word & 0xF800 != 0xE000:
                    continue
                later_displacement = (later_word & 0x7FF) * 2
                if later_displacement & 0x800:
                    later_displacement -= 0x1000
                later_address = pc + later * 2
                if later_address + 4 + later_displacement <= pc:
                    want_taken = True
                break
            try:
                target_word = struct.unpack("<H", self.uc.mem_read(target, 2))[0]
                if target_word & 0xFE00 == 0xBC00 or target_word == 0x4770:
                    want_taken = True
            except UcError:
                pass
            # The complementary form has a forward conditional edge into a
            # retry body and either an immediate forward B or MOV/POP/BX LR
            # as its non-taken return.  In that CFG carry=1 enters the busy
            # body, while carry=0 reaches the caller.  Require the complete
            # local graph before reversing it: the taken body must branch
            # directly back to this MMIO read.
            fallthrough = pc + (index + 2) * 2
            retry_exit = self._thumb_unconditional_target(
                fallthrough, words[index + 2]
            )
            if retry_exit is None:
                try:
                    move, pop, return_instruction = struct.unpack(
                        "<3H", self.uc.mem_read(fallthrough, 6)
                    )
                except UcError:
                    pass
                else:
                    if (move & 0xFFC0 == 0x1C00 and move & 7 == 0
                            and move >> 3 & 7 == read_register
                            and pop & 0xFE00 == 0xBC00
                            and not (pop & 0x0100)
                            and return_instruction == 0x4770):
                        retry_exit = target + 0x20
            if (target > fallthrough and retry_exit is not None
                    and retry_exit > target and retry_exit - target <= 0x40):
                retry_back = None
                try:
                    for candidate_address in range(target, retry_exit, 2):
                        candidate_word = struct.unpack(
                            "<H", self.uc.mem_read(candidate_address, 2)
                        )[0]
                        retry_back = self._thumb_unconditional_target(
                            candidate_address, candidate_word
                        )
                        if retry_back is not None:
                            break
                        # A conditional branch, branch exchange, return, or
                        # Thumb long branch before the back-edge makes this a
                        # real control-flow path rather than the proven busy
                        # retry grammar.
                        if ((candidate_word & 0xF000) == 0xD000
                                or (candidate_word & 0xFF00) == 0x4700
                                or (candidate_word & 0xFF00) == 0xBD00
                                or (candidate_word & 0xF800) in (0xF000, 0xF800)
                                or ((candidate_word & 0xFC00) == 0x4400
                                    and (candidate_word & 0x300) in (0, 0x200)
                                    and (candidate_word & 0x80)
                                    and (candidate_word & 7) == 7)):
                            break
                except UcError:
                    retry_back = None
                if retry_back is not None and pc - 0x20 <= retry_back <= pc:
                    want_taken = False
            carry = want_taken if condition == 2 else not want_taken
            bit = shift - 1
            if bit >= size * 8:
                return None
            current = int.from_bytes(self.uc.mem_read(address, size), "little")
            value = current | (1 << bit) if carry else current & ~(1 << bit)
            return value, bit, bool(carry)
        return None
