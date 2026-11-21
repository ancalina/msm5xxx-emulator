"""Closed boot-time instruction evidence owned by this domain."""
from __future__ import annotations
import re
import struct
from msm5xxx_emulator.detection.facts import facts_for
from msm5xxx_emulator.detection.signatures import find_all
REQUIRES = {'find_boot_nand_word': ('storage.boot_nand_word', 'find_boot_nand_word')}
DMD_DOWNLOAD_SIGNATURE = bytes.fromhex("f0b5002701250024354901200870")
DMD_DOWNLOAD_510X_SIGNATURE = bytes.fromhex("f0b539480027006801250024002800d060e0")
def find_mdsp_master_profile(image: bytes, *, code_limit: int | None = None):
    """Bind reset, ready, command and completion ports through Thumb callers.
    The uploaded master controller owns its ready halfword and command mailbox.
    These are DSP peripheral words, not ARM task state. Derive the varying
    mailbox/result offsets from their actual typed accesses.
    """
    from msm5xxx_emulator.detection.arm import thumb_bl_target, thumb_literal_value
    if not isinstance(image, bytes):
        return None
    limit = len(image) if code_limit is None else min(len(image), code_limit)
    profiles = []
    def half(at):
        return struct.unpack_from('<H', image, at)[0] if 0 <= at <= limit - 2 else None
    def branch(at):
        value = half(at)
        if value is None or value & 0xf800 != 0xe000:
            return None
        displacement = value & 0x7ff
        return at + 4 + 2 * (displacement - (0x800 if displacement & 0x400 else 0))
    for match in re.finditer(rb'.\x48\x80\x8a\x00\x28.\xd1', image[:limit], re.S):
        ready_pc = match.start()
        if (ready_pc & 1 or ready_pc < 0x40
                or thumb_literal_value(image, ready_pc, 0) != 0x50201500):
            continue
        release = thumb_bl_target(image, ready_pc - 0x22)
        if release is None or half(release) != 0x2000:
            continue
        reset = branch(release + 2)
        if (reset is None or thumb_literal_value(image, reset, 1) != 0x50c00000
                or image[reset + 2:reset + 14] != bytes.fromhex('012800d100e0002008607047')):
            continue
        uploads = []
        for pc in range(max(0, ready_pc - 0x64), ready_pc - 0x22, 2):
            target = thumb_bl_target(image, pc)
            if target is None or image[target:target + 6] != bytes.fromhex('b0b5041c0128'):
                continue
            hold = thumb_bl_target(image, target + 0x14)
            if (hold is not None and half(hold) == 0x2001
                    and branch(hold + 2) == reset
                    and (half(pc + 4) == 0x2800 or
                         half(pc + 4) == 0x2600 and half(pc + 6) == 0x2800)):
                uploads.append(target)
        if len(uploads) != 1:
            continue
        upload = uploads[0]
        # Completion checks command==0 before comparing a DSP result word with
        # the requested module mask. Both loads use the same literal base.
        completions = []
        for pc in range(ready_pc + 8, min(ready_pc + 0x200, limit - 20), 2):
            words = struct.unpack_from('<10H', image, pc)
            if (thumb_literal_value(image, pc, 0) != 0x50201500
                    or words[1] & 0xff00 != 0x3000
                    or words[2] & 0xf83f != 0x8800
                    or words[3] != 0x2800 or words[4] & 0xff00 != 0xd100
                    or words[6] & 0xf83f != 0x6800
                    or words[7:9] != (0x68e1, 0x4288)
                    or words[9] & 0xff00 != 0xd100):
                continue
            base = thumb_literal_value(image, pc + 10, 0)
            if base is None or not 0x50400000 <= base < 0x50401000:
                continue
            mailbox = 0x50201500 + (words[1] & 0xff) + ((words[2] >> 6) & 31) * 2
            response = base + ((words[6] >> 6) & 31) * 4
            completions.append((pc, mailbox, response))
        if len(completions) != 1:
            continue
        completion, mailbox, response = completions[0]
        requests = []
        for pc in range(completion, min(completion + 0x800, limit - 34), 2):
            words = struct.unpack_from('<17H', image, pc)
            base = thumb_literal_value(image, pc, 0)
            if (base is None or words[1] & 0xf83f != 0x6004
                    or base + ((words[1] >> 6) & 31) * 4 != response + 4
                    or thumb_literal_value(image, pc + 4, 0) != 0x50201500
                    or words[3] != 0x2201 or words[4] & 0xff00 != 0x3000
                    or words[5] & 0xf83f != 0x8002
                    or 0x50201500 + (words[4] & 0xff) + ((words[5] >> 6) & 31) * 2 != mailbox
                    or words[7] & 0xff07 != 0x2304
                    or words[8] != 0x6800
                    or words[10:15] != (0x4358, 0x1880, 0x6900, 0x0759, 0x4308)
                    or thumb_literal_value(image, pc + 30, 1) != 0x50c00000
                    or words[16] != 0x6088):
                continue
            requests.append(pc)
        if len(requests) != 1:
            continue
        irq = _mdsp_irq_profile(image, reset, completion, limit)
        if irq is None:
            continue
        profiles.append({**irq, 'reset': 0x50c00000, 'doorbell': 0x50c00008,
                         'ready': 0x50201514, 'mailbox': mailbox,
                         'response': response, 'request': response + 4,
                         'reset_pc': reset, 'release_pc': release,
                         'upload_pc': upload, 'ready_pc': ready_pc,
                         'completion_pc': completion, 'request_pc': requests[0]})
    return profiles[0] if len(profiles) == 1 else None
def _mdsp_irq_profile(image, reset, completion, limit):
    """Trace registered callbacks through a guest-copied interrupt descriptor."""
    from msm5xxx_emulator.detection.arm import thumb_bl_target, thumb_literal_value
    registration = reset + 0x136
    if registration + 28 > limit:
        return None
    words = struct.unpack_from('<14H', image, registration)
    if words[0] != 0xb580 or words[13] != 0xbd80 or (words[2], words[6], words[10]) != (0x2014, 0x2015, 0x2016):
        return None
    helpers = [thumb_bl_target(image, registration + offset) for offset in (6, 14, 22)]
    callbacks = [thumb_literal_value(image, registration + offset, 1) for offset in (2, 10, 18)]
    if helpers[0] is None or len(set(helpers)) != 1:
        return None
    common = []
    for channel, callback in enumerate(callbacks):
        if callback is None or not callback & 1 or not 0 < callback < limit - 10:
            return None
        entry = callback & ~1
        if image[entry:entry + 4] != struct.pack('<2H', 0xb580, 0x2000 + channel) or image[entry + 8:entry + 10] != b'\x80\xbd':
            return None
        common.append(thumb_bl_target(image, entry + 4))
    if common[0] is None or len(set(common)) != 1:
        return None
    # The master completion callback is selected from a ROM byte array indexed
    # by the uploaded image. The closed upload path above accepts image zero.
    channels = []
    for pc in range(common[0], min(common[0] + 0x100, limit - 14), 2):
        pointer = thumb_literal_value(image, pc, 0)
        if (pointer is not None and 0 <= pointer < len(image)
                and image[pc + 2:pc + 8] == bytes.fromhex('2168405ca842')
                and image[pc + 9] == 0xd1
                and thumb_bl_target(image, pc + 10) == completion - 12
                and image[pointer] < 3):
            channels.append(image[pointer])
    if len(channels) != 1:
        return None
    irq = _boot_irq_descriptor_profile(image, helpers[0], 0x14 + channels[0], limit)
    return {**irq, 'irq_registration_pc': registration} if irq else None
def _boot_irq_descriptor_profile(image, helper, index, limit):
    """Bind an IRQ index to its copied descriptor and pending-bank load."""
    from msm5xxx_emulator.detection.arm import thumb_literal_value
    if helper is None or not 0 <= helper < limit:
        return None
    tables = []
    for pc in range(helper, min(helper + 0x70, limit - 10), 2):
        if image[pc:pc + 4] == bytes.fromhex('1c226a43') and image[pc + 6:pc + 10] == bytes.fromhex('d218002d'):
            table = thumb_literal_value(image, pc + 4, 3)
            if table is not None:
                tables.append(table)
    if len(tables) != 1:
        return None
    table = tables[0]
    copied = _copied_boot_table(image, table, max(23, index + 1) * 28, limit)
    if copied is None:
        return None
    copy_pc, table_source = copied
    ack, enable, mask = struct.unpack_from('<3I', image, table_source + index * 28)
    if ack != 0x80000900 or enable != 0x80000914 or not mask or mask & (mask - 1):
        return None
    pending_reads = []
    for pc in range(max(0, helper - 0x400), helper, 2):
        if (thumb_literal_value(image, pc, 1) == ack
                and image[pc + 2:pc + 6] == bytes.fromhex('4031c868')
                and image[pc + 20:pc + 22] == bytes.fromhex('0869')):
            pending_reads.append(pc)
    if len(pending_reads) != 1:
        return None
    return {'irq_ack': ack, 'irq_enable': enable, 'irq_pending': ack + 0x4c,
            'irq_mask': mask,
            'irq_copy_pc': copy_pc, 'irq_table_source': table_source,
            'irq_pending_pc': pending_reads[0]}
def _copied_boot_table(image, table, size, limit):
    """Map a descriptor through the firmware's own source-to-RAM copy loop."""
    from msm5xxx_emulator.detection.arm import thumb_literal_value
    copies = []
    loop = (0x6828,  # LDR r0,[r5]: read source word
            0x6020,  # STR r0,[r4]: guest writes destination
            0x03a0, 0xd100, 0x63ca,  # boundary watchdog service
            0x3504, 0x3404,  # advance source/destination by four
            0x42b4, 0xd3f6)  # compare destination end; repeat
    for pc in find_all(image[:limit], bytes.fromhex('28682060')):
        if pc > limit - 18 or struct.unpack_from('<9H', image, pc) != loop:
            continue
        if pc < 18 or pc & 1 or image[pc - 14:pc - 8] != bytes.fromhex('036824681e19') or image[pc - 6:pc] != bytes.fromhex('1d68046806e0'):
            continue
        pointers = (thumb_literal_value(image, pc - 8, 3), thumb_literal_value(image, pc - 18, 0), thumb_literal_value(image, pc - 16, 4))
        if any(value is None or value < 0 or value > len(image) - 4 for value in pointers):
            continue
        source, destination, length = (struct.unpack_from('<I', image, value)[0] for value in pointers)
        if not 0 < length <= 0x400000 or source > len(image) - length or not destination <= table < table + size <= destination + length:
            continue
        copies.append((pc, source + table - destination))
    if len(copies) != 1:
        return None
    return copies[0]

def find_boot_sbi_fifo_profile(image: bytes, *, code_limit: int | None = None):
    """Close the serial FIFO start/completion handshake through both callers."""
    from msm5xxx_emulator.detection.arm import thumb_bl_target, thumb_literal_value

    if not isinstance(image, bytes):
        return None
    limit = len(image) if code_limit is None else min(len(image), code_limit)
    profiles = []

    def words(at, count):
        if at < 0 or at > limit - count * 2:
            return ()
        return struct.unpack_from(f'<{count}H', image, at)

    for done in find_all(image[:limit], struct.pack('<H', 0x0182)):
        # channel << 6; clear DONE; write START=0 then START=1.
        start = words(done, 10)
        if (done & 1 or len(start) != 10
                or thumb_literal_value(image, done + 2, 0) != 0x80001200
                or start[2:] != (0xb570, 0x2464, 0x2100, 0x1815,
                                 0x62e9, 0x6129, 0x2001, 0x6128)
                or words(done + 0x40, 5) != (0x6ae8, 0x2800, 0xd0ed, 0x2001, 0xbd70)
                or words(done + 0x32, 2) != (0x2000, 0xbd70)):
            continue
        status = done - 0x38
        if (words(status, 2) != (0xb570, 0x0181)
                or thumb_literal_value(image, status + 4, 0) != 0x80001200
                or words(status + 0x2e, 5) != (0x69a8, 0x0740, 0xd4ec, 0x2001, 0xbd70)):
            continue
        write, read = done + 0x4a, done + 0xe4
        if (words(write, 4) != (0xb5ff, 0x1c1f, 0x230c, 0x4358)
                or words(read, 3) != (0xb5ff, 0x230c, 0x4358)
                or words(write + 0x0c, 3) != (0x1844, 0x68a5, 0x1c28)
                or words(read + 0x0a, 3) != (0x1844, 0x68a7, 0x1c38)
                or words(write + 0x1a, 1) != (0x7864,)
                or words(read + 0x18, 1) != (0x7864,)
                or thumb_bl_target(image, write + 0x12) != status
                or thumb_bl_target(image, write + 0x82) != done
                or thumb_bl_target(image, read + 0x10) != status
                or thumb_bl_target(image, read + 0x88) != done):
            continue
        table = thumb_literal_value(image, write + 8, 1)
        if table is None or thumb_literal_value(image, read + 6, 1) != table:
            continue
        # Both callers load the slave byte and replace exactly config[5:0].
        slave = (0x06a4, 0x0992, 0x0192, 0x0ea4, 0x4322, 0x505a)
        if (words(write + 0x26, 6) != slave or words(read + 0x24, 6) != slave
                or thumb_literal_value(image, write + 0x32, 1) != 0x80001200
                or words(write + 0x34, 4) != (0x01ab, 0x1859, 0x9100, 0x604a)
                or thumb_literal_value(image, read + 0x30, 1) != 0x80001200
                or words(read + 0x32, 3) != (0x01bb, 0x185e, 0x6072)):
            continue
        # These producers submit exactly one word before each start edge.
        if (words(write + 0x4c, 5) != (0x2001, 0x1b39, 0x2901, 0xda00, 0x1c08)
                or words(read + 0x4c, 5) != (0x2001, 0x1b09, 0x2901, 0xda00, 0x1c08)):
            continue
        # Address byte -> bits14:8; reads add bit15; writes append data byte.
        if (words(write + 0x64, 11) != (0x9802, 0x217f, 0x5d00, 0x0200,
                0x0209, 0x4008, 0x9903, 0x5d09, 0x4308, 0x9900, 0x60c8)
                or words(read + 0x6a, 10) != (0x9804, 0x217f, 0x5d40,
                0x0209, 0x0200, 0x4008, 0x31ff, 0x3101, 0x1840, 0x60f0)):
            continue
        # Three-byte receive groups are consumed from +28,+24,+20, in order.
        if (words(read + 0x98, 6) != (0x2801, 0xd00d, 0x2802, 0xd006, 0x2803, 0xd113)
                or words(read + 0xa4, 5) != (0x6ab1, 0x1c20, 0x9a05, 0x3401, 0x5411)
                or words(read + 0xae, 5) != (0x6a71, 0x1c20, 0x9a05, 0x3401, 0x5411)
                or words(read + 0xb8, 5) != (0x6a31, 0x1c20, 0x9a05, 0x3401, 0x5411)):
            continue
        # A configuration-only producer calls the same START/DONE helper
        # without writing TX, then restores config mode bits[7:6] to 01.
        configure = read + 0xdc
        if (words(configure, 3) != (0xb5f8, 0x230c, 0x1c0e)
                or thumb_literal_value(image, configure + 6, 1) != table
                or words(configure + 8, 4) != (0x4358, 0x1840, 0x6884, 0x1c20)
                or thumb_bl_target(image, configure + 0x10) != status
                or words(configure + 0x14, 4) != (0x2801, 0xd001, 0x2000, 0xbdf8)
                or thumb_literal_value(image, configure + 0x26, 2) != 0x80001200
                or words(configure + 0x28, 7) != (0x0a09, 0x0209, 0x4331,
                    0x01a3, 0x189e, 0x5179, 0x6071)
                or words(configure + 0x3e, 1) != (0x1c20,)
                or thumb_bl_target(image, configure + 0x40) != done
                or words(configure + 0x4a, 6) != (0x5979, 0x22c0, 0x4391,
                    0x3140, 0x5179, 0x6071)):
            continue
        copied = _copied_boot_table(image, table, 10 * 12, limit)
        if copied is None:
            continue
        copy_pc, source = copied
        channels = set()
        for index in range(10):
            identity, ops, channel = struct.unpack_from('<3I', image, source + index * 12)
            if identity & 0xff != index or channel > 1:
                break
            operations = ops + source - table
            if (0 <= operations <= len(image) - 16 and
                    struct.unpack_from('<2I', image, operations + 8) == (read | 1, write | 1)):
                channels.add(channel)
        else:
            if channels == {0, 1}:
                profiles.append({'base': 0x80001200, 'stride': 0x40,
                                 'channels': 2, 'slave_mask': 0x3f,
                                 'read_bit': 0x8000, 'register_mask': 0x7f,
                                 'busy_mask': 4, 'done_pc': done,
                                 'status_pc': status, 'read_pc': read,
                                 'write_pc': write, 'configure_pc': configure, 'copy_pc': copy_pc,
                                 'table_source': source})
    return profiles[0] if len(profiles) == 1 else None


def find_boot_rex_timer_profile(image: bytes, *, code_limit: int | None = None):
    """Prove the free counter, absolute comparator and linked timer IRQ.

    Two source forms program the same peripheral: one clamps an absolute
    deadline through a helper, the other writes it directly. Neither form
    requests a periodic IRQ. Counter arithmetic and millisecond conversion
    prove a wrapping 32-bit counter running at 32768 Hz.
    """
    from msm5xxx_emulator.detection.arm import thumb_bl_target, thumb_literal_value

    if not isinstance(image, bytes):
        return None
    limit = len(image) if code_limit is None else min(len(image), code_limit)
    code = image[:limit]
    profiles = []

    def words(at, count):
        if at < 0 or at > limit - count * 2:
            return ()
        return struct.unpack_from(f'<{count}H', image, at)

    for match in re.finditer(rb'.\x4a\x50\x6b\x01\x1c\x50\x6b\x88\x42\xfb\xd1\x70\x47', code, re.S):
        counter = match.start()
        wrapper, frequency = counter + 0xe, counter + 0x76
        if (counter & 1 or thumb_literal_value(image, counter, 2) != 0x80001b00
                or words(wrapper, 1) != (0xb5b0,)
                or thumb_bl_target(image, wrapper + 8) != counter
                or thumb_bl_target(image, frequency + 8) != counter
                # Whole seconds: count >> 15, multiplied by 125 << 3 ms.
                or words(frequency + 0x10, 14) != (0x680a, 0x1a80,
                    0x0bc3, 0xd009, 0x03dd, 0x1952, 0x1c1d, 0x237d,
                    0x00db, 0x600a, 0x684a, 0x436b, 0x18d2, 0x604a)
                # Fraction: (count & 0x7fff) * 1000 >> 15.
                or words(frequency + 0x2c, 8) != (0x0440, 0x237d,
                    0x00db, 0x0c40, 0x4358, 0x6849, 0x0bc0, 0x1845)):
            continue
        for id_pc in find_all(code, struct.pack('<H', 0x2012)):
            if id_pc & 1:
                continue
            init = id_pc - 0x1e
            if (words(init, 1) == (0xb580,)
                    and thumb_bl_target(image, init + 2) == wrapper
                    and words(init + 6, 1) == (0x1c01,)
                    and words(init + 0xa, 7) == (0x2000, 0x6050, 0x6011,
                        0x1e88, 0x6150, 0x1e48, 0x6110)
                    and words(init + 0x24, 1) == (0xbd80,)):
                state = thumb_literal_value(image, init + 8, 2)
                program = thumb_bl_target(image, init + 0x18)
                callback = thumb_literal_value(image, init + 0x1c, 1)
                helper = thumb_bl_target(image, init + 0x20)
                if program is None or not state:
                    continue
                setter = thumb_bl_target(image, program + 0x1a)
                if (setter is None or words(program, 1) != (0xb570,)
                        or thumb_literal_value(image, program + 2, 6) != state
                        or words(program + 0x14, 3) != (0x2206, 0x1c29, 0x1c20)
                        or words(program + 0x1e, 4) != (0x61b0, 0x6174, 0x6135, 0xbd70)
                        # Stable read; unsigned max(requested, now + margin).
                        or words(setter, 13) != (0xe00e, 0x6828, 0x1c03,
                            0x6828, 0x4283, 0xd1fb, 0x1880, 0x42a0,
                            0xd200, 0x1c20, 0x1840, 0x6030, 0xbdf0)
                        or words(setter + 0x20, 7) != (0xb5f0, 0xa303,
                            0xcbe0, 0x1c04, 0x1a64, 0x1a52, 0xe7e9)
                        or setter + 0x38 > limit
                        or struct.unpack_from('<2I', image, setter + 0x30) != (0x80001b34, 0x80001d08)):
                    continue
                if callback is None or not callback & 1:
                    continue
                callback &= ~1
                expiry = thumb_bl_target(image, callback + 0x3a)
                if (expiry is None or words(callback, 1) != (0xb5f8,)
                        or thumb_bl_target(image, callback + 8) != counter
                        or thumb_literal_value(image, callback + 0xc, 1) != state
                        or words(callback + 0x1e, 4) != (0x1b30, 0x1b29, 0x4288, 0xd30b)
                        or thumb_literal_value(image, expiry + 8, 4) != state
                        or thumb_bl_target(image, expiry + 0x76) != counter
                        or words(expiry + 0x92, 3) != (0x211e, 0x2012, 0x6025)
                        or thumb_bl_target(image, expiry + 0xac) != program):
                    continue
                producer_pc = program + 0x14
            else:
                init = id_pc - 0x18
                if (words(init, 1) != (0xb5b0,)
                        or thumb_bl_target(image, init + 2) != wrapper
                        or words(init + 6, 1) != (0x1c04,)
                        or words(init + 0xa, 4) != (0x2000, 0x6068, 0x602c, 0x1e60)
                        or words(init + 0x1a, 1) != (0x612c,)
                        or words(init + 0x20, 1) != (0xbdb0,)):
                    continue
                state = thumb_literal_value(image, init + 8, 5)
                setter = thumb_bl_target(image, init + 0x12)
                callback = thumb_literal_value(image, init + 0x16, 1)
                helper = thumb_bl_target(image, init + 0x1c)
                if (setter is None or not state
                        or thumb_literal_value(image, setter, 1) != 0x80001d00
                        or words(setter + 2, 1) != (0x6088,)
                        or thumb_literal_value(image, setter + 4, 1) != state
                        or words(setter + 6, 2) != (0x6148, 0x4770)
                        or callback is None or not callback & 1):
                    continue
                callback &= ~1
                expiry = thumb_bl_target(image, callback + 0x2e)
                if (expiry is None or words(callback, 1) != (0xb5b0,)
                        or thumb_bl_target(image, callback + 8) != counter
                        or thumb_literal_value(image, callback + 0xc, 2) != state
                        or words(callback + 0x14, 4) != (0x1a43, 0x1a55, 0x42ab, 0xd30a)
                        or thumb_bl_target(image, expiry + 0x58) != counter
                        or thumb_literal_value(image, expiry + 2, 4) != state
                        # Queued deadlines are clamped to at least now + 16.
                        or words(expiry + 0x7c, 8) != (0x69c0, 0x1b41,
                            0x2910, 0xd803, 0x1c28, 0x3010, 0xe000, 0x1e68)
                        or thumb_bl_target(image, expiry + 0x8c) != setter):
                    continue
                producer_pc = expiry + 0x7c
            irq = _boot_irq_descriptor_profile(image, helper, 0x12, limit)
            if irq is None or irq['irq_mask'] != 0x40000000:
                continue
            profiles.append({**irq, 'counter': 0x80001b34, 'comparator': 0x80001d08,
                'frequency_hz': 32768, 'counter_bits': 32, 'irq_index': 0x12,
                'counter_pc': counter, 'frequency_pc': frequency, 'setter_pc': setter,
                'init_pc': init, 'irq_registration_pc': id_pc, 'callback_pc': callback,
                'expiry_pc': expiry, 'producer_pc': producer_pc})
    return profiles[0] if len(profiles) == 1 else None


def find_boot_power_key_profile(image: bytes, *, code_limit: int | None = None):
    """Bind a released external key level to the scanner and event callback.

    The scanner initializes the dedicated key to zero. A high GPIO bit skips
    the two pressed-key assignments; a low bit selects 0x51 or 0x75. Its
    debouncer passes that byte to the original registered event callback.
    """
    from msm5xxx_emulator.detection.arm import thumb_bl_target, thumb_literal_value

    if not isinstance(image, bytes):
        return None
    limit = len(image) if code_limit is None else min(len(image), code_limit)
    profiles = []

    def words(at, count):
        if at < 0 or at > limit - count * 2:
            return ()
        return struct.unpack_from(f'<{count}H', image, at)

    # MOV r4,0; LDR r0,[r0,28]; MOV r5,31; LDR r0,[r0]; LSL r0,29.
    prefix = struct.pack('<5H', 0x2400, 0x69c0, 0x251f, 0x6800, 0x0740)
    for at in find_all(image[:limit], prefix):
        scan, entry = at - 2, at - 0x5a
        if scan < 0 or scan & 1:
            continue
        table = thumb_literal_value(image, scan, 0)
        state = thumb_literal_value(image, scan + 0xe, 4)
        if (table is None or not 0 <= table <= len(image) - 0x44
                or struct.unpack_from('<I', image, table + 0x1c)[0] != 0x48000040
                or struct.unpack_from('<I', image, table + 0x40)[0] != 0x48000050
                or state is None or not 0x01000000 <= state < 0x04000000
                or words(entry, 1) != (0xb5fe,)
                or thumb_literal_value(image, entry + 4, 4) != state
                or words(entry + 0x10, 1) != (0x78a0,)
                # BMI skips both pressed-code assignments with r4 still zero.
                or words(scan + 0xc, 1) != (0xd46b,)
                or words(scan + 0x10, 6) != (0x7820, 0x2875, 0xd101,
                                             0x2475, 0xe000, 0x2451)
                or thumb_literal_value(image, scan + 0x94, 2) != table
                or words(scan + 0x96, 5) != (0x6c10, 0x6800, 0x06c0,
                                             0x0ec0, 0x281f)):
            continue
        debounce = scan + 0x4a8
        event = thumb_bl_target(image, debounce + 0x16)
        if (thumb_literal_value(image, debounce, 6) != state
                or words(debounce + 2, 3) != (0x7830, 0x4284, 0xd10b)
                or words(debounce + 0x14, 1) != (0x1c20,)
                or event is None or words(event + 2, 5) != (0xb508, 0x390a,
                                                         0x7809, 0x2900, 0xd009)
                or words(event + 0xe, 9) != (0x390c, 0x6889, 0x2900,
                    0xd004, 0xab00, 0x7018, 0x9800, 0x4788, 0xbd08)):
            continue
        callback_state = thumb_literal_value(image, event, 1)
        if (callback_state is None or not 0x0100000c <= callback_state < 0x04000000
                or thumb_literal_value(image, event + 0xc, 1) != callback_state):
            continue
        callers = [pc for pc in range(scan + 0x500, min(scan + 0x1000, limit - 6), 2)
                   if thumb_bl_target(image, pc) == entry
                   and words(pc + 4, 1) == (0xbd80,)]
        if len(callers) != 1:
            continue
        profiles.append({'input': 0x48000040, 'width': 4, 'mask': 4,
            'released': 4, 'pressed': 0, 'pressed_codes': (0x51, 0x75),
            'scan_pc': scan, 'entry_pc': entry, 'gpio_table': table,
            'release_branch_pc': scan + 0xc, 'debounce_pc': debounce,
            'event_pc': event, 'caller_pc': callers[0]})
    return profiles[0] if len(profiles) == 1 else None


def find_boot_wake_input_profile(image: bytes, *, code_limit: int | None = None):
    """Bind an inactive external wake input to the original boot classifier.

    A low input changes the classifier's local selector from two to one;
    that selector changes the returned boot reason to five. The caller stores
    the returned halfword in its own boot record. The GPIO mask differs
    between the two closed bootstrap forms and is returned to the device.
    """
    from msm5xxx_emulator.detection.arm import thumb_bl_target, thumb_literal_value

    if not isinstance(image, bytes) or len(image) < 0x200c:
        return None
    limit = len(image) if code_limit is None else min(len(image), code_limit)
    source, destination, size = struct.unpack_from('<3I', image, 0x2000)
    if (source != 0x4000 or destination != 0 or not 0x4000 <= size <= 0x10000
            or source + size > limit):
        return None
    stage = image[source:source + size]
    profiles = []

    def words(at, count):
        if at < 0 or at > size - count * 2:
            return ()
        return struct.unpack_from(f'<{count}H', stage, at)

    # MOV selector,2; MOV reason,0; clear the three local classification bytes.
    prefix = struct.pack('<6H', 0x2502, 0x2400, 0x2000,
                         0x70b8, 0x70f8, 0x7138)
    for at in find_all(stage, prefix):
        entry = at - 4
        scan = entry + 0x10
        table = thumb_literal_value(stage, scan, 0)
        if (entry < 0 or entry & 1 or words(entry, 1) != (0xb5f8,)
                or table is None or not 0 <= table <= size - 0x20
                or struct.unpack_from('<I', stage, table + 0x1c)[0] != 0x48000040
                or words(scan + 2, 2) != (0x69c0, 0x6800)
                # BMI skips MOV selector,1 when the external input is high.
                or words(scan + 8, 2) != (0xd400, 0x2501)):
            continue
        # One form saves the selector immediately; the other calls two
        # peripheral helpers before saving it. Bind the differing GPIO bit
        # to its complete source form instead of selecting by image identity.
        if words(entry + 0x1e, 1) == (0x8005,):
            shift, latch_pc, normal, result = 27, entry + 0x1c, entry + 0x6e, entry + 0xe0
            store_delta = 0xa
        elif (thumb_bl_target(stage, entry + 0x1c) is not None
                and thumb_bl_target(stage, entry + 0x20) is not None
                and words(entry + 0x26, 1) == (0x8005,)):
            shift, latch_pc, normal, result = 26, entry + 0x24, entry + 0x7a, entry + 0xe8
            store_delta = 8
        else:
            continue
        latch = thumb_literal_value(stage, latch_pc, 0)
        if (words(scan + 6, 1) != (shift << 6,)
                or latch is None or not 0x03ffd000 <= latch < 0x03ffe000
                or thumb_literal_value(stage, normal, 0) != table
                # The ordinary input branch leaves reason1; the active wake
                # selector overrides it with reason5 through this same path.
                or words(normal + 2, 8) != (0x69c0, 0x6800, 0x0780, 0xd400,
                    0x2401, 0x2d01, 0xd100, 0x2405)
                or words(result, 2) != (0x1c20, 0xbdf8)):
            continue
        callers = []
        for pc in range(result + 4, min(result + 0x1000, size - 14), 2):
            if (thumb_bl_target(stage, pc) != entry
                    or thumb_literal_value(stage, pc + 4, 1) != 0x03ffd00c
                    or words(pc + store_delta, 1) != (0x8008,)):
                continue
            if store_delta == 0xa:
                if (thumb_literal_value(stage, pc + 6, 6) is None
                        or words(pc + 8, 1) != (0x1c05,)):
                    continue
            elif thumb_literal_value(stage, pc + 6, 2) != 0x03ffd00e:
                continue
            callers.append(pc)
        if len(callers) != 1:
            continue
        mask = 1 << (31 - shift)
        profiles.append({'input': 0x48000040, 'width': 4, 'mask': mask,
            'inactive': mask, 'active': 0, 'active_reason': 5,
            'normal_reason': 1, 'stage_source': source, 'stage_size': size,
            'entry_pc': entry, 'scan_pc': scan, 'gpio_table': table,
            'latch_pc': latch_pc, 'latch': latch, 'normal_pc': normal,
            'reason_pc': normal + 0x10, 'return_pc': result,
            'caller_pc': callers[0], 'store_pc': callers[0] + store_delta,
            'boot_record': 0x03ffd00c})
    if len(profiles) != 1:
        return None
    # Reuse the storage domain's reset-linked NAND loader and supplied-stage
    # proof. Metadata alone is insufficient to establish file-to-PC mapping.
    boot = find_boot_nand_word(
        image[:source + size])
    if (boot is None or not boot.get('word_interface')
            or boot['stage_source'] != source or boot['stage_size'] != size):
        return None
    return profiles[0]
