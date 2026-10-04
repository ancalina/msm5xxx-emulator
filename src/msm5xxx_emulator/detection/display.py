"""Firmware display-layout detection."""
from __future__ import annotations

import re
import struct

from .arm import thumb_bl_target, thumb_literal_value


LCD_PIXEL_RE = re.compile(rb"m\.LCD_PIXEL\x00{1,4}(\d{3})(\d{3})\x00")
PAGE_PLANES_DESCRIPTOR_RE = re.compile(
    rb"\x90\xb5\x1c\x1c\x00\x28.\x4f\x0b\xd1"
    rb"(?P<width>.)\x20\x38\x82(?P<height>.)\x20\x78\x82"
    rb"(?P<pages>.)\x20\x38\x83\xc3\x01\xc8\x18\x38\x62"
    rb"\xf9\x61\x14\xc7\x90\xbd"
    rb"\x60\x20\xb8\x82\x40\x20\xf8\x82\x08\x20\xb8\x84"
    rb"\xb9\x62\x00\x20\xf8\x62\xba\x60\xfc\x60",
    re.S,
)
FRAMEBUFFER_DESCRIPTOR_PATTERN = re.compile(
    rb"\x10\x22\x00\x28\x07\xd1(?P<width>.)\x20\x08\x60"
    rb"(?P<height>.)\x20\x48\x60\x8a\x60\xca\x60\x08\x48\x08\xe0"
    rb"\x01\x28\x09\xd1(?P<sub_width>.)\x20\x08\x60\x48\x60.\x20"
    rb"\x88\x60\x04\x48\xca\x60\x08\x61\x01\x20\x70\x47"
    rb"\x00\x20\x70\x47\x00\x00(?P<main>.{4})(?P<sub>.{4})"
    rb"\x00\x48\x70\x47(?P<end>.{4})",
    re.S,
)


def detect_lcd_width_hint(image: bytes) -> int | None:
    """Return one plausible firmware-declared UI width, never its viewport height."""
    widths = {
        int(match.group(1))
        for match in LCD_PIXEL_RE.finditer(image)
        if 64 <= int(match.group(1)) <= 320
        and 32 <= int(match.group(2)) <= 320
    }
    if widths:
        # Keep established metadata authoritative over this newer inference.
        return widths.pop() if len(widths) == 1 else None
    return find_page_plane_width(image)


def find_page_plane_width(image: bytes) -> int | None:
    """Return the unique width of the paired page-buffer descriptor class."""
    widths = {width for _start, width, _pages in _page_plane_descriptors(image)}
    return widths.pop() if len(widths) == 1 else None


def _page_plane_descriptors(image: bytes) -> list[tuple[int, int, int]]:
    found = []
    for match in PAGE_PLANES_DESCRIPTOR_RE.finditer(image):
        width, height, pages = (match.group(key)[0]
                                for key in ("width", "height", "pages"))
        descriptor = thumb_literal_value(image, match.start() + 6, 7)
        # LSL #7 places the second bitplane after pages * 128 bytes.
        # Height is a software viewport; leave glass height to runtime scans.
        if (match.start() % 2 == 0
                and width == 1 << 7 and height == pages * 8 and 8 <= pages <= 16
                and descriptor is not None and descriptor % 4 == 0
                and 0x01000000 <= descriptor <= 0x02000000 - 0x30):
            found.append((match.start(), width, pages))
    return found


def find_dual_page_ports(image: bytes) -> tuple[int, int] | None:
    """Bind two page-panel ports to one validated descriptor initializer."""
    targets = {start: (width, pages)
               for start, width, pages in _page_plane_descriptors(image)}
    pairs: set[tuple[int, int]] = set()
    setup = re.compile(
        rb".\x4f\x00\x21\x38\x1c.{4}"
        rb".\x4b\x39\x1c\x00\x20\x1a\x1f.{4}"
        rb".\x4b\x01\x20\x1a\x1f.\x49.{4}", re.S)
    for match in setup.finditer(image):
        start = match.start()
        target = thumb_bl_target(image, start + 18)
        if (start % 2 or target not in targets
                or thumb_bl_target(image, start + 30) != target):
            continue
        main = thumb_literal_value(image, start, 7)
        sub = thumb_literal_value(image, start + 28, 1)
        first = thumb_literal_value(image, start + 10, 3)
        second = thumb_literal_value(image, start + 22, 3)
        width, pages = targets[target]
        if (main is None or sub is None or first is None or second is None
                or main % 4 or sub != main + width * pages * 2
                or not 0x01000000 <= main < sub <= 0x02000000 - 96 * 8
                or first == second
                or any(port - 4 not in (0x02000000, 0x02800000)
                       for port in (first, second))):
            continue
        pairs.add((first - 4, second - 4))
    return next(iter(pairs)) if len(pairs) == 1 else None


def find_byte_main_page_secondary(image: bytes) -> tuple[int | None, str]:
    """Temporary mixed-display class; require descriptor, caller and byte writer.

    Software signatures describe one independently verified implementation.
    Runtime page qualification remains mandatory; physical polarity is unproven.
    """
    initializer = re.compile(
        re.escape(bytes.fromhex("b0b5141c1f1c0028")) + rb".\x4d" +
        re.escape(bytes.fromhex("0fd17820288395206883122028844b221202081ce962ff21")) + rb".{4}" +
        re.escape(bytes.fromhex("ac60ef60b0bd6020a8834020e8830820288669632c616f61")), re.S)
    inits = list(initializer.finditer(image))
    if not inits:
        color_page = _find_color_page_secondary(image)
        if color_page is not None:
            return color_page
    if len(inits) != 1 or inits[0].start() % 2:
        return None, "mixed-descriptor-missing-or-ambiguous"
    init = inits[0].start()
    clear = thumb_bl_target(image, init + 0x22)
    clear_body = bytes.fromhex(
        "8446830705d0521e12d30170401c8307f9d1083a07d30b0219430b041943"
        "0b1c0ac0083afcd2d21d02d38154521efcd26046f746")
    if clear is None or clear < 0 or image[clear:clear + len(clear_body)] != clear_body:
        return None, "mixed-initializer-clear-unproven"
    descriptor = thumb_literal_value(image, init + 8, 5)
    if descriptor is None or descriptor % 4 or not 0x01000000 <= descriptor <= 0x02000000 - 0x74:
        return None, "mixed-descriptor-outside-ram"
    writer = re.compile(
        rb"\xf0\xb5.\x4e" + re.escape(bytes.fromhex(
            "0025706d002800da7565b06d5f2801dd5f20b065f06d002800daf565306e072801dd"
            "07203066f06d22e001204006f91da9310170716d20310911102319430170716d2031"
            "0907090f0170706d08e0b18b381c4843716b4018005d")) + rb".{4}" +
        re.escape(bytes.fromhex(
            "601c0404b06d240c844201dc602cefdb781c0704306e3f0c874201dc082fd5db"
            "5f207065f065b5653566f0bd")), re.S)
    writers = list(writer.finditer(image))
    if len(writers) != 1 or writers[0].start() % 2:
        return None, "mixed-consumer-missing-or-ambiguous"
    start = writers[0].start()
    helper = thumb_bl_target(image, start + 0x5e)
    if (thumb_literal_value(image, start + 2, 6) != descriptor or helper is None
            or helper < 0 or image[helper:helper + 8] != bytes.fromhex("012149068880f746")):
        return None, "mixed-consumer-port-or-object-mismatch"
    setup_target = thumb_bl_target(image, init + 0x3e)
    setup_body = re.compile(re.escape(bytes.fromhex(
        "90b5ae2001277f06387040203870a02038701020387000243c70a6203870a320"
        "3870c82038702c2038707d20c000")) + rb".{4}" +
        re.escape(bytes.fromhex("2e2038707d20c000")) + rb".{4}" +
        re.escape(bytes.fromhex("2f2038707d20c000")) + rb".{4}" +
        re.escape(bytes.fromhex("242038708120387023203870")) + rb".\x48" +
        re.escape(bytes.fromhex("07210166c4655f2181654465")) + rb".{4}\x90\xbd", re.S)
    if (setup_target is None or setup_target < 0
            or not setup_body.match(image, setup_target)
            or thumb_literal_value(image, setup_target + 0x56, 0) != descriptor
            or thumb_bl_target(image, setup_target + 0x64) != start):
        return None, "mixed-secondary-initializer-chain-unproven"
    delays = [thumb_bl_target(image, setup_target + off) for off in (0x2e, 0x3a, 0x46)]
    delay = delays[0]
    delay_body = bytes.fromhex("152201e00a8032383228fbdc002806dd1b2358432d3000d53f3080110880f746")
    if (delay is None or delay < 0 or delays != [delay] * 3
            or thumb_literal_value(image, delay, 1) is None
            or image[delay + 2:delay + 2 + len(delay_body)] != delay_body):
        return None, "mixed-secondary-setup-preservation-unproven"
    # Writer constructs 1<<25 for commands; the verified leaf writes base+4.
    port = 1 << 25
    setup = re.compile(rb".\x4b\x00\x20\x1a\x1f.\x49.{4}"
                       rb".\x4b\x01\x20\x1a\x1f.\x49.{4}", re.S)
    bindings = []
    for match in setup.finditer(image):
        call = match.start()
        if call % 2 or any(thumb_bl_target(image, call + off) != init for off in (8, 20)):
            continue
        main = thumb_literal_value(image, call + 6, 1)
        sub = thumb_literal_value(image, call + 18, 1)
        if (thumb_literal_value(image, call, 3) != 0x02800004
                or thumb_literal_value(image, call + 12, 3) != port + 4
                or main is None or sub is None or main % 4 or sub % 4
                or not 0x01000000 <= main <= 0x02000000 - 120 * 160
                or not 0x01000000 <= sub <= 0x02000000 - 96 * 8
                or any(buffer < descriptor + 0x74 and descriptor < buffer + length
                       for buffer, length in ((main, 120 * 160), (sub, 96 * 8)))
                or not (sub >= main + 120 * 160 or main >= sub + 96 * 8)):
            continue
        bindings.append(call)
    if len(bindings) != 1:
        return None, "mixed-caller-missing-or-ambiguous"
    return port, "temporary-mixed-descriptor-consumer-awaiting-runtime"


def _find_color_page_secondary(image: bytes) -> tuple[int | None, str] | None:
    """Separate temporary color-buffer/byte-page consumer contract.

    The additional output remains a raw page-RAM view; these software bounds
    do not establish physical panel dimensions or orientation.
    """
    byte_core = re.compile(
        re.escape(bytes.fromhex("e8690204120c60247c4307e068682018805c"))
        + rb".{4}" + re.escape(bytes.fromhex(
            "01321204120c286a824201dc602af2db01373f043f0ca86a874201dc042fd0db")), re.S)
    cores = list(byte_core.finditer(image))
    if not cores:
        return None
    reject = (None, "temporary-color-page-contract-rejected")
    if len(cores) != 1 or cores[0].start() % 2:
        return reject
    byte = cores[0].start() - 0x88
    if byte < 0 or image[byte:byte + 2] != bytes.fromhex("f0b5"):
        return reject
    descriptor = thumb_literal_value(image, byte + 2, 4)
    # The color pixels are inline at +0x2e; the byte-page pointer is at +4.
    if (descriptor is None or descriptor % 4
            or not 0x01000000 <= descriptor <= 0x02000000 - 0x2e - 120 * 144 * 2
            or image[byte + 6:byte + 10] != bytes.fromhex("e0690028")
            or image[byte + 0x18:byte + 0x1e] != bytes.fromhex("206a5f2806dd")
            or image[byte + 0x28:byte + 0x2c] != bytes.fromhex("5f202062")
            or image[byte + 0x2c:byte + 0x30] != bytes.fromhex("606a0028")
            or image[byte + 0x40:byte + 0x46] != bytes.fromhex("a06a032806dd")
            or image[byte + 0x50:byte + 0x54] != bytes.fromhex("0320a062")):
        return reject
    data = thumb_bl_target(image, byte + 0x9a)
    command = thumb_bl_target(image, byte + 0x70)
    if (data is None or command is None or min(data, command) < 0
            or image[data:data + 8] != bytes.fromhex("0121490688807047")
            or image[command:command + 8] != bytes.fromhex("0121490608807047")
            or any(thumb_bl_target(image, byte + offset) != command
                   for offset in (0x7a, 0x84))):
        return reject
    color_core = re.compile(rb".\x4c" + re.escape(bytes.fromhex("3a1ca068e1686369"))
        + rb".{4}" + re.escape(bytes.fromhex(
            "7820a168784340184000e11d273140180523db057821491b490009e02a1c03e0068802309e80")), re.S)
    clamps = bytes.fromhex(
        "a068002801da0020a060e068772801dd7720e0602069002801da0020206160698f2801dd8f206061")
    colors = [m.start() for m in color_core.finditer(image)
              if m.start() % 2 == 0 and m.start() >= 0xc0
              and image[m.start() - 0xc0:m.start() - 0xc0 + len(clamps)] == clamps
              and thumb_literal_value(image, m.start(), 4) == descriptor]
    if len(colors) != 1:
        return reject
    color = colors[0]
    window = thumb_bl_target(image, color + 10)
    if (window is None or window < 0
            or image[window:window + 26] != bytes.fromhex(
                "90b443270524e405278020802180422020802280238090bc7047")):
        return reject
    # Setup initializes the same dirty-page object and calls this consumer.
    setup = re.compile(rb"\x80\xb5\xae\x20.{4}\x40\x20.{4}\xa0\x20.{4}"
        rb"\x10\x20.{4}\x00\x20.{4}\xa6\x20.{4}\xa3\x20.{4}\xc8\x20.{4}"
        rb"\x2c\x20.{4}\x7d\x27\xff\x00\x38\x1c.{4}\x2e\x20.{4}\x38\x1c.{4}"
        rb"\x2f\x20.{4}\x38\x1c.{4}\x24\x20.{4}\x81\x20.{4}\x23\x20.{4}"
        rb".\x49\x03\x20\x88\x62\x00\x22\x4a\x62\x5f\x20\x08\x62\xca\x61.{4}"
        rb"\x80\xbc\x08\xbc\x18\x47", re.S)
    setups = [m.start() for m in setup.finditer(image) if m.start() % 2 == 0]
    if (len(setups) != 1
            or thumb_literal_value(image, setups[0] + 0x6c, 1) != descriptor
            or thumb_bl_target(image, setups[0] + 0x7c) != byte
            or any(thumb_bl_target(image, setups[0] + offset) != command
                   for offset in (4, 10, 16, 22, 28, 34, 40, 46, 52,
                                  68, 80, 92, 98, 104))):
        return reject
    bindings = []
    caller = re.compile(rb".\x4a\x04\x20\x10\x80\x51\x60\x01\x20.{4}", re.S)
    for match in caller.finditer(image):
        start = match.start()
        if (start % 2 == 0 and thumb_literal_value(image, start, 2) == descriptor
                and thumb_bl_target(image, start + 10) == setups[0]):
            bindings.append(start)
    selector = re.compile(re.escape(bytes.fromhex(
        "80b5002817d10527ff050029")) + rb".\x48\x0b\xd0\x2c\x21\x39\x80"
        rb".{4}\x51\x20\x38\x80.\x48.{4}\x80\xbc\x08\xbc\x18\x47"
        rb"\x50\x21\x39\x80.{4}\x2d\x20\x38\x80\xf5\xe7"
        rb"\x00\x29\x01\xd0\xaf\x20\x00\xe0\xae\x20.{4}\xed\xe7", re.S)
    selectors = [m.start() for m in selector.finditer(image) if m.start() % 2 == 0]
    if (len(bindings) != 1 or len(selectors) != 1
            or thumb_bl_target(image, selectors[0] + 0x40) != command):
        return reject
    paired = re.compile(rb"(?P<state>.{2})\x00\x20.{4}(?P=state)\x01\x20.{4}", re.S)
    callers = [m.start() for m in paired.finditer(image)
               if m.start() % 2 == 0
               and int.from_bytes(m.group("state"), "little") & 0xf807 == 0x7801
               and thumb_bl_target(image, m.start() + 4) == selectors[0]
               and thumb_bl_target(image, m.start() + 12) == selectors[0]]
    if len(callers) != 1:
        return reject
    return 0x02000000, "temporary-color-page-consumer-awaiting-runtime"


def find_mixed_primary_power_port(image: bytes) -> int | None:
    """Power-pair helper; caller must also admit the mixed descriptor class."""
    pattern = re.compile(rb"\x00\xb5\x00\x28\x04\xd0\xae\x20.{4}"
                         rb"\x95\x20\x09\xe0\x94\x20.{4}.\x48.{4}"
                         rb".\x48.{4}\xaf\x20.{4}\x00\xbd", re.S)
    hits = list(pattern.finditer(image))
    if len(hits) != 1 or hits[0].start() % 2:
        return None
    start = hits[0].start()
    commands = [thumb_bl_target(image, start + off) for off in (8, 18, 36)]
    helper = commands[0]
    if (helper is None or helper < 0 or commands != [helper] * 3
            or image[helper:helper + 8] != bytes.fromhex("0521c9050880f746")):
        return None
    delays = [thumb_bl_target(image, start + off) for off in (24, 30)]
    delay = delays[0]
    body = bytes.fromhex("152201e00a8032383228fbdc002806dd1b2358432d3000d53f3080110880f746")
    if (delay is None or delay < 0 or delays != [delay] * 2
            or thumb_literal_value(image, delay, 1) is None
            or image[delay + 2:delay + 2 + len(body)] != body
            or any(thumb_literal_value(image, start + off, 0) != 50000 for off in (22, 28))):
        return None
    return 5 << 23


def find_paired_display_state_ports(image: bytes) -> tuple[int, int] | None:
    """Temporary class: selector/state helper plus same-state paired caller.

    The instruction sequence constructs command bases, selects AE/AF from R1,
    and performs halfword stores. This proves no physical panel role.
    """
    helper = bytes.fromhex(
        "031caf20ae22002b04d10523db05002906d003e001235b06002901d0"
        "1880f7461a80f746")
    targets = {match.start() for match in re.finditer(re.escape(helper), image)
               if match.start() % 2 == 0}
    if not targets:
        return None
    caller = re.compile(rb"(?P<state>.{2})\x00\x20.{4}(?P=state)\x01\x20.{4}", re.S)
    for match in caller.finditer(image):
        start = match.start()
        state = int.from_bytes(match.group("state"), "little")
        target = thumb_bl_target(image, start + 4)
        # LDRB R1,[Rn,#imm], repeated unchanged for selector zero and one.
        if (start % 2 == 0 and state & 0xF807 == 0x7801
                and target in targets
                and thumb_bl_target(image, start + 12) == target):
            return (0x02800000, 0x02000000)
    return None


def find_framebuffer_layout(
        image: bytes) -> tuple[int, int, int, int, int, int] | None:
    """Find the validated Qualcomm/LG main-LCD RAM descriptor and flush calls."""
    found: list[tuple[int, int, int, int, int, int]] = []
    for match in FRAMEBUFFER_DESCRIPTOR_PATTERN.finditer(image):
        start = match.start()
        width = match.group("width")[0]
        height = match.group("height")[0]
        sub_width = match.group("sub_width")[0]
        main, sub, end = (struct.unpack("<I", match.group(name))[0]
                          for name in ("main", "sub", "end"))
        stride = ((width + 7) // 8) * 16
        sub_stride = ((sub_width + 7) // 8) * 16
        if (not 32 <= min(width, height, sub_width)
                or main & 1
                or not 0x00800000 <= main < 0x08000000
                or sub != main + stride * height
                or end != sub + sub_stride * sub_width):
            continue
        if image[start + 0x44:start + 0x4E] != bytes.fromhex(
                "0920c002704702207047"):
            continue
        if image[start + 0x4E:start + 0x5C] != bytes.fromhex(
                "021c081c002a00b505d1db220021"):
            continue
        if image[start + 0x6E:start + 0x7C] != bytes.fromhex(
                "80b5071c081c111c1a1c002f04d1"):
            continue
        if image[start + 0x8C:start + 0x9A] != bytes.fromhex(
                "ffb581b00aaf151c1e1cb32090cf"):
            continue
        if image[start + 0xD0:start + 0xDA] != bytes.fromhex(
                "231c321c291c00970298"):
            continue
        row = thumb_bl_target(image, start + 0x5C)
        second_row = thumb_bl_target(image, start + 0x7C)
        rect = thumb_bl_target(image, start + 0xDA)
        if (row is None or row != second_row or rect is None
                or not 0 <= row < len(image) or not 0 <= rect < len(image)):
            continue
        found.append((width, height, main, stride, row, rect))
    return found[0] if len(found) == 1 else None


def find_packed_cursor_port(image: bytes) -> int | None:
    """Temporary glyph-writer class; runtime qualification is still required.

    A single independently observed writer supports this narrow signature.
    Keep native rendering until full-window and ordered glyph traffic agree;
    broaden only after another independent firmware reproduces the grammar.
    """
    prefix = bytes.fromhex("f7b501240521cd05281c")
    fragments = {14: "2f1d381c4349", 24: "1621281c",
                 32: "3f214902281d", 42: "1721281c"}
    helper_bytes = bytes.fromhex("01807047")
    found = []
    for match in re.finditer(re.escape(prefix), image):
        start = match.start()
        if start % 2 or any(
                image[start + offset:start + offset + len(bytes.fromhex(fragment))]
                != bytes.fromhex(fragment) for offset, fragment in fragments.items()):
            continue
        if thumb_literal_value(image, start + 18, 1) != 0x1038:
            continue
        targets = [thumb_bl_target(image, start + offset)
                   for offset in (10, 20, 28, 38, 46, 0xBC)]
        helper = targets[0]
        if (helper is None or helper < 0 or helper % 2
                or image[helper:helper + 4] != helper_bytes
                or any(target != helper for target in targets)):
            continue
        body = image[start:start + 0x180]
        if (image[start + 0xB8:start + 0xBA] != bytes.fromhex("2221")
                or not all(bytes.fromhex(shape) in body for shape in
                           ("152a23db", "062ce8db", "102ff2db", "2121281c"))):
            continue
        if not any(thumb_bl_target(image, start + tail.start() + 6) == helper
                   for tail in re.finditer(re.escape(bytes.fromhex("034904480839")), body)):
            continue
        found.append(start)
    # Prefix constructs r5 = 5 << 23; helper stores halfwords at that base.
    return 0x02800000 if len(found) == 1 else None


def find_packed12_port(image: bytes) -> int | None:
    """Temporary packed12 writer candidate; runtime grammar must also qualify.

    Two 12-bit table samples become three byte stores. A separate byte-port
    clear initializer provides the aperture. This single-image signature stays
    narrow until an independent firmware reproduces the same relation.
    """
    writer = bytes.fromhex(
        "f45a6e6824093470194e203ef45ab65a2401360aa4196e683470"
        "144e6d68203eb45a2c70")
    initializer = bytes.fromhex("0120400601700c2181702821")
    writers = [m.start() for m in re.finditer(re.escape(writer), image)
               if m.start() % 2 == 0]
    initializers = [m.start() for m in re.finditer(re.escape(initializer), image)
                    if m.start() % 2 == 0]
    if len(writers) != 1 or len(initializers) != 1:
        return None
    return 0x02000000


def find_window_panel_port(image: bytes) -> int | None:
    """Temporary byte-command/halfword-data window class from one glyph writer.

    The same function derives its port, selects mode2 and windows, emits
    column-first glyph words, then restores mode0. Runtime full-raster evidence
    is still required; no model or filename participates in admission.
    """
    full_setup = bytes.fromhex(
        "0e2139704021397038704321397038707f223a704221397038709f213970")
    setups = [m.start() for m in re.finditer(re.escape(full_setup), image)
              if m.start() % 2 == 0]
    if len(setups) != 1:
        return None
    prefix = bytes.fromhex("f8b44022d40422700222227043232370002222707f222270")
    fragments = {0x18: "422727700f0127700f372770",
                 0x26: "01267606",
                 0x80: "1f25b5800132102af4db0133082beadb",
                 0x9A: "40223270371c00233b70f8bc7047"}
    found = []
    for match in re.finditer(re.escape(prefix), image):
        start = match.start()
        if start % 2:
            continue
        if all(image[start + off:start + off + len(bytes.fromhex(value))]
               == bytes.fromhex(value) for off, value in fragments.items()):
            found.append(start)
    return 0x02000000 if len(found) == 1 else None


# Temporary supplied-image class: selector halfwords and retained RGB565 windows.
_SELECTOR_FULL = bytes.fromhex(
    "f0b41a4800210125027843788778c478c0686d0629802e0c9219aa8003221202"
    "9a18aa80013f3a06120eeb0bd218aa80013c2206120e05231b02d218aa801522"
    "1202aa8007225202aa8001222a8000277b00c35aab80013705231b039f42f7db"
    "034802700170f0bc7047")
_SELECTOR_PARTIAL = bytes.fromhex(
    "feb534480778457881780291c27801920379009303231b02c6682f48d91ff939"
    "0022047b01204006002c08d002808180ea188280294a8280019a013a0be00280"
    "8180ea1d09321206120ed2188280234a8280019a0f321206204b120e8133d218"
    "8280152212028280072252028280012202802c1c28e0")
_SELECTOR_TAIL = bytes.fromhex(
    "c11b89184900715a9980013002998842f6db0b4901e0998001308028fbdb0134"
    "01988442d3dbfebc08bc1847")


def detect_packed_selector_port(image: bytes, ram_base: int,
                                ram_size: int) -> tuple[int | None, str]:
    """Admit one linked full/partial selector writer; all near misses stay raw."""
    def pattern(body: bytes, literals: tuple[int, ...]) -> bytes:
        return b"".join(b"." if i in literals else re.escape(bytes((v,)))
                        for i, v in enumerate(body))

    full = [m.start() for m in re.finditer(
        pattern(_SELECTOR_FULL, (2, 0x60)), image, re.S) if m.start() % 2 == 0]
    partial = [m.start() for m in re.finditer(
        pattern(_SELECTOR_PARTIAL, (2, 0x1A, 0x34, 0x4E, 0x58)), image, re.S)
        if m.start() % 2 == 0]
    if not full or not partial:
        return None, "writer-signature-not-found"
    if len(full) != 1 or len(partial) != 1:
        return None, "writer-signature-ambiguous"
    a, b = full[0], partial[0]
    # Match the row-copy contract, not the intervening service-call semantics.
    # No BL encoding is normalized or accepted as a wildcard.
    tail = image[b + 0xA8:b + 0xD4]
    if re.fullmatch(pattern(_SELECTOR_TAIL, (0x12,)), tail, re.S) is None:
        return None, "partial-row-loop-mismatch"
    if not (0 <= ram_base < 2**32 and 0 < ram_size <= 2**32 - ram_base):
        return None, "invalid-ram-range"
    record = thumb_literal_value(image, a + 2, 0)
    peer = thumb_literal_value(image, b + 2, 0)
    flag = thumb_literal_value(image, b + 0x1A, 0)
    if (record is None or peer != record or record % 4
            or not ram_base <= record <= ram_base + ram_size - 16
            or flag is None or not ram_base <= flag <= ram_base + ram_size - 13):
        return None, "writer-record-literal-mismatch"
    # Every normalized PC-relative literal remains supplied-image bounded.
    control = thumb_literal_value(image, a + 0x60, 0)
    x_end = thumb_literal_value(image, b + 0x34, 2)
    peer_end = thumb_literal_value(image, b + 0x4E, 2)
    y_base = thumb_literal_value(image, b + 0x58, 3)
    padding = thumb_literal_value(image, b + 0xBA, 1)
    if (control != 0x03000600 or x_end != 0x047F
            or peer_end != x_end or y_base != x_end
            or padding is None or not 0 <= padding <= 0xFFFF):
        return None, "writer-control-literal-mismatch"
    return 0x02000000, "temporary-static-writer-match"
