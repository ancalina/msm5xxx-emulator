from __future__ import annotations

import functools
import hashlib
from dataclasses import dataclass, replace
from pathlib import Path

try:
    from . import tables_embedded as _embedded_tables
except Exception:  # pragma: no cover - parser still works without embedded tables.
    _embedded_tables = None


TICK_SEC = 0.004

YAMAHA_CH_PARAM_BASE = 0x100
YAMAHA_EX_PARAM_BASE = 0x200
YAMAHA_SFX_CHANGE_CONTROLLER = 0x300
YAMAHA_PITCH_BEND_CONTROLLER = 0x301
YAMAHA_3D_EVENT_CONTROLLER = 0x302
YAMAHA_3D_CHANNEL_CONTROLLER = 0x303
YAMAHA_SFX0_CHANGE_CONTROLLER = 0x304
YAMAHA_MASTER_VOLUME_CONTROLLER = 0x305

FMT7_DEFAULT_CH_PARAM_VALUES = {
    0x15: 68,   # CCh::SetSfx1Volume stores 68 >> 2 == 17.
    0x16: 0,    # CCh::SetSfx2Volume stores 0.
    0x17: 124,  # CCh::SetDryVolume stores 124 >> 2 == 31.
}


@functools.lru_cache(maxsize=None)
def _embedded_u8_table(name: str) -> bytes:
    if _embedded_tables is not None and _embedded_tables.has_table(name):
        return _embedded_tables.read_bytes(name)
    return b""


def fmt7_channel_volume_param_value(value: int) -> int:
    value = max(0, min(127, int(value)))
    db = _embedded_u8_table("ma7_macmd_volume_db_0x42EE00_u8.bin")
    volume_map = _embedded_u8_table("ma7_macmd_volume_map_0x42EE80_u8.bin")
    if len(db) >= 128 and len(volume_map) >= 193:
        level = min(192, int(db[value]) + int(db[127]) + int(db[100]))
        return (int(volume_map[level]) & 0x7C) | 1
    return (((value * 4) // 5) & 0x7C) | 1


def fmt7_pan_param_value(value: int) -> int:
    return (max(0, min(127, int(value))) & 0x7C) | 1

TIMEBASE_MS = {
    0x00: 1,
    0x01: 2,
    0x02: 4,
    0x03: 5,
    0x10: 10,
    0x11: 20,
    0x12: 40,
    0x13: 50,
}


def sha1(data: bytes, n: int = 12) -> str:
    return hashlib.sha1(data).hexdigest()[:n]


def read_be32(data: bytes, off: int) -> int:
    return int.from_bytes(data[off:off + 4], "big") if off + 4 <= len(data) else 0


def ma_vlq(data: bytes, pos: int) -> tuple[int, int]:
    """Legacy biased Yamaha/SMAF-style variable value.

    Continuation groups are biased by +1.  This is kept for old probes that
    exercised the Handy-like form, but native fmt2/MTR6 score conversion uses
    normal MIDI VLQ arithmetic for both delta and gate values.
    """
    value = 0
    count = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        count += 1
        if b & 0x80:
            value = (value + (b & 0x7F) + 1) << 7
            if count >= 4:
                break
            continue
        value += b
        break
    return value, pos


def ma_vlq_unterminated(data: bytes, start: int, end: int) -> bool:
    return end - start >= 4 and all((b & 0x80) for b in data[start:start + 4])


def scale_ticks(value: int, timebase: int) -> int:
    ms = TIMEBASE_MS.get(timebase, 4)
    return (int(value) * ms + 2) // 4


def handy_compact_channel_volume_value(value: int) -> int:
    """Convert Handy family-3/code-7 volume to the MA CVol command domain."""
    idx = max(0, min(31, (int(value) & 0x7F) // 5))
    return min(127, (idx << 2) | 3)


def handy_var(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        return 0, pos
    b0 = data[pos]
    pos += 1
    if not (b0 & 0x80):
        return b0, pos
    if pos >= len(data):
        return 128 + ((b0 & 0x7F) << 7), pos
    b1 = data[pos] & 0x7F
    pos += 1
    return 128 + ((b0 & 0x7F) << 7) + b1, pos


def midi_vlq(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    count = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        count += 1
        value = (value << 7) | (b & 0x7F)
        if not (b & 0x80) or count >= 4:
            break
    return value, pos


class _BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.bit_pos = 0

    def read_bit(self) -> int:
        if self.bit_pos >= len(self.data) * 8:
            raise EOFError
        byte = self.data[self.bit_pos >> 3]
        bit = (byte >> (7 - (self.bit_pos & 7))) & 1
        self.bit_pos += 1
        return bit

    def read_byte(self) -> int:
        value = 0
        for _ in range(8):
            value = (value << 1) | self.read_bit()
        return value


def _read_smaf_huffman_tree(reader: _BitReader, depth: int = 0):
    if depth > 512:
        raise ValueError("huffman tree too deep")
    marker = reader.read_bit()
    if marker == 0:
        return reader.read_byte()
    return (
        _read_smaf_huffman_tree(reader, depth + 1),
        _read_smaf_huffman_tree(reader, depth + 1),
    )


def _decode_smaf_huffman_symbol(tree, reader: _BitReader) -> int:
    node = tree
    while not isinstance(node, int):
        node = node[reader.read_bit()]
    return node & 0xFF


def decompress_smaf_huffman_data(body: bytes, max_output: int = 1_000_000) -> bytes | None:
    """Decode SMAF FormatType=1 Huffman(Data): Size + tree + bitstream."""
    if len(body) < 5:
        return None
    out_size = int.from_bytes(body[:4], "big")
    if out_size <= 0 or out_size > max_output:
        return None
    reader = _BitReader(body[4:])
    try:
        tree = _read_smaf_huffman_tree(reader)
        if isinstance(tree, int):
            return bytes([tree & 0xFF]) * out_size
        out = bytearray()
        while len(out) < out_size:
            out.append(_decode_smaf_huffman_symbol(tree, reader))
        return bytes(out)
    except (EOFError, ValueError, IndexError):
        return None


@dataclass(frozen=True)
class Chunk:
    tag: bytes
    offset: int
    size: int
    body: bytes

    @property
    def name(self) -> str:
        return self.tag.decode("latin1", errors="replace")


@dataclass
class YamahaSysEx:
    offset: int
    end: int
    body: bytes

    @property
    def version(self) -> int:
        return self.body[2] if len(self.body) > 2 else -1

    @property
    def command(self) -> int:
        return self.body[4] if len(self.body) > 4 else -1


@dataclass
class MtsuVoiceDef:
    offset: int
    group: int
    payload: bytes
    voice_sha1: str
    version: int = 7

    @property
    def bank(self) -> int:
        return self.payload[0] if len(self.payload) > 0 else 0

    @property
    def program_or_key(self) -> int:
        return self.payload[1] if len(self.payload) > 1 else 0

    @property
    def key(self) -> int:
        return self.payload[2] if len(self.payload) > 2 else 0

    @property
    def mode(self) -> int:
        return self.payload[3] if len(self.payload) > 3 else 0

    @property
    def is_wt(self) -> bool:
        return bool(self.mode & 1)


@dataclass
class Cmd03Wave:
    offset: int
    index: int
    kind: int
    blob: bytes
    ram_addr: int = 0
    ram_data: bytes = b""


@dataclass
class NoteEvent:
    tick: int
    ch: int
    note: int
    velocity: int
    span: int
    bank_msb: int
    bank_lsb: int
    program: int
    pan: int
    raw: bytes
    raw_velocity: int = 127
    channel_volume: int = 127
    channel_expression: int = 127
    slot_velocity_raw: int | None = None
    trigger_one_shot: bool = False
    track_format: int = -1
    source_order: int = 0

    @property
    def start_sec(self) -> float:
        return self.tick * TICK_SEC

    @property
    def dur_sec(self) -> float:
        return max(1, self.span) * TICK_SEC


@dataclass
class ChannelControlEvent:
    tick: int
    ch: int
    controller: int
    value: int
    raw: bytes

    @property
    def start_sec(self) -> float:
        return self.tick * TICK_SEC


def append_yamaha_sysex_controls(
    controls: list[ChannelControlEvent] | None,
    tick: int,
    sysex: bytes,
    raw: bytes,
    channel_base: int = 0,
) -> None:
    if controls is None:
        return
    if len(sysex) < 6 or sysex[0] != 0x43 or sysex[3] != 0x7F:
        return
    payload_end = len(sysex) - (1 if sysex[-1:] == b"\xF7" else 0)
    if payload_end < 5:
        return
    cmd = sysex[4]
    if cmd in (0x00, 0x20) and payload_end >= 6:
        controls.append(ChannelControlEvent(
            tick,
            channel_base,
            YAMAHA_MASTER_VOLUME_CONTROLLER,
            sysex[5] & 0x7F,
            raw,
        ))
    elif cmd == 0x0B and payload_end >= 8:
        reg = sysex[5] & 0x7F
        local_ch = sysex[6] & 0x0F
        value = sysex[7] & 0x7F
        controls.append(ChannelControlEvent(
            tick,
            channel_base + local_ch,
            YAMAHA_CH_PARAM_BASE + reg,
            value,
            raw,
        ))
    elif cmd == 0x0C and payload_end >= 8:
        reg = sysex[5] & 0x7F
        ex_id = sysex[6] & 0x0F
        value = sysex[7] & 0x7F
        controls.append(ChannelControlEvent(
            tick,
            ex_id,
            YAMAHA_EX_PARAM_BASE + reg,
            value,
            raw,
        ))


def parse_macmd_3d_event(body: bytes, status_pos: int) -> tuple[int, int] | None:
    if (
        status_pos + 2 < len(body)
        and body[status_pos] == 0x9E
        and body[status_pos + 1] <= 0x0F
        and body[status_pos + 2] >= 0x80
    ):
        value = ((body[status_pos + 1] & 0x0F) << 7) | (body[status_pos + 2] & 0x7F)
        return value, status_pos + 3
    return None


def parse_macmd_3d_channel(body: bytes, status_pos: int) -> tuple[int, int, int] | None:
    if status_pos + 3 >= len(body) or body[status_pos] != 0x8B:
        return None
    if (
        body[status_pos + 1] >= 0x80
        and body[status_pos + 2] == 0x94
        and body[status_pos + 3] >= 0x80
    ):
        target = body[status_pos + 1] & 0x7F
        value = body[status_pos + 3] & 0x7F
        return target, value, status_pos + 4
    if (
        status_pos + 4 < len(body)
        and body[status_pos + 1] >= 0x80
        and body[status_pos + 2] == 0x80
        and body[status_pos + 3] == 0x94
        and body[status_pos + 4] >= 0x80
    ):
        target = body[status_pos + 1] & 0x7F
        value = body[status_pos + 4] & 0x7F
        return target, value, status_pos + 5
    return None


def parse_macmd_send_level(body: bytes, status_pos: int) -> tuple[int, int, int, int] | None:
    if status_pos + 3 >= len(body) or body[status_pos] != 0x8B:
        return None
    target = body[status_pos + 1]
    if target < 0x80:
        return None
    if body[status_pos + 2] in (0x95, 0x96, 0x97) and body[status_pos + 3] >= 0x80:
        code_pos = status_pos + 2
        end = status_pos + 4
    elif (
        status_pos + 4 < len(body)
        and body[status_pos + 2] == 0x80
        and body[status_pos + 3] in (0x95, 0x96, 0x97)
        and body[status_pos + 4] >= 0x80
    ):
        code_pos = status_pos + 3
        end = status_pos + 5
    else:
        return None
    reg = {
        0x95: 0x15,  # ReverbSendLevel -> native SetSfx1Volume slot.
        0x96: 0x16,  # ChorusSendLevel -> native SetSfx2Volume slot.
        0x97: 0x17,  # DrySendLevel.
    }[body[code_pos]]
    value = body[end - 1] & 0x7F
    return target & 0x7F, reg, value, end


@dataclass
class AudioWaveData:
    track: int
    wave_id: int
    wave_type: int
    channels: int
    fmt: int
    sample_rate: int
    base_bits: int
    data: bytes
    source: str = "atr"


@dataclass
class AudioEvent:
    tick: int
    track: int
    ch: int
    wave_id: int
    velocity: int
    span: int
    pan: int
    raw: bytes

    @property
    def start_sec(self) -> float:
        return self.tick * TICK_SEC

    @property
    def dur_sec(self) -> float:
        return max(1, self.span) * TICK_SEC


@dataclass
class HvScript:
    index: int
    body: bytes
    chunk: bytes

    @property
    def text(self) -> str:
        return self.body.decode("shift_jis", errors="replace")

    @property
    def header(self) -> str:
        return self.text.splitlines()[0] if self.text else ""


@dataclass
class HvResource:
    offset: int
    config: bytes
    channel: int | None
    voice_blob: bytes
    script_blob: bytes
    scripts: dict[int, HvScript]


@dataclass
class HvNoteEvent:
    tick: int
    ch: int
    script: int
    raw: bytes

    @property
    def start_sec(self) -> float:
        return self.tick * TICK_SEC


def _chunk_tag_matches(head: bytes, tag: bytes | None = None) -> bool:
    if tag is not None:
        return head[:len(tag)] == tag
    if head in (b"Mtsu", b"Mtsq", b"MspI", b"Mtsp", b"AspI", b"Atsq"):
        return True
    return head[:3] in (b"Mwa", b"Awa")


def find_chunks(data: bytes, tag: bytes | None = None) -> list[Chunk]:
    chunks: list[Chunk] = []
    i = 0
    while i + 8 <= len(data):
        head = data[i:i + 4]
        if not _chunk_tag_matches(head, tag):
            i += 1
            continue
        size = read_be32(data, i + 4)
        available = len(data) - i - 8
        if 0 <= size <= available:
            chunks.append(Chunk(head, i, size, data[i + 8:i + 8 + size]))
            i += 8 + size
            continue
        if (
            (head in (b"Mtsq",) or head[:3] in (b"Awa", b"Mwa"))
            and 0 <= available
            and size <= available + 4096
        ):
            chunks.append(Chunk(head, i, available, data[i + 8:]))
            i = len(data)
            continue
        i += 1
    return chunks


def _looks_like_track_header(data: bytes, off: int, end: int) -> bool:
    if off + 18 > end:
        return False
    fmt = data[off]
    if fmt not in (0, 1, 2, 3):
        return False
    if data[off + 2] not in TIMEBASE_MS or data[off + 3] not in TIMEBASE_MS:
        return False
    return True


def _expected_track_header_len(fmt: int) -> int | None:
    return {
        0: 6,   # Handy compact tracks
        2: 20,  # MA MIDI-like/HVS tracks
        3: 36,  # MTR7 compact MA tracks
    }.get(fmt)


def _looks_like_atr_header(data: bytes, off: int, end: int) -> bool:
    if off + 6 > end:
        return False
    if data[off] not in (0, 1, 2, 3):
        return False
    if data[off + 4] not in TIMEBASE_MS or data[off + 5] not in TIMEBASE_MS:
        return False
    return True


def _recover_atr_body_after_bad_size(data: bytes, tag_off: int, end: int) -> tuple[int, bytes] | None:
    search_end = min(end, tag_off + 256)
    child_offs = []
    for i in range(tag_off + 8, search_end - 3):
        head = data[i:i + 4]
        if not (head in (b"AspI", b"Atsq") or head[:3] == b"Awa"):
            continue
        size = read_be32(data, i + 4)
        if 0 <= size <= max(0, end - i - 8) + 4096:
            child_offs.append(i)
    if not child_offs:
        return None
    first_child = min(child_offs)
    header_off = first_child - 6
    if header_off > tag_off + 7 and _looks_like_atr_header(data, header_off, first_child):
        return header_off, data[header_off:end]
    for header_off in range(first_child - 40, tag_off + 7, -1):
        if _looks_like_atr_header(data, header_off, first_child):
            return header_off, data[header_off:end]
    return None


def _recover_track_body_after_bad_size(data: bytes, tag_off: int, end: int) -> tuple[int, bytes] | None:
    """Recover malformed MTR chunks seen in some carrier ringtone dumps.

    A few MMMD resources contain an `MTR\0` marker whose following four bytes do
    not form a normal chunk size, but the real track header appears shortly
    before the first `Mtsu`/`Mtsq`/`Mtsp` child.  The native parser accepts these
    resources; treating their children as global fallback Mtsq streams causes
    severe timeline drift.
    """
    search_end = min(end, tag_off + 256)
    child_tags = (b"Mtsu", b"Mtsq", b"MspI", b"Mtsp")
    child_offs = [
        i for i in range(tag_off + 8, search_end - 3)
        if data[i:i + 4] in child_tags and 0 <= read_be32(data, i + 4) <= end - i - 8
    ]
    if not child_offs:
        return None
    first_child = min(child_offs)
    for header_len in (6, 20, 36):
        header_off = first_child - header_len
        if header_off > tag_off + 7 and _looks_like_track_header(data, header_off, first_child):
            expected = _expected_track_header_len(data[header_off])
            if expected == header_len:
                return header_off, data[header_off:end]
    for header_off in range(first_child - 40, tag_off + 7, -1):
        if _looks_like_track_header(data, header_off, first_child):
            return header_off, data[header_off:end]
    return None


def _extend_track_end_for_overlong_children(data: bytes, body_start: int, body_end: int) -> int:
    """Accept child chunks whose declared end is just past the parent MTR size.

    Some carrier dumps keep a valid MTR size field but under-count the last
    child chunk by a few bytes.  Native playback still indexes the child by its
    own chunk size; if we trust only the parent size, the Mtsq is missed and the
    global fallback parser may read it with the wrong format.
    """
    extended = body_end
    search_end = min(body_end, len(data) - 8)
    for i in range(body_start, search_end + 1):
        head = data[i:i + 4]
        if not (
            head in (b"Mtsu", b"Mtsq", b"MspI", b"Mtsp", b"AspI", b"Atsq")
            or head[:3] in (b"Awa", b"Mwa")
        ):
            continue
        size = read_be32(data, i + 4)
        child_end = i + 8 + size
        clipped_end = min(child_end, len(data))
        if 0 <= size <= max(0, len(data) - i - 8) + 4096 and body_end < clipped_end <= body_end + 4096:
            extended = max(extended, clipped_end)
    return extended


def parse_mspi_timing(track_body: bytes) -> tuple[int, int] | None:
    for chunk in find_chunks(track_body, b"MspI"):
        body = chunk.body
        if (
            len(body) >= 16
            and body[:3] == b"st:"
            and body[7:11] == b",sp:"
        ):
            start = int.from_bytes(body[3:7], "big")
            span = int.from_bytes(body[11:15], "big")
            return start, span
    return None


def find_track_chunks(data: bytes, prefix: bytes = b"MTR") -> list[Chunk]:
    chunks: list[Chunk] = []
    i = 0
    while i + 8 <= len(data):
        head = data[i:i + 4]
        if head[:3] != prefix:
            i += 1
            continue
        size = read_be32(data, i + 4)
        if prefix == b"ATR" and 0 <= size < 6:
            recovered_atr = _recover_atr_body_after_bad_size(data, i, len(data))
            if recovered_atr is not None:
                header_off, body = recovered_atr
                chunks.append(Chunk(head, i, len(body), body))
                i = max(i + 8, header_off + len(body))
                continue
        available = len(data) - i - 8
        if 0 <= size <= available or (0 <= size <= available + 4096):
            body_start = i + 8
            body_end = min(body_start + size, len(data))
            body_end = _extend_track_end_for_overlong_children(data, body_start, body_end)
            chunks.append(Chunk(head, i, body_end - body_start, data[body_start:body_end]))
            i = body_end
            continue
        recovered = _recover_track_body_after_bad_size(data, i, len(data))
        if recovered is not None:
            header_off, body = recovered
            chunks.append(Chunk(head, i, len(body), body))
            i = max(i + 8, header_off + len(body))
            continue
        i += 1
    return chunks


def iter_yamaha_sysex(data: bytes):
    i = 0
    while i < len(data):
        if data[i] != 0xF0:
            i += 1
            continue
        length, body_pos = midi_vlq(data, i + 1)
        end = body_pos + length
        if end > len(data) or length <= 0:
            i += 1
            continue
        body = data[body_pos:end]
        if (
            len(body) >= 6
            and body[0] == 0x43
            and body[3] == 0x7F
        ):
            yield YamahaSysEx(i, end, body)
            i = max(end, i + 1)
        else:
            i += 1


def iter_handy_mtsu_fm_sysex(data: bytes):
    i = 0
    while i < len(data):
        if data[i] != 0xF0:
            i += 1
            continue
        length, body_pos = midi_vlq(data, i + 1)
        end = body_pos + length
        if end > len(data) or length <= 0:
            i += 1
            continue
        body = data[body_pos:end]
        if (
            len(body) == 18
            and body[0] == 0x43
            and body[1] == 0x03
            and body[6] in (0x00, 0x01)
            and body[-1] == 0xF7
        ):
            yield YamahaSysEx(i, end, body)
            i = max(end, i + 1)
        else:
            i += 1


def transfer_to_direct_ram(kind: int, blob: bytes) -> bytes:
    if kind == 0:
        return blob
    if kind == 1:
        out = bytearray()
        i = 0
        while i < len(blob):
            ctrl = blob[i]
            i += 1
            for bit in range(6, -1, -1):
                if i >= len(blob):
                    break
                out.append((((ctrl >> bit) & 1) << 7) | (blob[i] & 0x7F))
                i += 1
        return bytes(out)
    if kind in (2, 4):
        out = bytearray()
        for b in blob:
            out.extend((b, 0))
        return bytes(out)
    return blob


def ram_used(kind: int, n: int) -> int:
    if kind == 0:
        return n
    if kind == 1:
        return 7 * (n >> 3) + (((n & 7) - 1) if (n & 7) else 0)
    if kind in (2, 4):
        return 2 * n
    return n


def parse_mtsu(data: bytes) -> tuple[list[MtsuVoiceDef], dict[int, Cmd03Wave]]:
    voices: list[MtsuVoiceDef] = []
    waves: list[Cmd03Wave] = []
    for sx in iter_handy_mtsu_fm_sysex(data):
        body = sx.body
        bank_code = body[3]
        program = body[4]
        key = body[2]
        payload = bytes((bank_code, program, key, 0x80)) + body
        voices.append(MtsuVoiceDef(sx.offset, 0x7E, payload, sha1(payload), sx.version))
    for sx in iter_yamaha_sysex(data):
        cmd = sx.command
        if cmd == 0x01 and len(sx.body) >= 7:
            group = sx.body[5]
            payload = sx.body[6:-1] if sx.body[-1:] == b"\xF7" else sx.body[6:]
            voices.append(MtsuVoiceDef(sx.offset, group, payload, sha1(payload), sx.version))
        elif cmd == 0x21 and sx.version >= 8 and len(sx.body) >= 12:
            group = sx.body[5]
            body = sx.body[:-1] if sx.body[-1:] == b"\xF7" else sx.body
            # MA-7 v8 custom voices are the v7 cmd01 layout with an
            # additional level byte before the WT/FM mode flags:
            #   group bank program/key key/arg level flags payload...
            # The resolver expects the normalized v7 payload shape.
            payload = bytes((body[6], body[7], body[8], body[10])) + body[11:]
            voices.append(MtsuVoiceDef(sx.offset, group, payload, sha1(payload), sx.version))
        elif cmd == 0x03:
            if sx.version >= 7 and len(sx.body) >= 8:
                index = sx.body[5]
                kind = sx.body[6]
                blob = sx.body[7:-1] if sx.body[-1:] == b"\xF7" else sx.body[7:]
                waves.append(Cmd03Wave(sx.offset, index, kind, blob))
            elif sx.version == 6 and len(sx.body) >= 8:
                index = sx.body[5]
                kind = 1
                blob = sx.body[7:-1] if sx.body[-1:] == b"\xF7" else sx.body[7:]
                waves.append(Cmd03Wave(sx.offset, index, kind, blob))
        elif cmd == 0x23 and sx.version >= 8 and len(sx.body) >= 8:
            index = sx.body[5]
            kind = sx.body[6]
            blob = sx.body[7:-1] if sx.body[-1:] == b"\xF7" else sx.body[7:]
            if kind == 1:
                # v8 command 0x23 kind 1 is already direct WT sample data.  The
                # older command 0x03 kind 1 path is 7-bit packed, but unpacking
                # v8 kind 1 truncates fmt1 samples and clips native loop windows.
                kind = 0
            waves.append(Cmd03Wave(sx.offset, index, kind, blob))

    addr = 0x10000
    out: dict[int, Cmd03Wave] = {}
    for wave in sorted(waves, key=lambda w: w.offset):
        wave.ram_addr = addr
        wave.ram_data = transfer_to_direct_ram(wave.kind, wave.blob)
        out[wave.index] = wave
        addr += (ram_used(wave.kind, len(wave.blob)) + 1) & ~1
    return voices, out


def parse_mtsu_dsp_controls(data: bytes) -> list[ChannelControlEvent]:
    controls: list[ChannelControlEvent] = []
    for sx in iter_yamaha_sysex(data):
        if sx.version < 8 or sx.command != 0x22 or len(sx.body) < 6:
            continue
        profile = sx.body[5] & 0x7F
        if profile == 0x08:
            # MA-7 v8 Mtsu profile 8 uploads the input-side mod1 program and
            # the reverb-side echo program before sequence playback.
            controls.append(ChannelControlEvent(
                0,
                0,
                YAMAHA_SFX_CHANGE_CONTROLLER,
                0x00,
                sx.body,
            ))
            controls.append(ChannelControlEvent(
                0,
                0,
                YAMAHA_SFX0_CHANGE_CONTROLLER,
                0x15,
                sx.body,
            ))
    return controls


def _is_mtsq_transport_marker(body: bytes, pos: int) -> bool:
    return (
        pos + 16 <= len(body)
        and body[pos:pos + 4] == b"\xFF\x7F\x01\x00"
        and body[pos + 5] == 0x00
        and body[pos + 7] == 0x00
        and body[pos + 14:pos + 16] == b"\xFF\xFF"
        and (
            body[pos + 8:pos + 14] == b"\xF0\x03\x00\x00\x01\x00"
            or body[pos + 10:pos + 14] == b"\x00\x00\x01\x00"
        )
    )


def strip_mtsq_transport_markers(body: bytes) -> bytes:
    """Remove Mobile Mtsq page markers before event decoding.

    Some fmt2/MTR6 sequences splice a 16-byte FF7F transport marker into the
    event stream, including between two bytes of the same VLQ.  The marker is
    not a musical event; stripping it restores the native byte stream.
    """
    if b"\xFF\x7F\x01\x00" not in body:
        return body
    out = bytearray()
    pos = 0
    while pos < len(body):
        if _is_mtsq_transport_marker(body, pos):
            pos += 16
            continue
        out.append(body[pos])
        pos += 1
    return bytes(out)


def _is_handy_transport_marker(body: bytes, pos: int) -> bool:
    if not (
        pos + 12 <= len(body)
        and body[pos:pos + 2] == b"\xFE\x00"
        and body[pos + 2] != 0
        and body[pos + 7] == 0
        and body[pos + 9] == 0
    ):
        return False

    tail0 = body[pos + 10]
    tail1 = body[pos + 11]
    return (
        (tail0 == 0xF0 and tail1 in (0x00, 0x01, 0x03))
        or (tail0 == 0xEF and tail1 == 0x02)
    )


def strip_handy_transport_markers(body: bytes) -> bytes:
    """Remove Handy FE00 page markers that are spliced into score bytes.

    The four bytes immediately before the FE00 page header are a page
    terminator/checksum footer.  Leaving them in the event stream makes the next
    parser read them as zero-length pseudo notes or huge VLQ deltas.
    """
    if b"\xFE\x00" not in body:
        return body
    out = bytearray()
    pos = 0
    while pos < len(body):
        if _is_handy_transport_marker(body, pos):
            if len(out) >= 4:
                del out[-4:]
            else:
                out.clear()
            pos += 12
            continue
        out.append(body[pos])
        pos += 1
    return bytes(out)


def parse_mtsq_midi_like(
    body: bytes,
    timebase_d: int = 0x02,
    timebase_g: int = 0x02,
    channel_base: int = 0,
    controls: list[ChannelControlEvent] | None = None,
    max_tick: int | None = None,
    biased_gate_vlq: bool = False,
) -> list[NoteEvent]:
    body = strip_handy_transport_markers(strip_mtsq_transport_markers(body))
    tick = 0
    pos = 0
    bank_msb = [0] * 32
    bank_lsb = [0] * 32
    program = [0] * 32
    volume = [127] * 32
    expression = [127] * 32
    pan = [64] * 32
    note_velocity = [127] * 32
    events: list[NoteEvent] = []
    gate_vlq = ma_vlq if biased_gate_vlq else midi_vlq

    def fe_marker_resume(fe_pos: int) -> int | None:
        payload = fe_pos + 2
        if fe_pos < 0 or payload + 10 > len(body):
            return None
        if body[fe_pos:payload] != b"\xFE\x00":
            return None
        if (
            body[payload + 1] == 0x00
            and body[payload + 3] == 0x00
            and body[payload + 4:payload + 8] == b"\x01\x00\x00\x00"
            and body[payload + 8:payload + 10] == b"\xF0\x01"
        ):
            return payload + 7
        return None

    def ff_marker_resume(ff_pos: int) -> int | None:
        if ff_pos < 0 or ff_pos + 16 > len(body):
            return None
        if _is_mtsq_transport_marker(body, ff_pos):
            return ff_pos + 16
        return None

    while pos < len(body):
        marker_resume = None
        for candidate in (pos, pos + 1, pos + 2, pos + 3):
            marker_resume = fe_marker_resume(candidate)
            if marker_resume is not None:
                break
            marker_resume = ff_marker_resume(candidate)
            if marker_resume is not None:
                break
        if marker_resume is not None:
            pos = marker_resume
            continue
        event_start = pos
        try:
            delta, pos = midi_vlq(body, pos)
        except Exception:
            break
        if ma_vlq_unterminated(body, event_start, pos):
            break
        tick += scale_ticks(delta, timebase_d)
        if max_tick is not None and tick > max_tick:
            break
        if pos >= len(body):
            break
        status = body[pos]
        pos += 1
        if status == 0xF0:
            length, pos = midi_vlq(body, pos)
            sysex_start = pos
            sysex_end = pos + length
            sysex = body[sysex_start:sysex_end] if sysex_end <= len(body) else b""
            if len(sysex) >= 6 and sysex[0] == 0x43 and sysex[-1:] == b"\xF7":
                pos = sysex_end
                append_yamaha_sysex_controls(
                    controls,
                    tick,
                    sysex,
                    body[event_start:pos],
                    channel_base,
                )
            else:
                # Keep raw Mtsq alignment on the declared F payload length.
                # The native converter also probes ahead while it validates
                # Yamaha packets, but its caller clamps against the declared
                # track tick span.  Without that outer clamp, consuming probe
                # bytes here turns end/control sentinels into giant deltas.
                consume = max(length, 4) if length == 1 else length
                pos = min(len(body), sysex_start + consume)
            continue
        if status == 0xFF:
            if pos >= len(body):
                break
            meta = body[pos]
            pos += 1
            if meta == 0x2F:
                length, pos = midi_vlq(body, pos)
                pos = min(len(body), pos + length)
                break
            # Observed Mtsq streams use FF 00 as a SMAF control/NOP marker.
            # Native conversion does not let the marker's leading delta advance
            # musical time; before the first note it also acts as a sequence
            # start marker after setup controls.  The following byte is the next
            # event delta, not a MIDI meta length.
            if meta == 0x00:
                tick = 0 if not events else tick - scale_ticks(delta, timebase_d)
                continue
            try:
                length, pos = midi_vlq(body, pos)
            except Exception:
                break
            if length < 0 or pos + length > len(body):
                break
            pos += length
            continue
        if (status & 0xF0) == 0xF0:
            try:
                length, pos = midi_vlq(body, pos)
            except Exception:
                break
            status_pos = pos - 1
            payload_start = pos
            payload_end = min(len(body), payload_start + max(0, length))
            payload = body[payload_start:payload_end]
            if len(payload) >= 6 and payload[0] == 0x43 and payload[-1:] == b"\xF7":
                append_yamaha_sysex_controls(
                    controls,
                    tick,
                    payload,
                    body[event_start:payload_end],
                    channel_base,
                )
                pos = payload_end
            else:
                resume = fe_marker_resume(status_pos) if status == 0xFE and length == 0 else None
                pos = resume if resume is not None else payload_end
            continue
        if status < 0x80:
            # sub_E84D0/sub_E6E50 do not have Handy-style compact status 0
            # controls.  Low status bytes are NOP-shaped and consume only the
            # status byte; consuming an extra byte here shifts following F0/FE
            # boundaries into the delta stream.
            for candidate in (pos, pos + 1):
                resume = fe_marker_resume(candidate)
                if resume is not None:
                    pos = resume
                    break
            continue

        parsed_3d = parse_macmd_3d_event(body, pos - 1)
        if parsed_3d is not None:
            value, pos = parsed_3d
            if controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    channel_base,
                    YAMAHA_3D_EVENT_CONTROLLER,
                    value,
                    body[event_start:pos],
                ))
            continue
        parsed_3d_channel = parse_macmd_3d_channel(body, pos - 1)
        if parsed_3d_channel is not None:
            target, value, pos = parsed_3d_channel
            if controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    channel_base + (target & 0x0F),
                    YAMAHA_3D_CHANNEL_CONTROLLER,
                    ((target & 0x7F) << 7) | (value & 0x7F),
                    body[event_start:pos],
                ))
            continue
        parsed_send = parse_macmd_send_level(body, pos - 1)
        if parsed_send is not None:
            target, reg, value, pos = parsed_send
            if controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    channel_base + (target & 0x0F),
                    YAMAHA_CH_PARAM_BASE + reg,
                    value,
                    body[event_start:pos],
                ))
            continue

        cmd = status & 0xF0
        local_ch = status & 0x0F
        ch = channel_base + local_ch
        if status == 0xA4 and pos + 1 < len(body):
            subcmd = body[pos]
            value = body[pos + 1]
            pos += 2
            if subcmd in (0x00, 0x80) and controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    channel_base,
                    YAMAHA_SFX0_CHANGE_CONTROLLER if subcmd == 0x80 else YAMAHA_SFX_CHANGE_CONTROLLER,
                    value & 0x7F,
                    body[event_start:pos],
                ))
            continue
        if cmd == 0x80:
            resume = fe_marker_resume(pos)
            if resume is not None:
                pos = resume
                continue
            if pos >= len(body):
                break
            note = body[pos]
            pos += 1
            span_start = pos
            span, pos = gate_vlq(body, pos)
            if ma_vlq_unterminated(body, span_start, pos):
                break
            span = max(1, scale_ticks(span, timebase_g))
            if max_tick is not None and tick + span > max_tick:
                span = max(1, max_tick - tick)
            raw_vel = max(0, min(127, note_velocity[ch]))
            vel = int(round(volume[ch] * raw_vel / 127.0))
            vel = max(1, min(127, vel))
            events.append(NoteEvent(
                tick, ch, note, vel, span,
                bank_msb[ch], bank_lsb[ch], program[ch], pan[ch],
                body[event_start:pos],
                raw_velocity=raw_vel,
                channel_volume=volume[ch],
                channel_expression=expression[ch],
                slot_velocity_raw=raw_vel,
            ))
        elif cmd == 0x90:
            resume = fe_marker_resume(pos)
            if resume is not None:
                pos = resume
                continue
            if pos + 1 >= len(body):
                break
            note = body[pos]
            raw_vel = body[pos + 1]
            note_velocity[ch] = raw_vel & 0x7F
            pos += 2
            span_start = pos
            span, pos = gate_vlq(body, pos)
            if ma_vlq_unterminated(body, span_start, pos):
                break
            if raw_vel <= 0 or span <= 0:
                continue
            span = max(1, scale_ticks(span, timebase_g))
            if max_tick is not None and tick + span > max_tick:
                span = max(1, max_tick - tick)
            vel = int(round(volume[ch] * note_velocity[ch] / 127.0))
            vel = max(1, min(127, vel))
            events.append(NoteEvent(
                tick, ch, note, vel, span,
                bank_msb[ch], bank_lsb[ch], program[ch], pan[ch],
                body[event_start:pos],
                raw_velocity=note_velocity[ch],
                channel_volume=volume[ch],
                channel_expression=expression[ch],
                slot_velocity_raw=note_velocity[ch],
            ))
        elif cmd == 0xB0:
            resume = fe_marker_resume(pos)
            if resume is not None:
                pos = resume
                continue
            if pos + 1 >= len(body):
                break
            cc = body[pos]
            val = body[pos + 1]
            pos += 2
            if controls is not None:
                controls.append(ChannelControlEvent(tick, ch, cc, val & 0x7F, body[event_start:pos]))
            if cc == 0:
                bank_msb[ch] = val
            elif cc == 32:
                bank_lsb[ch] = val
            elif cc == 7:
                volume[ch] = val
            elif cc == 10:
                pan[ch] = val
            elif cc == 11:
                expression[ch] = val
        elif cmd == 0xC0:
            resume = fe_marker_resume(pos)
            if resume is not None:
                pos = resume
                continue
            if pos >= len(body):
                break
            program[ch] = body[pos]
            pos += 1
        elif cmd in (0xA0, 0xE0):
            resume = fe_marker_resume(pos)
            if resume is not None:
                pos = resume
                continue
            if pos + 1 >= len(body):
                break
            lo = body[pos] & 0x7F
            hi = body[pos + 1] & 0x7F
            pos += 2
            if cmd == 0xE0 and controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    ch,
                    YAMAHA_PITCH_BEND_CONTROLLER,
                    (hi << 7) | lo,
                    body[event_start:pos],
                ))
        elif cmd == 0xD0:
            resume = fe_marker_resume(pos)
            pos = resume if resume is not None else min(len(body), pos + 1)
        else:
            # Unsupported but status-shaped event.
            pass
    return events


def parse_mtsq_handy(
    body: bytes,
    timebase_d: int = 0x02,
    timebase_g: int = 0x02,
    channel_base: int = 0,
    controls: list[ChannelControlEvent] | None = None,
    default_channel_volume: list[int] | None = None,
    extended_controls: bool = False,
    max_tick: int | None = None,
) -> list[NoteEvent]:
    body = strip_handy_transport_markers(body)
    tick = 0
    pos = 0
    bank_msb = [0] * 32
    bank_lsb = [0] * 32
    program = [0] * 32
    volume = [64] * 32
    channel_volume = [127] * 32
    if default_channel_volume is not None:
        for i, value in enumerate(default_channel_volume[:32]):
            channel_volume[i] = max(0, min(127, int(value)))
    velocity = [64] * 32
    pan = [64] * 32
    octave_shift = [0] * 32
    events: list[NoteEvent] = []
    setup_controls = extended_controls

    def apply_cc(ch: int, cc: int, val: int, raw: bytes) -> None:
        if not (0 <= ch < 32):
            return
        cc &= 0x7F
        val &= 0x7F
        if controls is not None:
            controls.append(ChannelControlEvent(tick, ch, cc, val, raw))
        if cc == 0:
            bank_msb[ch] = val
        elif cc == 32:
            bank_lsb[ch] = val
        elif cc == 7:
            volume[ch] = val
            velocity[ch] = max(1, val)
        elif cc == 10:
            pan[ch] = val
        elif cc == 11:
            velocity[ch] = max(1, val)

    while pos < len(body):
        if body[pos:pos + 4] == b"\x00\x00\x00\x00":
            break
        event_start = pos
        parsed_3d = parse_macmd_3d_event(body, pos)
        if parsed_3d is not None:
            value, pos = parsed_3d
            if controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    channel_base,
                    YAMAHA_3D_EVENT_CONTROLLER,
                    value,
                    body[event_start:pos],
                ))
            continue
        parsed_3d_channel = parse_macmd_3d_channel(body, pos)
        if parsed_3d_channel is not None:
            target, value, pos = parsed_3d_channel
            if controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    channel_base + (target & 0x0F),
                    YAMAHA_3D_CHANNEL_CONTROLLER,
                    ((target & 0x7F) << 7) | (value & 0x7F),
                    body[event_start:pos],
                ))
            continue
        parsed_send = parse_macmd_send_level(body, pos)
        if parsed_send is not None:
            target, reg, value, pos = parsed_send
            if controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    channel_base + (target & 0x0F),
                    YAMAHA_CH_PARAM_BASE + reg,
                    value,
                    body[event_start:pos],
                ))
            continue
        if extended_controls and (
            body[pos:pos + 2] in (b"\xFF\x00", b"\xFF\x2F")
            or (
                body[pos:pos + 1] == b"\xF0"
                and pos + 2 < len(body)
                and body[pos + 2:pos + 4] == b"\x43\x79"
            )
        ):
            delta = 0
        else:
            delta, pos = handy_var(body, pos)
            tick += scale_ticks(delta, timebase_d)
        if max_tick is not None and tick > max_tick:
            break
        if pos >= len(body):
            break

        ev = body[pos]
        pos += 1

        parsed_3d = parse_macmd_3d_event(body, pos - 1)
        if parsed_3d is not None:
            value, pos = parsed_3d
            if controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    channel_base,
                    YAMAHA_3D_EVENT_CONTROLLER,
                    value,
                    body[event_start:pos],
                ))
            continue
        parsed_3d_channel = parse_macmd_3d_channel(body, pos - 1)
        if parsed_3d_channel is not None:
            target, value, pos = parsed_3d_channel
            if controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    channel_base + (target & 0x0F),
                    YAMAHA_3D_CHANNEL_CONTROLLER,
                    ((target & 0x7F) << 7) | (value & 0x7F),
                    body[event_start:pos],
                ))
            continue
        parsed_send = parse_macmd_send_level(body, pos - 1)
        if parsed_send is not None:
            target, reg, value, pos = parsed_send
            if controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    channel_base + (target & 0x0F),
                    YAMAHA_CH_PARAM_BASE + reg,
                    value,
                    body[event_start:pos],
                ))
            continue

        if ev == 0xF0 and pos < len(body):
            size = body[pos]
            pos += 1
            sysex_start = pos
            pos = min(len(body), pos + size)
            append_yamaha_sysex_controls(
                controls,
                tick,
                body[sysex_start:pos],
                body[event_start:pos],
                channel_base,
            )
            continue

        if ev == 0xFF:
            if pos >= len(body):
                break
            code = body[pos]
            pos += 1
            if code == 0x00:
                continue
            if code == 0xF0 and pos < len(body):
                size = body[pos]
                pos += 1
                sysex_start = pos
                pos = min(len(body), pos + size)
                append_yamaha_sysex_controls(
                    controls,
                    tick,
                    body[sysex_start:pos],
                    body[event_start:pos],
                    channel_base,
                )
                continue
            continue

        if extended_controls and (0x30 <= ev <= 0x3F) and (
            setup_controls or not (1 <= (ev & 0x0F) <= 12)
        ):
            if pos + 1 >= len(body):
                break
            ch = channel_base + (ev & 0x0F)
            cc = body[pos]
            val = body[pos + 1]
            pos += 2
            apply_cc(ch, cc, val, body[event_start:pos])
            continue

        if extended_controls and (0x40 <= ev <= 0x4F) and (
            setup_controls or not (1 <= (ev & 0x0F) <= 12)
        ):
            if pos >= len(body):
                break
            ch = channel_base + (ev & 0x0F)
            if 0 <= ch < 32:
                program[ch] = body[pos] & 0x7F
            pos += 1
            continue

        if extended_controls and (0x80 <= ev <= 0x9F):
            cmd = ev & 0xF0
            ch = channel_base + (ev & 0x0F)
            if cmd == 0x80:
                if pos >= len(body):
                    break
                note = body[pos] & 0x7F
                pos += 1
                span, pos = handy_var(body, pos)
                raw_vel = max(1, min(127, velocity[ch] if 0 <= ch < 32 else 64))
            else:
                if pos + 1 >= len(body):
                    break
                note = body[pos] & 0x7F
                raw_vel = body[pos + 1] & 0x7F
                if 0 <= ch < 32:
                    velocity[ch] = max(1, raw_vel)
                pos += 2
                span, pos = handy_var(body, pos)
            span = max(1, scale_ticks(span, timebase_g))
            if max_tick is not None and tick + span > max_tick:
                span = max(1, max_tick - tick)
            if 0 <= ch < 32:
                vel = int(round(volume[ch] * max(1, raw_vel) / 127.0))
                vel = max(1, min(127, vel))
                events.append(NoteEvent(
                    tick, ch, note, vel, span,
                    bank_msb[ch], bank_lsb[ch], program[ch], pan[ch],
                    body[event_start:pos],
                    raw_velocity=max(1, raw_vel),
                    channel_volume=channel_volume[ch],
                    channel_expression=127,
                    slot_velocity_raw=max(1, raw_vel),
                    track_format=0,
                    source_order=event_start,
                ))
                setup_controls = False
            continue

        if extended_controls and (0xB0 <= ev <= 0xBF):
            if pos + 1 >= len(body):
                break
            ch = channel_base + (ev & 0x0F)
            cc = body[pos]
            val = body[pos + 1]
            pos += 2
            apply_cc(ch, cc, val, body[event_start:pos])
            continue

        if extended_controls and (0xC0 <= ev <= 0xCF):
            if pos >= len(body):
                break
            ch = channel_base + (ev & 0x0F)
            if 0 <= ch < 32:
                program[ch] = body[pos] & 0x7F
            pos += 1
            continue

        if extended_controls and ((0xA0 <= ev <= 0xAF) or (0xE0 <= ev <= 0xEF)):
            if pos + 1 >= len(body):
                break
            lo = body[pos] & 0x7F
            hi = body[pos + 1] & 0x7F
            pos += 2
            if (ev & 0xF0) == 0xE0 and controls is not None:
                ch = channel_base + (ev & 0x0F)
                controls.append(ChannelControlEvent(
                    tick,
                    ch,
                    YAMAHA_PITCH_BEND_CONTROLLER,
                    (hi << 7) | lo,
                    body[event_start:pos],
                ))
            continue

        if extended_controls and (0xD0 <= ev <= 0xDF):
            pos = min(len(body), pos + 1)
            continue

        if ev == 0x00:
            if pos >= len(body):
                break
            ctrl = body[pos]
            pos += 1
            local_ch = (ctrl >> 6) & 3
            ch = channel_base + local_ch
            family = (ctrl >> 4) & 3
            code = ctrl & 0x0F
            if family == 3:
                if pos >= len(body):
                    break
                val = body[pos]
                pos += 1
                if code == 0x0:
                    program[ch] = val & 0x7F
                elif code == 0x1:
                    if val & 0x80:
                        bank_msb[ch] = 0x80
                        bank_lsb[ch] = val & 0x7F
                    else:
                        bank_msb[ch] = 0x00
                        bank_lsb[ch] = val
                elif code == 0x2:
                    octave_shift[ch] = val if val < 0x80 else -(val & 0x7F)
                elif code == 0x6:
                    velocity[ch] = max(1, val & 0x7F)
                elif code == 0x7:
                    volume[ch] = val & 0x7F
                    channel_volume[ch] = handy_compact_channel_volume_value(volume[ch])
                    velocity[ch] = max(1, volume[ch])
                    if controls is not None:
                        controls.append(ChannelControlEvent(tick, ch, 7, channel_volume[ch], body[event_start:pos]))
                elif code == 0xA:
                    pan[ch] = val & 0x7F
                    if controls is not None:
                        controls.append(ChannelControlEvent(tick, ch, 10, pan[ch], body[event_start:pos]))
                elif code == 0xB:
                    velocity[ch] = val & 0x7F
                continue
            if code:
                # Handy short expression/modulation/pitch events have no
                # payload byte.  Keep expression as the next note velocity.
                if family == 0:
                    expr_map = (0, 0, 0x1F, 0x27, 0x2F, 0x37, 0x3F, 0x47,
                                0x4F, 0x57, 0x5F, 0x67, 0x6F, 0x77, 0x7F, 0)
                    velocity[ch] = expr_map[code]
                elif family == 2 and code == 0x2 and controls is not None:
                    controls.append(ChannelControlEvent(
                        tick,
                        ch,
                        YAMAHA_CH_PARAM_BASE + 0x0F,
                        1,
                        body[event_start:pos],
                    ))
                continue
            continue

        local_ch = (ev >> 6) & 3
        ch = channel_base + local_ch
        octave = (ev >> 4) & 3
        note_in_oct = ev & 0x0F
        if not (1 <= note_in_oct <= 12):
            if pos < len(body):
                _gate, pos = handy_var(body, pos)
            continue
        if extended_controls and pos < len(body) and body[pos] in (0xF0, 0xFF):
            continue
        gate, pos = handy_var(body, pos)
        if gate <= 0:
            continue
        span = max(1, scale_ticks(gate, timebase_g))
        if max_tick is not None and tick + span > max_tick:
            span = max(1, max_tick - tick)
        # Handy format names notes C#=1 ... B=11, C=12.  Native MaCmd_NoteOnMa2
        # keeps that trailing C at the end of the octave, not at semitone 0.
        semitone = note_in_oct
        note = 36 + octave * 12 + semitone + octave_shift[ch] * 12
        note = max(0, min(127, note))
        vel = max(1, min(127, velocity[ch] or volume[ch] or 64))
        # Compact Handy/MA2 notes do not carry an explicit note velocity.
        # Native MaCmd_NoteOnMa2 dispatches these with velocity 127 and leaves
        # track loudness to channel volume/expression controls.
        note_raw_velocity = 127
        events.append(NoteEvent(
            tick, ch, note, vel, span,
            bank_msb[ch], bank_lsb[ch], program[ch], pan[ch],
            body[event_start:pos],
            raw_velocity=note_raw_velocity,
            channel_volume=channel_volume[ch],
            channel_expression=127,
            slot_velocity_raw=note_raw_velocity,
            track_format=0,
            source_order=event_start,
        ))
        setup_controls = False
    return events


def handy_mtsq_score_limit(body: bytes) -> int | None:
    """Return the score prefix length before packed Handy page/trailer data.

    Old phone corpora contain valid Handy Mtsq chunks where the score prefix is
    followed by fixed-width binary pages.  The native converter stops through
    its sequence boundary state, but a linear parser sees the page header as a
    huge note gate/duration.  The page header is byte-regular:
    FE 00 xx 00 yy 00 ... with zero high bytes in the following 16-bit fields.
    """
    for pos in range(0, max(0, len(body) - 12)):
        if body[pos:pos + 2] != b"\xFE\x00":
            continue
        if body[pos + 3] or body[pos + 5] or body[pos + 7] or body[pos + 9]:
            continue
        if body[pos + 2] == 0 or body[pos + 4] == 0:
            continue
        return pos
    return None


def choose_handy_mtsq_score_body(
    body: bytes,
    timebase_d: int = 0x02,
    timebase_g: int = 0x02,
) -> bytes:
    """Use Handy page/trailer clipping only when it improves a bad timeline."""
    score_limit = handy_mtsq_score_limit(body)
    if score_limit is None:
        return body
    prefix = body[:score_limit]
    prefix_events = parse_mtsq_handy(prefix, timebase_d, timebase_g)
    if not prefix_events:
        return body

    full_events = parse_mtsq_handy(body, timebase_d, timebase_g)
    if not full_events:
        return prefix

    prefix_end = _note_events_end_tick(prefix_events) * TICK_SEC
    full_end = _note_events_end_tick(full_events) * TICK_SEC
    if full_end > 600.0 and 0.0 < prefix_end <= 600.0:
        return prefix
    return body


def parse_mtsq_fmt1(
    body: bytes,
    timebase_d: int = 0x02,
    timebase_g: int = 0x02,
    controls: list[ChannelControlEvent] | None = None,
    max_tick: int | None = None,
) -> list[NoteEvent]:
    decompressed = decompress_smaf_huffman_data(body)
    if decompressed is None:
        return []
    return parse_mtsq_midi_like(
        decompressed,
        timebase_d,
        timebase_g,
        controls=controls,
        max_tick=max_tick,
    )


def parse_mtsq_fmt7(
    body: bytes,
    timebase_d: int = 0x02,
    timebase_g: int = 0x02,
    controls: list[ChannelControlEvent] | None = None,
    default_channel_volume: list[int] | None = None,
    max_tick: int | None = None,
) -> list[NoteEvent]:
    """Parse MTR7/fmt3 compact MA sequence events.

    The native fmt7 converter uses MIDI-style VLQ values for both delta and
    gate, but compacts low channels by subtracting 0x80 from the MIDI status
    high nibble: 0x30 is CC, 0x40 is program change, 0x10/0x20 are note-on
    with velocity, and 0x00 is note-on using the last per-channel velocity.
    Status bytes with bit7 set address channels 16..31.
    """
    tick = 0
    pos = 0
    bank_msb = [0] * 32
    bank_lsb = [0] * 32
    program = [0] * 32
    volume = [127] * 32
    expression = [127] * 32
    pan = [64] * 32
    last_velocity = [100] * 32
    channel_volume = [127] * 32
    if default_channel_volume is not None:
        for i, value in enumerate(default_channel_volume[:32]):
            channel_volume[i] = max(0, min(127, int(value)))
    events: list[NoteEvent] = []

    if controls is not None:
        for ch in range(16):
            for reg, value in FMT7_DEFAULT_CH_PARAM_VALUES.items():
                controls.append(ChannelControlEvent(
                    0,
                    ch,
                    YAMAHA_CH_PARAM_BASE + reg,
                    value,
                    b"",
                ))

    def apply_cc(ch: int, cc: int, val: int, raw: bytes) -> None:
        if not 0 <= ch < 32:
            return
        cc &= 0x7F
        val &= 0x7F
        if controls is not None:
            controls.append(ChannelControlEvent(tick, ch, cc, val, raw))
            if ch < 16 and cc == 7:
                controls.append(ChannelControlEvent(
                    tick,
                    ch,
                    YAMAHA_CH_PARAM_BASE + 0x0C,
                    fmt7_channel_volume_param_value(val),
                    raw,
                ))
            elif ch < 16 and cc == 10:
                controls.append(ChannelControlEvent(
                    tick,
                    ch,
                    YAMAHA_CH_PARAM_BASE + 0x0D,
                    fmt7_pan_param_value(val),
                    raw,
                ))
        if cc == 0:
            bank_msb[ch] = val
        elif cc == 32:
            bank_lsb[ch] = val
        elif cc == 7:
            volume[ch] = val
        elif cc == 10:
            pan[ch] = val
        elif cc == 11:
            expression[ch] = val
        elif cc == 121:
            last_velocity[ch] = 100

    def emit_note(event_start: int, ch: int, note: int, raw_vel: int, gate: int) -> None:
        if gate <= 0 or not 0 <= ch < 32:
            return
        span = max(1, scale_ticks(gate, timebase_g))
        if max_tick is not None and tick + span > max_tick:
            span = max(1, max_tick - tick)
        raw_vel = max(1, min(127, int(raw_vel)))
        vel = int(round(volume[ch] * raw_vel / 127.0))
        vel = max(1, min(127, vel))
        events.append(NoteEvent(
            tick, ch, max(0, min(127, int(note))), vel, span,
            bank_msb[ch], bank_lsb[ch], program[ch], pan[ch],
            body[event_start:pos],
            raw_velocity=raw_vel,
            channel_volume=channel_volume[ch],
            channel_expression=expression[ch],
            slot_velocity_raw=raw_vel,
            track_format=3,
        ))

    while pos < len(body):
        if body[pos:pos + 4] == b"\x00\x00\x00\x00":
            break
        event_start = pos
        try:
            delta, pos = midi_vlq(body, pos)
        except Exception:
            break
        tick += scale_ticks(delta, timebase_d)
        if max_tick is not None and tick > max_tick:
            break
        if pos >= len(body):
            break
        status = body[pos]
        pos += 1
        parsed_3d = parse_macmd_3d_event(body, pos - 1)
        if parsed_3d is not None:
            value, pos = parsed_3d
            if controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    0,
                    YAMAHA_3D_EVENT_CONTROLLER,
                    value,
                    body[event_start:pos],
                ))
            continue
        parsed_3d_channel = parse_macmd_3d_channel(body, pos - 1)
        if parsed_3d_channel is not None:
            target, value, pos = parsed_3d_channel
            if controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    target & 0x0F,
                    YAMAHA_3D_CHANNEL_CONTROLLER,
                    ((target & 0x7F) << 7) | (value & 0x7F),
                    body[event_start:pos],
                ))
            continue
        parsed_send = parse_macmd_send_level(body, pos - 1)
        if parsed_send is not None:
            target, reg, value, pos = parsed_send
            if controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    target & 0x0F,
                    YAMAHA_CH_PARAM_BASE + reg,
                    value,
                    body[event_start:pos],
                ))
            continue
        cmd = status & 0xF0
        local_ch = status & 0x0F
        ch = local_ch + (16 if (status & 0x80) else 0)

        if cmd in (0x00, 0x80):
            if pos >= len(body):
                break
            note = body[pos] & 0x7F
            pos += 1
            gate, pos = midi_vlq(body, pos)
            raw_vel = last_velocity[ch] if 0 <= ch < 32 else 100
            emit_note(event_start, ch, note, raw_vel, gate)
            continue

        if cmd in (0x10, 0x20, 0x90):
            if pos + 1 >= len(body):
                break
            note = body[pos] & 0x7F
            raw_vel = body[pos + 1] & 0x7F
            pos += 2
            gate, pos = midi_vlq(body, pos)
            if 0 <= ch < 32:
                last_velocity[ch] = max(1, raw_vel)
            emit_note(event_start, ch, note, raw_vel, gate)
            continue

        if cmd in (0x30, 0xB0):
            if pos + 1 >= len(body):
                break
            cc = body[pos] & 0x7F
            val = body[pos + 1] & 0x7F
            pos += 2
            apply_cc(ch, cc, val, body[event_start:pos])
            continue

        if cmd in (0x40, 0xC0):
            if pos >= len(body):
                break
            if 0 <= ch < 32:
                program[ch] = body[pos] & 0x7F
            pos += 1
            continue

        if cmd in (0x50, 0xD0):
            pos = min(len(body), pos + 1)
            continue

        if cmd in (0x60, 0xE0):
            if pos + 1 >= len(body):
                break
            lo = body[pos] & 0x7F
            hi = body[pos + 1] & 0x7F
            pos += 2
            if cmd == 0xE0 and controls is not None:
                controls.append(ChannelControlEvent(
                    tick,
                    ch,
                    YAMAHA_PITCH_BEND_CONTROLLER,
                    (hi << 7) | lo,
                    body[event_start:pos],
                ))
            continue

        if cmd in (0x70, 0xA0):
            pos = min(len(body), pos + 2)
            continue

        if cmd == 0xF0:
            if local_ch == 0x0F:
                if pos >= len(body):
                    break
                meta = body[pos] & 0x7F
                pos += 1
                if meta == 0x2F:
                    break
                continue
            length, pos = midi_vlq(body, pos)
            sysex_start = pos
            sysex_end = min(len(body), pos + length)
            pos = sysex_end
            append_yamaha_sysex_controls(
                controls,
                tick,
                body[sysex_start:sysex_end],
                body[event_start:pos],
                0,
            )
            continue

        break

    return events


def _declared_chunk_tag(tag: bytes) -> bool:
    return len(tag) == 4 and all(32 <= b < 127 for b in tag)


def iter_declared_chunks(data: bytes, start: int = 0, end: int | None = None):
    p = max(0, int(start))
    limit = len(data) if end is None else min(len(data), max(0, int(end)))
    while p + 8 <= limit:
        tag = data[p:p + 4]
        size = read_be32(data, p + 4)
        if _declared_chunk_tag(tag) and 0 <= size <= limit - p - 8:
            yield Chunk(tag, p, size, data[p + 8:p + 8 + size])
            p += 8 + size
            continue
        break


def extract_mmmg_body(data: bytes) -> bytes | None:
    if len(data) >= 8 and data[:4] == b"MMMD":
        end = min(len(data), 8 + read_be32(data, 4))
        for chunk in iter_declared_chunks(data, 8, end):
            if chunk.tag == b"MMMG":
                return chunk.body
        return None
    if len(data) >= 2 and data[:4] == b"MMMG":
        size = read_be32(data, 4)
        if 0 <= size <= len(data) - 8:
            return data[8:8 + size]
    return None


def _old_exvo_payload(body: bytes) -> bytes | None:
    if len(body) >= 4 and body[0] == 0xFF and body[1] == 0xF0:
        size = body[2]
        payload = body[3:3 + size]
        if payload.startswith(b"\x43"):
            return payload
    marker = body.find(b"\x43")
    if marker < 0:
        return None
    end = body.rfind(b"\xF7")
    return body[marker:(end + 1 if end >= marker else len(body))]


def _old_exwv_parts(body: bytes) -> tuple[int, int, bytes] | None:
    if len(body) >= 8 and body[:2] == b"\xFF\xF1" and body[4:6] == b"\x43\x05":
        inner_len = int.from_bytes(body[2:4], "little")
        end = min(len(body), 4 + max(0, inner_len))
        if end < 8:
            end = len(body)
        payload = body[8:end]
        if payload[-1:] == b"\xF7":
            payload = payload[:-1]
        return body[6] & 0x7F, body[7] & 0x7F, payload

    marker = body.find(b"\x43\x05")
    if marker < 0 or marker + 4 > len(body):
        return None
    end = body.rfind(b"\xF7")
    if end < marker:
        end = len(body)
    inner = body[marker:end + 1]
    payload = inner[4:-1] if inner[-1:] == b"\xF7" else inner[4:]
    return inner[2] & 0x7F, inner[3] & 0x7F, payload


def parse_old_mmmg(data: bytes) -> tuple[list[MtsuVoiceDef], dict[int, Cmd03Wave], list[NoteEvent]]:
    """Parse EV-W/Anycall old MMMG resources: MMMG/VOIC/SEQU/EXVO/EXWV.

    This is intentionally separate from the MTR/Mtsq path.  Firmware tables
    list MMMG, VOIC and SEQU as their own parser entries, and EXWV one-shot
    resources use a short SEQU trigger gate rather than a full note duration.
    """
    mmmg = extract_mmmg_body(data)
    if not mmmg or len(mmmg) < 2:
        return [], {}, []

    voices: list[MtsuVoiceDef] = []
    waves: dict[int, Cmd03Wave] = {}
    notes: list[NoteEvent] = []
    prog_guess_4304 = 0
    prog_guess_4303 = 0

    for chunk in iter_declared_chunks(mmmg, 2, len(mmmg)):
        if chunk.tag == b"VOIC":
            for item in iter_declared_chunks(chunk.body, 0, len(chunk.body)):
                if item.tag == b"EXWV":
                    parsed = _old_exwv_parts(item.body)
                    if parsed is None:
                        continue
                    index, kind, blob = parsed
                    waves[index] = Cmd03Wave(
                        item.offset,
                        index,
                        kind,
                        blob,
                        ram_addr=0x10000,
                        ram_data=blob,
                    )
                    continue
                if item.tag != b"EXVO":
                    continue
                sx = _old_exvo_payload(item.body)
                if not sx or len(sx) < 3:
                    continue
                if sx[:3] == b"\x43\x05\x01":
                    bank = sx[3] & 0x7F if len(sx) > 3 else 0
                    program = sx[4] & 0x7F if len(sx) > 4 else 0
                    key = sx[5] & 0x7F if len(sx) > 5 else 0
                    compact = sx[6:-1] if sx[-1:] == b"\xF7" else sx[6:]
                    payload = bytes((bank, program, key, 0x80, 0)) + compact
                    voices.append(MtsuVoiceDef(item.offset, 0x7E, payload, sha1(payload), version=7))
                elif sx[:3] == b"\x43\x04\x01":
                    program = prog_guess_4304
                    prog_guess_4304 += 1
                    compact = sx[3:-1] if sx[-1:] == b"\xF7" else sx[3:]
                    payload = bytes((0, program, 0, 0x80, 0)) + compact
                    voices.append(MtsuVoiceDef(item.offset, 0x7E, payload, sha1(payload), version=7))
                elif sx[:3] == b"\x43\x03\x01":
                    program = prog_guess_4303
                    prog_guess_4303 += 1
                    compact = sx[3:-1] if sx[-1:] == b"\xF7" else sx[3:]
                    payload = bytes((0, program, 0, 0x80, 0)) + compact
                    voices.append(MtsuVoiceDef(item.offset, 0x7E, payload, sha1(payload), version=7))
                elif sx[:3] == b"\x43\x05\x02":
                    bank_code = sx[3] if len(sx) > 3 else 0
                    program = sx[4] & 0x7F if len(sx) > 4 else 0
                    record = sx[6:20]
                    raw_wave = sx[20] if len(sx) > 20 else 0
                    payload = bytes((bank_code, program, 0, 0x01)) + b"\x00\x00" + record + bytes((raw_wave,))
                    voices.append(MtsuVoiceDef(item.offset, 0x7E, payload, sha1(payload), version=8))
        elif chunk.tag == b"SEQU":
            local = parse_mtsq_handy(chunk.body, 0x02, 0x02)
            if waves:
                local = [replace(event, trigger_one_shot=True) for event in local]
            notes.extend(local)

    if waves and notes and not any(event.trigger_one_shot for event in notes):
        notes = [replace(event, trigger_one_shot=True) for event in notes]
    return voices, waves, notes


def _note_events_end_tick(events: list[NoteEvent]) -> int:
    return max((event.tick + event.span for event in events), default=0)


def parse_mtsq_fallback(
    body: bytes,
    controls: list[ChannelControlEvent] | None = None,
) -> list[NoteEvent]:
    """Parse orphan Mtsq chunks whose parent MTR was not recoverable."""
    midi_probe = parse_mtsq_midi_like(body)
    handy_probe = parse_mtsq_handy(body)
    midi_end = _note_events_end_tick(midi_probe)
    handy_end = _note_events_end_tick(handy_probe)
    use_handy = (
        bool(handy_probe)
        and (
            not midi_probe
            or (
                midi_end * TICK_SEC > 600.0
                and 0 < handy_end * TICK_SEC <= 600.0
            )
            or (
                0 < handy_end < midi_end // 4
                and handy_end * TICK_SEC <= 120.0
                and len(handy_probe) >= len(midi_probe)
            )
        )
    )
    if use_handy:
        return parse_mtsq_handy(body, controls=controls)
    return parse_mtsq_midi_like(body, controls=controls)


def handy_track_cvol_index(nibble: int) -> int:
    """Decode the 4-bit Handy MTR channel default volume to a CVol index.

    Android `CFmSynth::CalcAlg0` traces for sd0 show MTR header nibble 0x3
    feeding CVol index 25 and nibble 0xA feeding index 7.  The surrounding
    values follow the same coarse logarithmic 16-step attenuation shape used by
    the MA-series compact channel mixer.
    """
    table = (31, 30, 28, 25, 22, 20, 17, 15, 12, 10, 7, 5, 3, 2, 1, 0)
    return table[max(0, min(15, int(nibble)))]


def handy_track_channel_volumes(track_body: bytes, channel_base: int = 0) -> list[int]:
    out = [127] * 32
    if len(track_body) < 6:
        return out
    nibbles = (
        (track_body[4] >> 4) & 0x0F,
        track_body[4] & 0x0F,
        (track_body[5] >> 4) & 0x0F,
        track_body[5] & 0x0F,
    )
    for local_ch, nibble in enumerate(nibbles):
        ch = channel_base + local_ch
        if 0 <= ch < len(out):
            idx = handy_track_cvol_index(nibble)
            out[ch] = min(127, (idx << 2) | 3)
    return out


def decode_audio_wave_type(wave_type: int) -> tuple[int, int, int, int]:
    b0 = (wave_type >> 8) & 0xFF
    b1 = wave_type & 0xFF
    channels = 2 if (b0 & 0x80) else 1
    fmt = (b0 >> 4) & 0x07
    sample_rate = {
        0: 4000,
        1: 8000,
        2: 11025,
        3: 22050,
        4: 44100,
    }.get(b0 & 0x07, 8000)
    base_bits = {0: 4, 1: 8, 2: 12, 3: 16}.get((b1 >> 6) & 0x03, 4)
    return channels, fmt, sample_rate, base_bits


def decode_stream_wave_type(type_byte: int, sample_rate: int) -> tuple[int, int, int, int]:
    """Decode the 3-byte compact stream wave header used by Mwa resources.

    The native MaAudCnv parser masks out bit 3 before selecting the codec.
    The value passed to MaSndDrv_SetStream is not the high nibble of this
    byte; for example 0x20 maps to native stream format 0.
    """
    b = int(type_byte) & 0xFF
    normalized = b & 0xF7
    mapping = {
        0x20: (1, 0x00, 4),   # mono Yamaha 4-bit ADPCM
        0xA0: (2, 0x40, 4),   # stereo Yamaha 4-bit ADPCM
        0x01: (1, 0x03, 8),   # mono signed 8-bit PCM
        0x81: (2, 0x43, 8),   # stereo signed 8-bit PCM
        0x11: (1, 0x02, 8),   # mono unsigned 8-bit PCM
        0x91: (2, 0x42, 8),   # stereo unsigned 8-bit PCM
        0x03: (1, 0x01, 16),  # mono signed little-endian 16-bit PCM
        0x83: (2, 0x41, 16),  # stereo signed little-endian 16-bit PCM
    }
    if normalized in mapping:
        channels, fmt, base_bits = mapping[normalized]
    else:
        channels = 2 if (b & 0x80) else 1
        fmt = (b >> 4) & 0x07
        base_bits = {0: 4, 1: 8, 2: 12, 3: 16}.get(b & 0x03, 4)
    return channels, fmt, max(1, int(sample_rate)), base_bits


def stream_wave_codec(type_byte: int) -> str:
    normalized = int(type_byte) & 0xF7
    return {
        0x20: "adpcm4",
        0xA0: "adpcm4",
        0x01: "pcm_s8",
        0x81: "pcm_s8",
        0x11: "pcm_u8",
        0x91: "pcm_u8",
        0x03: "pcm_s16le",
        0x83: "pcm_s16le",
    }.get(normalized, "unknown")


def parse_mtsp(track: Chunk, mtsp: Chunk) -> dict[tuple[int, int], AudioWaveData]:
    waves: dict[tuple[int, int], AudioWaveData] = {}
    track_no = track.tag[3] if len(track.tag) > 3 else 0
    for chunk in find_chunks(mtsp.body):
        if chunk.tag[:3] != b"Mwa" or len(chunk.body) < 3:
            continue
        wave_id = chunk.tag[3]
        type_byte = chunk.body[0]
        sample_rate = int.from_bytes(chunk.body[1:3], "big")
        channels, wave_fmt, sample_rate, base_bits = decode_stream_wave_type(type_byte, sample_rate)
        waves[(track_no, wave_id)] = AudioWaveData(
            track_no,
            wave_id,
            type_byte,
            channels,
            wave_fmt,
            sample_rate,
            base_bits,
            chunk.body[3:],
            source="mwa",
        )
    return waves


def parse_atsq_handy(
    body: bytes,
    track_no: int,
    timebase_d: int = 0x02,
    timebase_g: int = 0x02,
) -> list[AudioEvent]:
    tick = 0
    pos = 0
    volume = [127] * 4
    expression = [127] * 4
    pan = [64] * 4
    events: list[AudioEvent] = []

    while pos < len(body):
        if body[pos:pos + 4] == b"\x00\x00\x00\x00":
            break
        event_start = pos
        delta, pos = handy_var(body, pos)
        tick += scale_ticks(delta, timebase_d)
        if pos >= len(body):
            break
        ev = body[pos]
        pos += 1

        if ev == 0xFF:
            if pos >= len(body):
                break
            code = body[pos]
            pos += 1
            if code == 0x00:
                continue
            if code == 0x2F:
                if pos < len(body):
                    pos += 1
                break
            if code == 0xF0 and pos < len(body):
                size = body[pos]
                pos += 1
                pos = min(len(body), pos + size)
            continue

        if ev == 0x00:
            if pos >= len(body):
                break
            ctrl = body[pos]
            pos += 1
            ch = (ctrl >> 6) & 3
            family = (ctrl >> 4) & 3
            code = ctrl & 0x0F
            if family == 3:
                if pos >= len(body):
                    break
                val = body[pos] & 0x7F
                pos += 1
                if code == 0x7:
                    volume[ch] = val
                elif code == 0xA:
                    pan[ch] = val
                elif code == 0xB:
                    expression[ch] = val
                continue
            if family == 0 and code:
                expr_map = (0, 0, 0x1F, 0x27, 0x2F, 0x37, 0x3F, 0x47,
                            0x4F, 0x57, 0x5F, 0x67, 0x6F, 0x77, 0x7F, 0)
                expression[ch] = expr_map[code]
            continue

        ch = (ev >> 6) & 3
        wave_id = ev & 0x3F
        if not (1 <= wave_id <= 0x3E):
            continue
        gate, pos = handy_var(body, pos)
        span = max(1, scale_ticks(gate, timebase_g))
        vel = int(round(volume[ch] * expression[ch] / 127.0))
        vel = max(1, min(127, vel))
        events.append(AudioEvent(
            tick, track_no, ch, wave_id, vel, span, pan[ch],
            body[event_start:pos],
        ))
    return events


def parse_atr(track: Chunk) -> tuple[dict[tuple[int, int], AudioWaveData], list[AudioEvent]]:
    waves: dict[tuple[int, int], AudioWaveData] = {}
    events: list[AudioEvent] = []
    if len(track.body) < 6:
        return waves, events
    fmt = track.body[0]
    wave_type = int.from_bytes(track.body[2:4], "big")
    timebase_d = track.body[4]
    timebase_g = track.body[5]
    track_no = track.tag[3] if len(track.tag) > 3 else 0
    channels, wave_fmt, sample_rate, base_bits = decode_audio_wave_type(wave_type)

    for chunk in find_chunks(track.body):
        if chunk.tag[:3] == b"Awa":
            wave_id = chunk.tag[3]
            waves[(track_no, wave_id)] = AudioWaveData(
                track_no, wave_id, wave_type, channels, wave_fmt,
                sample_rate, base_bits, chunk.body,
                source="awa",
            )
        elif chunk.tag == b"Atsq" and fmt == 0:
            events.extend(parse_atsq_handy(chunk.body, track_no, timebase_d, timebase_g))
    return waves, events


def parse_mthv(data: bytes) -> list[HvResource]:
    """Parse SMAF Humanoid Voice resources.

    Observed MA-7 HV files carry a top-level `Mthv` chunk with:
      `Mhvs` channel config, optional full `HVP\0` voice blob, and `Mhsc`
      script container.  The native bridge passes the `Mhsc` body directly to
      `MaSndDrv_SetHvScript` and the full `HVP\0` chunk to
      `MaSndDrv_SetHvVoice`.
    """
    resources: list[HvResource] = []
    for chunk in find_chunks(data, b"Mthv"):
        body = chunk.body
        pos = 0
        config = b""
        channel: int | None = None
        voice_parts: list[bytes] = []
        script_blob = b""
        scripts: dict[int, HvScript] = {}

        if pos + 8 <= len(body) and body[pos:pos + 4] == b"Mhvs":
            size = read_be32(body, pos + 4)
            if 0 <= size <= len(body) - pos - 8:
                config = body[pos + 8:pos + 8 + size]
                if len(config) >= 5 and config[:2] == b"CH":
                    channel = config[-1] & 0x0F
                pos += 8 + size

        mhsc_pos = body.find(b"Mhsc", pos)
        if mhsc_pos < 0:
            mhsc_pos = len(body)
        while pos + 8 <= mhsc_pos:
            tag = body[pos:pos + 4]
            size = read_be32(body, pos + 4)
            if tag[:3] in (b"HVP", b"HVD") and 0 <= size <= mhsc_pos - pos - 8:
                voice_parts.append(body[pos:pos + 8 + size])
                pos += 8 + size
            else:
                break
        if not voice_parts and pos < mhsc_pos:
            # Some files may carry an unknown HV voice block.  Keep the raw
            # bytes so later dynamic comparisons can still use exact input.
            voice_parts.append(body[pos:mhsc_pos])

        if mhsc_pos + 8 <= len(body) and body[mhsc_pos:mhsc_pos + 4] == b"Mhsc":
            size = read_be32(body, mhsc_pos + 4)
            if 0 <= size <= len(body) - mhsc_pos - 8:
                script_blob = body[mhsc_pos + 8:mhsc_pos + 8 + size]
                s_pos = 0
                while s_pos + 8 <= len(script_blob):
                    tag = script_blob[s_pos:s_pos + 4]
                    size = read_be32(script_blob, s_pos + 4)
                    if tag[:3] != b"Msc" or size < 0 or size > len(script_blob) - s_pos - 8:
                        break
                    index = tag[3]
                    script_body = script_blob[s_pos + 8:s_pos + 8 + size]
                    scripts[index] = HvScript(
                        index,
                        script_body,
                        script_blob[s_pos:s_pos + 8 + size],
                    )
                    s_pos += 8 + size

        resources.append(HvResource(
            chunk.offset,
            config,
            channel,
            b"".join(voice_parts),
            script_blob,
            scripts,
        ))
    return resources


def _parse_hv_note_events_midi_like(
    body: bytes,
    hv_channels: set[int],
    timebase_d: int = 0x02,
    timebase_g: int = 0x02,
    channel_base: int = 0,
    max_tick: int | None = None,
    biased_gate_vlq: bool = False,
) -> list[HvNoteEvent]:
    body = strip_handy_transport_markers(strip_mtsq_transport_markers(body))
    tick = 0
    pos = 0
    events: list[HvNoteEvent] = []
    gate_vlq = ma_vlq if biased_gate_vlq else midi_vlq

    while pos < len(body):
        event_start = pos
        try:
            delta, pos = midi_vlq(body, pos)
        except Exception:
            break
        if ma_vlq_unterminated(body, event_start, pos):
            break
        tick += scale_ticks(delta, timebase_d)
        if max_tick is not None and tick > max_tick:
            break
        if pos >= len(body):
            break
        status_pos = pos
        status = body[pos]
        pos += 1
        if status == 0xF0:
            try:
                length, pos = midi_vlq(body, pos)
            except Exception:
                break
            pos = min(len(body), pos + max(0, length))
            continue
        if status == 0xFF:
            if pos >= len(body):
                break
            meta = body[pos]
            pos += 1
            if meta == 0x2F:
                break
            if meta == 0x00:
                tick = 0 if not events else tick - scale_ticks(delta, timebase_d)
                continue
            try:
                length, pos = midi_vlq(body, pos)
            except Exception:
                break
            pos = min(len(body), pos + max(0, length))
            continue
        if (status & 0xF0) == 0xF0:
            try:
                length, pos = midi_vlq(body, pos)
            except Exception:
                break
            pos = min(len(body), pos + max(0, length))
            continue
        if status < 0x80:
            continue

        parsed_3d = parse_macmd_3d_event(body, status_pos)
        if parsed_3d is not None:
            _value, pos = parsed_3d
            continue
        parsed_3d_channel = parse_macmd_3d_channel(body, status_pos)
        if parsed_3d_channel is not None:
            _target, _value, pos = parsed_3d_channel
            continue
        parsed_send = parse_macmd_send_level(body, status_pos)
        if parsed_send is not None:
            _target, _reg, _value, pos = parsed_send
            continue

        cmd = status & 0xF0
        local_ch = status & 0x0F
        ch = channel_base + local_ch
        if status == 0xA4 and pos + 1 < len(body):
            pos += 2
            continue
        if cmd == 0x80:
            if pos >= len(body):
                break
            pos += 1
            try:
                _span, pos = gate_vlq(body, pos)
            except Exception:
                break
            continue
        if cmd == 0x90:
            if pos + 1 >= len(body):
                break
            pos += 2
            try:
                _span, pos = gate_vlq(body, pos)
            except Exception:
                break
            continue
        if cmd in (0xA0, 0xB0, 0xE0):
            pos = min(len(body), pos + 2)
            continue
        if cmd == 0xC0:
            pos = min(len(body), pos + 1)
            continue
        if cmd == 0xD0:
            if pos >= len(body):
                break
            script = body[pos] & 0x7F
            pos += 1
            if ch in hv_channels:
                events.append(HvNoteEvent(tick, ch, script, body[event_start:pos]))
            continue
    return events


def _parse_hv_note_events_fmt7(
    body: bytes,
    hv_channels: set[int],
    timebase_d: int = 0x02,
    timebase_g: int = 0x02,
    max_tick: int | None = None,
) -> list[HvNoteEvent]:
    tick = 0
    pos = 0
    events: list[HvNoteEvent] = []
    while pos < len(body):
        if body[pos:pos + 4] == b"\x00\x00\x00\x00":
            break
        event_start = pos
        try:
            delta, pos = midi_vlq(body, pos)
        except Exception:
            break
        tick += scale_ticks(delta, timebase_d)
        if max_tick is not None and tick > max_tick:
            break
        if pos >= len(body):
            break
        status_pos = pos
        status = body[pos]
        pos += 1

        parsed_3d = parse_macmd_3d_event(body, status_pos)
        if parsed_3d is not None:
            _value, pos = parsed_3d
            continue
        parsed_3d_channel = parse_macmd_3d_channel(body, status_pos)
        if parsed_3d_channel is not None:
            _target, _value, pos = parsed_3d_channel
            continue
        parsed_send = parse_macmd_send_level(body, status_pos)
        if parsed_send is not None:
            _target, _reg, _value, pos = parsed_send
            continue

        cmd = status & 0xF0
        local_ch = status & 0x0F
        ch = local_ch + (16 if (status & 0x80) else 0)
        if cmd in (0x00, 0x80):
            if pos >= len(body):
                break
            pos += 1
            try:
                _gate, pos = midi_vlq(body, pos)
            except Exception:
                break
            continue
        if cmd in (0x10, 0x20, 0x90):
            if pos + 1 >= len(body):
                break
            pos += 2
            try:
                _gate, pos = midi_vlq(body, pos)
            except Exception:
                break
            continue
        if cmd in (0x30, 0x70, 0xA0, 0xB0, 0x60, 0xE0):
            pos = min(len(body), pos + 2)
            continue
        if cmd in (0x40, 0xC0):
            pos = min(len(body), pos + 1)
            continue
        if cmd in (0x50, 0xD0):
            if pos >= len(body):
                break
            script = body[pos] & 0x7F
            pos += 1
            if ch in hv_channels:
                events.append(HvNoteEvent(tick, ch, script, body[event_start:pos]))
            continue
        if cmd == 0xF0:
            if local_ch == 0x0F:
                if pos >= len(body):
                    break
                meta = body[pos] & 0x7F
                pos += 1
                if meta == 0x2F:
                    break
                continue
            try:
                length, pos = midi_vlq(body, pos)
            except Exception:
                break
            pos = min(len(body), pos + max(0, length))
            continue
        break
    return events


def parse_hv_note_events(data: bytes, resources: list[HvResource] | None = None) -> list[HvNoteEvent]:
    resources = resources if resources is not None else parse_mthv(data)
    hv_channels = {int(r.channel) for r in resources if r.channel is not None}
    if not hv_channels:
        return []
    events: list[HvNoteEvent] = []
    for track in find_track_chunks(data, b"MTR"):
        if len(track.body) < 6:
            continue
        fmt = track.body[0]
        timebase_d = track.body[2]
        timebase_g = track.body[3]
        track_no = track.tag[3] if len(track.tag) > 3 else 0
        channel_base = max(0, track_no - 1) * 4 if fmt == 0 else 0
        for chunk in find_chunks(track.body, b"Mtsq"):
            if fmt == 1:
                seq_body = decompress_smaf_huffman_data(chunk.body)
                if seq_body is None:
                    continue
                events.extend(_parse_hv_note_events_midi_like(
                    seq_body,
                    hv_channels,
                    timebase_d,
                    timebase_g,
                    channel_base=channel_base,
                ))
            elif fmt == 2:
                events.extend(_parse_hv_note_events_midi_like(
                    chunk.body,
                    hv_channels,
                    timebase_d,
                    timebase_g,
                ))
            elif fmt == 3:
                events.extend(_parse_hv_note_events_fmt7(
                    chunk.body,
                    hv_channels,
                    timebase_d,
                    timebase_g,
                ))
    events.sort(key=lambda e: e.tick)
    return events


def load_hv_note_events(path: Path, resources: list[HvResource] | None = None) -> list[HvNoteEvent]:
    return parse_hv_note_events(path.read_bytes(), resources)


def split_mwa_note_audio_events(
    track_no: int,
    notes: list[NoteEvent],
    track_audio_waves: dict[tuple[int, int], AudioWaveData],
) -> tuple[list[NoteEvent], list[AudioEvent]]:
    mwa_ids = {
        wave.wave_id
        for wave in track_audio_waves.values()
        if wave.source == "mwa"
    }
    if not mwa_ids:
        return notes, []
    keep: list[NoteEvent] = []
    audio: list[AudioEvent] = []
    for note in notes:
        wave_id = note.note + 1
        if wave_id in mwa_ids:
            audio.append(AudioEvent(
                note.tick,
                track_no,
                note.ch,
                wave_id,
                note.velocity,
                note.span,
                note.pan,
                note.raw,
            ))
        else:
            keep.append(note)
    return keep, audio


def fallback_single_mwa_audio_event(
    track: Chunk,
    track_audio_waves: dict[tuple[int, int], AudioWaveData],
) -> list[AudioEvent]:
    """Recover simple Mwa-only stream tracks when the score dialect is unknown.

    A few carrier files use a short fmt1 score dialect that only keys a single
    stream wave.  The track still carries an MspI start/span pair and exactly one
    Mwa resource; scheduling that stream once matches the observable resource
    intent without inventing melodic notes for Mtsu-only resource files.
    """
    mwa = [
        wave for wave in track_audio_waves.values()
        if wave.source == "mwa"
    ]
    if len(mwa) != 1:
        return []
    timing = parse_mspi_timing(track.body)
    if timing is None:
        return []
    start, span = timing
    if span <= 0:
        return []
    track_no = track.tag[3] if len(track.tag) > 3 else mwa[0].track
    return [AudioEvent(
        max(0, int(start)),
        track_no,
        9,
        mwa[0].wave_id,
        100,
        max(1, int(span)),
        64,
        b"",
    )]


def shift_event_ticks(
    notes: list[NoteEvent],
    controls: list[ChannelControlEvent],
    offset: int,
) -> tuple[list[NoteEvent], list[ChannelControlEvent]]:
    offset = max(0, int(offset))
    if offset <= 0:
        return notes, controls
    return (
        [replace(event, tick=max(0, int(event.tick) - offset)) for event in notes],
        [replace(event, tick=max(0, int(event.tick) - offset)) for event in controls],
    )


def load_mmf(path: Path) -> tuple[list[MtsuVoiceDef], dict[int, Cmd03Wave], list[NoteEvent]]:
    voices, waves, notes, _audio_waves, _audio_events = load_mmf_full(path)
    return voices, waves, notes


def load_hv_resources(path: Path) -> list[HvResource]:
    return parse_mthv(path.read_bytes())


def load_mmf_full(
    path: Path,
) -> tuple[
    list[MtsuVoiceDef],
    dict[int, Cmd03Wave],
    list[NoteEvent],
    dict[tuple[int, int], AudioWaveData],
    list[AudioEvent],
]:
    voices, waves, notes, audio_waves, audio_events, _controls = load_mmf_full_with_controls(path)
    return voices, waves, notes, audio_waves, audio_events


def load_mmf_full_with_controls(
    path: Path,
) -> tuple[
    list[MtsuVoiceDef],
    dict[int, Cmd03Wave],
    list[NoteEvent],
    dict[tuple[int, int], AudioWaveData],
    list[AudioEvent],
    list[ChannelControlEvent],
]:
    data = path.read_bytes()
    voices: list[MtsuVoiceDef] = []
    waves: dict[int, Cmd03Wave] = {}
    notes: list[NoteEvent] = []
    audio_waves: dict[tuple[int, int], AudioWaveData] = {}
    audio_events: list[AudioEvent] = []
    controls: list[ChannelControlEvent] = []

    parsed_tracks = False
    for track in find_track_chunks(data, b"MTR"):
        if len(track.body) < 6:
            continue
        fmt = track.body[0]
        timebase_d = track.body[2]
        timebase_g = track.body[3]
        track_no = track.tag[3] if len(track.tag) > 3 else 0
        channel_base = max(0, track_no - 1) * 4 if fmt == 0 else 0
        default_channel_volume = handy_track_channel_volumes(track.body, channel_base) if fmt in (0, 3) else None
        track_audio_waves: dict[tuple[int, int], AudioWaveData] = {}
        for chunk in find_chunks(track.body, b"Mtsp"):
            track_audio_waves.update(parse_mtsp(track, chunk))
        audio_waves.update(track_audio_waves)
        for chunk in find_chunks(track.body, b"Mtsu"):
            v, w = parse_mtsu(chunk.body)
            voices.extend(v)
            waves.update(w)
            controls.extend(parse_mtsu_dsp_controls(chunk.body))
        for chunk in find_chunks(track.body, b"Mtsq"):
            parsed_tracks = True
            track_controls: list[ChannelControlEvent] = []
            if fmt == 0:
                seq_body = choose_handy_mtsq_score_body(
                    chunk.body,
                    timebase_d,
                    timebase_g,
                )
                local_notes = parse_mtsq_handy(
                    seq_body,
                    timebase_d,
                    timebase_g,
                    channel_base,
                    track_controls,
                    default_channel_volume,
                )
            elif fmt == 1:
                local_notes = parse_mtsq_fmt1(
                    chunk.body,
                    timebase_d,
                    timebase_g,
                    controls=track_controls,
                )
                if _note_events_end_tick(local_notes) * TICK_SEC > 600.0:
                    local_notes = []
            elif fmt == 3:
                local_notes = parse_mtsq_fmt7(
                    chunk.body,
                    timebase_d,
                    timebase_g,
                    track_controls,
                    default_channel_volume,
                )
                if local_notes:
                    first_tick = min(event.tick for event in local_notes)
                    local_notes, track_controls = shift_event_ticks(
                        local_notes,
                        track_controls,
                        first_tick,
                    )
            elif fmt == 2:
                local_notes = parse_mtsq_midi_like(
                    chunk.body,
                    timebase_d,
                    timebase_g,
                    controls=track_controls,
                )
                if _note_events_end_tick(local_notes) * TICK_SEC > 600.0:
                    local_notes = []
            else:
                local_notes = []
            local_notes, local_audio = split_mwa_note_audio_events(track_no, local_notes, track_audio_waves)
            if not local_notes and not local_audio and track_audio_waves:
                local_audio = fallback_single_mwa_audio_event(track, track_audio_waves)
            notes.extend(local_notes)
            audio_events.extend(local_audio)
            controls.extend(track_controls)

    if not parsed_tracks:
        for chunk in find_chunks(data, b"Mtsu"):
            v, w = parse_mtsu(chunk.body)
            voices.extend(v)
            waves.update(w)
            controls.extend(parse_mtsu_dsp_controls(chunk.body))
        for chunk in find_chunks(data, b"Mtsq"):
            notes.extend(parse_mtsq_fallback(chunk.body, controls=controls))

    if not notes and not audio_events:
        old_voices, old_waves, old_notes = parse_old_mmmg(data)
        if old_voices or old_waves or old_notes:
            voices.extend(old_voices)
            waves.update(old_waves)
            notes.extend(old_notes)

    for track in find_track_chunks(data, b"ATR"):
        aw, ae = parse_atr(track)
        audio_waves.update(aw)
        audio_events.extend(ae)
    notes.sort(key=lambda e: (
        e.tick,
        int(getattr(e, "source_order", 0)) if int(getattr(e, "track_format", -1)) == 0 else 0,
    ))
    audio_events.sort(key=lambda e: e.tick)
    controls.sort(key=lambda e: e.tick)
    return voices, waves, notes, audio_waves, audio_events, controls
