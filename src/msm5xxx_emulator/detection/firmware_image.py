"""Strict source-container normalization for firmware images."""
from __future__ import annotations

from dataclasses import dataclass
import binascii
import hashlib
from io import BytesIO
from pathlib import Path
import struct
import zipfile


MAX_LOGICAL_IMAGE_SIZE = 64 * 1024 * 1024
MAX_HEX_SOURCE_SIZE = 256 * 1024 * 1024
MAX_HXB_SOURCE_SIZE = 320 * 1024 * 1024
MAX_HXB_MEMBERS = 4096
ADDRESS_SPACE = 1 << 32


@dataclass(frozen=True, slots=True)
class LoadedFirmwareImage:
    image: bytes
    source_size: int
    source_sha256: str
    format: str


def _invalid_hex(reason: str) -> ValueError:
    return ValueError(f"invalid Intel HEX: {reason}")


def decode_intel_hex(raw: bytes) -> bytes:
    """Decode one bounded Intel HEX stream; reject every ambiguous shape."""
    if not raw or len(raw) > MAX_HEX_SOURCE_SIZE:
        raise _invalid_hex("source size")

    base = 0
    eof = False
    segments: list[tuple[int, bytes]] = []
    first_address = ADDRESS_SPACE
    last_address = 0
    payload_size = 0

    for source_line in BytesIO(raw):
        line = source_line.rstrip(b"\r\n")
        if not line:
            continue
        if eof:
            raise _invalid_hex("record after EOF")
        if len(line) < 11 or line[0] != 0x3A or (len(line) - 1) % 2:
            raise _invalid_hex("record syntax")
        try:
            record = binascii.unhexlify(line[1:])
        except (binascii.Error, ValueError):
            raise _invalid_hex("record syntax") from None
        if len(record) != record[0] + 5:
            raise _invalid_hex("byte count")
        if sum(record) & 0xFF:
            raise _invalid_hex("checksum")

        count = record[0]
        address = int.from_bytes(record[1:3], "big")
        kind = record[3]
        payload = record[4:-1]
        if kind == 0:
            begin = base + address
            end = begin + count
            if end > ADDRESS_SPACE:
                raise _invalid_hex("32-bit address overflow")
            if count:
                first_address = min(first_address, begin)
                last_address = max(last_address, end)
                payload_size += count
                if (payload_size > MAX_LOGICAL_IMAGE_SIZE
                        or last_address - first_address > MAX_LOGICAL_IMAGE_SIZE):
                    raise _invalid_hex("logical image size")
                segments.append((begin, payload))
        elif kind == 1:
            if count or address:
                raise _invalid_hex("EOF shape")
            eof = True
        elif kind == 2:
            if count != 2 or address:
                raise _invalid_hex("extended segment address shape")
            base = int.from_bytes(payload, "big") << 4
        elif kind == 4:
            if count != 2 or address:
                raise _invalid_hex("extended linear address shape")
            base = int.from_bytes(payload, "big") << 16
        elif kind in (3, 5):
            if count != 4 or address:
                raise _invalid_hex("start address shape")
        else:
            raise _invalid_hex("unsupported record type")

    if not eof:
        raise _invalid_hex("missing EOF")
    if not segments:
        raise _invalid_hex("empty payload")

    segments.sort(key=lambda item: item[0])
    previous_end = segments[0][0]
    for begin, payload in segments:
        if begin < previous_end:
            raise _invalid_hex("overlapping data")
        previous_end = begin + len(payload)

    image = bytearray(b"\xFF" * (last_address - first_address))
    for begin, payload in segments:
        offset = begin - first_address
        image[offset:offset + len(payload)] = payload
    return bytes(image)


def _hxb_member_count(raw: bytes) -> int:
    """Read classic EOCD before ZipFile materializes its central directory."""
    lower = max(0, len(raw) - 65557)
    cursor = len(raw)
    while True:
        position = raw.rfind(b"PK\x05\x06", lower, cursor)
        if position < 0:
            raise ValueError("invalid HXB: missing end-of-central-directory")
        if position + 22 <= len(raw):
            fields = struct.unpack_from("<4s4H2LH", raw, position)
            disk, central_disk, disk_entries, entries = fields[1:5]
            central_size, central_offset, comment_size = fields[5:]
            if position + 22 + comment_size == len(raw):
                if (disk or central_disk or disk_entries != entries):
                    raise ValueError("invalid HXB: multi-disk archive")
                if (entries == 0xFFFF or central_size == 0xFFFFFFFF
                        or central_offset == 0xFFFFFFFF):
                    raise ValueError("invalid HXB: ZIP64 archive")
                if entries > MAX_HXB_MEMBERS:
                    raise ValueError("invalid HXB: too many members")
                return entries
        cursor = position


def _decode_hxb(path: Path, raw: bytes) -> bytes:
    _hxb_member_count(raw)
    try:
        with zipfile.ZipFile(BytesIO(raw)) as archive:
            stem = path.stem.casefold()
            candidates = [
                member for member in archive.infolist()
                if (not member.is_dir()
                    and "/" not in member.filename
                    and "\\" not in member.filename
                    and member.filename.casefold().endswith(".hex")
                    and member.filename[:-4].casefold() == stem)
            ]
            if len(candidates) != 1:
                raise ValueError(
                    "invalid HXB: expected one top-level stem-matched HEX member"
                )
            member = candidates[0]
            if member.flag_bits & 1:
                raise ValueError("invalid HXB: encrypted HEX member")
            if member.file_size > MAX_HEX_SOURCE_SIZE:
                raise ValueError("invalid HXB: HEX member too large")
            with archive.open(member) as stream:
                encoded = stream.read(MAX_HEX_SOURCE_SIZE + 1)
            if len(encoded) > MAX_HEX_SOURCE_SIZE:
                raise ValueError("invalid HXB: HEX member too large")
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError,
            RuntimeError) as error:
        raise ValueError(f"invalid HXB: {error}") from None
    return decode_intel_hex(encoded)


def load_firmware_image(path: Path) -> LoadedFirmwareImage:
    """Read source identity and return bytes consumed by detector and runtime."""
    suffix = path.suffix.casefold()
    source_size = path.stat().st_size
    if suffix == ".hex" and source_size > MAX_HEX_SOURCE_SIZE:
        raise ValueError("invalid Intel HEX: source size")
    if suffix == ".hxb" and source_size > MAX_HXB_SOURCE_SIZE:
        raise ValueError("invalid HXB: source too large")
    raw = path.read_bytes()
    if suffix == ".hex" and len(raw) > MAX_HEX_SOURCE_SIZE:
        raise ValueError("invalid Intel HEX: source size")
    if suffix == ".hxb" and len(raw) > MAX_HXB_SOURCE_SIZE:
        raise ValueError("invalid HXB: source too large")
    if suffix == ".hex":
        image = decode_intel_hex(raw)
        format_name = "intel-hex"
    elif suffix == ".hxb":
        image = _decode_hxb(path, raw)
        format_name = "hxb-intel-hex"
    else:
        image = raw
        format_name = "raw"
    return LoadedFirmwareImage(
        image=image,
        source_size=len(raw),
        source_sha256=hashlib.sha256(raw).hexdigest(),
        format=format_name,
    )
