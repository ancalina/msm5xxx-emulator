"""Strict Intel HEX/HXB normalization regressions."""
from __future__ import annotations

from io import BytesIO
import hashlib
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

import msm5xxx_emulator.detection.firmware_image as firmware_image
from msm5xxx_emulator.core.lifecycle import LifecycleMixin
from msm5xxx_emulator.detection.firmware import detect
from msm5xxx_emulator.detection.firmware_image import (
    MAX_LOGICAL_IMAGE_SIZE, decode_intel_hex, load_firmware_image,
)
from msm5xxx_emulator.gui.settings import (
    parse_settings_values, settings_values, validate_settings_values,
)


def _record(address: int, kind: int, payload: bytes = b"") -> bytes:
    body = (bytes((len(payload),)) + address.to_bytes(2, "big")
            + bytes((kind,)) + payload)
    return b":" + (body + bytes((-sum(body) & 0xFF,))).hex().upper().encode() + b"\n"


def _hex_image(image: bytes, *, address: int = 0) -> bytes:
    records = []
    for offset in range(0, len(image), 16):
        records.append(_record(address + offset, 0, image[offset:offset + 16]))
    records.append(_record(0, 1))
    return b"".join(records)


class FirmwareImageTests(unittest.TestCase):
    def test_raw_source_is_unchanged(self) -> None:
        raw = b"\x00\x01\xFE\xFF"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "phone.bin"
            path.write_bytes(raw)
            loaded = load_firmware_image(path)
        self.assertEqual(loaded.image, raw)
        self.assertEqual(loaded.source_size, len(raw))
        self.assertEqual(loaded.source_sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(loaded.format, "raw")

    def test_hex_sparse_segment_and_linear_addresses_normalize(self) -> None:
        encoded = b"".join((
            _record(0, 4, b"\x00\x01"),
            _record(0x10, 0, b"\x01\x02"),
            _record(0x14, 0, b"\x03"),
            _record(0, 5, b"\x00\x01\x00\x10"),
            _record(0, 1),
        ))
        self.assertEqual(decode_intel_hex(encoded), b"\x01\x02\xFF\xFF\x03")

        segmented = b"".join((
            _record(0, 2, b"\x10\x00"),
            _record(0x20, 0, b"\xAA"),
            _record(0, 3, b"\x10\x00\x00\x20"),
            _record(0, 1),
        ))
        self.assertEqual(decode_intel_hex(segmented), b"\xAA")

    def test_hex_rejects_ambiguous_or_malformed_streams(self) -> None:
        data = _record(0, 0, b"\x01")
        eof = _record(0, 1)
        cases = {
            "checksum": data[:-3] + b"00\n" + eof,
            "missing-eof": data,
            "record-after-eof": eof + data,
            "equal-overlap": data + data + eof,
            "different-overlap": data + _record(0, 0, b"\x02") + eof,
            "overflow": (
                _record(0, 4, b"\xFF\xFF")
                + _record(0xFFFF, 0, b"\x01\x02") + eof
            ),
            "empty": eof,
            "oversize-span": (
                _record(0, 0, b"\x01")
                + _record(0, 4,
                          ((MAX_LOGICAL_IMAGE_SIZE >> 16)
                           .to_bytes(2, "big")))
                + _record(0, 0, b"\x02") + eof
            ),
            "unsupported": _record(0, 6) + eof,
            "prefix": b"vendor\n" + data + eof,
            "non-hex": b":01000000GGFF\n" + eof,
        }
        for name, encoded in cases.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                decode_intel_hex(encoded)

    def test_hxb_selects_only_top_level_stem_matched_member(self) -> None:
        wanted = _hex_image(b"\x01\x02")
        other = _hex_image(b"\x99")
        archive_bytes = BytesIO()
        with zipfile.ZipFile(archive_bytes, "w") as archive:
            archive.writestr("PHONE.hex", wanted)
            archive.writestr("armprg.hex", other)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "phone.hxb"
            path.write_bytes(b"MZ-stub" + archive_bytes.getvalue())
            loaded = load_firmware_image(path)
        self.assertEqual(loaded.image, b"\x01\x02")
        self.assertEqual(loaded.format, "hxb-intel-hex")

    def test_hxb_rejects_missing_or_nested_stem_match(self) -> None:
        for member_name in ("other.hex", "nested/phone.hex"):
            with self.subTest(member_name=member_name):
                archive_bytes = BytesIO()
                with zipfile.ZipFile(archive_bytes, "w") as archive:
                    archive.writestr(member_name, _hex_image(b"\x01"))
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "phone.hxb"
                    path.write_bytes(archive_bytes.getvalue())
                    with self.assertRaisesRegex(ValueError, "stem-matched"):
                        load_firmware_image(path)

    def test_hxb_bounds_outer_source_and_member_count(self) -> None:
        archive_bytes = BytesIO()
        with zipfile.ZipFile(archive_bytes, "w") as archive:
            archive.writestr("phone.hex", _hex_image(b"\x01"))
            archive.writestr("other.bin", b"\x00")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "phone.hxb"
            path.write_bytes(archive_bytes.getvalue())
            with mock.patch.object(
                    firmware_image, "MAX_HXB_SOURCE_SIZE",
                    path.stat().st_size - 1):
                with self.assertRaisesRegex(ValueError, "source too large"):
                    load_firmware_image(path)
            with mock.patch.object(firmware_image, "MAX_HXB_MEMBERS", 1):
                with self.assertRaisesRegex(ValueError, "too many members"):
                    load_firmware_image(path)
            with mock.patch.object(
                    firmware_image, "MAX_HEX_SOURCE_SIZE",
                    len(_hex_image(b"\x01")) - 1):
                with self.assertRaisesRegex(ValueError, "member too large"):
                    load_firmware_image(path)

    def test_detect_runtime_and_settings_share_logical_image(self) -> None:
        image = bytearray(b"\xFF" * 0x100)
        for offset in range(0, 32, 4):
            struct.pack_into("<I", image, offset, 0xEA000000)
        encoded = _hex_image(image)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "phone.hex"
            path.write_bytes(encoded)
            config = detect(path)
            available, _ram_seed = LifecycleMixin._load_primary_image(
                SimpleNamespace(), config, None
            )
            self.assertEqual(available[:len(image)], image)
            self.assertEqual(config.file_size, len(encoded))
            self.assertEqual(
                config.firmware_sha256, hashlib.sha256(encoded).hexdigest()
            )

            raw_settings = settings_values(path, config, {})
            parsed = parse_settings_values(raw_settings)
            overrides = {name: getattr(config, name) for name in parsed}
            overrides["image_offset"] = len(image)
            with self.assertRaisesRegex(ValueError, "이미지 오프셋"):
                validate_settings_values(
                    path, config, overrides, {"image_offset"},
                    raw_settings["flash_state"],
                )

            path.write_bytes(_hex_image(bytes(image[:-1]) + b"\x00"))
            with self.assertRaisesRegex(
                    ValueError, "firmware source changed after detection"):
                LifecycleMixin._load_primary_image(
                    SimpleNamespace(), config, None
                )


if __name__ == "__main__":
    unittest.main()
