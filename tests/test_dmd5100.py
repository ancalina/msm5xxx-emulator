"""Private original-ROM fixtures plus relocation, near-miss and mutation cases."""
from pathlib import Path
import hashlib
import struct
import unittest

from msm5xxx_emulator.detection.boot import DMD_DOWNLOAD_SIGNATURE
from msm5xxx_emulator.detection.dmd5100 import find_dmd5100_profile

_FIRMWARE_ROOT = Path(__file__).resolve().parents[1] / "firmwares"
_FIRMWARES = (
    ("T030", (_FIRMWARE_ROOT / "incoming-20260719-r1/MSM5100/T030TEDT09_5.177_JTAG.bin"), "f236bcf02a9f16e9e5aa0d13c714a832f5e1ed8dbd5da4d58278ecfd103338ed", 0x7C31C),
    ("T050", (_FIRMWARE_ROOT / "incoming-msm5xxx-all-manufacturers-20260726/Audiovox/CDM-8500/T050VMDM01_3.191_JTAG/T050VMDM01_3.191_JTAG.bin"), "67f47b9ab99e9f4c8477fc56d3b969f2dc02a9713ed28bb57b8812de557b0ef8", 0x83838),
    ("T055-full", (_FIRMWARE_ROOT / "incoming-20260719-r1/MSM5100/T055BW1T19_1.242_JTAG.bin"), "24bf05931ac81cce005b1ad5e970e061b38daf25ea3d70f658e2fa66fb801491", 0x92070),
    ("T055-partial", (_FIRMWARE_ROOT / "incoming-msm5xxx-candidates-20260726/Audiovox/CDM-8600/T055BM1T16_2.242_Memory/T055BM1T16_2.242_Memory.bin"), "3ce5fac1b66816972a11236f239d62207dd584f067c809a44922631e0cbd8753", 0x9205C),
)
_DRIVER_SIZE = 0xF4
_CALL_OFFSETS = (0x0E, 0x26, 0x4E, 0x56, 0xD0, 0xD8)


def _firmware(index=0):
    _, path, digest, _ = _FIRMWARES[index]
    if not path.is_file():
        raise unittest.SkipTest("private original firmware fixture unavailable")
    image = path.read_bytes()
    if hashlib.sha256(image).hexdigest() != digest:
        raise AssertionError("private original firmware fixture changed")
    return image


def _put_bl(image, address, target):
    displacement = target - address - 4
    if displacement & 1 or not -(1 << 22) <= displacement < (1 << 22):
        raise AssertionError("test BL target out of range")
    displacement &= (1 << 23) - 1
    struct.pack_into("<HH", image, address,
                     0xF000 | ((displacement >> 12) & 0x7FF),
                     0xF800 | ((displacement >> 1) & 0x7FF))


def _relocated_fixture():
    original = _firmware(0)
    old_entry = _FIRMWARES[0][3]
    entry, caller, descriptor, payload = 0x100, 0x800, 0x4000, 0x1800
    image = bytearray(0x6000)
    image[entry:entry + _DRIVER_SIZE] = original[old_entry:old_entry + _DRIVER_SIZE]
    for offset, target in zip(_CALL_OFFSETS,
                              (0x1000, 0x1100, 0x1100, 0x1018, 0x1200, 0x1300)):
        _put_bl(image, entry + offset, target)
    struct.pack_into("<IIIII", image, entry + 0xE0,
                     0x01000100, 0x03000050, descriptor, 0x030007E0,
                     descriptor + 8)
    image[descriptor:descriptor + 8] = struct.pack("<IHH", payload, 0, 0x1400)
    image[descriptor + 8:descriptor + 23] = b"dmddown_510x.c\0"
    image[payload:descriptor] = bytes(descriptor - payload)
    for helper in (0x1000, 0x1018, 0x1100, 0x1200, 0x1300):
        struct.pack_into("<H", image, helper, 0x4770)
    _put_bl(image, caller, entry)
    return image


class DMD5100DetectorTests(unittest.TestCase):
    def test_original_typed_peers_link_driver_descriptor_and_caller(self):
        expected = ((0x7C31C, 0x200348, 0x1FDB48),
                    (0x83838, 0x25C244, 0x259A44),
                    (0x92070, 0x25B500, 0x258D00),
                    (0x9205C, 0x25B2DC, 0x258ADC))
        for index, (entry, descriptor, payload) in enumerate(expected):
            with self.subTest(source=_FIRMWARES[index][0]):
                profile, reason = find_dmd5100_profile(_firmware(index))
                self.assertEqual(reason, "accepted")
                self.assertEqual(profile["entry_file_offset"], entry)
                self.assertEqual(profile["descriptor_file_offset"], descriptor)
                self.assertEqual(profile["payload_file_offset"], payload)
                self.assertEqual(profile["pair_count"], 0xA00)
                self.assertEqual(profile["halfword_count"], 0x1400)
                self.assertEqual(profile["mode"], 0)
                self.assertIn((entry, entry + _DRIVER_SIZE), profile["source_intervals"])
                self.assertEqual(profile["failure_report_code"],
                                 0xC7 if index >= 2 else 0xCA)

    def test_relocated_bl_and_literal_layout(self):
        image = _relocated_fixture()
        profile, reason = find_dmd5100_profile(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertEqual((profile["entry_file_offset"], profile["caller_file_offset"]),
                         (0x100, 0x800))
        self.assertEqual((profile["descriptor_file_offset"], profile["payload_file_offset"]),
                         (0x4000, 0x1800))
        self.assertEqual(profile["filename_file_interval"], (0x4008, 0x4017))
        self.assertIn(profile["filename_file_interval"], profile["source_intervals"])
        self.assertEqual(profile["signature"], "dmd5100-paired-program-readback-v1")
        self.assertEqual(profile["admission"], "temporary-evidence-gated")
        self.assertEqual(profile["callee_entries"], (0x1000, 0x1018, 0x1100, 0x1200, 0x1300))
        self.assertEqual(len(profile["source_intervals"]), len(set(profile["source_intervals"])))

    def test_callee_entries_and_required_literals_are_guarded(self):
        image = _relocated_fixture()
        profile, reason = find_dmd5100_profile(bytes(image))
        self.assertEqual(reason, "accepted")
        before = bytes(image)
        loaded = bytearray(image)
        struct.pack_into("<HH", loaded, 0x1000, 0x6008, 0x4770)
        self.assertTrue(any(before[start:end] != loaded[start:end]
                            for start, end in profile["source_intervals"]))

        image = _relocated_fixture()
        struct.pack_into("<H", image, 0x1000, 0x4800)
        struct.pack_into("<I", image, 0x1004, 0x12345678)
        profile, reason = find_dmd5100_profile(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertIn((0x1004, 0x1008), profile["source_intervals"])

    def test_driver_consumer_near_miss_and_caller_disconnect(self):
        image = _relocated_fixture()
        image[0x100 + 0x94] ^= 1
        profile, reason = find_dmd5100_profile(bytes(image))
        self.assertIsNone(profile)
        self.assertEqual(reason, "dmd5100-typed-driver-not-found")
        image = _relocated_fixture()
        _put_bl(image, 0x800, 0x900)
        profile, reason = find_dmd5100_profile(bytes(image))
        self.assertIsNone(profile)
        self.assertEqual(reason, "dmd5100-caller-missing-or-ambiguous")
        image = _relocated_fixture()
        struct.pack_into("<H", image, 0x100 + 0xD7, 0x21)
        profile, reason = find_dmd5100_profile(bytes(image))
        self.assertIsNone(profile)
        self.assertEqual(reason, "dmd5100-typed-driver-not-found")

    def test_callee_must_be_code_inside_the_loaded_guard_spans(self):
        for target in (0x100 + 0x3C, 0x800, 0x1800, 0x4000, 0x4008):
            with self.subTest(target=target):
                image = _relocated_fixture()
                _put_bl(image, 0x100 + 0x0E, target)
                profile, reason = find_dmd5100_profile(bytes(image))
                self.assertIsNone(profile)
                self.assertEqual(reason, "dmd5100-callee-aliases-source-data")

        for value in (0, 0xFFFF):
            with self.subTest(callee_word=value):
                image = _relocated_fixture()
                struct.pack_into("<H", image, 0x1000, value)
                profile, reason = find_dmd5100_profile(bytes(image))
                self.assertIsNone(profile)
                self.assertEqual(reason, "dmd5100-callee-empty-or-unreadable")

    def test_readback_consumer_cannot_load_a_different_descriptor(self):
        image = _relocated_fixture()
        image[0x100 + 0x66] ^= 1
        profile, reason = find_dmd5100_profile(bytes(image))
        self.assertIsNone(profile)
        self.assertEqual(reason, "dmd5100-typed-driver-not-found")

    def test_filename_span_is_bounded_nonempty_and_not_string_matched(self):
        image = _relocated_fixture()
        image[0x4008:0x400A] = b"x\0"
        profile, reason = find_dmd5100_profile(bytes(image))
        self.assertEqual(reason, "accepted")
        self.assertEqual(profile["filename_file_interval"], (0x4008, 0x400A))
        for value in (b"\0", b"x" * 0x38):
            with self.subTest(value=value[:4]):
                image = _relocated_fixture()
                image[0x4008:0x4040] = value.ljust(0x38, b"x")
                profile, reason = find_dmd5100_profile(bytes(image))
                self.assertIsNone(profile)
                self.assertEqual(reason, "dmd5100-readonly-string-unclosed")

    def test_descriptor_mode_count_and_payload_bounds(self):
        cases = ((0x4004, 1, "dmd5100-mode-unsupported"),
                 (0x4006, 0, "dmd5100-halfword-count-out-of-range"),
                 (0x4006, 3, "dmd5100-halfword-count-out-of-range"),
                 (0x4006, 0x1402, "dmd5100-halfword-count-out-of-range"))
        for offset, value, expected in cases:
            with self.subTest(offset=offset, value=value):
                image = _relocated_fixture()
                struct.pack_into("<H", image, offset, value)
                profile, reason = find_dmd5100_profile(bytes(image))
                self.assertIsNone(profile)
                self.assertEqual(reason, expected)
        image = _relocated_fixture()
        struct.pack_into("<I", image, 0x4000, 0x1802)
        profile, reason = find_dmd5100_profile(bytes(image))
        self.assertIsNone(profile)
        self.assertEqual(reason, "dmd5100-payload-range-unclosed")

    def test_duplicate_driver_and_caller_are_ambiguous(self):
        image = _relocated_fixture()
        image[0x500:0x500 + _DRIVER_SIZE] = image[0x100:0x100 + _DRIVER_SIZE]
        profile, reason = find_dmd5100_profile(bytes(image))
        self.assertIsNone(profile)
        self.assertEqual(reason, "dmd5100-typed-driver-ambiguous")
        image = _relocated_fixture()
        _put_bl(image, 0x820, 0x100)
        profile, reason = find_dmd5100_profile(bytes(image))
        self.assertIsNone(profile)
        self.assertEqual(reason, "dmd5100-caller-missing-or-ambiguous")

    def test_invalid_input_and_signature_near_miss(self):
        profile, reason = find_dmd5100_profile(None)
        self.assertIsNone(profile)
        self.assertEqual(reason, "dmd5100-image-not-bytes")
        image = _relocated_fixture()
        image[0x100:0x100 + len(DMD_DOWNLOAD_SIGNATURE)] = b"\0" * len(DMD_DOWNLOAD_SIGNATURE)
        profile, reason = find_dmd5100_profile(bytes(image))
        self.assertIsNone(profile)
        self.assertEqual(reason, "dmd5100-typed-driver-not-found")
