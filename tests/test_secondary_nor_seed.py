import struct
import unittest

from msm5xxx_emulator.detection.devices.storage.secondary_nor_seed import (
    find_secondary_seed,
)


class SecondaryNorSeedTests(unittest.TestCase):
    bank_base = 0x12000000
    bank_length = 0x4000
    source_origin = 0x8000

    @staticmethod
    def _put_halfwords(image, offset, words):
        struct.pack_into("<" + "H" * len(words), image, offset, *words)

    def _image(self, *, mirrored=False):
        image = bytearray(0x10000)
        for function, record in ((0, self.bank_base + 0x100),
                                 (0x40, self.bank_base + 0x108)):
            literal = function + 0x30
            displacement = (literal - ((function + 4) & ~3)) // 4
            self._put_halfwords(image, function,
                (0x4900 | displacement, 0xE005, 0xBF00, 0xBF00,
                 0xBF00, 0xBF00, 0xBF00, 0xBF00,
                 0x6808, 0x60E0, 0x6848, 0x6120, 0x2002, 0x4770))
            struct.pack_into("<I", image, literal, record)
        for record_delta, payload_delta in ((0x100, 0x1000),
                                            (0x108, 0x2000)):
            record_offset = self.source_origin + record_delta
            payload = self.bank_base + payload_delta
            media = b"RIFF" + struct.pack("<I", 4) + b"TEST"
            struct.pack_into("<II", image, record_offset, payload, len(media))
            image[self.source_origin + payload_delta:
                  self.source_origin + payload_delta + len(media)] = media
        if mirrored:
            image[self.source_origin + self.bank_length:
                  self.source_origin + 2 * self.bank_length] = image[
                      self.source_origin:self.source_origin + self.bank_length]
        return image

    def _find(self, image):
        return find_secondary_seed(image, self.bank_base, self.bank_length,
                                   code_limit=0x100)

    def test_two_linked_records_select_aligned_source_bank(self):
        result = self._find(self._image())
        self.assertIsNotNone(result)
        self.assertEqual(result["source_offset"], self.source_origin)
        self.assertEqual(result["source_length"], self.bank_length)
        self.assertEqual(len(result["records"]), 2)
        self.assertEqual({record["format"] for record in result["records"]},
                         {"riff"})

    def test_cmid_uses_big_endian_parser_length(self):
        image = self._image()
        media = b"cmid" + (4).to_bytes(4, "big") + b"TEST"
        for record_delta, payload_delta in ((0x100, 0x1000),
                                            (0x108, 0x2000)):
            record_offset = self.source_origin + record_delta
            struct.pack_into("<I", image, record_offset + 4, len(media))
            start = self.source_origin + payload_delta
            image[start:start + len(media)] = media
        result = self._find(image)
        self.assertIsNotNone(result)
        self.assertEqual({record["format"] for record in result["records"]},
                         {"cmid"})

    def test_identical_mirror_windows_choose_lowest_origin(self):
        result = self._find(self._image(mirrored=True))
        self.assertIsNotNone(result)
        self.assertEqual(result["source_offset"], self.source_origin)
        self.assertEqual(result["identical_source_offsets"],
                         (self.source_origin, self.source_origin + self.bank_length))

    def test_nonidentical_mirrors_are_ambiguous(self):
        image = self._image(mirrored=True)
        image[self.source_origin + self.bank_length + 0x3000] ^= 1
        self.assertIsNone(self._find(image))

    def test_descriptor_base_clobber_is_rejected(self):
        image = self._image()
        # Overwrite the literal-derived R1 between the descriptor load and use.
        self._put_halfwords(image, 2, (0x2100, 0xE004))
        self.assertIsNone(self._find(image))

    def test_wrong_load_width_is_rejected(self):
        image = self._image()
        self._put_halfwords(image, 0x10, (0x8808, 0x60E0, 0x8848, 0x6120,
                                           0x2002, 0x4770))
        self.assertIsNone(self._find(image))

    def test_bad_descriptor_length_or_pointer_is_rejected(self):
        image = self._image()
        struct.pack_into("<I", image, self.source_origin + 0x104, 13)
        self.assertIsNone(self._find(image))
        image = self._image()
        struct.pack_into("<I", image, self.source_origin + 0x108,
                         self.bank_base + self.bank_length)
        self.assertIsNone(self._find(image))

    def test_unlinked_data_does_not_select_a_bank(self):
        image = self._image()
        image[:0x80] = bytes(0x80)
        self.assertIsNone(self._find(image))


if __name__ == "__main__":
    unittest.main()
