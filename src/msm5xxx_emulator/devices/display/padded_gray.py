"""Complete grayscale transfers from a source-qualified padded row writer."""


class PaddedGray:
    width = 128
    height = 160
    geometry_source = 'runtime:source-padded-gray'
    protocol = 'source-padded-gray'
    disable_fast = True

    def __init__(self):
        self.words = []
        self.qualified = False

    def write(self, address, size, value):
        if address != 0x02800010:
            self.words.clear()
            return False, None
        if size != 2 or not 0 <= value <= 0xffff:
            self.words.clear()
            return False, None
        self.words.append(value)
        if len(self.words) < 4 + self.height * self.width:
            return True, None
        words, self.words = self.words, []
        if (any(words[:4]) or
                any(words[4 + row * self.width + col]
                    for row in range(self.height) for col in range(120, 128))):
            return True, None
        pixels = words[:self.height * self.width]
        # shortcut: grayscale only; upgrade when colored pixel encoding is proven.
        # Only publish a transfer when all observed pixels encode equal
        # red and blue, with the corresponding six-bit green component.
        # Other pixel formats and colored transfers remain unclaimed.
        if any((p >> 11) != (p & 31) or ((p >> 5) & 63) not in
               (2 * (p & 31), 2 * (p & 31) + 1) for p in pixels):
            return True, None
        if not any(pixels) and not self.qualified:
            return True, None
        self.qualified = True
        frame = bytearray()
        for pixel in pixels:
            red, green, blue = pixel >> 11, (pixel >> 5) & 63, pixel & 31
            frame.extend(((red << 3) | (red >> 2),
                          (green << 2) | (green >> 4),
                          (blue << 3) | (blue >> 2)))
        return True, bytes(frame)
