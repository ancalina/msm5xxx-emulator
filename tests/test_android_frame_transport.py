"""Static contract for Android visible-frame diagnostics."""
from pathlib import Path
import unittest


JAVA = (Path(__file__).parents[1]
        / "android-client/app/src/main/java/org/msm5xxx/emulator/"
        "MainActivity.java")


class AndroidFrameTransportTests(unittest.TestCase):
    def test_visible_swap_keeps_packet_sequence_hash_and_generation(self) -> None:
        source = JAVA.read_text(encoding="utf-8")

        self.assertIn("int sequence = buffer.getInt();", source)
        self.assertIn(
            "digest.update(packet, offset, packet.length - offset);", source
        )
        self.assertIn("frameView.setFrame(frame, generation);", source)
        self.assertIn('"visible swap generation=" + generation', source)
        self.assertIn('" sequence=" + Integer.toUnsignedString(frame.sequence)',
                      source)
        self.assertIn('" sha256=" + frame.sha256', source)
        self.assertIn('" nonBlank=" + frame.nonBlank', source)
        self.assertIn('" geometry=" + bitmap.getWidth()', source)


if __name__ == "__main__":
    unittest.main()
