"""Write two minimal, synthetic ARM images outside the checkout for device checks."""
import json
from pathlib import Path
import struct
import sys

from msm5xxx_android_runtime import detect_profile


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: make_session_fixtures.py OUTPUT_DIRECTORY")
    directory = Path(sys.argv[1]).resolve()
    checkout = Path(__file__).resolve().parents[2]
    if directory == checkout or checkout in directory.parents:
        raise SystemExit("use an output directory outside the checkout")
    directory.mkdir(parents=True, exist_ok=True)
    for name, fill in (("session-a.bin", 0), ("session-b.bin", 255)):
        image = bytearray([fill]) * (1024 * 1024)
        for index in range(8):
            address = index * 4
            instruction = 0xea000000 | ((0x100 - address - 8) // 4)
            struct.pack_into("<I", image, address, instruction)
        # A self-branch keeps the image deterministic without real device code.
        struct.pack_into("<I", image, 0x100, 0xeafffffe)
        path = directory / name
        path.write_bytes(image)
        result = json.loads(detect_profile(str(path)))
        if not result["accepted"]:
            path.unlink()
            raise RuntimeError("synthetic image rejected: " + str(result["reject_reason"]))
        print(f"{path}: admitted")


if __name__ == "__main__":
    main()
