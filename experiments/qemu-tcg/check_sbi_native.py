#!/usr/bin/env python3
"""Check native SBI admission/readback with a paused QEMU, without firmware."""
import argparse
import select
import subprocess
import tempfile


def check(qemu, mode):
    machine = "msm5xxx-poc,sbi=on,board-adc-value=194"
    if mode == "bootstrap-only":
        machine += ",sbi-bootstrap-only=on"
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(
            [qemu, "-machine", machine, "-accel", "tcg", "-S",
             "-display", "none", "-monitor", "none", "-serial", "none",
             "-qtest", "stdio"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors,
            text=True, bufsize=1,
        )

        def command(operation, offset, value=None, base=0x03000780):
            request = f"{operation} {base + offset:#x}"
            if value is not None:
                request += f" {value:#x}"
            process.stdin.write(request + "\n")
            process.stdin.flush()
            if not select.select([process.stdout], [], [], 5)[0]:
                raise RuntimeError(f"qtest timed out: {request}")
            response = process.stdout.readline().split()
            if not response or response[0] != "OK":
                errors.seek(0)
                raise RuntimeError(f"qtest failed: {request}: {response}: {errors.read().decode()}")
            return int(response[1], 0) if len(response) > 1 else None

        try:
            for operation, offset, value in (
                ("writeb", 0, 0x45), ("writeb", 0, 0xC5),
                ("writew", 4, 0x085F), ("writew", 12, 0x041F),
                ("writeb", 16, 0), ("writeb", 16, 1),
            ):
                command(operation, offset, value)
            assert command("readw", 0) == 0x5F20
            command("writew", 12, 0x0900)
            assert command("readw", 0) == 0x5F20
            command("writew", 4, 0x086A)
            command("writew", 12, 0x0AA0)
            command("writeb", 16, 0)
            command("writeb", 16, 1)
            command("readw", 0)
            command("writew", 12, 0x0A20)
            command("readw", 0)
            if mode != "ordinary":
                command("writew", 12, 0x0C81 if mode == "wrong-value" else 0x0C80)
                if mode != "missing-poll":
                    command("readb" if mode == "wrong-poll-width" else "readw", 0)
            command("writew", 12, 0x8B00)
            command("readw", 0)
            value = command("readw", 12)
            count = command("readl", 0x34, base=0x10000000)
            accepted = mode in ("ordinary", "extended")
            assert (value, count) == ((0x8BC2, 1) if accepted else (0x8B00, 0)), (mode, value, count)
            assert command("readw", 12) == 0x8B00  # No second synthesized reply.
        finally:
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            process.stdin.close()
            process.stdout.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("qemu")
    args = parser.parse_args()
    for mode in ("ordinary", "extended", "wrong-value", "missing-poll",
                 "wrong-poll-width", "bootstrap-only"):
        check(args.qemu, mode)
        print(f"{mode}: PASS", flush=True)
