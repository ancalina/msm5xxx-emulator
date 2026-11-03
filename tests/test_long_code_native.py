"""Check the native CDMA long-code recurrence against direct chip steps."""
from pathlib import Path
import subprocess
import tempfile
import unittest


class LongCodeNativeTests(unittest.TestCase):
    def test_advance(self):
        native = Path(__file__).resolve().parents[1] / "native/qemu"
        source = r'''
#include "msm5xxx-search2.h"
#include <assert.h>
#include <stdint.h>
static uint64_t step(uint64_t s) {
    return ((s << 1) ^ ((s & (UINT64_C(1) << 41)) ?
            UINT64_C(0x40a8e6f04ef) : 0)) & ((UINT64_C(1) << 42) - 1);
}
int main(void) {
    uint64_t states[] = {0, 1, 3, UINT64_C(1) << 41, UINT64_C(0x319a0200000)};
    for (unsigned i = 0; i < sizeof(states)/sizeof(states[0]); i++) {
        uint64_t s = states[i];
        for (unsigned n = 0; n <= 10000; n++) {
            if (n < 100 || n % 97 == 0)
                assert(msm5xxx_long_code_advance(states[i], n) == s);
            s = step(s);
        }
    }
    assert(msm5xxx_long_code_advance(1, 32768) == UINT64_C(0x291cbe16bf9));
    assert(msm5xxx_long_code_advance(1, 393216) == UINT64_C(0x1478c2e38d1));
    assert(msm5xxx_long_code_advance(1, (UINT64_C(1) << 42) - 1) == 1);
    assert(msm5xxx_long_code_advance(UINT64_MAX, 0) == ((UINT64_C(1) << 42)-1));
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "test.c").write_text(source)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-I", str(native), str(path / "test.c"),
                            str(native / "msm5xxx-search2.c"), "-o", str(path / "test")],
                           check=True)
            subprocess.run([str(path / "test")], check=True)
