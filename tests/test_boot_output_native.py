from pathlib import Path
import subprocess
import tempfile
import unittest

from test_protected_nor_native import function


class BootOutputNativeTest(unittest.TestCase):
    def test_writes_are_retained_and_reads_remain_unknown(self):
        source = (Path(__file__).resolve().parents[1] / 'native/qemu/msm5xxx-poc.c').read_text()
        harness = r'''
#include <assert.h>
#include <stdint.h>
typedef uint64_t hwaddr;
typedef int MemTxAttrs;
typedef enum { MEMTX_OK, MEMTX_DECODE_ERROR } MemTxResult;
'''
        harness += '\n'.join(function(source, name) for name in (
            'msm5xxx_poc_boot_output_read', 'msm5xxx_poc_boot_output_write'))
        harness += r'''
int main(void) {
    uint32_t output = 0;
    uint64_t value = 0xfeed;
    assert(msm5xxx_poc_boot_output_write(&output, 0, 0x10008, 2, 0) == MEMTX_OK);
    assert(output == 8);
    assert(msm5xxx_poc_boot_output_write(&output, 0, 0, 2, 0) == MEMTX_OK);
    assert(output == 0);
    assert(msm5xxx_poc_boot_output_write(&output, 0, 3, 4, 0) == MEMTX_OK);
    assert(output == 3);
    assert(msm5xxx_poc_boot_output_read(&output, 0, &value, 4, 0) == MEMTX_DECODE_ERROR);
    assert(value == 0xfeed);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'check.c').write_text(harness)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            str(path / 'check.c'), '-o', str(path / 'check')], check=True)
            subprocess.run([str(path / 'check')], check=True)
