"""Exercise the SD810 accessory input against its shared GPIO latch."""
from pathlib import Path
import unittest

from test_matrix_row734_native import native_function, compile_and_run


class SD810AccessoryTests(unittest.TestCase):
    def test_disconnected_contact_preserves_latch_and_requires_descriptor(self):
        source = (Path(__file__).resolve().parents[1] / 'native/qemu/msm5xxx-poc.c').read_text()
        functions = ''.join(native_function(source, name) for name in (
            'msm5xxx_poc_sd810_accessory_read', 'msm5xxx_poc_sd810_accessory_write'))
        compile_and_run(r'''
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#define hwaddr uint64_t
#define MSM5XXX_POC_MSM_BASE 0x03000000
#define CPU(p) (p)
typedef struct { bool can_do_io; } Neg;
typedef struct { bool running; Neg neg; } CPUState;
typedef struct { uint8_t bytes[0x800]; } Region;
typedef struct { Region msm; CPUState *cpu; uint32_t board_status_input_descriptor; } MSM5xxxPOCMachineState;
static CPUState *current_cpu; static bool in_vcpu = true; static uint32_t port;
static bool qemu_in_vcpu_thread(void) { return in_vcpu; }
static uint8_t *memory_region_get_ram_ptr(Region *r) { return r->bytes; }
static uint32_t msm5xxx_poc_guest_u32(uint32_t address) { (void)address; return port; }
static uint64_t msm5xxx_poc_backing_read(uint8_t *p, unsigned off, unsigned size) {
    uint64_t v=0; for(unsigned i=0;i<size;i++) v|=(uint64_t)p[off+i]<<(8*i); return v;
}
static void msm5xxx_poc_backing_write(uint8_t *p, unsigned off, uint64_t v, unsigned size) {
    for(unsigned i=0;i<size;i++) p[off+i]=v>>(8*i);
}
''' + functions + r'''
int main(void) {
    CPUState cpu={.running=true,.neg={.can_do_io=true}};
    MSM5xxxPOCMachineState s={.cpu=&cpu,.board_status_input_descriptor=0x1816618};
    current_cpu=&cpu; port=0x3000724;
    msm5xxx_poc_sd810_accessory_write(&s,0,0x123,2);
    assert(msm5xxx_poc_sd810_accessory_read(&s,0,2)==0x523);
    assert(msm5xxx_poc_sd810_accessory_read(&s,0,1)==0x23);
    assert(msm5xxx_poc_sd810_accessory_read(&s,1,1)==1);
    port=0; assert(msm5xxx_poc_sd810_accessory_read(&s,0,2)==0x123);
    port=0x3000724; in_vcpu=false;
    assert(msm5xxx_poc_sd810_accessory_read(&s,0,2)==0x123);
}
''')
