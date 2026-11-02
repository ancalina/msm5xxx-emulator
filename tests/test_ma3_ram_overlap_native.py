"""Exercise MA3 RAM-overlap dispatch and RAM fallback with QEMU stubs."""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


class MA3RAMOverlapNativeTests(unittest.TestCase):
    def test_owned_bytes_and_ram_fallback_across_unaligned_ranges(self):
        native = Path(__file__).resolve().parents[1] / "native/qemu"
        source = (native / "msm5xxx-poc.c").read_text()

        def function(name):
            match = re.search(r"^static [^;\n]*\b" + name +
                              r"\([^;]*?\)\n\{", source, re.MULTILINE)
            self.assertIsNotNone(match, name)
            opening = source.index("{", match.start())
            depth, end = 1, opening + 1
            while depth:
                depth += (source[end] == "{") - (source[end] == "}")
                end += 1
            return source[match.start():end]

        helpers = "\n".join((
            function("msm5xxx_poc_backing_read"),
            function("msm5xxx_poc_backing_write"),
            function("msm5xxx_poc_audio_site_owned"),
            function("msm5xxx_poc_ma3_ram_overlap_sites_valid"),
            function("msm5xxx_poc_ma3_ram_overlap_profile_valid"),
            function("msm5xxx_poc_audio_ram_overlap_read"),
            function("msm5xxx_poc_audio_ram_overlap_write"),
        ))
        harness = r'''#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
typedef uint64_t hwaddr;
typedef int MemTxAttrs;
typedef enum { MEMTX_OK, MEMTX_ERROR } MemTxResult;
typedef struct MemoryRegion { uint8_t *data; } MemoryRegion;
typedef struct MachineState { uint64_t ram_size; MemoryRegion *ram; } MachineState;
typedef struct CPUState CPUState;
struct CPUState { bool running; struct { bool can_do_io; } neg; };
typedef struct {
    MachineState machine;
    MemoryRegion *ram;
    uint32_t ram_base, audio_base;
    uint32_t primary_nor_size;
    uint32_t ram_reserved_size;
    uint8_t audio_data_offset;
    bool audio_site_write[8];
    uint8_t audio_site_port[8];
    uint32_t audio_site_pc[8];
    unsigned audio_site_count;
    bool audio_sites_enabled;
    bool audio_ma3, memory_profile_enabled;
    CPUState *cpu;
} MSM5xxxPOCMachineState;
#define MACHINE(s) (&(s)->machine)
#define CPU(p) (p)
#define CPU_GET_CLASS(cpu) ((cpu)->cc)
static CPUState *current_cpu;
static uint8_t *memory_region_get_ram_ptr(MemoryRegion *r) { return r->data; }
static uint64_t dirty_offset;
static unsigned dirty_size, dirty_calls;
static void memory_region_set_dirty(MemoryRegion *r, hwaddr at, hwaddr size) {
    assert(r && size); dirty_offset=at; dirty_size=size; dirty_calls++;
}
static bool qemu_in_vcpu_thread(void) { return true; }
static uint32_t current_pc;
static bool precise_pc_valid=true;
static bool msm5xxx_poc_mmio_access_pc(MSM5xxxPOCMachineState *s, uint32_t *pc) {
    if (!precise_pc_valid || current_cpu != s->cpu) return false;
    *pc=current_pc; return true;
}
static unsigned opaque_reads, opaque_writes;
static MemTxResult msm5xxx_poc_audio_opaque_read(void *opaque, hwaddr offset,
    uint64_t *value, unsigned size, MemTxAttrs attrs) {
    (void)opaque; (void)attrs; assert(size==1); opaque_reads++;
    *value=0xa0+offset; return MEMTX_OK;
}
static MemTxResult msm5xxx_poc_audio_opaque_write(void *opaque, hwaddr offset,
    uint64_t value, unsigned size, MemTxAttrs attrs) {
    (void)opaque; (void)attrs; assert(size==1); opaque_writes++;
    assert(value==0x5a && (offset==0 || offset==2)); return MEMTX_OK;
}
#define AUDIO_BASE 0x01400000u
#define RAM_BASE 0x01000000u
#define RAM_SIZE 0x00800000u
#define RAM_AUDIO_OFFSET (AUDIO_BASE-RAM_BASE)
''' + helpers + r'''
int main(void) {
    static uint8_t bytes[RAM_SIZE];
    MemoryRegion ram={.data=bytes};
    CPUState cpu={.running=true,.neg={.can_do_io=true}};
    MSM5xxxPOCMachineState s={0};
    uint64_t value;
    memset(bytes,0,sizeof(bytes));
    s.machine.ram_size=RAM_SIZE; s.machine.ram=&ram; s.ram=&ram;
    s.ram_base=RAM_BASE; s.audio_base=AUDIO_BASE; s.audio_data_offset=2;
    s.primary_nor_size=0x01000000;
    s.audio_sites_enabled=true; s.audio_site_count=4; s.cpu=&cpu; current_cpu=&cpu;
    s.audio_ma3=true; s.memory_profile_enabled=true;
    s.audio_site_write[0]=true;  s.audio_site_port[0]=0; s.audio_site_pc[0]=0x8c53c;
    s.audio_site_write[1]=false; s.audio_site_port[1]=0; s.audio_site_pc[1]=0x8c54e;
    s.audio_site_write[2]=true;  s.audio_site_port[2]=2; s.audio_site_pc[2]=0x8c566;
    s.audio_site_write[3]=false; s.audio_site_port[3]=2; s.audio_site_pc[3]=0x8c578;
    assert(msm5xxx_poc_ma3_ram_overlap_sites_valid(&s));
    assert(msm5xxx_poc_ma3_ram_overlap_profile_valid(&s,RAM_SIZE));
    assert(!msm5xxx_poc_ma3_ram_overlap_profile_valid(&s,RAM_SIZE-0x1000));
    s.audio_site_pc[3]++;
    assert(!msm5xxx_poc_ma3_ram_overlap_sites_valid(&s));
    assert(!msm5xxx_poc_ma3_ram_overlap_profile_valid(&s,RAM_SIZE));
    s.audio_site_pc[3]--;

    /* Only exact read/write PC+port byte pairs dispatch to the opaque device. */
    current_pc=0x8c54e; value=0;
    assert(msm5xxx_poc_audio_ram_overlap_read(&s,3,&value,1,0)==MEMTX_OK);
    assert(value==0xa0 && opaque_reads==1);
    current_pc=0x8c578; value=0;
    assert(msm5xxx_poc_audio_ram_overlap_read(&s,5,&value,1,0)==MEMTX_OK);
    assert(value==0xa2 && opaque_reads==2);
    precise_pc_valid=false; current_pc=0x8c54e; value=0;
    assert(msm5xxx_poc_audio_ram_overlap_read(&s,3,&value,1,0)==MEMTX_OK);
    assert(value==bytes[3] && opaque_reads==2);
    precise_pc_valid=true;
    current_pc=0x8c53c;
    assert(msm5xxx_poc_audio_ram_overlap_write(&s,3,0x5a,1,0)==MEMTX_OK);
    assert(opaque_writes==1 && dirty_calls==0);
    current_pc=0x8c566;
    assert(msm5xxx_poc_audio_ram_overlap_write(&s,5,0x5a,1,0)==MEMTX_OK);
    assert(opaque_writes==2 && dirty_calls==0);

    /* Foreign PCs, wrong direction, and non-byte operations stay ordinary RAM. */
    current_pc=0x8c53c; bytes[RAM_AUDIO_OFFSET]=0x31; value=0;
    assert(msm5xxx_poc_audio_ram_overlap_read(&s,3,&value,1,0)==MEMTX_OK);
    assert(value==0x31 && opaque_reads==2);
    current_pc=0x8c54e;
    assert(msm5xxx_poc_audio_ram_overlap_write(&s,3,0x5a,1,0)==MEMTX_OK);
    assert(bytes[RAM_AUDIO_OFFSET]==0x5a && dirty_calls==1 &&
           dirty_offset==RAM_AUDIO_OFFSET && dirty_size==1);

    /* Exercise sizes 1..4, including unaligned spans crossing each port. */
    for (unsigned n=1;n<=4;n++) {
        unsigned at=3+n%3;
        uint64_t pattern=0x44332211u;
        dirty_calls=0;
        current_pc=0xdeadbeec;
        assert(msm5xxx_poc_audio_ram_overlap_write(&s,at,pattern,n,0)==MEMTX_OK);
        assert(dirty_calls==1 && dirty_offset==RAM_AUDIO_OFFSET-3+at &&
               dirty_size==n);
        value=0;
        assert(msm5xxx_poc_audio_ram_overlap_read(&s,at,&value,n,0)==MEMTX_OK);
        assert(value==(pattern & ((1ull<<(8*n))-1)));
    }
    /* Cross-boundary four-byte accesses are RAM transactions, never chip I/O. */
    current_pc=0x8c53c;
    assert(msm5xxx_poc_audio_ram_overlap_write(&s,2,0x88776655,4,0)==MEMTX_OK);
    assert(opaque_writes==2 && dirty_size==4);
    value=0; assert(msm5xxx_poc_audio_ram_overlap_read(&s,2,&value,4,0)==MEMTX_OK);
    assert(value==0x88776655 && opaque_reads==2);
    current_pc=0x8c566;
    assert(msm5xxx_poc_audio_ram_overlap_write(&s,4,0x12345678,4,0)==MEMTX_OK);
    assert(opaque_writes==2 && dirty_size==4);
    value=0; assert(msm5xxx_poc_audio_ram_overlap_read(&s,4,&value,4,0)==MEMTX_OK);
    assert(value==0x12345678 && opaque_reads==2);
    assert(msm5xxx_poc_audio_ram_overlap_read(&s,0,NULL,1,0)==MEMTX_ERROR);
    assert(msm5xxx_poc_audio_ram_overlap_read(&s,0,&value,5,0)==MEMTX_ERROR);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            c = Path(temporary) / "ma3-overlap.c"
            binary = Path(temporary) / "ma3-overlap"
            c.write_text(harness, encoding="utf-8")
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-pedantic", "-o", str(binary), str(c)],
                           check=True, capture_output=True, text=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
